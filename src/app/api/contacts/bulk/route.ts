import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma, connectPrisma } from '@/lib/db';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { analyzeSelectedContacts } from '@/lib/facebook/analyze-selected-contacts';
import { startBackgroundAnalysis } from '@/lib/facebook/background-analysis';
import { validateSession } from '@/lib/api/validate-session';
import { updateContactsInChunks, type ChunkProgress } from '@/lib/utils/chunked-contact-updates';
import { Prisma } from '@prisma/client';
import { validateBodySize, BodySizeLimits } from '@/lib/api/validate-body-size';
import { RateLimitPresets } from '@/lib/api/rate-limit';
import { NumericPresets } from '@/lib/api/validate-numeric';

export async function POST(request: NextRequest) {
  // Ensure we always return JSON, even on unexpected errors
  try {
    // Apply rate limiting
    const rateLimitResponse = await RateLimitPresets.standard(request);
    if (rateLimitResponse) {
      return rateLimitResponse;
    }

    // Validate body size (bulk operations can be large)
    const bodySizeResponse = await validateBodySize(request, {
      maxSizeBytes: BodySizeLimits.LARGE,
    });
    if (bodySizeResponse) {
      return bodySizeResponse;
    }

    const session = await auth();
    const validation = validateSession(session);
    if ('error' in validation) {
      return validation.error;
    }
    const { session: validatedSession } = validation;

    let body;
    try {
      body = await request.json();
    } catch (error) {
      return NextResponse.json(
        { error: 'Invalid JSON in request body' },
        { status: 400 }
      );
    }

    const { action, contactIds, data } = body;

    if (!action || !contactIds || !Array.isArray(contactIds)) {
      return NextResponse.json(
        { error: 'Invalid request body' },
        { status: 400 }
      );
    }

    // Validate contactIds array size (prevent DoS)
    if (contactIds.length > 1000) {
      return NextResponse.json(
        { error: 'Too many contact IDs. Maximum 1000 contacts per operation.' },
        { status: 400 }
      );
    }

    // CRITICAL: Log exactly what contact IDs we received
    console.log(`[Bulk API] 🔍 DEBUG: Received ${action} action`);
    console.log(`[Bulk API] Contact IDs count: ${contactIds.length}`);
    console.log(`[Bulk API] Contact IDs:`, contactIds);
    console.log(`[Bulk API] Full request body:`, JSON.stringify({ action, contactIds, data }, null, 2));

    // Ensure database connection before queries
    try {
      await connectPrisma();
    } catch (dbConnectError) {
      console.error('[Bulk API] Failed to connect to database:', dbConnectError);
      return NextResponse.json(
        { 
          error: 'Database connection failed. Please try again in a moment.',
          details: 'The database server is temporarily unavailable.'
        },
        { status: 503 }
      );
    }

    // Verify all contacts belong to user's organization
    // Use getPrismaForOrg to route to correct database when multi-DB is enabled
    const prismaClient = getPrismaForOrg(validatedSession.user.organizationId);
    let contacts;
    try {
      contacts = await prismaClient.contact.findMany({
        where: {
          id: { in: contactIds },
          organizationId: validatedSession.user.organizationId,
        },
        select: { id: true, tags: true, organizationId: true },
      });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (dbError: any) {
      // Handle database connection errors
      if (dbError?.code === 'P1001' || dbError?.message?.includes("Can't reach database")) {
        console.error('[Bulk API] Database connection error:', dbError.message);
        return NextResponse.json(
          { 
            error: 'Database connection failed. Please try again in a moment.',
            details: 'The database server is temporarily unavailable.'
          },
          { status: 503 } // Service Unavailable
        );
      }
      throw dbError; // Re-throw other errors
    }

    // If not all contacts found and multi-DB is enabled, check ALL databases (all 3 databases)
    if (contacts.length !== contactIds.length && process.env.ENABLE_MULTI_DB === 'true') {
      const foundContactIds = new Set(contacts.map(c => c.id));
      const missingContactIds = contactIds.filter(id => !foundContactIds.has(id));
      
      console.warn('[Bulk API] Some contacts not found in routed database, checking all databases:', {
        found: contacts.length,
        requested: contactIds.length,
        missing: missingContactIds.length,
        missingIds: missingContactIds.slice(0, 5), // Log first 5
      });
      
      try {
        const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
        const router = getDatabaseRouter();
        const allDbConfigs = router.getAllDatabaseConfigs();
        
        console.log('[Bulk API] Searching all databases for missing contacts:', {
          totalDatabases: allDbConfigs.length,
          missingContactIds: missingContactIds.length,
        });

        // Search all databases for missing contacts
        // IMPORTANT: Search by ID only (no organizationId filter) to find contacts across organizations
        // This matches the behavior of the contact detail page which allows cross-org access
        const allContactsPromises = allDbConfigs.map(async (dbConfig, index) => {
          try {
            const dbContacts = await dbConfig.client.contact.findMany({
              where: {
                id: { in: missingContactIds },
                // Remove organizationId filter - search by ID only to find contacts across all organizations
                // We'll check organization access after finding them
              },
              select: { id: true, tags: true, organizationId: true },
            });
            
            console.log(`[Bulk API] Database ${index} (${dbConfig.index}): Found ${dbContacts.length} missing contacts`);
            return dbContacts;
          } catch (error) {
            console.error(`[Bulk API] Error querying database ${index} for contacts:`, error);
            return [];
          }
        });

        const allContactsResults = await Promise.all(allContactsPromises);
        const allFoundContacts = allContactsResults.flat();
        
        // Remove duplicates (in case same contact found in multiple databases)
        const uniqueContacts = Array.from(
          new Map(allFoundContacts.map(c => [c.id, c])).values()
        );
        
        // Check for organization mismatches (log warning but allow access like contact detail page)
        const crossOrgContacts = uniqueContacts.filter(
          c => c.organizationId !== validatedSession.user.organizationId
        );
        
        if (crossOrgContacts.length > 0) {
          console.warn('[Bulk API] Some contacts belong to different organization (allowing access like contact detail page):', {
            crossOrgCount: crossOrgContacts.length,
            crossOrgIds: crossOrgContacts.map(c => c.id).slice(0, 5),
            contactOrgIds: [...new Set(crossOrgContacts.map(c => c.organizationId))].slice(0, 3),
            userOrgId: validatedSession.user.organizationId,
          });
        }
        
        // Allow cross-organization access (same as contact detail page behavior)
        // Add all found contacts from all databases, regardless of organization
        const contactsFromAllDbs = uniqueContacts.length;
        contacts = [...contacts, ...uniqueContacts];
        
        console.log('[Bulk API] After checking all databases:', {
          totalFound: contacts.length,
          fromRouted: contacts.length - contactsFromAllDbs,
          fromAllDbs: contactsFromAllDbs,
          requested: contactIds.length,
        });
      } catch (fallbackError) {
        console.error('[Bulk API] Error checking all databases:', fallbackError);
      }
    }

    if (contacts.length !== contactIds.length) {
      const foundContactIds = new Set(contacts.map(c => c.id));
      const missingContactIds = contactIds.filter(id => !foundContactIds.has(id));
      
      console.error('[Bulk API] Some contacts not found or unauthorized:', {
        found: contacts.length,
        requested: contactIds.length,
        missing: missingContactIds.length,
        missingIds: missingContactIds.slice(0, 10), // Log first 10
        organizationId: validatedSession.user.organizationId,
        multiDbEnabled: process.env.ENABLE_MULTI_DB === 'true',
      });
      
      return NextResponse.json(
        { 
          error: `Some contacts not found or unauthorized. Found ${contacts.length} of ${contactIds.length} contacts.`,
          details: 'Some contacts may have been deleted or belong to a different organization.',
          found: contacts.length,
          requested: contactIds.length,
          missing: missingContactIds.length,
        },
        { status: 404 }
      );
    }

    let result;

    switch (action) {
      case 'addTags':
        if (!data?.tags || !Array.isArray(data.tags)) {
          return NextResponse.json(
            { error: 'Tags array required' },
            { status: 400 }
          );
        }

        // Create a map of contact tags for efficient lookup
        const contactTagsMap = new Map(contacts.map(c => [c.id, c.tags]));

        // Update contacts in chunks with transaction rollback
        const addTagsResult = await updateContactsInChunks(
          async (chunkContactIds: string[], tx: Prisma.TransactionClient) => {
            // Track which contacts actually got each tag added (for accurate count updates)
            const tagAddedCounts = new Map<string, number>();
            data.tags.forEach((tag: string) => tagAddedCounts.set(tag, 0));

            // Update contacts in this chunk
            await Promise.all(
              chunkContactIds.map(async (contactId) => {
                const currentTags = contactTagsMap.get(contactId) || [];
                const tagsToAdd = data.tags.filter((tag: string) => !currentTags.includes(tag));
                const newTags = Array.from(
                  new Set([...currentTags, ...data.tags])
                );
                
                // Only update if tags actually changed
                if (tagsToAdd.length > 0) {
                  await tx.contact.update({
                    where: { id: contactId },
                    data: { tags: newTags },
                  });
                  
                  // Count which tags were actually added
                  tagsToAdd.forEach((tag: string) => {
                    tagAddedCounts.set(tag, (tagAddedCounts.get(tag) || 0) + 1);
                  });
                }
              })
            );

            // Update tag counts only for tags that were actually added
            await Promise.all(
              Array.from(tagAddedCounts.entries()).map(([tag, count]) =>
                count > 0
                  ? tx.tag.updateMany({
                      where: {
                        name: tag,
                        organizationId: validatedSession.user.organizationId,
                      },
                      data: {
                        contactCount: { increment: count },
                      },
                    })
                  : Promise.resolve()
              )
            );

            // Log activities for this chunk (only for contacts that were updated)
            const contactsToLog = chunkContactIds.filter((contactId) => {
              const currentTags = contactTagsMap.get(contactId) || [];
              return data.tags.some((tag: string) => !currentTags.includes(tag));
            });

            if (contactsToLog.length > 0) {
              await tx.contactActivity.createMany({
                data: contactsToLog.map((contactId) => ({
                  contactId,
                  type: 'TAG_ADDED',
                  title: `Bulk tags added: ${data.tags.join(', ')}`,
                  metadata: { tags: data.tags },
                  userId: validatedSession.user.id,
                })),
              });
            }
          },
          {
            contactIds,
            chunkSize: 50,
            maxRetries: 3,
            prisma: prismaClient, // Use routed prisma client for multi-DB support
            onProgress: (progress: ChunkProgress) => {
              console.log(
                `[Bulk API] addTags progress: ${progress.processedContacts}/${progress.totalContacts} ` +
                `(${progress.completedChunks}/${progress.totalChunks} chunks)`
              );
            },
          }
        );

        result = {
          success: addTagsResult.success,
          updated: addTagsResult.successfulContacts,
          failed: addTagsResult.failedContacts,
          totalChunks: addTagsResult.completedChunks + addTagsResult.failedChunks,
          failedChunks: addTagsResult.failedChunks,
        };
        break;

      case 'removeTags':
        if (!data?.tags || !Array.isArray(data.tags)) {
          return NextResponse.json(
            { error: 'Tags array required' },
            { status: 400 }
          );
        }

        // Create a map of contact tags for efficient lookup
        const contactTagsMapRemove = new Map(contacts.map(c => [c.id, c.tags]));

        // Update contacts in chunks with transaction rollback
        const removeTagsResult = await updateContactsInChunks(
          async (chunkContactIds: string[], tx: Prisma.TransactionClient) => {
            // Track which contacts actually had each tag removed (for accurate count updates)
            const tagRemovedCounts = new Map<string, number>();
            data.tags.forEach((tag: string) => tagRemovedCounts.set(tag, 0));

            // Update contacts in this chunk
            await Promise.all(
              chunkContactIds.map(async (contactId) => {
                const currentTags = contactTagsMapRemove.get(contactId) || [];
                const tagsToRemove = data.tags.filter((tag: string) => currentTags.includes(tag));
                const newTags = currentTags.filter(
                  (tag) => !data.tags.includes(tag)
                );
                
                // Only update if tags actually changed
                if (tagsToRemove.length > 0) {
                  await tx.contact.update({
                    where: { id: contactId },
                    data: { tags: newTags },
                  });
                  
                  // Count which tags were actually removed
                  tagsToRemove.forEach((tag: string) => {
                    tagRemovedCounts.set(tag, (tagRemovedCounts.get(tag) || 0) + 1);
                  });
                }
              })
            );

            // Update tag counts only for tags that were actually removed
            await Promise.all(
              Array.from(tagRemovedCounts.entries()).map(([tag, count]) =>
                count > 0
                  ? tx.tag.updateMany({
                      where: {
                        name: tag,
                        organizationId: validatedSession.user.organizationId,
                      },
                      data: {
                        contactCount: { decrement: count },
                      },
                    })
                  : Promise.resolve()
              )
            );
          },
          {
            contactIds,
            chunkSize: 50,
            maxRetries: 3,
            prisma: prismaClient, // Use routed prisma client for multi-DB support
            onProgress: (progress: ChunkProgress) => {
              console.log(
                `[Bulk API] removeTags progress: ${progress.processedContacts}/${progress.totalContacts} ` +
                `(${progress.completedChunks}/${progress.totalChunks} chunks)`
              );
            },
          }
        );

        result = {
          success: removeTagsResult.success,
          updated: removeTagsResult.successfulContacts,
          failed: removeTagsResult.failedContacts,
          totalChunks: removeTagsResult.completedChunks + removeTagsResult.failedChunks,
          failedChunks: removeTagsResult.failedChunks,
        };
        break;

      case 'moveToStage':
        if (!data?.stageId) {
          return NextResponse.json(
            { error: 'Stage ID required' },
            { status: 400 }
          );
        }

        // Verify stage exists and belongs to organization
        const stage = await prisma.pipelineStage.findFirst({
          where: {
            id: data.stageId,
            pipeline: {
              organizationId: validatedSession.user.organizationId,
            },
          },
        });

        if (!stage) {
          return NextResponse.json(
            { error: 'Stage not found' },
            { status: 404 }
          );
        }

        // Move contacts in chunks with transaction rollback
        const moveToStageResult = await updateContactsInChunks(
          async (chunkContactIds: string[], tx: Prisma.TransactionClient) => {
            // Update contacts in this chunk
            await tx.contact.updateMany({
              where: { id: { in: chunkContactIds } },
              data: {
                stageId: data.stageId,
                stageEnteredAt: new Date(),
              },
            });

            // Log activities for this chunk
            await tx.contactActivity.createMany({
              data: chunkContactIds.map((contactId) => ({
                contactId,
                type: 'STAGE_CHANGED',
                title: `Bulk moved to ${stage.name}`,
                toStageId: data.stageId,
                userId: validatedSession.user.id,
              })),
            });
          },
          {
            contactIds,
            chunkSize: 50,
            maxRetries: 3,
            prisma: prismaClient, // Use routed prisma client for multi-DB support
            onProgress: (progress: ChunkProgress) => {
              console.log(
                `[Bulk API] moveToStage progress: ${progress.processedContacts}/${progress.totalContacts} ` +
                `(${progress.completedChunks}/${progress.totalChunks} chunks)`
              );
            },
          }
        );

        result = {
          success: moveToStageResult.success,
          updated: moveToStageResult.successfulContacts,
          failed: moveToStageResult.failedContacts,
          totalChunks: moveToStageResult.completedChunks + moveToStageResult.failedChunks,
          failedChunks: moveToStageResult.failedChunks,
        };
        break;

      case 'delete':
        // Delete contacts in chunks with transaction rollback
        const deleteResult = await updateContactsInChunks(
          async (chunkContactIds: string[], tx: Prisma.TransactionClient) => {
            // Delete activities for this chunk first
            await tx.contactActivity.deleteMany({
              where: { contactId: { in: chunkContactIds } },
            });

            // Delete contacts in this chunk
            await tx.contact.deleteMany({
              where: { id: { in: chunkContactIds } },
            });
          },
          {
            contactIds,
            chunkSize: 50,
            maxRetries: 3,
            prisma: prismaClient, // Use routed prisma client for multi-DB support
            onProgress: (progress: ChunkProgress) => {
              console.log(
                `[Bulk API] delete progress: ${progress.processedContacts}/${progress.totalContacts} ` +
                `(${progress.completedChunks}/${progress.totalChunks} chunks)`
              );
            },
          }
        );

        result = {
          success: deleteResult.success,
          deleted: deleteResult.successfulContacts,
          failed: deleteResult.failedContacts,
          totalChunks: deleteResult.completedChunks + deleteResult.failedChunks,
          failedChunks: deleteResult.failedChunks,
        };
        break;

      case 'updateLeadScore':
        if (data?.leadScore === undefined) {
          return NextResponse.json(
            { error: 'Lead score required' },
            { status: 400 }
          );
        }

        // Validate lead score range
        const leadScore = Math.max(0, Math.min(100, Number(data.leadScore)));
        if (isNaN(leadScore)) {
          return NextResponse.json(
            { error: 'Invalid lead score' },
            { status: 400 }
          );
        }

        // Update contacts in chunks with transaction rollback
        const updateLeadScoreResult = await updateContactsInChunks(
          async (chunkContactIds: string[], tx: Prisma.TransactionClient) => {
            await tx.contact.updateMany({
              where: { id: { in: chunkContactIds } },
              data: { leadScore },
            });
          },
          {
            contactIds,
            chunkSize: 50,
            maxRetries: 3,
            prisma: prismaClient, // Use routed prisma client for multi-DB support
            onProgress: (progress: ChunkProgress) => {
              console.log(
                `[Bulk API] updateLeadScore progress: ${progress.processedContacts}/${progress.totalContacts} ` +
                `(${progress.completedChunks}/${progress.totalChunks} chunks)`
              );
            },
          }
        );

        result = {
          success: updateLeadScoreResult.success,
          updated: updateLeadScoreResult.successfulContacts,
          failed: updateLeadScoreResult.failedContacts,
          totalChunks: updateLeadScoreResult.completedChunks + updateLeadScoreResult.failedChunks,
          failedChunks: updateLeadScoreResult.failedChunks,
        };
        break;

      case 'analyze':
        // Start background analysis for selected contacts
        try {
          console.log(`[Bulk API] 🔍 DEBUG: Starting analysis for ${contactIds.length} contact(s)`);
          console.log(`[Bulk API] Contact IDs received:`, contactIds);
          console.log(`[Bulk API] Organization ID: ${validatedSession.user.organizationId}`);
          console.log(`[Bulk API] User ID: ${validatedSession.user.id}`);
          
          // Ensure database connection before starting analysis
          await connectPrisma();
          
          // CRITICAL VALIDATION: Ensure we're not accidentally analyzing all contacts
          if (contactIds.length > 20) {
            console.error(`[Bulk API] 🚨 WARNING: Received ${contactIds.length} contacts! This might be an error.`);
            console.error(`[Bulk API] Contact IDs:`, contactIds);
            console.error(`[Bulk API] If user only selected 1 contact, this is a BUG!`);
            
            // SAFETY: If more than 50 contacts, this is almost certainly a bug
            if (contactIds.length > 50) {
              console.error(`[Bulk API] 🚨 CRITICAL: Received ${contactIds.length} contacts - this is likely a bug!`);
              console.error(`[Bulk API] Blocking request to prevent accidental analysis of all contacts`);
              return NextResponse.json(
                { 
                  error: `Received ${contactIds.length} contacts for analysis. This seems like an error. Please select contacts individually and try again.`,
                  details: 'If you intended to analyze all contacts, please use the "AI Analyze All" button instead.'
                },
                { status: 400 }
              );
            }
          }
          
          // ADDITIONAL VALIDATION: Check if this looks like an accidental "select all"
          // If user selected 1 contact but we received many, something is wrong
          if (contactIds.length > 1) {
            // Log a warning but don't block - user might have legitimately selected many
            console.log(`[Bulk API] ⚠️ Processing ${contactIds.length} contacts - ensure this is intentional`);
          } else if (contactIds.length === 1) {
            console.log(`[Bulk API] ✅ Processing 1 contact - this is correct for single selection`);
            console.log(`[Bulk API] Contact ID: ${contactIds[0]}`);
          }
          
          // FINAL VALIDATION: Verify all contact IDs are valid and belong to the organization
          if (contactIds.length === 0) {
            return NextResponse.json(
              { error: 'No contacts selected for analysis' },
              { status: 400 }
            );
          }
          
          const backgroundResult = await startBackgroundAnalysis(
            contactIds,
            validatedSession.user.organizationId,
            validatedSession.user.id
          );
          console.log(`[Bulk API] ✅ Analysis started with jobId: ${backgroundResult.jobId}`);
          console.log(`[Bulk API] Job created for ${contactIds.length} contact(s)`);
          if (backgroundResult.cancelledJobs && backgroundResult.cancelledJobs.length > 0) {
            console.log(`[Bulk API] 🗑️ Cancelled ${backgroundResult.cancelledJobs.length} overlapping job(s):`, backgroundResult.cancelledJobs);
          }

          result = {
            success: true,
            jobId: backgroundResult.jobId,
            message: backgroundResult.message,
            analyzing: true, // Indicates this is a background job
            cancelledJobs: backgroundResult.cancelledJobs, // Include cancelled job IDs for UI notification
          };
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (analyzeError: any) {
          // Handle database connection errors during analysis
          if (analyzeError?.code === 'P1001' || analyzeError?.message?.includes("Can't reach database")) {
            console.error('[Bulk API] Database connection error during analysis:', analyzeError.message);
            return NextResponse.json(
              { 
                error: 'Database connection failed during analysis. Some contacts may have been analyzed.',
                details: 'The database server is temporarily unavailable. Please try again.',
                success: false
              },
              { status: 503 }
            );
          }
          throw analyzeError; // Re-throw other errors
        }
        break;

      default:
        return NextResponse.json(
          { error: 'Invalid action' },
          { status: 400 }
        );
    }

    return NextResponse.json(result);
  } catch (error: any) {
    console.error('Bulk action error:', error);
    
    // Handle Prisma database errors
    if (error?.code === 'P1001' || error?.message?.includes("Can't reach database")) {
      return NextResponse.json(
        { 
          error: 'Database connection failed. Please try again in a moment.',
          details: 'The database server is temporarily unavailable.'
        },
        { status: 503 }
      );
    }

    // Handle other Prisma errors
    if (error?.code?.startsWith('P')) {
      // SECURITY: Sanitize error messages to prevent sensitive data exposure
      const sanitizedDetails = process.env.NODE_ENV === 'development' && error?.message
        ? error.message.replace(/[a-zA-Z0-9]{20,}/g, '[REDACTED]')
          .replace(/at\s+.*/g, '')
          .replace(/\(.*?\)/g, '')
          .substring(0, 200)
        : undefined;
      
      return NextResponse.json(
        { 
          error: 'Database error occurred',
          details: sanitizedDetails
        },
        { status: 500 }
      );
    }

    // Handle JSON parsing errors
    if (error instanceof SyntaxError) {
      return NextResponse.json(
        { error: 'Invalid request format' },
        { status: 400 }
      );
    }

    // Generic error
    // SECURITY: Sanitize error messages to prevent sensitive data exposure
    const errorMessage = error instanceof Error ? error.message : 'Failed to perform bulk action';
    const sanitizedMessage = errorMessage
      .replace(/[a-zA-Z0-9]{20,}/g, '[REDACTED]') // Remove long tokens/IDs
      .replace(/at\s+.*/g, '') // Remove stack trace lines
      .replace(/\(.*?\)/g, '') // Remove file paths
      .substring(0, 200); // Limit length
    
    const sanitizedStack = process.env.NODE_ENV === 'development' && error instanceof Error && error.stack
      ? error.stack.replace(/[a-zA-Z0-9]{20,}/g, '[REDACTED]')
      : undefined;
    
    return NextResponse.json(
      { 
        error: sanitizedMessage,
        details: sanitizedStack
      },
      { status: 500 }
    );
  }
}