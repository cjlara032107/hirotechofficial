import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { analyzeSelectedContacts } from '@/lib/facebook/analyze-selected-contacts';
import { startBackgroundAnalysis } from '@/lib/facebook/background-analysis';
import { validateSession } from '@/lib/api/validate-session';

export async function POST(request: NextRequest) {
  try {
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

    // CRITICAL: Log exactly what contact IDs we received
    console.log(`[Bulk API] 🔍 DEBUG: Received ${action} action`);
    console.log(`[Bulk API] Contact IDs count: ${contactIds.length}`);
    console.log(`[Bulk API] Contact IDs:`, contactIds);
    console.log(`[Bulk API] Full request body:`, JSON.stringify({ action, contactIds, data }, null, 2));

    // Verify all contacts belong to user's organization
    let contacts;
    try {
      contacts = await prisma.contact.findMany({
        where: {
          id: { in: contactIds },
          organizationId: validatedSession.user.organizationId,
        },
        select: { id: true, tags: true },
      });
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

    if (contacts.length !== contactIds.length) {
      return NextResponse.json(
        { error: 'Some contacts not found or unauthorized' },
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

        // Add tags to each contact
        await Promise.all(
          contacts.map(async (contact) => {
            const newTags = Array.from(
              new Set([...contact.tags, ...data.tags])
            );
            return prisma.contact.update({
              where: { id: contact.id },
              data: { tags: newTags },
            });
          })
        );

        // Update tag counts
        await Promise.all(
          data.tags.map((tag: string) =>
            prisma.tag.updateMany({
              where: {
                name: tag,
                organizationId: validatedSession.user.organizationId,
              },
              data: {
                contactCount: { increment: contactIds.length },
              },
            })
          )
        );

        // Log activities
        await prisma.contactActivity.createMany({
          data: contactIds.map((contactId) => ({
            contactId,
            type: 'TAG_ADDED',
            title: `Bulk tags added: ${data.tags.join(', ')}`,
            metadata: { tags: data.tags },
            userId: validatedSession.user.id,
          })),
        });

        result = { success: true, updated: contactIds.length };
        break;

      case 'removeTags':
        if (!data?.tags || !Array.isArray(data.tags)) {
          return NextResponse.json(
            { error: 'Tags array required' },
            { status: 400 }
          );
        }

        // Remove tags from each contact
        await Promise.all(
          contacts.map((contact) => {
            const newTags = contact.tags.filter(
              (tag) => !data.tags.includes(tag)
            );
            return prisma.contact.update({
              where: { id: contact.id },
              data: { tags: newTags },
            });
          })
        );

        // Update tag counts
        await Promise.all(
          data.tags.map((tag: string) =>
            prisma.tag.updateMany({
              where: {
                name: tag,
                organizationId: validatedSession.user.organizationId,
              },
              data: {
                contactCount: { decrement: contactIds.length },
              },
            })
          )
        );

        result = { success: true, updated: contactIds.length };
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

        // Move all contacts to stage
        await prisma.contact.updateMany({
          where: { id: { in: contactIds } },
          data: {
            stageId: data.stageId,
            stageEnteredAt: new Date(),
          },
        });

        // Log activities
        await prisma.contactActivity.createMany({
          data: contactIds.map((contactId) => ({
            contactId,
            type: 'STAGE_CHANGED',
            title: `Bulk moved to ${stage.name}`,
            toStageId: data.stageId,
            userId: validatedSession.user.id,
          })),
        });

        result = { success: true, updated: contactIds.length };
        break;

      case 'delete':
        // Delete all activities first
        await prisma.contactActivity.deleteMany({
          where: { contactId: { in: contactIds } },
        });

        // Delete contacts
        await prisma.contact.deleteMany({
          where: { id: { in: contactIds } },
        });

        result = { success: true, deleted: contactIds.length };
        break;

      case 'updateLeadScore':
        if (data?.leadScore === undefined) {
          return NextResponse.json(
            { error: 'Lead score required' },
            { status: 400 }
          );
        }

        await prisma.contact.updateMany({
          where: { id: { in: contactIds } },
          data: { leadScore: data.leadScore },
        });

        result = { success: true, updated: contactIds.length };
        break;

      case 'analyze':
        // Start background analysis for selected contacts
        try {
          console.log(`[Bulk API] 🔍 DEBUG: Starting analysis for ${contactIds.length} contact(s)`);
          console.log(`[Bulk API] Contact IDs received:`, contactIds);
          console.log(`[Bulk API] Organization ID: ${validatedSession.user.organizationId}`);
          console.log(`[Bulk API] User ID: ${validatedSession.user.id}`);
          
          // CRITICAL VALIDATION: Ensure we're not accidentally analyzing all contacts
          if (contactIds.length > 20) {
            console.error(`[Bulk API] 🚨 WARNING: Received ${contactIds.length} contacts! This might be an error.`);
            console.error(`[Bulk API] Contact IDs:`, contactIds);
          }
          
          const backgroundResult = await startBackgroundAnalysis(
            contactIds,
            validatedSession.user.organizationId,
            validatedSession.user.id
          );
          console.log(`[Bulk API] ✅ Analysis started with jobId: ${backgroundResult.jobId}`);
          console.log(`[Bulk API] Job created for ${contactIds.length} contact(s)`);

          result = {
            success: true,
            jobId: backgroundResult.jobId,
            message: backgroundResult.message,
            analyzing: true, // Indicates this is a background job
          };
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
      return NextResponse.json(
        { 
          error: 'Database error occurred',
          details: process.env.NODE_ENV === 'development' ? error.message : undefined
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
    const errorMessage = error instanceof Error ? error.message : 'Failed to perform bulk action';
    return NextResponse.json(
      { 
        error: errorMessage,
        details: process.env.NODE_ENV === 'development' ? error.stack : undefined
      },
      { status: 500 }
    );
  }
}

