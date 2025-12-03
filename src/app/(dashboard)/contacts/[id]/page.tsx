import { auth } from '@/auth';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { notFound, redirect } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { EditableNotes } from '@/components/contacts/editable-notes';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { ArrowLeft, MessageSquare } from 'lucide-react';
import { ContactTagEditorOptimized } from '@/components/contacts/contact-tag-editor-optimized';
import { ActivityTimeline } from '@/components/contacts/activity-timeline';
import { UpdateBestTimesButton } from '@/components/contacts/update-best-times-button';
// Debug: Uncomment to test
// import { UpdateBestTimesButton } from '@/components/contacts/update-best-times-button-debug';
import Link from 'next/link';
import { Suspense } from 'react';
import { Skeleton } from '@/components/ui/skeleton';
import { ContactDetailRefresh } from '@/components/contacts/contact-detail-refresh';

interface ContactDetailPageProps {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ returnTo?: string; pipelineId?: string; activityPage?: string }>;
}

// Separate data fetching functions with caching
async function getContact(id: string, organizationId: string) {
  // First try the expected organization's database
  let prisma = getPrismaForOrg(organizationId);
  try {
    // Log for debugging
    console.log(`[Contact Page] Fetching contact ${id} for organization ${organizationId}`);
    
    let contact = await prisma.contact.findFirst({
      where: {
        id,
        organizationId,
      },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        profilePicUrl: true,
        leadScore: true,
        leadStatus: true,
        hasMessenger: true,
        hasInstagram: true,
        tags: true,
        notes: true,
        aiContext: true,
        aiSummary: true,
        aiContextUpdatedAt: true,
        conversionProbability: true,
        buyerIntent: true,
        sentiment: true,
        productInterests: true,
        intentSignals: true,
        nextBestAction: true,
        agentSuggestions: true,
        contactInfo: true, // Include contact info (may not exist in production yet)
        bestContactTimes: true, // Include best contact times (may not exist in production yet)
        stage: {
          select: {
            id: true,
            name: true,
            color: true,
          },
        },
        pipeline: {
          select: {
            id: true,
            name: true,
          },
        },
      },
    });

    if (!contact) {
      // Contact not found in expected organization's database
      // Try searching across all databases (cross-database search)
      console.log(`[Contact Page] Contact ${id} not found in organization ${organizationId}, searching across all databases...`);
      
      const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
      const router = getDatabaseRouter();
      const allDatabases = router.getAllDatabaseConfigs();
      
      console.log(`[Contact Page] Searching ${allDatabases.length} database(s) for contact ${id}...`);
      
      let foundInDifferentOrg = false;
      type ContactResult = {
        id: string;
        organizationId: string;
        firstName: string;
        lastName: string | null;
        profilePicUrl: string | null;
        leadScore: number;
        leadStatus: any;
        hasMessenger: boolean;
        hasInstagram: boolean;
        tags: any;
        notes: string | null;
        aiContext: any;
        aiSummary: string | null;
        aiContextUpdatedAt: Date | null;
        conversionProbability?: number | null;
        buyerIntent?: string | null;
        sentiment?: string | null;
        productInterests?: string[] | null;
        intentSignals?: any;
        nextBestAction?: string | null;
        agentSuggestions?: string[] | null;
        contactInfo?: any;
        bestContactTimes?: any;
        stage?: { id: string; name: string; color: string } | null;
        pipeline?: { id: string; name: string } | null;
      };
      let foundContact: ContactResult | null = null;
      
      // Search across all databases - search by ID only (no organizationId filter)
      for (const db of allDatabases) {
        if (!db.client) {
          console.warn(`[Contact Page] ⚠️ Database ${db.index} client is undefined - skipping`);
          continue;
        }
        
        try {
          console.log(`[Contact Page] Searching database ${db.index} for contact ${id}...`);
          
          const searchResult = await db.client.contact.findFirst({
            where: { id }, // Search by ID only - no organizationId filter
            select: {
              id: true,
              organizationId: true,
              firstName: true,
              lastName: true,
              profilePicUrl: true,
              leadScore: true,
              leadStatus: true,
              hasMessenger: true,
              hasInstagram: true,
              tags: true,
              notes: true,
              aiContext: true,
              aiSummary: true,
              aiContextUpdatedAt: true,
              conversionProbability: true,
              buyerIntent: true,
              sentiment: true,
              productInterests: true,
              intentSignals: true,
              nextBestAction: true,
              agentSuggestions: true,
              contactInfo: true,
              bestContactTimes: true,
              stage: {
                select: {
                  id: true,
                  name: true,
                  color: true,
                },
              },
              pipeline: {
                select: {
                  id: true,
                  name: true,
                },
              },
            },
          });
          
          if (searchResult) {
            console.log(`[Contact Page] ✅ Found contact ${id} in database ${db.index}`);
            console.log(`[Contact Page] Contact organization: ${searchResult.organizationId}, User organization: ${organizationId}`);
            
            // Check if user has access
            if (searchResult.organizationId === organizationId) {
              // Same organization - return it
              console.log(`[Contact Page] ✅ Contact belongs to same organization - returning`);
              return searchResult;
            } else {
              // Different organization - log but continue searching
              console.warn(`[Contact Page] ⚠️ Contact ${id} found in database ${db.index} but belongs to organization ${searchResult.organizationId} (user is in ${organizationId})`);
              console.warn(`[Contact Page] Contact name: ${searchResult.firstName} ${searchResult.lastName}`);
              foundInDifferentOrg = true;
              foundContact = searchResult as ContactResult; // Store for potential error message
              // Continue searching - maybe it exists in the correct org's database
              continue;
            }
          } else {
            console.log(`[Contact Page] Contact ${id} not found in database ${db.index}`);
          }
        } catch (error) {
          // Database might be down or have connection issues - log and continue
          const errorMsg = error instanceof Error ? error.message : String(error);
          console.warn(`[Contact Page] ⚠️ Error searching database ${db.index} for contact ${id}:`, errorMsg);
          
          // If it's a schema error, try a simpler query
          if (errorMsg.includes('does not exist') || errorMsg.includes('P2022')) {
            try {
              console.log(`[Contact Page] Retrying with simpler query (without new columns) for database ${db.index}...`);
              const simpleResult = await db.client.contact.findFirst({
                where: { id },
                select: {
                  id: true,
                  organizationId: true,
                  firstName: true,
                  lastName: true,
                  profilePicUrl: true,
                  leadScore: true,
                  leadStatus: true,
                  hasMessenger: true,
                  hasInstagram: true,
                  tags: true,
                  notes: true,
                  aiContext: true,
                  aiSummary: true,
                  aiContextUpdatedAt: true,
                },
              });
              
              if (simpleResult) {
                console.log(`[Contact Page] ✅ Found contact ${id} in database ${db.index} (simplified query)`);
                if (simpleResult.organizationId === organizationId) {
                  // Return with null values for missing columns
                  return {
                    ...simpleResult,
                    conversionProbability: null,
                    buyerIntent: null,
                    sentiment: null,
                    productInterests: null,
                    intentSignals: null,
                    nextBestAction: null,
                    agentSuggestions: null,
                    contactInfo: null,
                    bestContactTimes: null,
                    stage: null,
                    pipeline: null,
                  };
                } else {
                  foundInDifferentOrg = true;
                  foundContact = {
                    ...simpleResult,
                    conversionProbability: null,
                    buyerIntent: null,
                    sentiment: null,
                    productInterests: null,
                    intentSignals: null,
                    nextBestAction: null,
                    agentSuggestions: null,
                    contactInfo: null,
                    bestContactTimes: null,
                    stage: null,
                    pipeline: null,
                  } as ContactResult;
                  continue;
                }
              }
            } catch (retryError) {
              console.warn(`[Contact Page] ⚠️ Retry query also failed for database ${db.index}:`, retryError instanceof Error ? retryError.message : String(retryError));
              continue;
            }
          }
          continue;
        }
      }
      
      // Contact not found in any database
      if (foundInDifferentOrg && foundContact) {
        // Contact exists but in different organization
        // Allow viewing but with a warning - return the contact with a flag
        console.warn(`[Contact Page] ⚠️ Contact ${id} exists but belongs to organization ${foundContact.organizationId}, not ${organizationId}`);
        console.warn(`[Contact Page] Contact name: ${foundContact.firstName} ${foundContact.lastName}`);
        console.warn(`[Contact Page] ⚠️ Allowing access with cross-organization warning`);
        
        // Return the contact but mark it as cross-organization
        // The UI will show a warning banner
        return {
          ...foundContact,
          conversionProbability: 'conversionProbability' in foundContact ? foundContact.conversionProbability : null,
          buyerIntent: 'buyerIntent' in foundContact ? foundContact.buyerIntent : null,
          sentiment: 'sentiment' in foundContact ? foundContact.sentiment : null,
          productInterests: 'productInterests' in foundContact ? foundContact.productInterests : null,
          intentSignals: 'intentSignals' in foundContact ? foundContact.intentSignals : null,
          nextBestAction: 'nextBestAction' in foundContact ? foundContact.nextBestAction : null,
          agentSuggestions: 'agentSuggestions' in foundContact ? foundContact.agentSuggestions : null,
          contactInfo: 'contactInfo' in foundContact ? (foundContact.contactInfo ?? null) : null,
          bestContactTimes: 'bestContactTimes' in foundContact ? (foundContact.bestContactTimes ?? null) : null,
          stage: 'stage' in foundContact ? foundContact.stage : null,
          pipeline: 'pipeline' in foundContact ? foundContact.pipeline : null,
          // Mark as cross-org for UI warning
          _crossOrgWarning: true as const,
          _actualOrgId: foundContact.organizationId,
        };
      } else {
        console.error(`[Contact Page] ❌ Contact ${id} does not exist in any of the ${allDatabases.length} database(s)`);
        console.error(`[Contact Page] Searched databases: ${allDatabases.map(db => db.index).join(', ')}`);
        notFound();
      }
    }

    console.log(`[Contact Page] ✅ Found contact ${id}: ${contact.firstName} ${contact.lastName}`);
    return contact;
  } catch (error: unknown) {
    // Handle case where contactInfo or bestContactTimes columns don't exist
    const dbError = error as { code?: string; message?: string };
    if (dbError.code === 'P2022' || dbError.message?.includes('does not exist')) {
      // Only log once per session to reduce noise
      if (!(globalThis as any).__contactPageSchemaWarningLogged) {
        console.warn('[Contact Page] ⚠️ Database schema error - contactInfo/bestContactTimes columns may not exist');
        console.warn('[Contact Page] If you see this error, run the migration: apply-production-migration.sql');
        (globalThis as any).__contactPageSchemaWarningLogged = true;
      }
      
      // First, try cross-database search with simplified query (no new columns)
      console.log(`[Contact Page] Schema error detected, searching across all databases with simplified query...`);
      const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
      const router = getDatabaseRouter();
      const allDatabases = router.getAllDatabaseConfigs();
      
      for (const db of allDatabases) {
        if (!db.client) continue;
        
        try {
          const foundContact = await db.client.contact.findFirst({
            where: { id }, // Search by ID only
            select: {
              id: true,
              organizationId: true,
              firstName: true,
              lastName: true,
              profilePicUrl: true,
              leadScore: true,
              leadStatus: true,
              hasMessenger: true,
              hasInstagram: true,
              tags: true,
              notes: true,
              aiContext: true,
              aiSummary: true,
              aiContextUpdatedAt: true,
              conversionProbability: true,
              buyerIntent: true,
              sentiment: true,
              productInterests: true,
              intentSignals: true,
              nextBestAction: true,
              agentSuggestions: true,
              stage: {
                select: {
                  id: true,
                  name: true,
                  color: true,
                },
              },
              pipeline: {
                select: {
                  id: true,
                  name: true,
                },
              },
            },
          });
          
          if (foundContact) {
            // Check if user has access
            if (foundContact.organizationId === organizationId) {
              console.log(`[Contact Page] ✅ Found contact ${id} in database ${db.index} (simplified query, same organization)`);
              // Return with null values for missing columns
              return {
                ...foundContact,
                contactInfo: null,
                bestContactTimes: null,
                aiSummary: foundContact.aiSummary ?? null,
                conversionProbability: foundContact.conversionProbability ?? null,
                buyerIntent: foundContact.buyerIntent ?? null,
                sentiment: foundContact.sentiment ?? null,
                productInterests: foundContact.productInterests ?? null,
                intentSignals: foundContact.intentSignals ?? null,
                nextBestAction: foundContact.nextBestAction ?? null,
                agentSuggestions: foundContact.agentSuggestions ?? null,
              };
            } else {
              console.warn(`[Contact Page] ⚠️ Contact ${id} found in database ${db.index} but belongs to different organization ${foundContact.organizationId}`);
              continue;
            }
          }
        } catch (searchError) {
          console.warn(`[Contact Page] ⚠️ Error searching database ${db.index} (simplified query):`, searchError instanceof Error ? searchError.message : String(searchError));
          continue;
        }
      }
      
      // If cross-database search failed, try the original database with simplified query
      try {
        const contact = await prisma.contact.findFirst({
          where: {
            id,
            organizationId,
          },
          select: {
            id: true,
            firstName: true,
            lastName: true,
            profilePicUrl: true,
            leadScore: true,
            leadStatus: true,
            hasMessenger: true,
            hasInstagram: true,
            tags: true,
            notes: true,
            aiContext: true,
            aiSummary: true,
            aiContextUpdatedAt: true,
            conversionProbability: true,
            buyerIntent: true,
            sentiment: true,
            productInterests: true,
            intentSignals: true,
            nextBestAction: true,
            agentSuggestions: true,
            stage: {
              select: {
                id: true,
                name: true,
                color: true,
              },
            },
            pipeline: {
              select: {
                id: true,
                name: true,
              },
            },
          },
        });

        if (contact) {
          console.log(`[Contact Page] ✅ Found contact ${id} in original database (simplified query)`);
          // Add null values for missing columns (contactInfo/bestContactTimes)
          return {
            ...contact,
            contactInfo: null,
            bestContactTimes: null,
            // Ensure all AI fields are present
            aiSummary: contact.aiSummary ?? null,
            conversionProbability: contact.conversionProbability ?? null,
            buyerIntent: contact.buyerIntent ?? null,
            sentiment: contact.sentiment ?? null,
            productInterests: contact.productInterests ?? null,
            intentSignals: contact.intentSignals ?? null,
            nextBestAction: contact.nextBestAction ?? null,
            agentSuggestions: contact.agentSuggestions ?? null,
          };
        }
      } catch (retryError) {
        console.error(`[Contact Page] ❌ Retry query also failed:`, retryError instanceof Error ? retryError.message : String(retryError));
      }
      
      // Contact not found even with simplified queries
      console.error(`[Contact Page] ❌ Contact ${id} not found in any database (even with simplified query)`);
      notFound();
    }
    
    // For other errors, log and re-throw
    console.error(`[Contact Page] ❌ Unexpected error fetching contact ${id}:`, error instanceof Error ? error.message : String(error));
    throw error;
  }
}

async function getContactActivities(contactId: string, organizationId: string, page: number = 1, limit: number = 50) {
  // First, find the contact to get its actual organizationId (in case it's cross-org)
  const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
  const router = getDatabaseRouter();
  const allDatabases = router.getAllDatabaseConfigs();
  
  let actualOrgId = organizationId;
  
  // Find the contact's actual organization across all databases
  for (const db of allDatabases) {
    if (!db.client) continue;
    try {
      const contact = await db.client.contact.findFirst({
        where: { id: contactId },
        select: { organizationId: true },
      });
      if (contact) {
        actualOrgId = contact.organizationId;
        break;
      }
    } catch {
      continue;
    }
  }
  
  // Use the contact's actual organization for querying activities
  const prisma = getPrismaForOrg(actualOrgId);
  const skip = (page - 1) * limit;
  
  try {
    const [activities, total] = await Promise.all([
      prisma.contactActivity.findMany({
        where: {
          contactId,
          // Don't filter by organizationId in the nested contact relation
          // since the contact might be in a different org
        },
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip,
        include: {
          user: {
            select: {
              name: true,
            },
          },
        },
      }),
      prisma.contactActivity.count({
        where: {
          contactId,
        },
      }),
    ]);

    return {
      activities,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
      hasMore: skip + activities.length < total,
    };
  } catch (error) {
    // If query fails (e.g., contact doesn't exist in this org's DB), return empty
    console.warn(`[Contact Activities] Error fetching activities for contact ${contactId}:`, error instanceof Error ? error.message : String(error));
    return {
      activities: [],
      total: 0,
      page,
      limit,
      totalPages: 0,
      hasMore: false,
    };
  }
}

async function getTags(organizationId: string) {
  const prisma = getPrismaForOrg(organizationId);
  return prisma.tag.findMany({
    where: { organizationId },
    select: {
      id: true,
      name: true,
      color: true,
    },
    orderBy: { name: 'asc' },
  });
}

// Loading components for Suspense boundaries
function ProfileSkeleton() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Profile</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-col items-center">
          <Skeleton className="h-24 w-24 rounded-full" />
          <Skeleton className="h-6 w-32 mt-4" />
        </div>
        <Separator />
        <div className="space-y-2">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="flex items-center justify-between">
              <Skeleton className="h-4 w-20" />
              <Skeleton className="h-5 w-16" />
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function ActivitySkeleton() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Activity Timeline</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="flex gap-4">
              <Skeleton className="h-10 w-10 rounded-full" />
              <div className="flex-1 space-y-2">
                <Skeleton className="h-4 w-3/4" />
                <Skeleton className="h-3 w-1/2" />
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// Server component for profile section
async function ContactProfile({ contactId, organizationId }: { contactId: string; organizationId: string }) {
  const [contact, availableTags] = await Promise.all([
    getContact(contactId, organizationId),
    getTags(organizationId),
  ]);

  // Check if this is a cross-organization contact
  const isCrossOrg = (contact as any)?._crossOrgWarning === true;
  const actualOrgId = (contact as any)?._actualOrgId;

  return (
    <div className="md:col-span-1 space-y-6">
      {/* Cross-organization warning banner */}
      {isCrossOrg && (
        <div className="bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-amber-600 dark:text-amber-400" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="flex-1">
              <h3 className="text-sm font-medium text-amber-800 dark:text-amber-200">
                Cross-Organization Contact
              </h3>
              <p className="mt-1 text-sm text-amber-700 dark:text-amber-300">
                This contact belongs to a different organization. You are viewing it from your current organization&apos;s context.
                {actualOrgId && (
                  <span className="block mt-1 text-xs">
                    Contact&apos;s organization: {actualOrgId}
                  </span>
                )}
              </p>
            </div>
          </div>
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Profile</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-col items-center">
            <Avatar className="h-24 w-24">
              <AvatarImage src={contact.profilePicUrl || undefined} />
              <AvatarFallback className="text-2xl">
                {contact.firstName[0]}
                {contact.lastName?.[0]}
              </AvatarFallback>
            </Avatar>
            <h2 className="mt-4 text-xl font-bold">
              {contact.firstName} {contact.lastName}
            </h2>
          </div>

          <Separator />

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Lead Score</span>
              <Badge variant="default">{contact.leadScore}</Badge>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Status</span>
              <Badge variant="outline">{contact.leadStatus}</Badge>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Platforms</span>
              <div className="flex gap-1">
                {contact.hasMessenger && (
                  <Badge variant="secondary" className="text-xs">
                    Messenger
                  </Badge>
                )}
                {contact.hasInstagram && (
                  <Badge variant="secondary" className="text-xs">
                    Instagram
                  </Badge>
                )}
              </div>
            </div>

            {contact.pipeline && (
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Pipeline</span>
                <span className="text-sm font-medium">{contact.pipeline.name}</span>
              </div>
            )}

            {contact.stage && (
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Stage</span>
                <Badge
                  variant="outline"
                  style={{
                    backgroundColor: `${contact.stage.color}20`,
                    color: contact.stage.color,
                  }}
                >
                  {contact.stage.name}
                </Badge>
              </div>
            )}
          </div>

          <Separator />

          <div>
            <h4 className="text-sm font-medium mb-2">Tags</h4>
            <ContactTagEditorOptimized
              contactId={contact.id}
              currentTags={contact.tags}
              availableTags={availableTags}
            />
          </div>

          <Separator />

          <Button className="w-full">
            <MessageSquare className="h-4 w-4 mr-2" />
            Send Message
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

// Server component for activity section
async function ContactActivity({ 
  contactId, 
  organizationId,
  activityPage = 1 
}: { 
  contactId: string; 
  organizationId: string;
  activityPage?: number;
}) {
  const [contact, activityData] = await Promise.all([
    getContact(contactId, organizationId),
    getContactActivities(contactId, organizationId, activityPage),
  ]);
  
  const { activities, total, page, totalPages, hasMore } = activityData;

  return (
    <div className="md:col-span-2 space-y-6">
      <EditableNotes contactId={contactId} initialNotes={contact.notes} />

      {contact.aiSummary && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Summary</CardTitle>
              {contact.aiContextUpdatedAt && (
                <span className="text-xs text-muted-foreground">
                  Updated {new Date(contact.aiContextUpdatedAt).toLocaleDateString()}
                </span>
              )}
            </div>
          </CardHeader>
          <CardContent>
            <p className="text-sm whitespace-pre-wrap">
              {contact.aiSummary}
            </p>
          </CardContent>
        </Card>
      )}

      {contact.aiContext && (() => {
        // Try to parse aiContext as JSON (comprehensive format)
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let parsedAnalysis: any = null;
        
        // DEBUG: Log the raw aiContext to help diagnose issues
        console.log('[Contact Page] 🔍 Raw aiContext type:', typeof contact.aiContext);
        console.log('[Contact Page] 🔍 Raw aiContext length:', typeof contact.aiContext === 'string' ? contact.aiContext.length : 'N/A');
        if (typeof contact.aiContext === 'string') {
          console.log('[Contact Page] 🔍 Raw aiContext first 1000 chars:', contact.aiContext.substring(0, 1000));
          console.log('[Contact Page] 🔍 Raw aiContext last 1000 chars:', contact.aiContext.substring(Math.max(0, contact.aiContext.length - 1000)));
          // Check for common issues
          const openBraces = (contact.aiContext.match(/\{/g) || []).length;
          const closeBraces = (contact.aiContext.match(/\}/g) || []).length;
          const openQuotes = (contact.aiContext.match(/"/g) || []).length;
          console.log('[Contact Page] 🔍 JSON structure check - Open braces:', openBraces, 'Close braces:', closeBraces, 'Quotes:', openQuotes);
          
          // Check if it looks like valid JSON structure
          if (openBraces !== closeBraces) {
            console.warn('[Contact Page] ⚠️ JSON structure mismatch - braces don\'t match!');
          }
          if (openQuotes % 2 !== 0) {
            console.warn('[Contact Page] ⚠️ JSON structure issue - odd number of quotes (unterminated string)!');
          }
          
          // Try to find where the JSON might be broken
          if (openBraces !== closeBraces || openQuotes % 2 !== 0) {
            // Find the position where it might break
            let quoteCount = 0;
            let inString = false;
            for (let i = 0; i < contact.aiContext.length; i++) {
              if (contact.aiContext[i] === '"' && (i === 0 || contact.aiContext[i-1] !== '\\')) {
                quoteCount++;
                inString = !inString;
                if (quoteCount > 100 && quoteCount % 2 !== 0) {
                  console.warn(`[Contact Page] ⚠️ Potential unterminated string starting around position ${i}`);
                  console.warn(`[Contact Page] ⚠️ Context around position ${i}:`, contact.aiContext.substring(Math.max(0, i-50), Math.min(contact.aiContext.length, i+50)));
                  break;
                }
              }
            }
          }
        }
        
        // Check if aiContext is just a plain summary string (old format)
        const isPlainSummary = typeof contact.aiContext === 'string' && 
                               !contact.aiContext.trim().startsWith('{') && 
                               !contact.aiContext.trim().startsWith('[') &&
                               contact.aiContext.length < 500; // Likely just a summary if short
        
        if (isPlainSummary) {
          // This is an old format - show a message suggesting re-analysis
          return (
            <Card>
              <CardHeader>
                <CardTitle>AI Analysis Details</CardTitle>
                {contact.aiContextUpdatedAt && (
                  <span className="text-xs text-muted-foreground">
                    Updated {new Date(contact.aiContextUpdatedAt).toLocaleDateString()}
                  </span>
                )}
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800 rounded-lg p-4">
                  <div className="flex items-start gap-3">
                    <div className="flex-shrink-0">
                      <svg className="h-5 w-5 text-amber-600 dark:text-amber-400" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                      </svg>
                    </div>
                    <div className="flex-1">
                      <h3 className="text-sm font-medium text-amber-800 dark:text-amber-200">
                        Basic Analysis Format Detected
                      </h3>
                      <p className="mt-1 text-sm text-amber-700 dark:text-amber-300">
                        This contact was analyzed with an older format that only includes a summary. 
                        To see the full comprehensive analysis (conversation analysis, customer insights, 
                        engagement metrics, business intelligence, scoring, pipeline recommendations, 
                        action items, green flags, red flags, and more), please re-analyze this contact 
                        from the contacts page.
                      </p>
                    </div>
                  </div>
                </div>
                
                <div className="space-y-2">
                  <h4 className="text-sm font-semibold">Executive Summary</h4>
                  <div className="text-sm text-muted-foreground whitespace-pre-wrap leading-relaxed">
                    {contact.aiContext}
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        }
        
        try {
          // Check if aiContext is a JSON string
          if (typeof contact.aiContext === 'string') {
            const trimmed = contact.aiContext.trim();
            
            // Check if content looks like instructions instead of JSON
            const instructionIndicators = [
              'We need to parse',
              'We need to produce',
              'Now we need to',
              'Let\'s fill',
              'Now fill',
              'Now produce',
              'Now ensure',
              'Now check',
              'Now we need to ensure',
              'Now we need to produce',
              'Now we need to fill',
              'Now we need to craft',
              'Now we need to write',
              'Now we need to double-check',
              'Now we need to verify',
              'Interpretation:',
              'Conversation lines:',
              'Thus the conversation',
              'Now we need to produce JSON',
            ];
            
            const looksLikeInstructions = instructionIndicators.some(indicator => 
              trimmed.toLowerCase().includes(indicator.toLowerCase())
            );
            
            if (looksLikeInstructions) {
              console.warn('[Contact Page] ⚠️ aiContext appears to contain instructions instead of JSON. Attempting to extract JSON...');
              
              // Strategy 1: Try to find JSON blocks using regex (more robust)
              const jsonBlockRegex = /\{[\s\S]*?(?:\{[^{}]*\}|[^{}])*?\}/g;
              const jsonMatches = trimmed.match(jsonBlockRegex);
              
              if (jsonMatches && jsonMatches.length > 0) {
                // Try each JSON block from last to first (usually the final output is last)
                for (let i = jsonMatches.length - 1; i >= 0; i--) {
                  const jsonBlock = jsonMatches[i];
                  try {
                    // Clean up the JSON block
                    let cleanedJson = jsonBlock.trim();
                    // Remove trailing commas
                    cleanedJson = cleanedJson.replace(/,(\s*[}\]])/g, '$1');
                    // Try to fix incomplete JSON
                    if (!cleanedJson.endsWith('}')) {
                      // Count braces to see if we need to close it
                      const openBraces = (cleanedJson.match(/\{/g) || []).length;
                      const closeBraces = (cleanedJson.match(/\}/g) || []).length;
                      if (openBraces > closeBraces) {
                        cleanedJson += '}'.repeat(openBraces - closeBraces);
                      }
                    }
                    
                    const extracted = JSON.parse(cleanedJson);
                    // Validate it's actually JSON data, not instructions
                    if (extracted && typeof extracted === 'object' && !Array.isArray(extracted)) {
                      // Check for any analysis-related keys
                      const hasAnalysisKeys = Object.keys(extracted).some(key => 
                        ['executiveSummary', 'summary', 'conversationAnalysis', 'customerInsights', 
                         'engagementMetrics', 'businessIntelligence', 'scoring', 'pipelineRecommendations',
                         'actionItems', 'greenFlags', 'redFlags', 'leadScore', 'confidence'].includes(key)
                      );
                      
                      if (hasAnalysisKeys) {
                        parsedAnalysis = extracted;
                        console.log('[Contact Page] ✅ Successfully extracted JSON from instruction-like content using regex');
                        break;
                      }
                    }
                  } catch (parseError) {
                    // Continue to next match
                    continue;
                  }
                }
              }
              
              // Strategy 2: If regex didn't work, try the original brace-matching approach
              if (!parsedAnalysis) {
                const lastBrace = trimmed.lastIndexOf('}');
                if (lastBrace !== -1) {
                  let depth = 0;
                  let firstBrace = -1;
                  for (let i = lastBrace; i >= 0; i--) {
                    if (trimmed[i] === '}') depth++;
                    if (trimmed[i] === '{') {
                      depth--;
                      if (depth === 0) {
                        firstBrace = i;
                        break;
                      }
                    }
                  }
                  if (firstBrace !== -1) {
                    const potentialJson = trimmed.substring(firstBrace, lastBrace + 1);
                    try {
                      let cleanedJson = potentialJson.trim();
                      // Remove trailing commas
                      cleanedJson = cleanedJson.replace(/,(\s*[}\]])/g, '$1');
                      
                      const extracted = JSON.parse(cleanedJson);
                      // Validate it's actually JSON data, not instructions
                      if (extracted && typeof extracted === 'object' && 
                          (extracted.executiveSummary || extracted.summary || extracted.conversationAnalysis ||
                           extracted.leadScore || extracted.confidence || extracted.engagementLevel)) {
                        parsedAnalysis = extracted;
                        console.log('[Contact Page] ✅ Successfully extracted JSON from instruction-like content using brace matching');
                      }
                    } catch {
                      // Failed to parse
                    }
                  }
                }
              }
              
              // Strategy 3: If all else fails, try to parse the entire string as-is with error recovery
              if (!parsedAnalysis) {
                // Try one more time with aggressive error recovery
                try {
                  // Remove any leading/trailing non-JSON content
                  let recoverableJson = trimmed;
                  
                  // Find the first { and last } that might form a complete object
                  const firstBrace = recoverableJson.indexOf('{');
                  const lastBrace = recoverableJson.lastIndexOf('}');
                  
                  if (firstBrace >= 0 && lastBrace > firstBrace) {
                    recoverableJson = recoverableJson.substring(firstBrace, lastBrace + 1);
                    
                    // Try to fix unterminated strings by closing them at the last quote before }
                    // This is a last resort - try to make it parseable
                    const quoteMatches = [...recoverableJson.matchAll(/"/g)];
                    if (quoteMatches.length % 2 !== 0) {
                      // Odd number of quotes - unterminated string
                      const lastQuoteIndex = recoverableJson.lastIndexOf('"');
                      if (lastQuoteIndex > 0 && lastQuoteIndex < recoverableJson.length - 2) {
                        // Try to close the string and object
                        recoverableJson = recoverableJson.substring(0, lastQuoteIndex + 1) + '}';
                      }
                    }
                    
                    // Remove trailing commas
                    recoverableJson = recoverableJson.replace(/,(\s*[}\]])/g, '$1');
                    
                    const recovered = JSON.parse(recoverableJson);
                    if (recovered && typeof recovered === 'object') {
                      parsedAnalysis = recovered;
                      console.log('[Contact Page] ✅ Recovered JSON with aggressive error recovery');
                    }
                  }
                } catch (recoveryError) {
                  console.warn('[Contact Page] ⚠️ Aggressive recovery also failed:', recoveryError instanceof Error ? recoveryError.message : String(recoveryError));
                }
              }
              
              // If we still couldn't extract valid JSON, log but don't return null
              // We'll show a fallback UI instead
              if (!parsedAnalysis) {
                console.warn('[Contact Page] ⚠️ Could not extract valid JSON from instruction-like content');
                console.warn('[Contact Page] ⚠️ This indicates the stored aiContext is severely malformed');
                // Don't return null - let it fall through to show raw content or fallback
              }
            }
            
            // Try to parse if it looks like JSON (and we haven't already parsed it above)
            if (!parsedAnalysis && (trimmed.startsWith('{') || trimmed.startsWith('['))) {
              try {
                // Try to fix incomplete JSON by finding the last complete object/array
                let jsonString = contact.aiContext.trim();
                
                // If JSON appears incomplete (doesn't end with } or ]), try to fix it
                if (!jsonString.endsWith('}') && !jsonString.endsWith(']')) {
                  // Find the last complete closing brace/bracket
                  let lastCompleteIndex = -1;
                  let braceCount = 0;
                  let bracketCount = 0;
                  
                  for (let i = jsonString.length - 1; i >= 0; i--) {
                    if (jsonString[i] === '}') braceCount++;
                    if (jsonString[i] === '{') braceCount--;
                    if (jsonString[i] === ']') bracketCount++;
                    if (jsonString[i] === '[') bracketCount--;
                    
                    if (braceCount === 0 && bracketCount === 0 && (jsonString[i] === '}' || jsonString[i] === ']')) {
                      lastCompleteIndex = i;
                      break;
                    }
                  }
                  
                  if (lastCompleteIndex > 0) {
                    jsonString = jsonString.substring(0, lastCompleteIndex + 1);
                  } else {
                    // If we can't find a complete ending, try to close it
                    if (jsonString.startsWith('{')) {
                      jsonString = jsonString.replace(/,\s*$/, '') + '}';
                    } else if (jsonString.startsWith('[')) {
                      jsonString = jsonString.replace(/,\s*$/, '') + ']';
                    }
                  }
                }
                
                // Try to fix common JSON issues before parsing
                // Remove trailing commas (safe fix)
                jsonString = jsonString.replace(/,(\s*[}\]])/g, '$1');
                
                // Try to fix unterminated strings by finding and closing them
                // Count quotes to see if we have unterminated strings
                const quoteMatches = [...jsonString.matchAll(/(?<!\\)"/g)];
                if (quoteMatches.length % 2 !== 0) {
                  // Odd number of quotes - we have an unterminated string
                  console.warn('[Contact Page] ⚠️ Detected unterminated string in JSON, attempting to fix...');
                  
                  // Find the last unescaped quote
                  let lastQuoteIndex = -1;
                  for (let i = jsonString.length - 1; i >= 0; i--) {
                    if (jsonString[i] === '"' && (i === 0 || jsonString[i-1] !== '\\')) {
                      lastQuoteIndex = i;
                      break;
                    }
                  }
                  
                  if (lastQuoteIndex > 0) {
                    // Try to find where the string should end (before the next } or ,)
                    let endIndex = lastQuoteIndex + 1;
                    for (let i = lastQuoteIndex + 1; i < jsonString.length; i++) {
                      const char = jsonString[i];
                      if (char === '}' || char === ',' || char === '\n') {
                        // Insert closing quote before this character
                        jsonString = jsonString.substring(0, i) + '"' + jsonString.substring(i);
                        console.log('[Contact Page] ✅ Fixed unterminated string by inserting closing quote');
                        break;
                      }
                    }
                  }
                }
                
                try {
                  parsedAnalysis = JSON.parse(jsonString);
                } catch (parseError) {
                  // If parsing still fails, try one more aggressive fix
                  console.warn('[Contact Page] ⚠️ JSON parse failed after fixes, trying aggressive recovery...', parseError instanceof Error ? parseError.message : String(parseError));
                  
                  // Try to extract just the valid parts by finding complete key-value pairs
                  const keyValueRegex = /"([^"]+)":\s*("([^"]*)"|(\d+)|(true|false|null)|(\[[^\]]*\])|(\{[^}]*\}))/g;
                  const extracted: any = {};
                  let match;
                  while ((match = keyValueRegex.exec(jsonString)) !== null) {
                    const key = match[1];
                    try {
                      if (match[2].startsWith('"')) {
                        extracted[key] = match[3] || '';
                      } else if (match[4]) {
                        extracted[key] = parseInt(match[4], 10);
                      } else if (match[5]) {
                        extracted[key] = match[5] === 'true' ? true : match[5] === 'false' ? false : null;
                      } else if (match[6]) {
                        extracted[key] = JSON.parse(match[6]);
                      } else if (match[7]) {
                        extracted[key] = JSON.parse(match[7]);
                      }
                    } catch {
                      // Skip this key-value pair if it can't be parsed
                    }
                  }
                  
                  if (Object.keys(extracted).length > 0) {
                    parsedAnalysis = extracted;
                    console.log('[Contact Page] ✅ Recovered partial JSON using aggressive extraction');
                  } else {
                    throw parseError; // Re-throw if we couldn't extract anything
                  }
                }
                // Handle double-encoded JSON (if the result is still a string that looks like JSON)
                if (typeof parsedAnalysis === 'string' && (parsedAnalysis.trim().startsWith('{') || parsedAnalysis.trim().startsWith('['))) {
                  try {
                    parsedAnalysis = JSON.parse(parsedAnalysis);
                  } catch {
                    // If second parse fails, use the first parse result
                  }
                }
                
                // Ensure all required fields exist with defaults if missing
                if (parsedAnalysis && typeof parsedAnalysis === 'object') {
                  // Ensure executiveSummary exists
                  if (!parsedAnalysis.executiveSummary && parsedAnalysis.summary) {
                    parsedAnalysis.executiveSummary = parsedAnalysis.summary;
                  }
                  
                  // Ensure all sections have defaults
                  if (!parsedAnalysis.conversationAnalysis) {
                    parsedAnalysis.conversationAnalysis = {
                      mainTopic: '',
                      keyTopics: [],
                      keyPoints: [],
                      decisionsMade: [],
                      questionsAsked: [],
                      informationProvided: [],
                    };
                  }
                  if (!parsedAnalysis.customerInsights) {
                    parsedAnalysis.customerInsights = {
                      customerIntent: 'UNKNOWN',
                      customerNeeds: [],
                      customerGoals: [],
                      painPoints: [],
                      preferences: [],
                      budgetIndicated: false,
                      timelineIndicated: false,
                      authorityLevel: 'UNKNOWN',
                    };
                  }
                  if (!parsedAnalysis.engagementMetrics) {
                    parsedAnalysis.engagementMetrics = {
                      engagementLevel: 'UNKNOWN',
                      responseTime: 'UNKNOWN',
                      messageFrequency: 'UNKNOWN',
                      conversationDepth: 'UNKNOWN',
                      sentiment: 'NEUTRAL',
                      tone: 'NEUTRAL',
                    };
                  }
                  if (!parsedAnalysis.businessIntelligence) {
                    parsedAnalysis.businessIntelligence = {
                      buyingSignals: [],
                      objections: [],
                      competitorsMentioned: [],
                      priceSensitivity: 'UNKNOWN',
                      productInterest: [],
                      conversionProbability: 0,
                      riskFactors: [],
                      opportunitySize: 'UNKNOWN',
                    };
                  }
                  if (!parsedAnalysis.scoring) {
                    parsedAnalysis.scoring = {
                      leadScore: 0,
                      confidence: 0,
                      fitScore: 0,
                      engagementScore: 0,
                      urgencyScore: 0,
                    };
                  }
                  if (!parsedAnalysis.pipelineRecommendation) {
                    parsedAnalysis.pipelineRecommendation = {
                      recommendedStage: 'New Lead',
                      leadStatus: 'NEW',
                      stageReason: '',
                      nextStage: '',
                      estimatedCloseDate: null,
                    };
                  }
                  if (!parsedAnalysis.actionItems) {
                    parsedAnalysis.actionItems = {
                      immediateActions: [],
                      followUpActions: [],
                      nextBestAction: '',
                      bestReply: '',
                      followUpMessage: '',
                      deadline: null,
                    };
                  }
                  // Ensure arrays exist
                  if (!Array.isArray(parsedAnalysis.greenFlags)) parsedAnalysis.greenFlags = [];
                  if (!Array.isArray(parsedAnalysis.redFlags)) parsedAnalysis.redFlags = [];
                  if (!Array.isArray(parsedAnalysis.upsellOpportunities)) parsedAnalysis.upsellOpportunities = [];
                  if (!Array.isArray(parsedAnalysis.conversationTips)) parsedAnalysis.conversationTips = [];
                  if (!Array.isArray(parsedAnalysis.objectionHandling)) parsedAnalysis.objectionHandling = [];
                  if (!parsedAnalysis.reasoning) parsedAnalysis.reasoning = '';
                }
              } catch (parseError) {
                // JSON is malformed - try to extract what we can using a more lenient approach
                if (process.env.NODE_ENV === 'development') {
                  console.warn('Failed to parse aiContext as JSON (malformed):', (parseError as Error).message);
                }
                // Try to extract at least the executiveSummary if possible
                try {
                  const execSummaryMatch = contact.aiContext.match(/"executiveSummary"\s*:\s*"([^"]*(?:\\.[^"]*)*)"/);
                  if (execSummaryMatch) {
                    parsedAnalysis = { executiveSummary: execSummaryMatch[1].replace(/\\"/g, '"') };
                  } else {
                    parsedAnalysis = null;
                  }
                } catch {
                  parsedAnalysis = null;
                }
              }
            }
          } else if (typeof contact.aiContext === 'object') {
            // Already an object, use directly
            parsedAnalysis = contact.aiContext;
          }
        } catch (error) {
          // Not valid JSON, will fall back to plain text display
          // Only log in development to reduce production noise
          if (process.env.NODE_ENV === 'development') {
            console.warn('Failed to parse aiContext:', error);
          }
          parsedAnalysis = null;
        }

        // Fix: If executiveSummary contains a JSON object (malformed storage), parse it and merge
        if (parsedAnalysis && typeof parsedAnalysis.executiveSummary === 'string' && 
            parsedAnalysis.executiveSummary.trim().startsWith('{')) {
          try {
            let nestedJsonString = parsedAnalysis.executiveSummary.trim();
            
            // Try to fix malformed JSON by finding the last complete JSON object
            // Strategy: Work backwards from the end to find where the JSON is complete
            let fixedJson = nestedJsonString;
            
            // If it doesn't end with }, try to find the last complete structure
            if (!fixedJson.endsWith('}')) {
              // Find all potential closing braces
              let lastValidIndex = -1;
              let braceDepth = 0;
              let inString = false;
              let escapeNext = false;
              
              for (let i = fixedJson.length - 1; i >= 0; i--) {
                const char = fixedJson[i];
                
                if (escapeNext) {
                  escapeNext = false;
                  continue;
                }
                
                if (char === '\\') {
                  escapeNext = true;
                  continue;
                }
                
                if (char === '"' && !escapeNext) {
                  inString = !inString;
                  continue;
                }
                
                if (!inString) {
                  if (char === '}') {
                    braceDepth++;
                  } else if (char === '{') {
                    braceDepth--;
                    if (braceDepth === 0) {
                      lastValidIndex = i;
                      break;
                    }
                  }
                }
              }
              
              if (lastValidIndex > 0) {
                fixedJson = fixedJson.substring(0, lastValidIndex + 1);
              } else {
                // Fallback: try to close it properly
                fixedJson = fixedJson.replace(/,\s*$/, '') + '}';
              }
            }
            
            // Remove trailing commas
            fixedJson = fixedJson.replace(/,(\s*[}\]])/g, '$1');
            
            const nestedJson = JSON.parse(fixedJson);
            // If nestedJson has the full structure, use it as the main parsedAnalysis
            if (nestedJson.conversationAnalysis || nestedJson.customerInsights || nestedJson.scoring) {
              // This is the full comprehensive format stored incorrectly in executiveSummary
              parsedAnalysis = nestedJson;
              console.log('[Contact Page] ✅ Fixed: Extracted full comprehensive JSON from executiveSummary field');
            } else {
              // Merge the nested JSON with the existing parsedAnalysis, prioritizing nested data
              parsedAnalysis = {
                ...parsedAnalysis,
                ...nestedJson,
                // Keep the actual executiveSummary from nested if it exists
                executiveSummary: nestedJson.executiveSummary || parsedAnalysis.executiveSummary,
              };
              console.log('[Contact Page] ✅ Fixed: Merged nested JSON from executiveSummary field');
            }
          } catch (e) {
            // If parsing fails completely, check if we already have comprehensive data in the main parsedAnalysis
            // If so, just extract the executiveSummary text and keep the rest
            const error = e instanceof Error ? e : new Error(String(e));
            console.warn('[Contact Page] ⚠️ Could not parse nested JSON in executiveSummary:', error.message);
            
            // Check if the main parsedAnalysis already has comprehensive data
            const hasMainData = parsedAnalysis.conversationAnalysis || parsedAnalysis.customerInsights || parsedAnalysis.scoring;
            
            if (hasMainData) {
              // We already have the comprehensive data, just try to extract a clean executiveSummary
              const summaryMatch = parsedAnalysis.executiveSummary.match(/"executiveSummary"\s*:\s*"((?:[^"\\]|\\.)*)"/);
              if (summaryMatch && summaryMatch[1]) {
                parsedAnalysis.executiveSummary = summaryMatch[1].replace(/\\"/g, '"').replace(/\\n/g, '\n');
                console.log('[Contact Page] ✅ Extracted clean executiveSummary from malformed JSON, keeping comprehensive data');
              } else {
                // If we can't extract it, just set it to a default message
                parsedAnalysis.executiveSummary = 'Analysis completed. See details below.';
                console.log('[Contact Page] ⚠️ Could not extract executiveSummary, using default message');
              }
            } else {
              // No comprehensive data in main object, so this is a real problem
              console.warn('[Contact Page] ⚠️ No comprehensive data found and JSON parsing failed');
            }
          }
        }

        // Extract executive summary - prioritize parsed data, fallback to plain text only if not JSON
        let executiveSummary = parsedAnalysis?.executiveSummary || 
                                 parsedAnalysis?.summary || 
                                 (parsedAnalysis ? null : (typeof contact.aiContext === 'string' && !contact.aiContext.trim().startsWith('{') ? contact.aiContext : null));
        
        // Ensure executiveSummary is a string, not an object
        if (executiveSummary && typeof executiveSummary !== 'string') {
          if (typeof executiveSummary === 'object') {
            // If it's an object, try to stringify it or use a fallback
            executiveSummary = null;
          } else {
            executiveSummary = String(executiveSummary);
          }
        }
        
        const greenFlags = parsedAnalysis?.greenFlags || [];
        const redFlags = parsedAnalysis?.redFlags || [];
        const upsellOpportunities = parsedAnalysis?.upsellOpportunities || [];
        const conversationTips = parsedAnalysis?.conversationTips || [];
        const objectionHandling = parsedAnalysis?.objectionHandling || [];
        
        // Extract additional sections from comprehensive format - use defaults if missing
        const conversationAnalysis = parsedAnalysis?.conversationAnalysis || {
          mainTopic: '',
          keyTopics: [],
          keyPoints: [],
          decisionsMade: [],
          questionsAsked: [],
          informationProvided: [],
        };
        const customerInsights = parsedAnalysis?.customerInsights || {
          customerIntent: 'UNKNOWN',
          customerNeeds: [],
          customerGoals: [],
          painPoints: [],
          preferences: [],
          budgetIndicated: false,
          timelineIndicated: false,
          authorityLevel: 'UNKNOWN',
        };
        const engagementMetrics = parsedAnalysis?.engagementMetrics || {
          engagementLevel: 'UNKNOWN',
          responseTime: 'UNKNOWN',
          messageFrequency: 'UNKNOWN',
          conversationDepth: 'UNKNOWN',
          sentiment: 'NEUTRAL',
          tone: 'NEUTRAL',
        };
        const businessIntelligence = parsedAnalysis?.businessIntelligence || {
          buyingSignals: [],
          objections: [],
          competitorsMentioned: [],
          priceSensitivity: 'UNKNOWN',
          productInterest: [],
          conversionProbability: 0,
          riskFactors: [],
          opportunitySize: 'UNKNOWN',
        };
        const scoring = parsedAnalysis?.scoring || {
          leadScore: 0,
          confidence: 0,
          fitScore: 0,
          engagementScore: 0,
          urgencyScore: 0,
        };
        const pipelineRecommendation = parsedAnalysis?.pipelineRecommendation || {
          recommendedStage: 'New Lead',
          leadStatus: 'NEW',
          stageReason: '',
          nextStage: '',
          estimatedCloseDate: null,
        };
        const actionItems = parsedAnalysis?.actionItems || {
          immediateActions: [],
          followUpActions: [],
          nextBestAction: '',
          bestReply: '',
          followUpMessage: '',
          deadline: null,
        };

        // Debug: Log what fields are available in parsed analysis
        if (process.env.NODE_ENV === 'development' && parsedAnalysis) {
          console.log('[Contact Page] 📊 Parsed analysis structure:', {
            hasExecutiveSummary: !!parsedAnalysis.executiveSummary,
            hasConversationAnalysis: !!conversationAnalysis,
            hasCustomerInsights: !!customerInsights,
            hasEngagementMetrics: !!engagementMetrics,
            hasBusinessIntelligence: !!businessIntelligence,
            hasScoring: !!scoring,
            hasPipelineRecommendation: !!pipelineRecommendation,
            hasActionItems: !!actionItems,
            hasGreenFlags: greenFlags.length > 0,
            hasRedFlags: redFlags.length > 0,
            hasUpsellOpportunities: upsellOpportunities.length > 0,
            hasConversationTips: conversationTips.length > 0,
            hasObjectionHandling: objectionHandling.length > 0,
            hasReasoning: !!parsedAnalysis.reasoning,
            allKeys: Object.keys(parsedAnalysis),
          });
        }

        // Check if we have a comprehensive format (has at least one section beyond executiveSummary with actual data)
        const hasComprehensiveData = !!(
          (conversationAnalysis.mainTopic || conversationAnalysis.keyTopics.length > 0 || conversationAnalysis.keyPoints.length > 0) ||
          (customerInsights.customerIntent !== 'UNKNOWN' || customerInsights.customerNeeds.length > 0) ||
          (engagementMetrics.engagementLevel !== 'UNKNOWN') ||
          (businessIntelligence.priceSensitivity !== 'UNKNOWN' || businessIntelligence.buyingSignals.length > 0 || businessIntelligence.conversionProbability > 0) ||
          (scoring.leadScore > 0 || scoring.confidence > 0) ||
          (pipelineRecommendation.recommendedStage !== 'New Lead' || pipelineRecommendation.leadStatus !== 'NEW' || pipelineRecommendation.stageReason) ||
          (actionItems.nextBestAction || actionItems.immediateActions.length > 0 || actionItems.followUpActions.length > 0) ||
          greenFlags.length > 0 ||
          redFlags.length > 0 ||
          upsellOpportunities.length > 0 ||
          conversationTips.length > 0 ||
          objectionHandling.length > 0 ||
          (parsedAnalysis?.reasoning && parsedAnalysis.reasoning !== 'Analysis completed based on conversation data.')
        );

        return (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>AI Analysis Details</CardTitle>
              {contact.aiContextUpdatedAt && (
                <span className="text-xs text-muted-foreground">
                  Updated {new Date(contact.aiContextUpdatedAt).toLocaleDateString()}
                </span>
              )}
            </div>
          </CardHeader>
            <CardContent className="space-y-6">
              {/* Executive Summary */}
              {executiveSummary && typeof executiveSummary === 'string' && (
                <div className="space-y-2">
                  <h4 className="text-sm font-semibold">Executive Summary</h4>
                  <div className="text-sm text-muted-foreground whitespace-pre-wrap leading-relaxed">
                    {executiveSummary}
                  </div>
                </div>
              )}

              {/* Warning if only executive summary is available */}
              {parsedAnalysis && executiveSummary && !hasComprehensiveData && (
                <div className="bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800 rounded-lg p-4">
                  <div className="flex items-start gap-3">
                    <div className="flex-shrink-0">
                      <svg className="h-5 w-5 text-amber-600 dark:text-amber-400" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                      </svg>
                    </div>
                    <div className="flex-1">
                      <h3 className="text-sm font-medium text-amber-800 dark:text-amber-200">
                        Limited Analysis Data
                      </h3>
                      <p className="mt-1 text-sm text-amber-700 dark:text-amber-300">
                        This analysis only contains the executive summary. The comprehensive analysis sections 
                        (Conversation Analysis, Customer Insights, Engagement Metrics, Business Intelligence, 
                        Scoring, Pipeline Recommendation, Action Items, etc.) are not available. 
                        Please re-analyze this contact to generate the full comprehensive format.
                      </p>
                      {process.env.NODE_ENV === 'development' && (
                        <details className="mt-3">
                          <summary className="text-xs text-amber-600 dark:text-amber-400 cursor-pointer">
                            Debug: View stored JSON structure
                          </summary>
                          <pre className="mt-2 text-xs bg-amber-100 dark:bg-amber-900/30 p-2 rounded overflow-auto max-h-40">
                            {JSON.stringify(parsedAnalysis, null, 2)}
                          </pre>
                        </details>
                      )}
                    </div>
                  </div>
                </div>
              )}
              
              {/* Fallback: Show warning and raw content if parsing completely failed */}
              {!parsedAnalysis && contact.aiContext && typeof contact.aiContext === 'string' && (
                <div className="space-y-4">
                  <div className="bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
                    <div className="flex items-start gap-3">
                      <div className="flex-shrink-0">
                        <svg className="h-5 w-5 text-red-600 dark:text-red-400" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                        </svg>
                      </div>
                      <div className="flex-1">
                        <h3 className="text-sm font-medium text-red-800 dark:text-red-200">
                          Analysis Data Format Error
                        </h3>
                        <p className="mt-1 text-sm text-red-700 dark:text-red-300">
                          The AI analysis data could not be parsed properly. This may be due to a malformed response from the AI service. 
                          Please try re-analyzing this contact to regenerate the analysis data.
                        </p>
                      </div>
                    </div>
                  </div>
                  
                  {/* Show raw content in a collapsible section for debugging */}
                  <details className="mt-2">
                    <summary className="text-xs text-muted-foreground cursor-pointer hover:text-foreground">
                      View raw analysis data (for debugging)
                    </summary>
                    <div className="mt-2 p-3 bg-muted/50 rounded-md">
                      <pre className="text-xs whitespace-pre-wrap break-words max-h-60 overflow-auto">
                        {contact.aiContext.length > 5000 
                          ? contact.aiContext.substring(0, 5000) + '\n\n... (truncated, ' + (contact.aiContext.length - 5000) + ' more characters)'
                          : contact.aiContext
                        }
                      </pre>
                    </div>
                  </details>
                </div>
              )}

              {/* Green Flags */}
              {greenFlags.length > 0 && (
                <div className="space-y-2 pt-4 border-t">
                  <h4 className="text-sm font-semibold text-green-700 dark:text-green-400">✅ Green Flags</h4>
                  <ul className="space-y-1.5">
                    {greenFlags.map((flag: string, idx: number) => (
                      <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                        <span className="text-green-600 dark:text-green-400 mt-0.5">•</span>
                        <span>{flag}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Red Flags */}
              {redFlags.length > 0 && (
                <div className="space-y-2 pt-4 border-t">
                  <h4 className="text-sm font-semibold text-red-700 dark:text-red-400">⚠️ Red Flags</h4>
                  <ul className="space-y-1.5">
                    {redFlags.map((flag: string, idx: number) => (
                      <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                        <span className="text-red-600 dark:text-red-400 mt-0.5">•</span>
                        <span>{flag}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Upsell Opportunities */}
              {upsellOpportunities.length > 0 && (
                <div className="space-y-2 pt-4 border-t">
                  <h4 className="text-sm font-semibold text-blue-700 dark:text-blue-400">💰 Upsell Opportunities</h4>
                  <ul className="space-y-1.5">
                    {upsellOpportunities.map((opportunity: string, idx: number) => (
                      <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                        <span className="text-blue-600 dark:text-blue-400 mt-0.5">•</span>
                        <span>{opportunity}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Conversation Tips */}
              {conversationTips.length > 0 && (
                <div className="space-y-2 pt-4 border-t">
                  <h4 className="text-sm font-semibold">💡 Conversation Tips</h4>
                  <ul className="space-y-1.5">
                    {conversationTips.map((tip: string, idx: number) => (
                      <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                        <span className="text-amber-600 dark:text-amber-400 mt-0.5">•</span>
                        <span>{tip}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Objection Handling */}
              {objectionHandling.length > 0 && (
                <div className="space-y-2 pt-4 border-t">
                  <h4 className="text-sm font-semibold">🛡️ Objection Handling</h4>
                  <ul className="space-y-1.5">
                    {objectionHandling.map((rebuttal: string, idx: number) => (
                      <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                        <span className="text-purple-600 dark:text-purple-400 mt-0.5">•</span>
                        <span>{rebuttal}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Reasoning / AI Analysis Details */}
              {parsedAnalysis?.reasoning && typeof parsedAnalysis.reasoning === 'string' && (
                <div className="space-y-2 pt-4 border-t">
                  <h4 className="text-sm font-semibold">🧠 AI Reasoning</h4>
                  <div className="text-sm text-muted-foreground whitespace-pre-wrap leading-relaxed bg-muted/50 p-3 rounded-md">
                    {parsedAnalysis.reasoning}
                  </div>
                </div>
              )}

              {/* Contact Details / Information Provided */}
              {conversationAnalysis?.informationProvided && conversationAnalysis.informationProvided.length > 0 && (
                <div className="space-y-2 pt-4 border-t">
                  <h4 className="text-sm font-semibold">📋 Contact Details</h4>
                  <ul className="space-y-1.5">
                    {conversationAnalysis.informationProvided.map((info: string, idx: number) => (
                      <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                        <span className="text-blue-600 dark:text-blue-400 mt-0.5">•</span>
                        <span>{info}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Conversion Probability & Scoring */}
              {(scoring?.conversionProbability !== undefined || scoring?.leadScore !== undefined || scoring?.confidence !== undefined) && (
                <div className="space-y-3 pt-4 border-t">
                  <h4 className="text-sm font-semibold">📊 Conversion Probability & Scoring</h4>
                  <div className="grid grid-cols-2 gap-3">
                    {scoring.conversionProbability !== undefined && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Conversion Probability</p>
                        <Badge variant={scoring.conversionProbability >= 70 ? "default" : scoring.conversionProbability >= 50 ? "secondary" : "outline"} className="text-sm">
                          {scoring.conversionProbability}%
                        </Badge>
                      </div>
                    )}
                    {scoring.leadScore !== undefined && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Lead Score</p>
                        <Badge variant="default" className="text-sm">{scoring.leadScore}</Badge>
                      </div>
                    )}
                    {scoring.confidence !== undefined && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Confidence</p>
                        <Badge variant="outline" className="text-sm">{scoring.confidence}%</Badge>
                      </div>
                    )}
                    {scoring.fitScore !== undefined && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Fit Score</p>
                        <Badge variant="outline" className="text-sm">{scoring.fitScore}</Badge>
                      </div>
                    )}
                    {scoring.engagementScore !== undefined && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Engagement Score</p>
                        <Badge variant="outline" className="text-sm">{scoring.engagementScore}</Badge>
                      </div>
                    )}
                    {scoring.urgencyScore !== undefined && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Urgency Score</p>
                        <Badge variant="outline" className="text-sm">{scoring.urgencyScore}</Badge>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Conversation Analysis */}
              {conversationAnalysis && (
                <div className="space-y-3 pt-4 border-t">
                  <h4 className="text-sm font-semibold">💬 Conversation Analysis</h4>
                  {conversationAnalysis.mainTopic && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Main Topic</p>
                      <p className="text-sm">{conversationAnalysis.mainTopic}</p>
                    </div>
                  )}
                  {conversationAnalysis.keyTopics && conversationAnalysis.keyTopics.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Key Topics</p>
                      <div className="flex flex-wrap gap-1.5">
                        {conversationAnalysis.keyTopics.map((topic: string, idx: number) => (
                          <Badge key={idx} variant="secondary" className="text-xs">{topic}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  {conversationAnalysis.keyPoints && conversationAnalysis.keyPoints.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Key Points</p>
                      <ul className="space-y-1">
                        {conversationAnalysis.keyPoints.map((point: string, idx: number) => (
                          <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                            <span className="mt-0.5">•</span>
                            <span>{point}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {conversationAnalysis.decisionsMade && conversationAnalysis.decisionsMade.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Decisions Made</p>
                      <ul className="space-y-1">
                        {conversationAnalysis.decisionsMade.map((decision: string, idx: number) => (
                          <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                            <span className="mt-0.5">•</span>
                            <span>{decision}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {conversationAnalysis.questionsAsked && conversationAnalysis.questionsAsked.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Questions Asked</p>
                      <ul className="space-y-1">
                        {conversationAnalysis.questionsAsked.map((question: string, idx: number) => (
                          <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                            <span className="mt-0.5">?</span>
                            <span>{question}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {/* Customer Insights */}
              {customerInsights && (
                <div className="space-y-3 pt-4 border-t">
                  <h4 className="text-sm font-semibold">👤 Customer Insights</h4>
                  <div className="grid grid-cols-2 gap-3">
                    {customerInsights.customerIntent && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Customer Intent</p>
                        <Badge variant="outline">{customerInsights.customerIntent}</Badge>
                      </div>
                    )}
                    {customerInsights.authorityLevel && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Authority Level</p>
                        <Badge variant="outline">{customerInsights.authorityLevel}</Badge>
                      </div>
                    )}
                    {customerInsights.budgetIndicated !== undefined && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Budget Indicated</p>
                        <Badge variant={customerInsights.budgetIndicated ? "default" : "outline"}>
                          {customerInsights.budgetIndicated ? "Yes" : "No"}
                        </Badge>
                      </div>
                    )}
                    {customerInsights.timelineIndicated !== undefined && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Timeline Indicated</p>
                        <Badge variant={customerInsights.timelineIndicated ? "default" : "outline"}>
                          {customerInsights.timelineIndicated ? "Yes" : "No"}
                        </Badge>
                      </div>
                    )}
                  </div>
                  {customerInsights.customerNeeds && customerInsights.customerNeeds.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Customer Needs</p>
                      <ul className="space-y-1">
                        {customerInsights.customerNeeds.map((need: string, idx: number) => (
                          <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                            <span className="mt-0.5">•</span>
                            <span>{need}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {customerInsights.customerGoals && customerInsights.customerGoals.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Customer Goals</p>
                      <ul className="space-y-1">
                        {customerInsights.customerGoals.map((goal: string, idx: number) => (
                          <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                            <span className="mt-0.5">•</span>
                            <span>{goal}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {customerInsights.painPoints && customerInsights.painPoints.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Pain Points</p>
                      <ul className="space-y-1">
                        {customerInsights.painPoints.map((pain: string, idx: number) => (
                          <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                            <span className="text-red-600 dark:text-red-400 mt-0.5">•</span>
                            <span>{pain}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {customerInsights.preferences && customerInsights.preferences.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Preferences</p>
                      <ul className="space-y-1">
                        {customerInsights.preferences.map((pref: string, idx: number) => (
                          <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                            <span className="mt-0.5">•</span>
                            <span>{pref}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {/* Engagement Metrics */}
              {engagementMetrics && (
                <div className="space-y-3 pt-4 border-t">
                  <h4 className="text-sm font-semibold">📈 Engagement Metrics</h4>
                  <div className="grid grid-cols-2 gap-3">
                    {engagementMetrics.engagementLevel && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Engagement Level</p>
                        <Badge variant="outline">{engagementMetrics.engagementLevel}</Badge>
                      </div>
                    )}
                    {engagementMetrics.responseTime && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Response Time</p>
                        <Badge variant="outline">{engagementMetrics.responseTime}</Badge>
                      </div>
                    )}
                    {engagementMetrics.messageFrequency && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Message Frequency</p>
                        <Badge variant="outline">{engagementMetrics.messageFrequency}</Badge>
                      </div>
                    )}
                    {engagementMetrics.conversationDepth && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Conversation Depth</p>
                        <Badge variant="outline">{engagementMetrics.conversationDepth}</Badge>
                      </div>
                    )}
                    {engagementMetrics.sentiment && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Sentiment</p>
                        <Badge variant="outline">{engagementMetrics.sentiment}</Badge>
                      </div>
                    )}
                    {engagementMetrics.tone && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Tone</p>
                        <Badge variant="outline">{engagementMetrics.tone}</Badge>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Business Intelligence */}
              {businessIntelligence && (
                <div className="space-y-3 pt-4 border-t">
                  <h4 className="text-sm font-semibold">💼 Business Intelligence</h4>
                  <div className="grid grid-cols-2 gap-3">
                    {businessIntelligence.priceSensitivity && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Price Sensitivity</p>
                        <Badge variant="outline">{businessIntelligence.priceSensitivity}</Badge>
                      </div>
                    )}
                    {businessIntelligence.opportunitySize && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Opportunity Size</p>
                        <Badge variant="outline">{businessIntelligence.opportunitySize}</Badge>
                      </div>
                    )}
                  </div>
                  {businessIntelligence.buyingSignals && businessIntelligence.buyingSignals.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Buying Signals</p>
                      <ul className="space-y-1">
                        {businessIntelligence.buyingSignals.map((signal: string, idx: number) => (
                          <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                            <span className="text-green-600 dark:text-green-400 mt-0.5">✓</span>
                            <span>{signal}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {businessIntelligence.objections && businessIntelligence.objections.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Objections</p>
                      <ul className="space-y-1">
                        {businessIntelligence.objections.map((objection: string, idx: number) => (
                          <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                            <span className="text-red-600 dark:text-red-400 mt-0.5">⚠</span>
                            <span>{objection}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {businessIntelligence.riskFactors && businessIntelligence.riskFactors.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Risk Factors</p>
                      <ul className="space-y-1">
                        {businessIntelligence.riskFactors.map((risk: string, idx: number) => (
                          <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                            <span className="text-red-600 dark:text-red-400 mt-0.5">•</span>
                            <span>{risk}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {businessIntelligence.productInterest && businessIntelligence.productInterest.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Product Interest</p>
                      <div className="flex flex-wrap gap-1.5">
                        {businessIntelligence.productInterest.map((interest: string, idx: number) => (
                          <Badge key={idx} variant="secondary" className="text-xs">{interest}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  {businessIntelligence.competitorsMentioned && businessIntelligence.competitorsMentioned.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Competitors Mentioned</p>
                      <div className="flex flex-wrap gap-1.5">
                        {businessIntelligence.competitorsMentioned.map((competitor: string, idx: number) => (
                          <Badge key={idx} variant="destructive" className="text-xs">{competitor}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Pipeline Recommendation */}
              {pipelineRecommendation && (
                <div className="space-y-3 pt-4 border-t">
                  <h4 className="text-sm font-semibold">🎯 Pipeline Recommendation</h4>
                  <div className="grid grid-cols-2 gap-3">
                    {pipelineRecommendation.recommendedStage && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Recommended Stage</p>
                        <Badge variant="default">{pipelineRecommendation.recommendedStage}</Badge>
                      </div>
                    )}
                    {pipelineRecommendation.leadStatus && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Lead Status</p>
                        <Badge variant="outline">{pipelineRecommendation.leadStatus}</Badge>
                      </div>
                    )}
                    {pipelineRecommendation.nextStage && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Next Stage</p>
                        <Badge variant="secondary">{pipelineRecommendation.nextStage}</Badge>
                      </div>
                    )}
                    {pipelineRecommendation.estimatedCloseDate && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Estimated Close Date</p>
                        <p className="text-sm">{new Date(pipelineRecommendation.estimatedCloseDate).toLocaleDateString()}</p>
                      </div>
                    )}
                  </div>
                  {pipelineRecommendation.stageReason && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Stage Reason</p>
                      <p className="text-sm">{pipelineRecommendation.stageReason}</p>
                    </div>
                  )}
                </div>
              )}

              {/* Action Items */}
              {actionItems && (
                <div className="space-y-3 pt-4 border-t">
                  <h4 className="text-sm font-semibold">✅ Action Items</h4>
                  {actionItems.immediateActions && actionItems.immediateActions.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Immediate Actions</p>
                      <ul className="space-y-1">
                        {actionItems.immediateActions.map((action: string, idx: number) => (
                          <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                            <span className="text-red-600 dark:text-red-400 mt-0.5">⚡</span>
                            <span>{action}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {actionItems.followUpActions && actionItems.followUpActions.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Follow-up Actions</p>
                      <ul className="space-y-1">
                        {actionItems.followUpActions.map((action: string, idx: number) => (
                          <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                            <span className="text-blue-600 dark:text-blue-400 mt-0.5">•</span>
                            <span>{action}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {actionItems.nextBestAction && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Next Best Action</p>
                      <p className="text-sm font-medium">{actionItems.nextBestAction}</p>
                    </div>
                  )}
                  {actionItems.bestReply && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Best Reply</p>
                      <p className="text-sm bg-muted p-2 rounded-md">{actionItems.bestReply}</p>
                    </div>
                  )}
                  {actionItems.followUpMessage && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Follow-up Message</p>
                      <p className="text-sm bg-muted p-2 rounded-md">{actionItems.followUpMessage}</p>
                    </div>
                  )}
                  {actionItems.deadline && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Deadline</p>
                      <p className="text-sm">{new Date(actionItems.deadline).toLocaleDateString()}</p>
                    </div>
                  )}
                </div>
              )}

              {/* Fallback: Display raw text if not parsed */}
              {!parsedAnalysis && !executiveSummary && (
            <div className="text-sm text-muted-foreground whitespace-pre-wrap">
              {contact.aiContext}
            </div>
              )}
            
            {/* Legacy fields (for backward compatibility) */}
            {(contact.buyerIntent || contact.sentiment || contact.conversionProbability !== null) && (
              <div className="grid grid-cols-2 gap-4 pt-4 border-t">
                {contact.buyerIntent && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1">Buyer Intent</p>
                    <Badge variant="outline">{contact.buyerIntent}</Badge>
                  </div>
                )}
                {contact.sentiment && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1">Sentiment</p>
                    <Badge variant="outline">{contact.sentiment}</Badge>
                  </div>
                )}
                {contact.conversionProbability !== null && contact.conversionProbability !== undefined && !scoring?.conversionProbability && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1">Conversion Probability</p>
                    <Badge variant={contact.conversionProbability >= 70 ? "default" : contact.conversionProbability >= 50 ? "secondary" : "outline"}>
                      {contact.conversionProbability}%
                    </Badge>
                  </div>
                )}
                {contact.nextBestAction && !actionItems?.nextBestAction && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1">Next Best Action</p>
                    <p className="text-sm">{contact.nextBestAction}</p>
                  </div>
                )}
              </div>
            )}
            
            {contact.productInterests && contact.productInterests.length > 0 && (
              <div className="pt-4 border-t">
                <p className="text-xs font-medium text-muted-foreground mb-2">Product Interests</p>
                <div className="flex flex-wrap gap-2">
                  {contact.productInterests.map((interest: string, idx: number) => (
                    <Badge key={idx} variant="secondary">{interest}</Badge>
                  ))}
                </div>
              </div>
            )}
            
            {contact.agentSuggestions && typeof contact.agentSuggestions === 'object' && !Array.isArray(contact.agentSuggestions) && (
              <div className="pt-4 border-t space-y-2">
                <p className="text-xs font-medium text-muted-foreground mb-2">Agent Suggestions</p>
                {'bestReply' in contact.agentSuggestions && contact.agentSuggestions.bestReply && (
                  <div>
                    <p className="text-xs font-medium mb-1">Best Reply:</p>
                    <p className="text-sm">{String(contact.agentSuggestions.bestReply)}</p>
                  </div>
                )}
                {'followUpMessage' in contact.agentSuggestions && contact.agentSuggestions.followUpMessage && (
                  <div>
                    <p className="text-xs font-medium mb-1">Follow-up:</p>
                    <p className="text-sm">{String(contact.agentSuggestions.followUpMessage)}</p>
                  </div>
                )}
                {'bestOffer' in contact.agentSuggestions && contact.agentSuggestions.bestOffer && (
                  <div>
                    <p className="text-xs font-medium mb-1">Best Offer:</p>
                    <p className="text-sm">{String(contact.agentSuggestions.bestOffer)}</p>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
        );
      })()}

      {(() => {
        // Helper function to check if contactInfo has meaningful data
        // This prevents showing an empty card when contactInfo is {} or has no actual data
        const hasContactInfoData = (info: unknown): boolean => {
          if (!info || typeof info !== 'object' || info === null) {
            return false;
          }
          
          const data = info as Record<string, unknown>;
          
          // Check age
          if (data.age !== null && data.age !== undefined && typeof data.age === 'number') {
            return true;
          }
          
          // Check arrays
          const arrayFields = ['phoneNumbers', 'emails', 'businessNames', 'pageLinks', 
            'facebookPages', 'locations', 'occupations', 'companies', 'websites'];
          for (const field of arrayFields) {
            const value = data[field];
            if (Array.isArray(value) && value.length > 0) {
              return true;
            }
          }
          
          // Check legacy single-value fields
          const singleFields = ['phoneNumber', 'email', 'facebookPage', 'location', 
            'occupation', 'company', 'website'];
          for (const field of singleFields) {
            const value = data[field];
            if (value !== null && value !== undefined && value !== '') {
              return true;
            }
          }
          
          // Check socialMedia
          if (data.socialMedia && typeof data.socialMedia === 'object') {
            const socialValues = Object.values(data.socialMedia);
            if (socialValues.some(v => v !== null && v !== undefined && v !== '' && 
              (Array.isArray(v) ? v.length > 0 : true))) {
              return true;
            }
          }
          
          // Check otherInfo
          if (data.otherInfo && typeof data.otherInfo === 'object' && 
              Object.keys(data.otherInfo).length > 0) {
            return true;
          }
          
          return false;
        };
        
        return hasContactInfoData(contact.contactInfo);
      })() && (
        <Card>
          <CardHeader>
            <CardTitle>Contact Information</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {typeof contact.contactInfo === 'object' && contact.contactInfo !== null && (() => {
              const info = contact.contactInfo as Record<string, unknown>;
              
              // Helper to normalize arrays (handle both single values and arrays for backward compatibility)
              const normalizeArray = (value: unknown): string[] => {
                if (!value) return [];
                if (Array.isArray(value)) {
                  return value.filter((v): v is string => typeof v === 'string' && Boolean(v));
                }
                if (typeof value === 'string') {
                  return [value];
                }
                return [];
              };

              // Helper to render multiple entries
              const renderMultipleEntries = (
                label: string,
                values: string[],
                renderItem: (value: string, index: number) => React.ReactNode
              ) => {
                if (values.length === 0) return null;
                return (
                  <div className="space-y-2">
                    <span className="text-sm font-medium text-muted-foreground">{label}</span>
                    <div className="space-y-1.5">
                      {values.map((value, index) => (
                        <div key={index} className="flex items-center justify-between">
                          {renderItem(value, index)}
                        </div>
                      ))}
                    </div>
                  </div>
                );
              };

              return (
                <>
                  {info.age && typeof info.age === 'number' && (
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Age</span>
                      <span className="text-sm font-medium">{info.age}</span>
                    </div>
                  )}

                  {/* Phone Numbers - Multiple entries */}
                  {(() => {
                    const phones = normalizeArray(info.phoneNumbers || info.phoneNumber);
                    return renderMultipleEntries('Phone Numbers', phones, (phone) => (
                      <a 
                        href={`tel:${phone}`}
                        className="text-sm font-medium text-blue-600 hover:underline"
                      >
                        {phone}
                      </a>
                    ));
                  })()}

                  {/* Emails - Multiple entries */}
                  {(() => {
                    const emails = normalizeArray(info.emails || info.email);
                    return renderMultipleEntries('Email Addresses', emails, (email) => (
                      <a 
                        href={`mailto:${email}`}
                        className="text-sm font-medium text-blue-600 hover:underline"
                      >
                        {email}
                      </a>
                    ));
                  })()}

                  {/* Business Names - Multiple entries */}
                  {(() => {
                    const businesses = normalizeArray(info.businessNames);
                    return renderMultipleEntries('Business Names', businesses, (business) => (
                      <span className="text-sm font-medium">{business}</span>
                    ));
                  })()}

                  {/* Page Links - Multiple entries */}
                  {(() => {
                    const pageLinks = normalizeArray(info.pageLinks);
                    return renderMultipleEntries('Page Links', pageLinks, (link) => (
                      <a 
                        href={link.startsWith('http') ? link : `https://${link}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm font-medium text-blue-600 hover:underline truncate max-w-[200px]"
                      >
                        {link}
                      </a>
                    ));
                  })()}

                  {/* Locations - Multiple entries */}
                  {(() => {
                    const locations = normalizeArray(info.locations || info.location);
                    return renderMultipleEntries('Locations', locations, (location) => (
                      <span className="text-sm font-medium">{location}</span>
                    ));
                  })()}

                  {/* Occupations - Multiple entries */}
                  {(() => {
                    const occupations = normalizeArray(info.occupations || info.occupation);
                    return renderMultipleEntries('Occupations', occupations, (occupation) => (
                      <span className="text-sm font-medium">{occupation}</span>
                    ));
                  })()}

                  {/* Companies - Multiple entries */}
                  {(() => {
                    const companies = normalizeArray(info.companies || info.company);
                    return renderMultipleEntries('Companies', companies, (company) => (
                      <span className="text-sm font-medium">{company}</span>
                    ));
                  })()}

                  {/* Websites - Multiple entries */}
                  {(() => {
                    const websites = normalizeArray(info.websites || info.website);
                    return renderMultipleEntries('Websites', websites, (website) => (
                      <a 
                        href={website.startsWith('http') ? website : `https://${website}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm font-medium text-blue-600 hover:underline truncate max-w-[200px]"
                      >
                        {website}
                      </a>
                    ));
                  })()}

                  {/* Facebook Pages - Multiple entries */}
                  {(() => {
                    const fbPages = normalizeArray(info.facebookPages || info.facebookPage);
                    return renderMultipleEntries('Facebook Pages', fbPages, (page) => (
                      <a 
                        href={page.startsWith('http') ? page : `https://facebook.com/${page}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm font-medium text-blue-600 hover:underline"
                      >
                        {page}
                      </a>
                    ));
                  })()}

                  {/* Social Media - Multiple entries per platform */}
                  {info.socialMedia && typeof info.socialMedia === 'object' && (
                    <div className="mt-3 pt-3 border-t space-y-3">
                      <h5 className="text-sm font-medium mb-2">Social Media</h5>
                      <div className="space-y-2">
                        {(() => {
                          const socialMedia = info.socialMedia as Record<string, unknown>;
                          const facebook = normalizeArray(socialMedia.facebook);
                          return facebook.length > 0 && (
                            <div className="space-y-1">
                              <span className="text-xs text-muted-foreground">Facebook</span>
                              <div className="space-y-1">
                                {facebook.map((handle, index) => (
                                  <div key={index} className="flex items-center justify-between">
                                    <a 
                                      href={handle.startsWith('http') ? handle : `https://facebook.com/${handle}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="text-xs font-medium text-blue-600 hover:underline"
                                    >
                                      {handle.startsWith('@') ? handle : `@${handle}`}
                                    </a>
                                  </div>
                                ))}
                              </div>
                            </div>
                          );
                        })()}
                        {(() => {
                          const socialMedia = info.socialMedia as Record<string, unknown>;
                          const instagram = normalizeArray(socialMedia.instagram);
                          return instagram.length > 0 && (
                            <div className="space-y-1">
                              <span className="text-xs text-muted-foreground">Instagram</span>
                              <div className="space-y-1">
                                {instagram.map((handle, index) => (
                                  <div key={index} className="flex items-center justify-between">
                                    <a 
                                      href={handle.startsWith('http') ? handle : `https://instagram.com/${handle}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="text-xs font-medium text-blue-600 hover:underline"
                                    >
                                      {handle.startsWith('@') ? handle : `@${handle}`}
                                    </a>
                                  </div>
                                ))}
                              </div>
                            </div>
                          );
                        })()}
                        {(() => {
                          const socialMedia = info.socialMedia as Record<string, unknown>;
                          const twitter = normalizeArray(socialMedia.twitter);
                          return twitter.length > 0 && (
                            <div className="space-y-1">
                              <span className="text-xs text-muted-foreground">Twitter/X</span>
                              <div className="space-y-1">
                                {twitter.map((handle, index) => (
                                  <div key={index} className="flex items-center justify-between">
                                    <a 
                                      href={handle.startsWith('http') ? handle : `https://twitter.com/${handle}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="text-xs font-medium text-blue-600 hover:underline"
                                    >
                                      {handle.startsWith('@') ? handle : `@${handle}`}
                                    </a>
                                  </div>
                                ))}
                              </div>
                            </div>
                          );
                        })()}
                        {(() => {
                          const socialMedia = info.socialMedia as Record<string, unknown>;
                          const linkedin = normalizeArray(socialMedia.linkedin);
                          return linkedin.length > 0 && (
                            <div className="space-y-1">
                              <span className="text-xs text-muted-foreground">LinkedIn</span>
                              <div className="space-y-1">
                                {linkedin.map((profile, index) => (
                                  <div key={index} className="flex items-center justify-between">
                                    <a 
                                      href={profile.startsWith('http') ? profile : `https://linkedin.com/in/${profile}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="text-xs font-medium text-blue-600 hover:underline"
                                    >
                                      {profile.startsWith('@') ? profile : `@${profile}`}
                                    </a>
                                  </div>
                                ))}
                              </div>
                            </div>
                          );
                        })()}
                        {(() => {
                          const socialMedia = info.socialMedia as Record<string, unknown>;
                          const tiktok = normalizeArray(socialMedia.tiktok);
                          return tiktok.length > 0 && (
                            <div className="space-y-1">
                              <span className="text-xs text-muted-foreground">TikTok</span>
                              <div className="space-y-1">
                                {tiktok.map((handle, index) => (
                                  <div key={index} className="flex items-center justify-between">
                                    <a 
                                      href={handle.startsWith('http') ? handle : `https://tiktok.com/@${handle}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="text-xs font-medium text-blue-600 hover:underline"
                                    >
                                      {handle.startsWith('@') ? handle : `@${handle}`}
                                    </a>
                                  </div>
                                ))}
                              </div>
                            </div>
                          );
                        })()}
                        {(() => {
                          const socialMedia = info.socialMedia as Record<string, unknown>;
                          const youtube = normalizeArray(socialMedia.youtube);
                          return youtube.length > 0 && (
                            <div className="space-y-1">
                              <span className="text-xs text-muted-foreground">YouTube</span>
                              <div className="space-y-1">
                                {youtube.map((channel, index) => (
                                  <div key={index} className="flex items-center justify-between">
                                    <a 
                                      href={channel.startsWith('http') ? channel : `https://youtube.com/@${channel}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="text-xs font-medium text-blue-600 hover:underline"
                                    >
                                      {channel.startsWith('@') ? channel : `@${channel}`}
                                    </a>
                                  </div>
                                ))}
                              </div>
                            </div>
                          );
                        })()}
                      </div>
                    </div>
                  )}
                </>
              );
            })()}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-4">
            <div className="flex-1 min-w-0">
              <CardTitle>Best Contact Times</CardTitle>
              {contact.bestContactTimes && typeof contact.bestContactTimes === 'object' && contact.bestContactTimes !== null && (
                <p className="text-xs text-muted-foreground mt-1">
                  Based on reply time analysis of {(contact.bestContactTimes as Record<string, unknown>).totalMessagesAnalyzed as number || 0} messages
                </p>
              )}
            </div>
            <div className="shrink-0">
              <UpdateBestTimesButton contactId={contact.id} />
            </div>
          </div>
        </CardHeader>
        {contact.bestContactTimes ? (
          <CardContent className="space-y-4">
            {typeof contact.bestContactTimes === 'object' && contact.bestContactTimes !== null && (() => {
              const times = contact.bestContactTimes as Record<string, unknown>;
              const bestTimes = times.bestContactTimes as Array<{
                dayOfWeek: string;
                timeRange: string;
                confidence: number;
                averageReplyTime?: number;
                messageCount?: number;
                isDefault?: boolean;
              }> | undefined;
              const isBorrowed = times.isBorrowed === true;
              const borrowedSource = times.borrowedSource as string | undefined;
              const isDefault = times.isDefault === true;
              const note = times.note as string | undefined;
              
              return (
                <>
                  {isBorrowed && borrowedSource && (
                    <div className="mb-4 p-3 bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800 rounded-lg">
                      <p className="text-xs text-amber-900 dark:text-amber-200">
                        <strong>Note:</strong> These best contact times are borrowed from a similar contact ({borrowedSource}) because this contact doesn&apos;t have enough message history yet. Once you have at least 2 messages with this contact, personalized times will be computed.
                      </p>
                    </div>
                  )}
                  {isDefault && note && (
                    <div className="mb-4 p-3 bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-800 rounded-lg">
                      <p className="text-xs text-blue-900 dark:text-blue-200">{note}</p>
                    </div>
                  )}
                  {bestTimes && Array.isArray(bestTimes) && bestTimes.length > 0 ? (
                    <div className="space-y-3">
                      {bestTimes.map((time, index) => (
                        <div key={index} className="flex items-center justify-between p-2 rounded-lg bg-muted/50">
                          <div className="flex-1">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium">{time.dayOfWeek}</span>
                              <span className="text-sm text-muted-foreground">{time.timeRange}</span>
                              {isBorrowed && (
                                <Badge variant="outline" className="text-xs">From Similar Contact</Badge>
                              )}
                              {time.isDefault && !isBorrowed && (
                                <Badge variant="secondary" className="text-xs">Default</Badge>
                              )}
                            </div>
                            {time.averageReplyTime && (
                              <p className="text-xs text-muted-foreground mt-1">
                                Avg reply: {time.averageReplyTime} min
                                {time.messageCount && ` • ${time.messageCount} messages`}
                              </p>
                            )}
                          </div>
                          <Badge variant="outline" className="ml-2">
                            {time.confidence}% confidence
                          </Badge>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground">No contact time data available yet</p>
                  )}
                  
                  {(() => {
                    const avgTime = times.averageReplyTime;
                    const fastest = times.fastestReplyTime;
                    const slowest = times.slowestReplyTime;
                    
                    if (avgTime && typeof avgTime === 'number') {
                      return (
                        <div className="mt-4 pt-4 border-t space-y-2">
                          <div className="flex items-center justify-between text-sm">
                            <span className="text-muted-foreground">Average Reply Time</span>
                            <span className="font-medium">{avgTime} minutes</span>
                          </div>
                          {typeof fastest === 'number' && (
                            <div className="flex items-center justify-between text-sm">
                              <span className="text-muted-foreground">Fastest Reply</span>
                              <span className="font-medium">{fastest} minutes</span>
                            </div>
                          )}
                          {typeof slowest === 'number' && (
                            <div className="flex items-center justify-between text-sm">
                              <span className="text-muted-foreground">Slowest Reply</span>
                              <span className="font-medium">{slowest} minutes</span>
                            </div>
                          )}
                        </div>
                      );
                    }
                    return null;
                  })()}
                </>
              );
            })()}
          </CardContent>
        ) : (
          <CardContent>
            <div className="text-center py-6">
              <p className="text-sm text-muted-foreground mb-2">
                Best contact times haven&apos;t been computed yet.
              </p>
              <p className="text-xs text-muted-foreground mb-4">
                Click the Update button above to analyze message history. You need at least 2 messages to get personalized times.
              </p>
            </div>
          </CardContent>
        )}
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Activity Timeline</CardTitle>
            {total > activities.length && (
              <span className="text-xs text-muted-foreground">
                Showing {activities.length} of {total}
              </span>
            )}
          </div>
        </CardHeader>
        <CardContent>
          <ActivityTimeline 
            activities={activities} 
            total={total}
            currentPage={page}
            totalPages={totalPages}
            hasMore={hasMore}
            contactId={contactId}
          />
        </CardContent>
      </Card>
    </div>
  );
}

// Main page component with streaming
export default async function ContactDetailPage({ params, searchParams }: ContactDetailPageProps) {
  const session = await auth();
  if (!session?.user) {
    redirect('/login');
  }

  const { id } = await params;
  const { returnTo, pipelineId, activityPage } = await searchParams;
  const activityPageNum = activityPage ? parseInt(activityPage as string, 10) : 1;

  // Determine back navigation based on query parameters
  const getBackUrl = () => {
    if (returnTo === 'pipeline' && pipelineId) {
      return `/pipelines/${pipelineId}`;
    }
    return '/contacts';
  };

  const getBackLabel = () => {
    if (returnTo === 'pipeline' && pipelineId) {
      return 'Back to Pipeline';
    }
    return 'Back to Contacts';
  };

  return (
    <div className="space-y-6">
      <ContactDetailRefresh />
      <Button variant="ghost" asChild className="mb-4">
        <Link href={getBackUrl()}>
          <ArrowLeft className="h-4 w-4 mr-2" />
          {getBackLabel()}
        </Link>
      </Button>

      <div className="grid gap-6 md:grid-cols-3">
        <Suspense fallback={<ProfileSkeleton />}>
          <ContactProfile contactId={id} organizationId={session.user.organizationId} />
        </Suspense>

        <Suspense fallback={<ActivitySkeleton />}>
          <ContactActivity 
            contactId={id} 
            organizationId={session.user.organizationId}
            activityPage={activityPageNum}
          />
        </Suspense>
      </div>
    </div>
  );
}

// Enable static params caching for production
export const dynamic = 'force-dynamic';
export const revalidate = 0;
