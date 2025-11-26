import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { notFound, redirect } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { ArrowLeft, MessageSquare } from 'lucide-react';
import { ContactTagEditorOptimized } from '@/components/contacts/contact-tag-editor-optimized';
import { ActivityTimeline } from '@/components/contacts/activity-timeline';
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
        aiContextUpdatedAt: true,
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
      notFound();
    }

    return contact;
  } catch (error: unknown) {
    // Handle case where contactInfo or bestContactTimes columns don't exist
    console.warn('[Contact Page] ⚠️ Database schema error - contactInfo/bestContactTimes columns may not exist');
    console.warn('[Contact Page] If you see this error, run the migration: apply-production-migration.sql');
    const dbError = error as { code?: string; message?: string };
    if (dbError.code === 'P2022' || dbError.message?.includes('does not exist')) {
      // Retry without the new columns
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
          aiContextUpdatedAt: true,
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
        notFound();
      }

      // Add null values for missing columns
      return {
        ...contact,
        contactInfo: null,
        bestContactTimes: null,
      };
    }
    throw error;
  }
}

async function getContactActivities(contactId: string, organizationId: string, page: number = 1, limit: number = 50) {
  const skip = (page - 1) * limit;
  
  const [activities, total] = await Promise.all([
    prisma.contactActivity.findMany({
      where: {
        contactId,
        contact: {
          organizationId,
        },
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
        contact: {
          organizationId,
        },
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
}

async function getTags(organizationId: string) {
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

  return (
    <div className="md:col-span-1 space-y-6">
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
      <Card>
        <CardHeader>
          <CardTitle>Notes</CardTitle>
        </CardHeader>
        <CardContent>
          {contact.notes ? (
            <p className="text-sm">{contact.notes}</p>
          ) : (
            <p className="text-sm text-muted-foreground">No notes yet</p>
          )}
        </CardContent>
      </Card>

      {contact.aiContext && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>AI Context</CardTitle>
              {contact.aiContextUpdatedAt && (
                <span className="text-xs text-muted-foreground">
                  Updated {new Date(contact.aiContextUpdatedAt).toLocaleDateString()}
                </span>
              )}
            </div>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground whitespace-pre-wrap">
              {contact.aiContext}
            </p>
          </CardContent>
        </Card>
      )}

      {(() => {
        // Helper function to check if contactInfo has meaningful data
        // This prevents showing an empty card when contactInfo is {} or has no actual data
        // CRITICAL: Made less strict to catch more cases where data exists
        const hasContactInfoData = (info: unknown): boolean => {
          if (!info || typeof info !== 'object' || info === null) {
            return false;
          }
          
          const data = info as Record<string, unknown>;
          
          // Check age
          if (data.age !== null && data.age !== undefined && typeof data.age === 'number') {
            return true;
          }
          
          // Check arrays - be more lenient, check for any non-empty array
          const arrayFields = ['phoneNumbers', 'emails', 'businessNames', 'pageLinks', 
            'facebookPages', 'locations', 'occupations', 'companies', 'websites'];
          for (const field of arrayFields) {
            const value = data[field];
            if (Array.isArray(value) && value.length > 0) {
              // Additional check: ensure at least one element is non-empty string
              if (value.some(v => typeof v === 'string' && v.trim().length > 0)) {
                return true;
              }
            }
          }
          
          // Check legacy single-value fields
          const singleFields = ['phoneNumber', 'email', 'facebookPage', 'location', 
            'occupation', 'company', 'website'];
          for (const field of singleFields) {
            const value = data[field];
            if (value !== null && value !== undefined && value !== '' && 
                (typeof value === 'string' ? value.trim().length > 0 : true)) {
              return true;
            }
          }
          
          // Check socialMedia - be more lenient
          if (data.socialMedia && typeof data.socialMedia === 'object') {
            const socialValues = Object.values(data.socialMedia);
            if (socialValues.some(v => {
              if (v === null || v === undefined || v === '') return false;
              if (Array.isArray(v)) {
                return v.length > 0 && v.some(item => typeof item === 'string' && item.trim().length > 0);
              }
              if (typeof v === 'string') {
                return v.trim().length > 0;
              }
              return true;
            })) {
              return true;
            }
          }
          
          // Check otherInfo - be more lenient
          if (data.otherInfo && typeof data.otherInfo === 'object' && 
              Object.keys(data.otherInfo).length > 0) {
            // Check if any value is non-empty
            const hasNonEmptyValue = Object.values(data.otherInfo).some(v => {
              if (v === null || v === undefined || v === '') return false;
              if (typeof v === 'string') return v.trim().length > 0;
              if (Array.isArray(v)) return v.length > 0;
              return true;
            });
            if (hasNonEmptyValue) {
              return true;
            }
          }
          
          return false;
        };
        
        const hasData = hasContactInfoData(contact.contactInfo);
        if (!hasData && contact.contactInfo) {
          // Log when contactInfo exists but validation fails - helps debug
          console.log('[Contact Detail Page] ⚠️ contactInfo exists but validation failed:', JSON.stringify(contact.contactInfo, null, 2));
        }
        return hasData;
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

      {contact.bestContactTimes && (
        <Card>
          <CardHeader>
            <CardTitle>Best Contact Times</CardTitle>
            {typeof contact.bestContactTimes === 'object' && contact.bestContactTimes !== null && (
              <p className="text-xs text-muted-foreground mt-1">
                Based on reply time analysis of {(contact.bestContactTimes as Record<string, unknown>).totalMessagesAnalyzed as number || 0} messages
              </p>
            )}
          </CardHeader>
          <CardContent className="space-y-4">
            {typeof contact.bestContactTimes === 'object' && contact.bestContactTimes !== null && (() => {
              const times = contact.bestContactTimes as Record<string, unknown>;
              const bestTimes = times.bestContactTimes as Array<{
                dayOfWeek: string;
                timeRange: string;
                confidence: number;
                averageReplyTime?: number;
                messageCount?: number;
              }> | undefined;
              
              return (
                <>
                  {bestTimes && Array.isArray(bestTimes) && bestTimes.length > 0 ? (
                    <div className="space-y-3">
                      {bestTimes.map((time, index) => (
                        <div key={index} className="flex items-center justify-between p-2 rounded-lg bg-muted/50">
                          <div className="flex-1">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium">{time.dayOfWeek}</span>
                              <span className="text-sm text-muted-foreground">{time.timeRange}</span>
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
        </Card>
      )}

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
