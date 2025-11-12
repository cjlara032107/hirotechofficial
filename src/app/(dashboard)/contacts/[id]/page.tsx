import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { notFound, redirect } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { ArrowLeft, MessageSquare } from 'lucide-react';
import { ContactTagEditor } from '@/components/contacts/contact-tag-editor';
import { ActivityTimeline } from '@/components/contacts/activity-timeline';
import Link from 'next/link';

interface ContactDetailPageProps {
  params: Promise<{ id: string }>;
}

async function getContact(id: string) {
  const session = await auth();
  if (!session?.user) {
    redirect('/login');
  }

  const contact = await prisma.contact.findFirst({
    where: {
      id,
      organizationId: session.user.organizationId,
    },
    include: {
      stage: true,
      pipeline: true,
      activities: {
        orderBy: { createdAt: 'desc' },
        take: 20,
        include: {
          user: {
            select: {
              name: true,
            },
          },
        },
      },
    },
  });

  if (!contact) {
    notFound();
  }

  return contact;
}

async function getTags() {
  const session = await auth();
  if (!session?.user) return [];

  return prisma.tag.findMany({
    where: { organizationId: session.user.organizationId },
    select: {
      id: true,
      name: true,
      color: true,
    },
  });
}

export default async function ContactDetailPage({ params }: ContactDetailPageProps) {
  const { id } = await params;
  const [contact, availableTags] = await Promise.all([getContact(id), getTags()]);

  return (
    <div className="space-y-6">
      <Button variant="ghost" asChild className="mb-4">
        <Link href="/contacts">
          <ArrowLeft className="h-4 w-4 mr-2" />
          Back to Contacts
        </Link>
      </Button>

      <div className="grid gap-6 md:grid-cols-3">
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
                <ContactTagEditor
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

          <Card>
            <CardHeader>
              <CardTitle>Activity Timeline</CardTitle>
            </CardHeader>
            <CardContent>
              <ActivityTimeline activities={contact.activities} />
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
