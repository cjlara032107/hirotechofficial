'use client';

import { useState, useEffect } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Users,
  Clock,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Calendar,
  MessageSquare,
  Loader2,
  RefreshCw,
} from 'lucide-react';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { ScrollArea } from '@/components/ui/scroll-area';
import { formatDistanceToNow, format } from 'date-fns';

interface ContactData {
  id: string;
  firstName: string;
  lastName: string | null;
  profilePicUrl: string | null;
  tags: string[];
  lastInteraction: string;
  nextTriggerTime: string;
  isEligible: boolean;
  isStopped: boolean;
  isInCooldown?: boolean;
  cooldownExpiresAt?: string | null;
  stopInfo: {
    reason: string;
    followUpsSent: number;
    stoppedAt: string;
  } | null;
  executions: Array<{
    id: string;
    status: string;
    executedAt: string;
    generatedMessage: string | null;
    errorMessage: string | null;
  }>;
  timeUntilTriggerMs: number;
  timeSinceEligibleMs: number;
  facebookPage: {
    id: string;
    pageName: string;
  } | null;
}

interface RuleDetails {
  id: string;
  name: string;
  includeTags: string[];
  excludeTags: string[];
  timeIntervalMinutes: number | null;
  timeIntervalHours: number | null;
  timeIntervalDays: number | null;
  enabled: boolean;
  facebookPage: {
    id: string;
    pageName: string;
    pageId: string;
  } | null;
}

interface RuleDetailsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  ruleId: string;
}

export function RuleDetailsDialog({
  open,
  onOpenChange,
  ruleId,
}: RuleDetailsDialogProps) {
  const [loading, setLoading] = useState(true);
  const [rule, setRule] = useState<RuleDetails | null>(null);
  const [contacts, setContacts] = useState<ContactData[]>([]);
  const [statistics, setStatistics] = useState({
    totalMatching: 0,
    eligibleCount: 0,
    stoppedCount: 0,
    ineligibleCount: 0,
  });
  const [error, setError] = useState<string | null>(null);

  const fetchDetails = async () => {
    if (!ruleId) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(`/api/ai-automations/${ruleId}/details`);
      
      if (!response.ok) {
        throw new Error('Failed to fetch rule details');
      }
      
      const data = await response.json();
      setRule(data.rule);
      setContacts(data.contacts);
      setStatistics(data.statistics);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load details';
      setError(errorMessage);
      console.error('Error fetching rule details:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (open && ruleId) {
      fetchDetails();
    }
  }, [open, ruleId]);

  const formatTimeInterval = (rule: RuleDetails | null) => {
    if (!rule) return 'Not set';
    const parts = [];
    if (rule.timeIntervalDays) parts.push(`${rule.timeIntervalDays}d`);
    if (rule.timeIntervalHours) parts.push(`${rule.timeIntervalHours}h`);
    if (rule.timeIntervalMinutes) parts.push(`${rule.timeIntervalMinutes}m`);
    return parts.join(' ') || 'Not set';
  };

  const formatTimeUntil = (ms: number) => {
    if (ms === 0) return 'Now';
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days}d ${hours % 24}h`;
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m`;
    return `${seconds}s`;
  };

  const getContactInitials = (firstName: string, lastName: string | null) => {
    const first = firstName.charAt(0).toUpperCase();
    const last = lastName ? lastName.charAt(0).toUpperCase() : '';
    return `${first}${last}`;
  };

  const eligibleContacts = contacts.filter(c => c.isEligible && !c.isStopped && !c.isInCooldown);
  const ineligibleContacts = contacts.filter(c => (!c.isEligible || c.isInCooldown) && !c.isStopped);
  const stoppedContacts = contacts.filter(c => c.isStopped);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Users className="w-5 h-5" />
            Automation Details
          </DialogTitle>
          <DialogDescription>
            View contacts, trigger times, and execution history for this automation rule
          </DialogDescription>
        </DialogHeader>

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : error ? (
          <div className="text-center py-12">
            <AlertCircle className="w-12 h-12 text-destructive mx-auto mb-4" />
            <p className="text-destructive mb-4">{error}</p>
            <Button onClick={fetchDetails} variant="outline">
              <RefreshCw className="w-4 h-4 mr-2" />
              Retry
            </Button>
          </div>
        ) : (
          <div className="space-y-4">
            {/* Rule Info */}
            {rule && (
              <Card className="p-4">
                <div className="space-y-2">
                  <h3 className="font-semibold text-lg">{rule.name}</h3>
                  <div className="flex flex-wrap gap-4 text-sm text-muted-foreground">
                    <div className="flex items-center gap-1">
                      <Clock className="w-4 h-4" />
                      Interval: {formatTimeInterval(rule)}
                    </div>
                    {rule.facebookPage && (
                      <div>Page: {rule.facebookPage.pageName}</div>
                    )}
                    <Badge variant={rule.enabled ? 'default' : 'secondary'}>
                      {rule.enabled ? 'Active' : 'Paused'}
                    </Badge>
                  </div>
                  {rule.includeTags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      <span className="text-xs text-muted-foreground">Include tags:</span>
                      {rule.includeTags.map(tag => (
                        <Badge key={tag} variant="default" className="bg-green-600">
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  )}
                  {rule.excludeTags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      <span className="text-xs text-muted-foreground">Exclude tags:</span>
                      {rule.excludeTags.map(tag => (
                        <Badge key={tag} variant="destructive">
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  )}
                </div>
              </Card>
            )}

            {/* Statistics */}
            <div className="grid grid-cols-4 gap-4">
              <Card className="p-4">
                <div className="text-2xl font-bold">{statistics.totalMatching}</div>
                <div className="text-xs text-muted-foreground">Total Matching</div>
              </Card>
              <Card className="p-4 border-green-500">
                <div className="text-2xl font-bold text-green-600">
                  {statistics.eligibleCount}
                </div>
                <div className="text-xs text-muted-foreground">Eligible Now</div>
              </Card>
              <Card className="p-4 border-yellow-500">
                <div className="text-2xl font-bold text-yellow-600">
                  {statistics.ineligibleCount}
                </div>
                <div className="text-xs text-muted-foreground">Scheduled</div>
              </Card>
              <Card className="p-4 border-red-500">
                <div className="text-2xl font-bold text-red-600">
                  {statistics.stoppedCount}
                </div>
                <div className="text-xs text-muted-foreground">Stopped</div>
              </Card>
            </div>

            {/* Next Message Due Summary */}
            {(() => {
              const upcomingContacts = contacts
                .filter(c => !c.isStopped && !c.isEligible)
                .sort((a, b) => a.nextTriggerTime.localeCompare(b.nextTriggerTime));
              
              const nextUpcoming = upcomingContacts[0];
              const eligibleNow = contacts.filter(c => c.isEligible && !c.isStopped).length;

              if (nextUpcoming) {
                return (
                  <Card className="p-4 bg-primary/5 border-primary/20">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="text-sm font-medium text-muted-foreground mb-1">
                          Next Message Due
                        </div>
                        <div className="text-lg font-bold">
                          {format(new Date(nextUpcoming.nextTriggerTime), 'MMM d, yyyy h:mm a')}
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">
                          {nextUpcoming.firstName} {nextUpcoming.lastName} • {formatTimeUntil(nextUpcoming.timeUntilTriggerMs)} from now
                        </div>
                      </div>
                      {eligibleNow > 0 && (
                        <div className="text-right">
                          <div className="text-2xl font-bold text-green-600">{eligibleNow}</div>
                          <div className="text-xs text-muted-foreground">Ready now</div>
                        </div>
                      )}
                    </div>
                  </Card>
                );
              } else if (eligibleNow > 0) {
                return (
                  <Card className="p-4 bg-green-500/10 border-green-500/20">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="text-sm font-medium text-green-600 mb-1">
                          Messages Ready to Send
                        </div>
                        <div className="text-lg font-bold text-green-600">
                          {eligibleNow} contact{eligibleNow !== 1 ? 's' : ''} eligible now
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">
                          Will be sent on next cron run (every minute)
                        </div>
                      </div>
                    </div>
                  </Card>
                );
              }
              return null;
            })()}

            {/* Contacts Tabs */}
            <Tabs defaultValue="eligible" className="w-full">
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="eligible">
                  Eligible ({eligibleContacts.length})
                </TabsTrigger>
                <TabsTrigger value="scheduled">
                  Scheduled ({ineligibleContacts.length})
                </TabsTrigger>
                <TabsTrigger value="stopped">
                  Stopped ({stoppedContacts.length})
                </TabsTrigger>
              </TabsList>

              <TabsContent value="eligible" className="mt-4">
                <ScrollArea className="h-[400px]">
                  <div className="space-y-2">
                    {eligibleContacts.length === 0 ? (
                      <div className="text-center py-8 text-muted-foreground">
                        No eligible contacts at this time
                      </div>
                    ) : (
                      eligibleContacts.map(contact => (
                        <ContactCard
                          key={contact.id}
                          contact={contact}
                          formatTimeUntil={formatTimeUntil}
                          getContactInitials={getContactInitials}
                        />
                      ))
                    )}
                  </div>
                </ScrollArea>
              </TabsContent>

              <TabsContent value="scheduled" className="mt-4">
                <ScrollArea className="h-[400px]">
                  <div className="space-y-2">
                    {ineligibleContacts.length === 0 ? (
                      <div className="text-center py-8 text-muted-foreground">
                        No scheduled contacts
                      </div>
                    ) : (
                      ineligibleContacts.map(contact => (
                        <ContactCard
                          key={contact.id}
                          contact={contact}
                          formatTimeUntil={formatTimeUntil}
                          getContactInitials={getContactInitials}
                        />
                      ))
                    )}
                  </div>
                </ScrollArea>
              </TabsContent>

              <TabsContent value="stopped" className="mt-4">
                <ScrollArea className="h-[400px]">
                  <div className="space-y-2">
                    {stoppedContacts.length === 0 ? (
                      <div className="text-center py-8 text-muted-foreground">
                        No stopped contacts
                      </div>
                    ) : (
                      stoppedContacts.map(contact => (
                        <ContactCard
                          key={contact.id}
                          contact={contact}
                          formatTimeUntil={formatTimeUntil}
                          getContactInitials={getContactInitials}
                        />
                      ))
                    )}
                  </div>
                </ScrollArea>
              </TabsContent>
            </Tabs>

            <div className="flex justify-end">
              <Button onClick={fetchDetails} variant="outline" size="sm">
                <RefreshCw className="w-4 h-4 mr-2" />
                Refresh
              </Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

interface ContactCardProps {
  contact: ContactData;
  formatTimeUntil: (ms: number) => string;
  getContactInitials: (firstName: string, lastName: string | null) => string;
}

function ContactCard({ contact, formatTimeUntil, getContactInitials }: ContactCardProps) {
  const [showExecutions, setShowExecutions] = useState(false);

  return (
    <Card className="p-4">
      <div className="flex items-start gap-3">
        <Avatar>
          <AvatarImage src={contact.profilePicUrl || undefined} />
          <AvatarFallback>
            {getContactInitials(contact.firstName, contact.lastName)}
          </AvatarFallback>
        </Avatar>
        
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h4 className="font-medium">
              {contact.firstName} {contact.lastName}
            </h4>
            {contact.isStopped && (
              <Badge variant="destructive" className="text-xs">
                Stopped
              </Badge>
            )}
            {contact.isEligible && !contact.isStopped && !contact.isInCooldown && (
              <Badge variant="default" className="bg-green-600 text-xs">
                Ready
              </Badge>
            )}
            {contact.isInCooldown && !contact.isStopped && (
              <Badge variant="secondary" className="bg-yellow-500 text-xs">
                In Cooldown
              </Badge>
            )}
          </div>

          <div className="space-y-1 text-xs text-muted-foreground">
            <div className="flex items-center gap-1">
              <Calendar className="w-3 h-3" />
              Last interaction: {formatDistanceToNow(new Date(contact.lastInteraction), { addSuffix: true })}
            </div>
            <div className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {contact.isInCooldown && contact.cooldownExpiresAt
                ? `Cooldown expires in ${formatTimeUntil(contact.timeUntilTriggerMs)}`
                : contact.isEligible
                ? `Eligible for ${formatTimeUntil(contact.timeSinceEligibleMs)}`
                : `Triggers in ${formatTimeUntil(contact.timeUntilTriggerMs)}`}
            </div>
            {contact.isInCooldown && contact.cooldownExpiresAt && (
              <div className="flex items-center gap-1 mt-1 p-2 bg-yellow-500/10 rounded border border-yellow-500/20">
                <Clock className="w-3 h-3 text-yellow-600" />
                <span className="text-xs font-medium text-yellow-700">
                  Cooldown until: {format(new Date(contact.cooldownExpiresAt), 'MMM d, yyyy h:mm a')}
                </span>
              </div>
            )}
            <div className="flex items-center gap-1 mt-2 p-2 bg-muted/50 rounded border border-border/50">
              <Calendar className="w-3 h-3 text-primary" />
              <span className="font-medium text-foreground">
                {contact.isInCooldown && contact.cooldownExpiresAt
                  ? `Next eligible: ${format(new Date(contact.cooldownExpiresAt), 'MMM d, yyyy h:mm a')}`
                  : `Next message due: ${format(new Date(contact.nextTriggerTime), 'MMM d, yyyy h:mm a')}`}
              </span>
            </div>
            {contact.stopInfo && (
              <div className="flex items-center gap-1 text-red-600">
                <AlertCircle className="w-3 h-3" />
                Stopped: {contact.stopInfo.reason} ({contact.stopInfo.followUpsSent} messages sent)
              </div>
            )}
            {contact.tags.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-1">
                {contact.tags.map(tag => (
                  <Badge key={tag} variant="outline" className="text-xs">
                    {tag}
                  </Badge>
                ))}
              </div>
            )}
          </div>

          {contact.executions.length > 0 && (
            <div className="mt-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowExecutions(!showExecutions)}
                className="text-xs"
              >
                <MessageSquare className="w-3 h-3 mr-1" />
                {contact.executions.length} execution{contact.executions.length !== 1 ? 's' : ''}
              </Button>

              {showExecutions && (
                <div className="mt-2 space-y-2 pl-4 border-l-2">
                  {contact.executions.map(execution => (
                    <div key={execution.id} className="text-xs">
                      <div className="flex items-center gap-2 mb-1">
                        <Badge
                          variant={
                            execution.status === 'sent'
                              ? 'default'
                              : execution.status === 'failed'
                              ? 'destructive'
                              : 'secondary'
                          }
                          className="text-xs"
                        >
                          {execution.status}
                        </Badge>
                        <span className="text-muted-foreground">
                          {format(new Date(execution.executedAt), 'MMM d, yyyy h:mm a')}
                        </span>
                      </div>
                      {execution.generatedMessage && (
                        <p className="text-muted-foreground mt-1 line-clamp-2">
                          {execution.generatedMessage}
                        </p>
                      )}
                      {execution.errorMessage && (
                        <p className="text-red-600 mt-1 text-xs">
                          Error: {execution.errorMessage}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}

