'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { toast } from 'sonner';
import { 
  Calendar, 
  Clock, 
  Send, 
  Trash2, 
  Eye,
  AlertCircle,
  Sparkles,
  RefreshCw,
  Users
} from 'lucide-react';
import { format, parseISO, isPast, formatDistanceToNow } from 'date-fns';

interface ScheduledCampaign {
  id: string;
  name: string;
  description: string | null;
  status: string;
  platform: string;
  scheduledAt: string;
  totalRecipients: number;
  autoFetchEnabled: boolean;
  useAiPersonalization: boolean;
  includeTags: string[];
  excludeTags: string[];
  createdAt: string;
  targetingType?: string;
  targetTags?: string[];
  facebookPage: {
    pageName: string;
    id: string;
  };
  template: {
    name: string;
    content: string;
  } | null;
}

export default function ScheduledCampaignsPage() {
  const router = useRouter();
  const [campaigns, setCampaigns] = useState<ScheduledCampaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [campaignToDelete, setCampaignToDelete] = useState<string | null>(null);
  const [sendNowDialogOpen, setSendNowDialogOpen] = useState(false);
  const [campaignToSendNow, setCampaignToSendNow] = useState<string | null>(null);
  const [isSending, setIsSending] = useState(false);

  useEffect(() => {
    fetchScheduledCampaigns();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(() => {
      fetchScheduledCampaigns();
    }, 30000);
    
    return () => clearInterval(interval);
  }, []);

  const fetchScheduledCampaigns = async () => {
    try {
      const response = await fetch('/api/campaigns');
      const data = await response.json();
      
      if (response.ok) {
        // Filter only scheduled campaigns
        const scheduled = data.filter((c: ScheduledCampaign) => c.status === 'SCHEDULED');
        setCampaigns(scheduled);
        
        // Fetch recipient counts for campaigns that don't have them
        const campaignsNeedingCounts = scheduled.filter((c: ScheduledCampaign) => !c.totalRecipients || c.totalRecipients === 0);
        if (campaignsNeedingCounts.length > 0) {
          fetchRecipientCounts(campaignsNeedingCounts);
        }
      } else {
        toast.error(data.error || 'Failed to fetch campaigns');
      }
    } catch (error) {
      toast.error('Failed to fetch scheduled campaigns');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = (campaignId: string) => {
    setCampaignToDelete(campaignId);
    setDeleteDialogOpen(true);
  };

  const confirmDelete = async () => {
    if (!campaignToDelete) return;

    try {
      const response = await fetch(`/api/campaigns/${campaignToDelete}`, {
        method: 'DELETE',
      });

      if (response.ok) {
        toast.success('Campaign deleted successfully');
        fetchScheduledCampaigns();
      } else {
        const data = await response.json();
        toast.error(data.error || 'Failed to delete campaign');
      }
    } catch (error) {
      toast.error('Failed to delete campaign');
      console.error(error);
    } finally {
      setDeleteDialogOpen(false);
      setCampaignToDelete(null);
    }
  };

  const handleSendNow = (campaignId: string) => {
    setCampaignToSendNow(campaignId);
    setSendNowDialogOpen(true);
  };

  const fetchRecipientCounts = async (campaignsToCheck: ScheduledCampaign[]) => {
    const counts: Record<string, number> = {};
    
    // Fetch counts in parallel
    await Promise.all(
      campaignsToCheck.map(async (campaign) => {
        try {
          const response = await fetch('/api/campaigns/preview-contacts', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              facebookPageId: campaign.facebookPage.id,
              platform: campaign.platform,
              targetingType: campaign.targetingType || (campaign.targetTags && campaign.targetTags.length > 0 ? 'TAGS' : 'ALL_CONTACTS'),
              targetTags: campaign.targetTags || [],
            }),
          });
          
          if (response.ok) {
            const data = await response.json();
            counts[campaign.id] = data.total || 0;
          }
        } catch (error) {
          console.error(`Error fetching recipient count for campaign ${campaign.id}:`, error);
        }
      })
    );
    
    setRecipientCounts((prev) => ({ ...prev, ...counts }));
  };

  const confirmSendNow = async () => {
    if (!campaignToSendNow) return;

    setIsSending(true);
    try {
      const response = await fetch(`/api/campaigns/${campaignToSendNow}/send-now`, {
        method: 'POST',
      });

      const data = await response.json();

      if (response.ok) {
        toast.success('Campaign sent successfully!');
        fetchScheduledCampaigns();
        router.push('/campaigns');
      } else {
        toast.error(data.error || 'Failed to send campaign');
      }
    } catch (error) {
      toast.error('Failed to send campaign');
      console.error(error);
    } finally {
      setIsSending(false);
      setSendNowDialogOpen(false);
      setCampaignToSendNow(null);
    }
  };

  // Separate campaigns into past due and upcoming
  const now = new Date();
  const pastDueCampaigns = campaigns.filter(c => isPast(parseISO(c.scheduledAt)));
  const upcomingCampaigns = campaigns.filter(c => !isPast(parseISO(c.scheduledAt)));

  const getStatusBadge = (status: string) => {
    const variants: Record<string, 'default' | 'secondary' | 'destructive' | 'outline'> = {
      SCHEDULED: 'outline',
      SENDING: 'default',
      SENT: 'secondary',
      DRAFT: 'secondary',
      PAUSED: 'secondary',
      CANCELLED: 'destructive',
      COMPLETED: 'secondary',
    };

    return (
      <Badge variant={variants[status] || 'default'}>
        {status}
      </Badge>
    );
  };

  return (
    <div className="container mx-auto py-8 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Scheduled Campaigns</h1>
          <p className="text-muted-foreground mt-2">
            Campaigns scheduled to be sent automatically
          </p>
          <div className="flex items-center gap-2 mt-2">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
            </span>
            <span className="text-sm text-green-600">Auto-send active • Checking every minute</span>
          </div>
        </div>
        <Button onClick={() => router.push('/campaigns/new')}>
          <Calendar className="w-4 h-4 mr-2" />
          Schedule New Campaign
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Scheduled</p>
                <p className="text-3xl font-bold mt-2">{campaigns.length}</p>
              </div>
              <div className="bg-blue-100 p-3 rounded-lg">
                <Calendar className="w-6 h-6 text-blue-600" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Upcoming</p>
                <p className="text-3xl font-bold mt-2">{upcomingCampaigns.length}</p>
              </div>
              <div className="bg-green-100 p-3 rounded-lg">
                <Clock className="w-6 h-6 text-green-600" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Past Due</p>
                <p className="text-3xl font-bold mt-2">{pastDueCampaigns.length}</p>
              </div>
              <div className="bg-orange-100 p-3 rounded-lg">
                <AlertCircle className="w-6 h-6 text-orange-600" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Past Due Campaigns */}
      {pastDueCampaigns.length > 0 && (
        <Card className="border-orange-200 bg-orange-50/50">
          <CardHeader>
            <CardTitle className="text-orange-900 flex items-center gap-2">
              <AlertCircle className="w-5 h-5" />
              Past Due Campaigns ({pastDueCampaigns.length})
            </CardTitle>
            <CardDescription className="text-orange-700">
              These campaigns were scheduled for the past. Send them now or delete them.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {pastDueCampaigns.map((campaign) => (
                <CampaignCard
                  key={campaign.id}
                  campaign={campaign}
                  isPastDue={true}
                  onDelete={handleDelete}
                  onSendNow={handleSendNow}
                  recipientCount={recipientCounts[campaign.id]}
                />
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Upcoming Campaigns */}
      <Card>
        <CardHeader>
          <CardTitle>Upcoming Scheduled Campaigns ({upcomingCampaigns.length})</CardTitle>
          <CardDescription>
            These campaigns will be sent automatically at their scheduled time
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="space-y-4">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-32 bg-muted animate-pulse rounded-lg" />
              ))}
            </div>
          ) : upcomingCampaigns.length === 0 ? (
            <div className="text-center py-12">
              <Calendar className="w-16 h-16 text-muted-foreground mx-auto mb-4" />
              <h3 className="text-lg font-semibold mb-2">No Scheduled Campaigns</h3>
              <p className="text-muted-foreground mb-6">
                You don&apos;t have any campaigns scheduled for the future.
              </p>
              <Button onClick={() => router.push('/campaigns/new')}>
                <Calendar className="w-4 h-4 mr-2" />
                Schedule a Campaign
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              {upcomingCampaigns.map((campaign) => (
                <CampaignCard
                  key={campaign.id}
                  campaign={campaign}
                  isPastDue={false}
                  onDelete={handleDelete}
                  onSendNow={handleSendNow}
                  recipientCount={recipientCounts[campaign.id]}
                />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Delete Dialog */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Scheduled Campaign?</AlertDialogTitle>
            <AlertDialogDescription>
              This action cannot be undone. The scheduled campaign will be permanently deleted.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmDelete}
              className="bg-red-600 hover:bg-red-700"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Send Now Dialog */}
      <AlertDialog open={sendNowDialogOpen} onOpenChange={setSendNowDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Send Campaign Now?</AlertDialogTitle>
            <AlertDialogDescription>
              This will send the campaign immediately instead of waiting for the scheduled time.
              This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isSending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmSendNow}
              disabled={isSending}
              className="bg-blue-600 hover:bg-blue-700"
            >
              {isSending ? 'Sending...' : 'Send Now'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}


interface CampaignCardProps {
  campaign: ScheduledCampaign;
  isPastDue: boolean;
  onDelete: (id: string) => void;
  onSendNow: (id: string) => void;
  recipientCount?: number;
}

function CampaignCard({ campaign, isPastDue, onDelete, onSendNow, recipientCount }: CampaignCardProps) {
  const scheduledDate = parseISO(campaign.scheduledAt);
  const now = new Date();
  const timeUntilSend = Math.ceil((scheduledDate.getTime() - now.getTime()) / (1000 * 60));
  
  // Use provided recipientCount or fall back to campaign.totalRecipients
  const displayRecipientCount = recipientCount !== undefined ? recipientCount : (campaign.totalRecipients || 0);

  return (
    <div
      className={`p-4 rounded-lg border shadow-sm hover:shadow-md transition-shadow ${
        isPastDue ? 'border-orange-200 bg-white' : 'border-border'
      }`}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-2">
            <h3 className="font-semibold text-lg">{campaign.name}</h3>
            {timeUntilSend < 60 && timeUntilSend > 0 && (
              <Badge className="bg-orange-500">
                Sending in {timeUntilSend} min
              </Badge>
            )}
            {campaign.autoFetchEnabled && (
              <Badge variant="outline" className="gap-1">
                <RefreshCw className="w-3 h-3" />
                Auto-fetch
              </Badge>
            )}
            {campaign.useAiPersonalization && (
              <Badge variant="outline" className="gap-1">
                <Sparkles className="w-3 h-3" />
                AI Personalized
              </Badge>
            )}
          </div>

          {campaign.description && (
            <p className="text-sm text-muted-foreground mb-3">
              {campaign.description}
            </p>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4 p-4 bg-muted/30 rounded-lg border border-border/50">
            {/* Scheduled Time Section */}
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
                <Clock className="w-4 h-4 text-primary" />
                Scheduled Send Time
              </div>
              <div className="flex flex-col gap-1">
                <div className="text-lg font-bold text-foreground">
                  {format(scheduledDate, 'MMM dd, yyyy')}
                </div>
                <div className="text-base font-semibold text-primary">
                  {format(scheduledDate, 'h:mm a')}
                </div>
                {!isPastDue && (
                  <div className="text-xs text-muted-foreground mt-1">
                    {formatDistanceToNow(scheduledDate, { addSuffix: true })}
                  </div>
                )}
                {isPastDue && (
                  <div className="text-xs text-orange-600 font-medium mt-1">
                    ⚠️ Past due - should have been sent already
                  </div>
                )}
              </div>
            </div>

            {/* Recipients Section */}
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
                <Users className="w-4 h-4 text-primary" />
                Recipients
              </div>
              <div className="flex items-baseline gap-2">
                <div className="text-3xl font-bold text-foreground">
                  {displayRecipientCount}
                </div>
                <div className="text-sm text-muted-foreground">
                  {displayRecipientCount === 1 ? 'recipient' : 'recipients'}
                </div>
              </div>
              {campaign.autoFetchEnabled && (
                <div className="text-xs text-muted-foreground mt-1">
                  🔄 Auto-fetch enabled - recipients will be updated at send time
                </div>
              )}
              {!displayRecipientCount && !campaign.autoFetchEnabled && (
                <div className="text-xs text-amber-600 mt-1">
                  ⚠️ No recipients set - will be determined at send time
                </div>
              )}
              {displayRecipientCount > 0 && campaign.autoFetchEnabled && (
                <div className="text-xs text-blue-600 mt-1">
                  ℹ️ Current count: {displayRecipientCount}. May increase with new conversations.
                </div>
              )}
            </div>
          </div>

          {/* Additional Info */}
          <div className="flex items-center gap-4 text-sm text-muted-foreground mt-3">
            <span className="flex items-center gap-1">
              <Calendar className="w-4 h-4" />
              {campaign.facebookPage.pageName}
            </span>
            <Badge variant="secondary">
              {campaign.platform}
            </Badge>
          </div>

          {(campaign.includeTags.length > 0 || campaign.excludeTags.length > 0) && (
            <div className="mt-2 text-xs text-muted-foreground">
              {campaign.includeTags.length > 0 && (
                <span>Include: {campaign.includeTags.join(', ')} </span>
              )}
              {campaign.excludeTags.length > 0 && (
                <span>Exclude: {campaign.excludeTags.join(', ')}</span>
              )}
            </div>
          )}
        </div>

        <div className="flex gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => window.location.href = `/campaigns/${campaign.id}`}
          >
            <Eye className="w-4 h-4" />
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => onSendNow(campaign.id)}
            className="border-blue-600 text-blue-600 hover:bg-blue-50"
          >
            <Send className="w-4 h-4" />
          </Button>
          <Button
            size="sm"
            variant="destructive"
            onClick={() => onDelete(campaign.id)}
          >
            <Trash2 className="w-4 h-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}

