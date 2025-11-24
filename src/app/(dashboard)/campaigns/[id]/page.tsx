'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { LoadingSpinner } from '@/components/ui/loading-spinner';
import { Progress } from '@/components/ui/progress';
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
import { 
  ArrowLeft, 
  Send, 
  CheckCircle2, 
  XCircle, 
  Clock,
  MessageSquare,
  Users,
  Ban,
  RotateCw
} from 'lucide-react';
import { toast } from 'sonner';
import { formatDistance } from 'date-fns';

interface Campaign {
  id: string;
  name: string;
  description?: string;
  status: string;
  platform: string;
  messageTag?: string;
  totalRecipients: number;
  sentCount: number;
  deliveredCount: number;
  readCount: number;
  failedCount: number;
  targetingType: string;
  targetTags: string[];
  rateLimit: number;
  startedAt?: string;
  createdAt: string;
  template?: {
    name: string;
    content: string;
  };
  facebookPage?: {
    pageName: string;
    pageId: string;
  };
  _count?: {
    messages: number;
  };
}

export default function CampaignDetailPage() {
  const params = useParams();
  const router = useRouter();
  const [campaign, setCampaign] = useState<Campaign | null>(null);
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [resending, setResending] = useState(false);
  const [showCancelDialog, setShowCancelDialog] = useState(false);
  const [showResendDialog, setShowResendDialog] = useState(false);
  
  // Use ref to avoid stale closure in interval
  const campaignRef = useRef(campaign);

  // Update ref whenever campaign changes
  useEffect(() => {
    campaignRef.current = campaign;
  }, [campaign]);

  // Wrap fetchCampaign in useCallback to satisfy React hooks exhaustive-deps
  const fetchCampaign = useCallback(async () => {
    try {
      const response = await fetch(`/api/campaigns/${params.id}`);
      
      // Check if response is JSON
      const contentType = response.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        throw new Error('Server returned non-JSON response');
      }
      
      const data = await response.json();

      if (response.ok) {
        setCampaign(data);
      } else {
        toast.error(data.error || 'Failed to fetch campaign');
      }
    } catch (error) {
      console.error('Error fetching campaign:', error);
      toast.error('An error occurred while fetching campaign');
    } finally {
      setLoading(false);
    }
  }, [params.id]); // fetchCampaign depends on params.id

  // Fetch campaign data initially and set up polling
  useEffect(() => {
    fetchCampaign();
    
    // Poll for updates if campaign is sending or recently completed
    // Using ref to access current campaign status without triggering re-renders
    const interval = setInterval(() => {
      const currentCampaign = campaignRef.current;
      const currentStatus = currentCampaign?.status;
      
      // Poll if sending, or if recently completed (to catch final state)
      if (currentStatus === 'SENDING' || (currentStatus === 'COMPLETED' && currentCampaign && !(currentCampaign as any).completedAt)) {
        fetchCampaign();
      }
    }, 1000); // Poll every 1 second for real-time updates during sending

    return () => clearInterval(interval);
  }, [params.id, fetchCampaign]); // Now includes fetchCampaign which is stable due to useCallback

  const handleStartCampaign = async () => {
    if (!confirm('Are you sure you want to start this campaign? Messages will be sent to all target contacts.')) {
      return;
    }

    setSending(true);
    try {
      const response = await fetch(`/api/campaigns/${params.id}/send`, {
        method: 'POST',
      });

      // Check if response is JSON
      const contentType = response.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        throw new Error('Server returned non-JSON response');
      }

      const data = await response.json();

      if (response.ok) {
        toast.success(`Campaign started! ${data.queued} messages are being sent in parallel batches - Fast mode! ⚡`);
        fetchCampaign();
      } else {
        toast.error(data.error || 'Failed to start campaign');
      }
    } catch (error) {
      console.error('Error starting campaign:', error);
      const err = error as Error;
      toast.error(err.message || 'An error occurred while starting campaign');
    } finally {
      setSending(false);
    }
  };

  const handleCancelCampaign = async () => {
    setCancelling(true);
    setShowCancelDialog(false);
    
    try {
      const response = await fetch(`/api/campaigns/${params.id}/cancel`, {
        method: 'POST',
      });

      // Check if response is JSON
      const contentType = response.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        throw new Error('Server returned non-JSON response');
      }

      const data = await response.json();

      if (response.ok) {
        toast.success('Campaign cancelled successfully. No more messages will be sent.');
        fetchCampaign();
      } else {
        toast.error(data.error || 'Failed to cancel campaign');
      }
    } catch (error) {
      console.error('Error cancelling campaign:', error);
      const err = error as Error;
      toast.error(err.message || 'An error occurred while cancelling campaign');
    } finally {
      setCancelling(false);
    }
  };

  const handleResendCampaign = async () => {
    setResending(true);
    setShowResendDialog(false);
    
    try {
      const response = await fetch(`/api/campaigns/${params.id}/resend`, {
        method: 'POST',
      });

      // Check if response is JSON
      const contentType = response.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        throw new Error('Server returned non-JSON response');
      }

      const data = await response.json();

      if (response.ok) {
        toast.success(`Campaign is being resent! ${data.queued} messages are being sent - Fast mode! ⚡`);
        fetchCampaign();
      } else {
        toast.error(data.error || 'Failed to resend campaign');
      }
    } catch (error) {
      console.error('Error resending campaign:', error);
      const err = error as Error;
      toast.error(err.message || 'An error occurred while resending campaign');
    } finally {
      setResending(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  if (!campaign) {
    return (
      <div className="space-y-6">
        <Button variant="ghost" onClick={() => router.push('/campaigns')}>
          <ArrowLeft className="h-4 w-4 mr-2" />
          Back to Campaigns
        </Button>
        <div className="text-center py-12">
          <p className="text-muted-foreground">Campaign not found</p>
        </div>
      </div>
    );
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'DRAFT':
        return <Badge variant="secondary">Draft</Badge>;
      case 'SENDING':
        return <Badge className="bg-blue-500">Sending</Badge>;
      case 'SENT':
      case 'COMPLETED':
        return <Badge className="bg-green-500">Completed</Badge>;
      case 'PAUSED':
        return <Badge variant="secondary">Paused</Badge>;
      default:
        return <Badge variant="secondary">{status}</Badge>;
    }
  };

  // Calculate progress based on sent count vs total recipients
  // Cap at 100% to avoid showing more than 100%
  const progress = campaign.totalRecipients > 0 
    ? Math.min((campaign.sentCount / campaign.totalRecipients) * 100, 100)
    : 0;

  const deliveryRate = campaign.sentCount > 0
    ? ((campaign.deliveredCount / campaign.sentCount) * 100).toFixed(1)
    : 0;

  const readRate = campaign.deliveredCount > 0
    ? ((campaign.readCount / campaign.deliveredCount) * 100).toFixed(1)
    : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => router.push('/campaigns')}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-3xl font-bold">{campaign.name}</h1>
              {getStatusBadge(campaign.status)}
            </div>
            {campaign.description && (
              <p className="text-muted-foreground mt-1">{campaign.description}</p>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2">
          {campaign.status === 'DRAFT' && (
            <Button onClick={handleStartCampaign} disabled={sending}>
              <Send className="h-4 w-4 mr-2" />
              {sending ? 'Starting...' : 'Start Campaign'}
            </Button>
          )}

          {campaign.status === 'SENDING' && (
            <Button 
              variant="destructive" 
              onClick={() => setShowCancelDialog(true)} 
              disabled={cancelling}
            >
              <Ban className="h-4 w-4 mr-2" />
              {cancelling ? 'Cancelling...' : 'Cancel Campaign'}
            </Button>
          )}

          {['COMPLETED', 'SENT', 'CANCELLED', 'PAUSED'].includes(campaign.status) && (
            <Button 
              onClick={() => setShowResendDialog(true)} 
              disabled={resending}
              variant="outline"
            >
              <RotateCw className="h-4 w-4 mr-2" />
              {resending ? 'Resending...' : 'Resend Campaign'}
            </Button>
          )}
        </div>
      </div>

      {/* Stats Overview */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Recipients</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{campaign.totalRecipients}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Sent</CardTitle>
            <Send className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{campaign.sentCount}</div>
            {campaign.totalRecipients > 0 && (
              <p className="text-xs text-muted-foreground mt-1">
                {progress.toFixed(1)}% complete
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Delivered</CardTitle>
            <CheckCircle2 className="h-4 w-4 text-green-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{campaign.deliveredCount}</div>
            {campaign.sentCount > 0 && (
              <p className="text-xs text-muted-foreground mt-1">
                {deliveryRate}% delivery rate
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Failed</CardTitle>
            <XCircle className="h-4 w-4 text-red-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{campaign.failedCount}</div>
          </CardContent>
        </Card>
      </div>

      {/* Progress */}
      {campaign.status === 'SENDING' && campaign.totalRecipients > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Sending Progress</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">
                  {campaign.sentCount} of {campaign.totalRecipients} sent
                </span>
                <span className="font-medium">{progress.toFixed(1)}%</span>
              </div>
              <Progress value={progress} className="h-2" />
            </div>
            <div className="flex items-center gap-2 text-sm text-green-600 font-medium">
              <Clock className="h-4 w-4" />
              <span>
                ⚡ Fast parallel sending - No rate limits!
              </span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Campaign Details */}
      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Campaign Settings</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Platform</span>
              <Badge variant="outline">{campaign.platform}</Badge>
            </div>

            {campaign.messageTag && (
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Message Tag</span>
                <Badge variant="outline">{campaign.messageTag}</Badge>
              </div>
            )}

            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Targeting</span>
              <Badge variant="outline">{campaign.targetingType}</Badge>
            </div>

            {campaign.targetTags && campaign.targetTags.length > 0 && (
              <div className="space-y-2">
                <span className="text-sm text-muted-foreground">Target Tags</span>
                <div className="flex flex-wrap gap-1">
                  {campaign.targetTags.map((tag) => (
                    <Badge key={tag} variant="secondary" className="text-xs">
                      {tag}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Sending Speed</span>
              <span className="text-sm font-medium text-green-600">⚡ Fast (No Limits)</span>
            </div>

            {campaign.facebookPage && (
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Facebook Page</span>
                <span className="text-sm font-medium">{campaign.facebookPage.pageName}</span>
              </div>
            )}

            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Created</span>
              <span className="text-sm font-medium">
                {formatDistance(new Date(campaign.createdAt), new Date(), { addSuffix: true })}
              </span>
            </div>

            {campaign.startedAt && (
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Started</span>
                <span className="text-sm font-medium">
                  {formatDistance(new Date(campaign.startedAt), new Date(), { addSuffix: true })}
                </span>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Message Template</CardTitle>
          </CardHeader>
          <CardContent>
            {campaign.template ? (
              <div className="space-y-2">
                <p className="text-sm font-medium">{campaign.template.name}</p>
                <div className="rounded-md bg-muted p-3">
                  <p className="text-sm whitespace-pre-wrap">{campaign.template.content}</p>
                </div>
                <p className="text-xs text-muted-foreground">
                  Variables: {'{firstName}'}, {'{lastName}'}, {'{name}'} will be replaced with contact data
                </p>
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No template assigned</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Engagement Stats */}
      {campaign.sentCount > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Engagement Metrics</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-3">
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <MessageSquare className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm font-medium">Read Rate</span>
                </div>
                <p className="text-2xl font-bold">{readRate}%</p>
                <p className="text-xs text-muted-foreground">
                  {campaign.readCount} of {campaign.deliveredCount} delivered messages
                </p>
              </div>

              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-600" />
                  <span className="text-sm font-medium">Delivery Rate</span>
                </div>
                <p className="text-2xl font-bold text-green-600">{deliveryRate}%</p>
                <p className="text-xs text-muted-foreground">
                  {campaign.deliveredCount} of {campaign.sentCount} sent messages
                </p>
              </div>

              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <XCircle className="h-4 w-4 text-red-600" />
                  <span className="text-sm font-medium">Failure Rate</span>
                </div>
                <p className="text-2xl font-bold text-red-600">
                  {campaign.sentCount > 0 
                    ? ((campaign.failedCount / campaign.sentCount) * 100).toFixed(1) 
                    : 0}%
                </p>
                <p className="text-xs text-muted-foreground">
                  {campaign.failedCount} failed deliveries
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Cancel Campaign Dialog */}
      <AlertDialog open={showCancelDialog} onOpenChange={setShowCancelDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Cancel Campaign?</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to cancel this campaign? This will stop all pending messages from being sent.
              Messages that have already been sent cannot be recalled.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={cancelling}>Keep Sending</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleCancelCampaign}
              disabled={cancelling}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {cancelling ? 'Cancelling...' : 'Yes, Cancel Campaign'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Resend Campaign Dialog */}
      <AlertDialog open={showResendDialog} onOpenChange={setShowResendDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Resend Campaign?</AlertDialogTitle>
            <AlertDialogDescription>
              This will reset the campaign and send messages to all target contacts again. 
              Previous campaign messages and statistics will be cleared. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={resending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleResendCampaign}
              disabled={resending}
            >
              {resending ? 'Resending...' : 'Yes, Resend Campaign'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

