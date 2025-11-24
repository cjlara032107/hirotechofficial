'use client';

import { useState, useEffect, useRef } from 'react';
import { usePathname } from 'next/navigation';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Checkbox } from '@/components/ui/checkbox';
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
import { EmptyState } from '@/components/ui/empty-state';
import { Plus, Send, TrendingUp, Clock, CheckCircle2, XCircle, Users, Calendar, Trash2 } from 'lucide-react';
import { format, formatDistanceToNow } from 'date-fns';

interface Campaign {
  id: string;
  name: string;
  status: string;
  platform: string;
  totalRecipients: number;
  sentCount: number;
  deliveredCount: number;
  readCount: number;
  failedCount: number;
  repliedCount: number;
  createdAt: string;
  startedAt?: string | null;
  completedAt?: string | null;
  template?: {
    name: string;
    content: string;
  } | null;
  facebookPage?: {
    pageName: string;
  } | null;
}

export default function CampaignsPage() {
  const router = useRouter();
  const pathname = usePathname();

  // Check page access on mount
  useEffect(() => {
    async function checkPageAccess() {
      try {
        const response = await fetch(`/api/developer/page-access/check?path=${encodeURIComponent(pathname)}`);
        if (response.ok) {
          const data = await response.json();
          if (data.isEnabled === false) {
            router.replace(`/under-development?page=${encodeURIComponent(pathname)}`);
          }
        }
      } catch (error) {
        console.error('Error checking page access:', error);
      }
    }
    checkPageAccess();
  }, [pathname, router]);
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<string>('active');
  const [selectedCampaigns, setSelectedCampaigns] = useState<Set<string>>(new Set());
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  
  // Use ref to track campaigns without causing re-renders
  const campaignsRef = useRef(campaigns);

  // Update ref whenever campaigns change
  useEffect(() => {
    campaignsRef.current = campaigns;
  }, [campaigns]);

  // Fetch campaigns initially and set up polling
  useEffect(() => {
    fetchCampaigns();
    
    // Poll every 2 seconds if there are campaigns in SENDING status or recently completed
    const interval = setInterval(() => {
      const currentCampaigns = campaignsRef.current;
      const hasActiveCampaigns = currentCampaigns.some(
        (c) => c.status === 'SENDING' || (c.status === 'COMPLETED' && !c.completedAt)
      );
      
      if (hasActiveCampaigns) {
        fetchCampaigns();
      }
    }, 2000); // Poll every 2 seconds for faster updates

    return () => clearInterval(interval);
  }, []); // Empty dependency array - only run once on mount
  
  // Force refresh when any campaign completes
  useEffect(() => {
    const completedCampaigns = campaigns.filter(
      (c) => c.status === 'COMPLETED' && c.completedAt
    );
    
    if (completedCampaigns.length > 0) {
      // Final refresh to ensure all data is up to date
      const timeout = setTimeout(() => {
        fetchCampaigns();
      }, 500);
      
      return () => clearTimeout(timeout);
    }
  }, [campaigns]);

  const fetchCampaigns = async () => {
    try {
      const response = await fetch('/api/campaigns');
      
      // Check if response is JSON
      const contentType = response.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        throw new Error('Server returned non-JSON response');
      }
      
      const data = await response.json();
      if (response.ok) {
        setCampaigns(data);
      } else {
        toast.error(data.error || 'Failed to fetch campaigns');
      }
    } catch (error) {
      console.error('Error fetching campaigns:', error);
      const err = error as Error;
      toast.error(err.message || 'An error occurred while fetching campaigns');
    } finally {
      setLoading(false);
    }
  };

  const handleSelectCampaign = (campaignId: string, checked: boolean) => {
    setSelectedCampaigns((prev) => {
      const newSet = new Set(prev);
      if (checked) {
        newSet.add(campaignId);
      } else {
        newSet.delete(campaignId);
      }
      return newSet;
    });
  };

  const handleSelectAll = (campaignList: Campaign[], checked: boolean) => {
    if (checked) {
      const ids = new Set(campaignList.map((c) => c.id));
      setSelectedCampaigns(ids);
    } else {
      setSelectedCampaigns(new Set());
    }
  };

  const handleDeleteSelected = async () => {
    if (selectedCampaigns.size === 0) return;

    setIsDeleting(true);
    let successCount = 0;
    let errorCount = 0;

    try {
      // Delete campaigns one by one
      const deletePromises = Array.from(selectedCampaigns).map(async (id) => {
        try {
          const response = await fetch(`/api/campaigns/${id}`, {
            method: 'DELETE',
          });

          if (!response.ok) {
            errorCount++;
            return false;
          }
          
          successCount++;
          return true;
        } catch (error) {
          console.error(`Error deleting campaign ${id}:`, error);
          errorCount++;
          return false;
        }
      });

      await Promise.all(deletePromises);

      // Show appropriate toast message
      if (successCount > 0 && errorCount === 0) {
        toast.success(`Successfully deleted ${successCount} campaign${successCount > 1 ? 's' : ''}`);
      } else if (successCount > 0 && errorCount > 0) {
        toast.warning(`Deleted ${successCount} campaign${successCount > 1 ? 's' : ''}, ${errorCount} failed`);
      } else {
        toast.error('Failed to delete campaigns');
      }

      // Refresh campaigns list
      await fetchCampaigns();
      
      // Clear selection
      setSelectedCampaigns(new Set());
    } catch (error) {
      console.error('Error during bulk delete:', error);
      toast.error('An error occurred while deleting campaigns');
    } finally {
      setIsDeleting(false);
      setShowDeleteDialog(false);
    }
  };

  const handleClearSelection = () => {
    setSelectedCampaigns(new Set());
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <div className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-current border-r-transparent align-[-0.125em] motion-reduce:animate-[spin_1.5s_linear_infinite]" />
          <p className="mt-4 text-sm text-muted-foreground">Loading campaigns...</p>
        </div>
      </div>
    );
  }

  const getStatusColor = (status: string): "default" | "secondary" | "outline" | "destructive" => {
    switch (status) {
      case 'DRAFT':
        return 'secondary';
      case 'SENDING':
      case 'SCHEDULED':
        return 'default';
      case 'SENT':
      case 'COMPLETED':
        return 'outline';
      case 'PAUSED':
        return 'secondary';
      case 'CANCELLED':
        return 'destructive';
      default:
        return 'secondary';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'COMPLETED':
      case 'SENT':
        return <CheckCircle2 className="h-4 w-4" />;
      case 'SENDING':
        return <Clock className="h-4 w-4 animate-pulse" />;
      case 'CANCELLED':
        return <XCircle className="h-4 w-4" />;
      default:
        return null;
    }
  };

  // Separate campaigns into active and history
  const activeCampaigns = campaigns.filter(
    (c) => ['DRAFT', 'SCHEDULED', 'SENDING'].includes(c.status)
  );
  
  const historyCampaigns = campaigns.filter(
    (c) => ['SENT', 'COMPLETED', 'CANCELLED', 'PAUSED'].includes(c.status)
  );

  // Calculate aggregate stats for history
  const historyStats = {
    totalCampaigns: historyCampaigns.length,
    totalRecipients: historyCampaigns.reduce((sum, c) => sum + c.totalRecipients, 0),
    totalSent: historyCampaigns.reduce((sum, c) => sum + c.sentCount, 0),
    totalDelivered: historyCampaigns.reduce((sum, c) => sum + c.deliveredCount, 0),
    totalReplied: historyCampaigns.reduce((sum, c) => sum + c.repliedCount, 0),
    totalFailed: historyCampaigns.reduce((sum, c) => sum + c.failedCount, 0),
  };

  const calculateSuccessRate = (campaign: Campaign) => {
    if (campaign.totalRecipients === 0) return 0;
    return Math.round((campaign.deliveredCount / campaign.totalRecipients) * 100);
  };

  const calculateEngagementRate = (campaign: Campaign) => {
    if (campaign.deliveredCount === 0) return 0;
    return Math.round((campaign.repliedCount / campaign.deliveredCount) * 100);
  };

  const renderCampaignCard = (campaign: Campaign) => {
    const isSelected = selectedCampaigns.has(campaign.id);
    
    return (
      <div key={campaign.id} className="relative">
        <Card className={`hover:shadow-md transition-shadow ${isSelected ? 'ring-2 ring-primary' : ''}`}>
          <CardHeader className="pb-3">
            <div className="flex items-start gap-3">
              <Checkbox
                checked={isSelected}
                onCheckedChange={(checked) => handleSelectCampaign(campaign.id, checked as boolean)}
                onClick={(e) => e.stopPropagation()}
                className="mt-1"
              />
              <Link href={`/campaigns/${campaign.id}`} className="flex-1 min-w-0">
                <div className="flex items-start justify-between">
                  <div className="flex-1 min-w-0">
                    <CardTitle className="text-base truncate">{campaign.name}</CardTitle>
                    {campaign.facebookPage && (
                      <p className="text-xs text-muted-foreground mt-1 truncate">
                        {campaign.facebookPage.pageName}
                      </p>
                    )}
                  </div>
                  <div className="flex items-center gap-2 ml-2 shrink-0">
                    {getStatusIcon(campaign.status)}
                    <Badge variant={getStatusColor(campaign.status)}>
                      {campaign.status}
                    </Badge>
                  </div>
                </div>
              </Link>
            </div>
          </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Platform</span>
            <Badge variant="outline">{campaign.platform}</Badge>
          </div>

          {campaign.totalRecipients > 0 && (
            <>
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Recipients</span>
                <span className="font-medium">{campaign.totalRecipients}</span>
              </div>

              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Sent</span>
                <span className="font-medium">
                  {campaign.sentCount} / {campaign.totalRecipients}
                </span>
              </div>

              {campaign.deliveredCount > 0 && (
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Delivered</span>
                  <span className="font-medium text-green-600">
                    {campaign.deliveredCount}
                  </span>
                </div>
              )}

              {campaign.repliedCount > 0 && (
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Replied</span>
                  <span className="font-medium text-blue-600">
                    {campaign.repliedCount}
                  </span>
                </div>
              )}

              {campaign.failedCount > 0 && (
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Failed</span>
                  <span className="font-medium text-red-600">
                    {campaign.failedCount}
                  </span>
                </div>
              )}
            </>
          )}

          {campaign.completedAt && (
            <div className="pt-2 border-t text-xs text-muted-foreground">
              Completed {formatDistanceToNow(new Date(campaign.completedAt), { addSuffix: true })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
    );
  };

  // Get the current visible campaigns based on active tab
  const visibleCampaigns = activeTab === 'active' ? activeCampaigns : historyCampaigns;
  const allVisibleSelected = visibleCampaigns.length > 0 && 
    visibleCampaigns.every((c) => selectedCampaigns.has(c.id));

  return (
    <div className="space-y-6 relative">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Campaigns</h1>
          <p className="text-muted-foreground mt-2">
            Create and manage bulk messaging campaigns
          </p>
        </div>

        <Button onClick={() => router.push('/campaigns/new')}>
          <Plus className="h-4 w-4 mr-2" />
          New Campaign
        </Button>
      </div>

      {/* Floating Action Bar */}
      {selectedCampaigns.size > 0 && (
        <div className="fixed bottom-6 left-1/2 transform -translate-x-1/2 z-50 animate-in slide-in-from-bottom-5">
          <Card className="shadow-lg border-2">
            <CardContent className="p-4">
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <Checkbox
                    checked={allVisibleSelected}
                    onCheckedChange={(checked) => handleSelectAll(visibleCampaigns, checked as boolean)}
                    className="data-[state=checked]:bg-primary"
                  />
                  <span className="text-sm font-medium">
                    {selectedCampaigns.size} selected
                  </span>
                </div>
                
                <div className="h-6 w-px bg-border" />
                
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleClearSelection}
                  >
                    Clear
                  </Button>
                  
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={() => setShowDeleteDialog(true)}
                    disabled={isDeleting}
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    {isDeleting ? 'Deleting...' : 'Delete'}
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you sure?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete {selectedCampaigns.size} campaign{selectedCampaigns.size > 1 ? 's' : ''} and all associated messages.
              This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isDeleting}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteSelected}
              disabled={isDeleting}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {isDeleting ? 'Deleting...' : 'Delete'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {campaigns.length === 0 ? (
        <EmptyState
          icon={<Send className="h-12 w-12" />}
          title="No campaigns yet"
          description="Create your first campaign to start sending bulk messages"
          action={{
            label: 'Create Campaign',
            onClick: () => router.push('/campaigns/new'),
          }}
        />
      ) : (
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList>
            <TabsTrigger value="active" className="relative">
              Active
              {activeCampaigns.length > 0 && (
                <Badge variant="secondary" className="ml-2 h-5 px-1.5">
                  {activeCampaigns.length}
                </Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="history" className="relative">
              History
              {historyCampaigns.length > 0 && (
                <Badge variant="secondary" className="ml-2 h-5 px-1.5">
                  {historyCampaigns.length}
                </Badge>
              )}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="active" className="space-y-4">
            {activeCampaigns.length === 0 ? (
              <Card>
                <CardContent className="pt-6">
                  <EmptyState
                    icon={<Clock className="h-12 w-12" />}
                    title="No active campaigns"
                    description="All your campaigns are either completed or paused. Create a new campaign to get started."
                    action={{
                      label: 'Create Campaign',
                      onClick: () => router.push('/campaigns/new'),
                    }}
                  />
                </CardContent>
              </Card>
            ) : (
              <>
                {/* Select All Checkbox */}
                <div className="flex items-center gap-2 px-1">
                  <Checkbox
                    checked={allVisibleSelected}
                    onCheckedChange={(checked) => handleSelectAll(activeCampaigns, checked as boolean)}
                    id="select-all-active"
                  />
                  <label
                    htmlFor="select-all-active"
                    className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 cursor-pointer"
                  >
                    Select all {activeCampaigns.length} campaign{activeCampaigns.length > 1 ? 's' : ''}
                  </label>
                </div>
                
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                  {activeCampaigns.map(renderCampaignCard)}
                </div>
              </>
            )}
          </TabsContent>

          <TabsContent value="history" className="space-y-6">
            {historyCampaigns.length === 0 ? (
              <Card>
                <CardContent className="pt-6">
                  <EmptyState
                    icon={<Calendar className="h-12 w-12" />}
                    title="No campaign history"
                    description="You haven't completed any campaigns yet. Start your first campaign to see results here."
                  />
                </CardContent>
              </Card>
            ) : (
              <>
                {/* Campaign History Stats */}
                <div className="grid gap-4 md:grid-cols-4">
                  <Card>
                    <CardHeader className="pb-3">
                      <CardDescription className="flex items-center gap-2">
                        <Send className="h-4 w-4" />
                        Total Campaigns
                      </CardDescription>
                      <CardTitle className="text-2xl">{historyStats.totalCampaigns}</CardTitle>
                    </CardHeader>
                  </Card>

                  <Card>
                    <CardHeader className="pb-3">
                      <CardDescription className="flex items-center gap-2">
                        <Users className="h-4 w-4" />
                        Total Recipients
                      </CardDescription>
                      <CardTitle className="text-2xl">{historyStats.totalRecipients.toLocaleString()}</CardTitle>
                    </CardHeader>
                  </Card>

                  <Card>
                    <CardHeader className="pb-3">
                      <CardDescription className="flex items-center gap-2">
                        <CheckCircle2 className="h-4 w-4 text-green-600" />
                        Delivered
                      </CardDescription>
                      <CardTitle className="text-2xl text-green-600">
                        {historyStats.totalDelivered.toLocaleString()}
                      </CardTitle>
                      <p className="text-xs text-muted-foreground mt-1">
                        {historyStats.totalRecipients > 0
                          ? `${Math.round((historyStats.totalDelivered / historyStats.totalRecipients) * 100)}% success rate`
                          : 'No data'}
                      </p>
                    </CardHeader>
                  </Card>

                  <Card>
                    <CardHeader className="pb-3">
                      <CardDescription className="flex items-center gap-2">
                        <TrendingUp className="h-4 w-4 text-blue-600" />
                        Engagement
                      </CardDescription>
                      <CardTitle className="text-2xl text-blue-600">
                        {historyStats.totalReplied.toLocaleString()}
                      </CardTitle>
                      <p className="text-xs text-muted-foreground mt-1">
                        {historyStats.totalDelivered > 0
                          ? `${Math.round((historyStats.totalReplied / historyStats.totalDelivered) * 100)}% reply rate`
                          : 'No data'}
                      </p>
                    </CardHeader>
                  </Card>
                </div>

                {/* Campaign History List */}
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold">Campaign Timeline</h3>
                    <div className="flex items-center gap-2">
                      <Checkbox
                        checked={allVisibleSelected}
                        onCheckedChange={(checked) => handleSelectAll(historyCampaigns, checked as boolean)}
                        id="select-all-history"
                      />
                      <label
                        htmlFor="select-all-history"
                        className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 cursor-pointer"
                      >
                        Select all {historyCampaigns.length} campaign{historyCampaigns.length > 1 ? 's' : ''}
                      </label>
                    </div>
                  </div>
                  <div className="space-y-3">
                    {historyCampaigns.map((campaign) => {
                      const isSelected = selectedCampaigns.has(campaign.id);
                      
                      return (
                        <div key={campaign.id} className="relative">
                          <Card className={`hover:shadow-md transition-shadow ${isSelected ? 'ring-2 ring-primary' : ''}`}>
                            <CardContent className="pt-6">
                              <div className="flex items-start gap-3">
                                <Checkbox
                                  checked={isSelected}
                                  onCheckedChange={(checked) => handleSelectCampaign(campaign.id, checked as boolean)}
                                  onClick={(e) => e.stopPropagation()}
                                  className="mt-1"
                                />
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-start justify-between mb-4">
                                    <div className="flex-1">
                                      <div className="flex items-center gap-2 mb-1">
                                        <h4 className="font-semibold">{campaign.name}</h4>
                                        <Badge variant={getStatusColor(campaign.status)}>
                                          {campaign.status}
                                        </Badge>
                                      </div>
                                      <div className="flex items-center gap-4 text-xs text-muted-foreground">
                                        {campaign.facebookPage && (
                                          <span>{campaign.facebookPage.pageName}</span>
                                        )}
                                        <Badge variant="outline" className="text-xs">
                                          {campaign.platform}
                                        </Badge>
                                        {campaign.completedAt && (
                                          <span>
                                            Completed on {format(new Date(campaign.completedAt), 'MMM dd, yyyy')}
                                          </span>
                                        )}
                                      </div>
                                    </div>
                                  </div>

                                  <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-sm">
                                    <div>
                                      <p className="text-muted-foreground text-xs mb-1">Recipients</p>
                                      <p className="font-semibold">{campaign.totalRecipients}</p>
                                    </div>
                                    <div>
                                      <p className="text-muted-foreground text-xs mb-1">Sent</p>
                                      <p className="font-semibold">{campaign.sentCount}</p>
                                    </div>
                                    <div>
                                      <p className="text-muted-foreground text-xs mb-1">Delivered</p>
                                      <p className="font-semibold text-green-600">
                                        {campaign.deliveredCount}
                                        <span className="text-xs ml-1 text-muted-foreground">
                                          ({calculateSuccessRate(campaign)}%)
                                        </span>
                                      </p>
                                    </div>
                                    <div>
                                      <p className="text-muted-foreground text-xs mb-1">Replied</p>
                                      <p className="font-semibold text-blue-600">
                                        {campaign.repliedCount}
                                        <span className="text-xs ml-1 text-muted-foreground">
                                          ({calculateEngagementRate(campaign)}%)
                                        </span>
                                      </p>
                                    </div>
                                    <div>
                                      <p className="text-muted-foreground text-xs mb-1">Failed</p>
                                      <p className="font-semibold text-red-600">{campaign.failedCount}</p>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            </CardContent>
                          </Card>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </>
            )}
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}

