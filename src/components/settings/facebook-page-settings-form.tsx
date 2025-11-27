'use client';

import { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { toast } from 'sonner';
import Link from 'next/link';
import { ArrowLeft, RefreshCw, CheckCircle2, XCircle } from 'lucide-react';

interface Pipeline {
  id: string;
  name: string;
}

interface PageSettings {
  autoPipelineId: string | null;
  autoPipelineMode: string;
}

interface FacebookPageSettingsFormProps {
  pageId: string;
  pipelines: Pipeline[];
  initialSettings: PageSettings;
}

interface SyncJobStatus {
  id: string;
  status: string;
  syncedContacts: number;
  failedContacts: number;
  totalContacts: number;
  startedAt: string | null;
  completedAt: string | null;
}

export function FacebookPageSettingsForm({ 
  pageId, 
  pipelines, 
  initialSettings 
}: FacebookPageSettingsFormProps) {
  const [settings, setSettings] = useState({
    autoPipelineId: initialSettings.autoPipelineId || 'none',
    autoPipelineMode: initialSettings.autoPipelineMode || 'SKIP_EXISTING'
  });
  const [loading, setLoading] = useState(false);
  const [syncJob, setSyncJob] = useState<SyncJobStatus | null>(null);
  const [isPolling, setIsPolling] = useState(false);

  // Fetch latest sync job status
  const fetchSyncStatus = useCallback(async () => {
    try {
      const response = await fetch(`/api/facebook/pages/${pageId}/latest-sync`);
      if (response.ok) {
        const data = await response.json();
        if (data.job) {
          setSyncJob(data.job);
          // Continue polling if sync is in progress
          const shouldPoll = data.job.status === 'PENDING' || data.job.status === 'IN_PROGRESS';
          setIsPolling(shouldPoll);
        } else {
          setSyncJob(null);
          setIsPolling(false);
        }
      }
    } catch (error) {
      console.error('Error fetching sync status:', error);
    }
  }, [pageId]);

  // Initial fetch on mount and poll when sync is in progress
  useEffect(() => {
    // Always do initial fetch
    fetchSyncStatus();

    // Only set up polling if sync is in progress
    if (!isPolling) return;

    const interval = setInterval(() => {
      fetchSyncStatus();
    }, 2000);

    return () => clearInterval(interval);
  }, [isPolling, fetchSyncStatus]);

  // Also check for sync status when page becomes visible (in case user navigated away)
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        fetchSyncStatus();
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, [fetchSyncStatus]);

  async function saveSettings() {
    setLoading(true);
    try {
      // Convert "none" to null for database
      const settingsToSave = {
        autoPipelineId: settings.autoPipelineId === 'none' ? null : settings.autoPipelineId,
        autoPipelineMode: settings.autoPipelineMode
      };
      
      const res = await fetch(`/api/facebook/pages/${pageId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settingsToSave)
      });
      
      if (res.ok) {
        toast.success('Settings saved successfully! Auto-assignment will apply on next sync.');
      } else {
        const errorData = await res.json();
        toast.error(errorData.error || 'Failed to save settings');
      }
    } catch (error) {
      console.error('Error saving settings:', error);
      toast.error('Error saving settings');
    } finally {
      setLoading(false);
    }
  }

  // Calculate progress percentage
  const progressPercentage = syncJob && syncJob.totalContacts > 0
    ? Math.round((syncJob.syncedContacts / syncJob.totalContacts) * 100)
    : 0;

  // Format elapsed time
  const formatElapsedTime = (startedAt: string | null) => {
    if (!startedAt) return '';
    const start = new Date(startedAt);
    const now = new Date();
    const seconds = Math.floor((now.getTime() - start.getTime()) / 1000);
    
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
    const hours = Math.floor(minutes / 60);
    return `${hours}h ${minutes % 60}m`;
  };

  return (
    <div className="space-y-6">
      <Link href="/settings/integrations">
        <Button variant="ghost" className="mb-4">
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Integrations
        </Button>
      </Link>
      
      <div>
        <h1 className="text-3xl font-bold">Facebook Page Settings</h1>
        <p className="text-muted-foreground mt-2">
          Configure automatic pipeline assignment for contacts
        </p>
      </div>

      {/* Real-time Sync Progress Counter */}
      {syncJob && (syncJob.status === 'PENDING' || syncJob.status === 'IN_PROGRESS') && (
        <Card className="bg-gradient-to-br from-blue-50 to-indigo-50 dark:from-blue-950/20 dark:to-indigo-950/20 border-blue-200 dark:border-blue-800">
          <CardHeader className="pb-3">
            <CardTitle className="text-lg flex items-center gap-2">
              <RefreshCw className="h-5 w-5 text-blue-600 animate-spin" />
              Sync in Progress
            </CardTitle>
            <CardDescription>
              Processing contacts in the background
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Processed Contacts</span>
                <span className="font-semibold text-blue-600 dark:text-blue-400">
                  {syncJob.syncedContacts.toLocaleString()}
                </span>
              </div>
              {syncJob.totalContacts > 0 && (
                <Progress value={progressPercentage} className="h-2" />
              )}
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span>{progressPercentage}% complete</span>
                {syncJob.startedAt && (
                  <span>Elapsed: {formatElapsedTime(syncJob.startedAt)}</span>
                )}
              </div>
            </div>
            {syncJob.failedContacts > 0 && (
              <div className="flex items-center gap-2 text-sm text-destructive">
                <XCircle className="h-4 w-4" />
                <span>{syncJob.failedContacts} contact{syncJob.failedContacts !== 1 ? 's' : ''} failed</span>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Completed Sync Summary */}
      {syncJob && syncJob.status === 'COMPLETED' && (
        <Card className="bg-gradient-to-br from-green-50 to-emerald-50 dark:from-green-950/20 dark:to-emerald-950/20 border-green-200 dark:border-green-800">
          <CardHeader className="pb-3">
            <CardTitle className="text-lg flex items-center gap-2">
              <CheckCircle2 className="h-5 w-5 text-green-600" />
              Last Sync Completed
            </CardTitle>
            <CardDescription>
              {syncJob.completedAt && new Date(syncJob.completedAt).toLocaleString()}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-6">
              <div>
                <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                  {syncJob.syncedContacts.toLocaleString()}
                </div>
                <div className="text-xs text-muted-foreground">Synced</div>
              </div>
              {syncJob.failedContacts > 0 && (
                <div>
                  <div className="text-2xl font-bold text-destructive">
                    {syncJob.failedContacts.toLocaleString()}
                  </div>
                  <div className="text-xs text-muted-foreground">Failed</div>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Auto-Pipeline Assignment</CardTitle>
          <CardDescription>
            Automatically assign synced contacts to pipeline stages based on AI analysis
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {pipelines.length === 0 ? (
            <div className="text-center py-8 space-y-4">
              <p className="text-muted-foreground">
                No pipelines found. Create a pipeline first to enable auto-assignment.
              </p>
              <Link href="/pipelines">
                <Button>
                  Create Pipeline
                </Button>
              </Link>
            </div>
          ) : (
            <>
              <div className="space-y-2">
                <Label>Target Pipeline</Label>
                <Select
                  value={settings.autoPipelineId}
                  onValueChange={(value) => setSettings({ ...settings, autoPipelineId: value })}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select pipeline (optional)" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">None - Manual assignment only</SelectItem>
                    {pipelines.map((p) => (
                      <SelectItem key={p.id} value={p.id}>
                        {p.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-sm text-muted-foreground">
                  AI will analyze conversations and assign contacts to the best matching stage
                </p>
              </div>

              {settings.autoPipelineId && settings.autoPipelineId !== 'none' && (
                <div className="space-y-2">
                  <Label>Update Mode</Label>
                  <RadioGroup
                    value={settings.autoPipelineMode}
                    onValueChange={(value) => setSettings({ ...settings, autoPipelineMode: value })}
                  >
                    <div className="flex items-center space-x-2">
                      <RadioGroupItem value="SKIP_EXISTING" id="skip" />
                      <Label htmlFor="skip" className="font-normal">
                        Skip Existing - Only assign new contacts without a pipeline
                      </Label>
                    </div>
                    <div className="flex items-center space-x-2">
                      <RadioGroupItem value="UPDATE_EXISTING" id="update" />
                      <Label htmlFor="update" className="font-normal">
                        Update Existing - Re-evaluate and update all contacts on every sync
                      </Label>
                    </div>
                  </RadioGroup>
                </div>
              )}

              <Button onClick={saveSettings} disabled={loading}>
                {loading ? 'Saving...' : 'Save Settings'}
              </Button>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

