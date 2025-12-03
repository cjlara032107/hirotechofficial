'use client';

import { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Switch } from '@/components/ui/switch';
import { Input } from '@/components/ui/input';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { toast } from 'sonner';
import Link from 'next/link';
import { ArrowLeft, RefreshCw, CheckCircle2, XCircle, Sparkles, Loader2 } from 'lucide-react';

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
  
  // AI Pipeline Generation state
  const [showAIGenerator, setShowAIGenerator] = useState(false);
  const [aiGenerating, setAiGenerating] = useState(false);
  const [aiStageCount, setAiStageCount] = useState<string>('');
  const [useCustomStageCount, setUseCustomStageCount] = useState(false);
  const [aiDecideStages, setAiDecideStages] = useState(true);
  const [pipelineDetailLevel, setPipelineDetailLevel] = useState(5); // 1-10 scale, default 5
  const [aiSuggestion, setAiSuggestion] = useState<any>(null);

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
        // Refresh the page to get updated pipelines list
        window.location.reload();
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

  // Handle pipeline selection change
  const handlePipelineChange = (value: string) => {
    if (value === 'generate-ai') {
      setShowAIGenerator(true);
      // Don't change the settings value, keep current selection
    } else {
      setSettings({ ...settings, autoPipelineId: value });
    }
  };

  // Generate AI pipeline
  const handleGenerateAI = async () => {
    setAiGenerating(true);
    try {
      const response = await fetch('/api/pipelines/generate-ai', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          facebookPageId: pageId,
          stageCount: (!aiDecideStages && useCustomStageCount) ? parseInt(aiStageCount) || undefined : undefined,
          detailLevel: aiDecideStages ? pipelineDetailLevel : undefined,
        }),
      });

      if (response.ok) {
        const suggestion = await response.json();
        setAiSuggestion(suggestion);
        toast.success('AI pipeline generated successfully');
      } else {
        const error = await response.json();
        toast.error(error.error || 'Failed to generate AI pipeline');
      }
    } catch (error) {
      console.error('Generate AI pipeline error:', error);
      toast.error('An error occurred while generating pipeline');
    } finally {
      setAiGenerating(false);
    }
  };

  // Create AI pipeline and assign to page
  const handleCreateAIPipeline = async () => {
    if (!aiSuggestion) return;

    setAiGenerating(true);
    try {
      // Create the pipeline
      const createResponse = await fetch('/api/pipelines', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: aiSuggestion.name,
          description: aiSuggestion.description,
          color: '#3b82f6',
          stages: aiSuggestion.stages.map((stage: any) => ({
            name: stage.name,
            description: stage.description,
            color: stage.color,
            type: stage.type,
          })),
        }),
      });

      if (!createResponse.ok) {
        throw new Error('Failed to create pipeline');
      }

      const pipelineData = await createResponse.json();

      // Assign pipeline to the Facebook page
      const assignResponse = await fetch(`/api/facebook/pages/${pageId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          autoPipelineId: pipelineData.id,
          autoPipelineMode: settings.autoPipelineMode,
        }),
      });

      if (!assignResponse.ok) {
        throw new Error('Failed to assign pipeline to page');
      }

      toast.success('AI pipeline created and assigned successfully');
      setShowAIGenerator(false);
      setAiSuggestion(null);
      
      // Refresh the page to show the new pipeline in the dropdown
      window.location.reload();
    } catch (error) {
      console.error('Create AI pipeline error:', error);
      toast.error('An error occurred while creating pipeline');
    } finally {
      setAiGenerating(false);
    }
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
                  onValueChange={handlePipelineChange}
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
                    <SelectItem value="generate-ai" className="text-primary font-medium">
                      <div className="flex items-center gap-2">
                        <Sparkles className="h-4 w-4" />
                        Generate with AI...
                      </div>
                    </SelectItem>
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

      {/* AI Pipeline Generator Dialog */}
      <Dialog open={showAIGenerator} onOpenChange={setShowAIGenerator}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Sparkles className="h-5 w-5" />
              AI Pipeline Generator
            </DialogTitle>
            <DialogDescription>
              AI will analyze contacts from this Facebook page to create an optimal pipeline structure
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="flex items-center justify-between">
              <Label htmlFor="ai-decide-stages">Let AI Decide Number of Stages</Label>
              <Switch
                id="ai-decide-stages"
                checked={aiDecideStages}
                onCheckedChange={(checked) => {
                  setAiDecideStages(checked);
                  if (checked) {
                    setUseCustomStageCount(false);
                  }
                }}
              />
            </div>

            {!aiDecideStages && (
              <div className="flex items-center justify-between">
                <Label htmlFor="custom-stage-count">Custom Stage Count</Label>
                <Switch
                  id="custom-stage-count"
                  checked={useCustomStageCount}
                  onCheckedChange={setUseCustomStageCount}
                />
              </div>
            )}

            {!aiDecideStages && useCustomStageCount && (
              <div>
                <Label htmlFor="stage-count">Number of Stages (minimum 3)</Label>
                <Input
                  id="stage-count"
                  type="text"
                  inputMode="numeric"
                  value={aiStageCount}
                  onChange={(e) => {
                    const value = e.target.value;
                    // Allow typing any number, including starting with 1
                    if (value === '' || /^\d+$/.test(value)) {
                      setAiStageCount(value);
                    }
                  }}
                  onBlur={(e) => {
                    // Validate on blur - ensure minimum 3
                    const numValue = parseInt(e.target.value);
                    if (isNaN(numValue) || numValue < 3) {
                      setAiStageCount('');
                    } else {
                      setAiStageCount(numValue.toString());
                    }
                  }}
                  className="mt-2"
                  placeholder="e.g., 3, 5, 7, 12..."
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Specify the exact number of stages you want (minimum 3)
                </p>
              </div>
            )}

            {aiDecideStages && (
              <div className="space-y-2">
                <Label htmlFor="detail-level">Pipeline Detail Level (1 = Simple, 10 = Very Detailed)</Label>
                <div className="flex items-center gap-4">
                  <span className="text-xs text-muted-foreground min-w-[60px]">Simple</span>
                  <input
                    id="detail-level"
                    type="range"
                    min="1"
                    max="10"
                    value={pipelineDetailLevel}
                    onChange={(e) => setPipelineDetailLevel(parseInt(e.target.value))}
                    className="flex-1 h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer accent-primary"
                  />
                  <span className="text-xs text-muted-foreground min-w-[80px]">Very Detailed</span>
                </div>
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span>Current: {pipelineDetailLevel}/10</span>
                  <span>
                    {pipelineDetailLevel <= 3 && 'Simple (3-5 stages)'}
                    {pipelineDetailLevel > 3 && pipelineDetailLevel <= 6 && 'Moderate (5-8 stages)'}
                    {pipelineDetailLevel > 6 && pipelineDetailLevel <= 8 && 'Detailed (8-12 stages)'}
                    {pipelineDetailLevel > 8 && 'Very Detailed (12-15+ stages)'}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground">
                  AI will create {pipelineDetailLevel <= 3 ? '3-5' : pipelineDetailLevel <= 6 ? '5-8' : pipelineDetailLevel <= 8 ? '8-12' : '12-15+'} stages based on your contact data
                </p>
              </div>
            )}

            {!aiDecideStages && !useCustomStageCount && (
              <p className="text-sm text-muted-foreground">
                Enable "Custom Stage Count" to specify an exact number, or enable "Let AI Decide" for automatic optimization
              </p>
            )}

            {aiSuggestion && (
              <div className="space-y-4 pt-4 border-t">
                <div>
                  <h3 className="font-semibold mb-2">{aiSuggestion.name}</h3>
                  <p className="text-sm text-muted-foreground mb-4">{aiSuggestion.description}</p>
                  {aiSuggestion.confidence > 0 && (
                    <p className="text-xs text-muted-foreground">
                      Confidence: {aiSuggestion.confidence}% • Based on {aiSuggestion.totalContacts} contacts
                    </p>
                  )}
                </div>

                {aiSuggestion.stages && aiSuggestion.stages.length > 0 ? (
                  <div className="space-y-2">
                    <h4 className="font-medium text-sm">Suggested Stages:</h4>
                    {aiSuggestion.stages.map((stage: any, index: number) => (
                    <Card key={index} className="p-3">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <div
                              className="w-3 h-3 rounded-full"
                              style={{ backgroundColor: stage.color }}
                            />
                            <span className="font-medium">{stage.name}</span>
                            <span className="text-xs text-muted-foreground">
                              ({stage.leadScoreMin}-{stage.leadScoreMax})
                            </span>
                          </div>
                          <p className="text-xs text-muted-foreground mb-2">{stage.description}</p>
                          {stage.expectedContacts > 0 && (
                            <p className="text-xs text-muted-foreground">
                              Expected: ~{stage.expectedContacts} contacts
                            </p>
                          )}
                        </div>
                      </div>
                    </Card>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800 rounded-lg">
                    <p className="text-sm text-amber-900 dark:text-amber-200">
                      ⚠️ {aiSuggestion.description || 'No stages can be generated. Contacts need to be analyzed first.'}
                    </p>
                    <p className="text-xs text-amber-700 dark:text-amber-300 mt-2">
                      Please run pipeline analysis on your contacts first, then try generating the pipeline again.
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowAIGenerator(false);
                setAiSuggestion(null);
                setAiStageCount('');
                setAiDecideStages(true);
                setPipelineDetailLevel(5);
                setUseCustomStageCount(false);
              }}
            >
              Cancel
            </Button>
            {!aiSuggestion ? (
              <Button onClick={handleGenerateAI} disabled={aiGenerating}>
                {aiGenerating ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Generating...
                  </>
                ) : (
                  <>
                    <Sparkles className="h-4 w-4 mr-2" />
                    Generate Pipeline
                  </>
                )}
              </Button>
            ) : (
              <Button onClick={handleCreateAIPipeline} disabled={aiGenerating}>
                {aiGenerating ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Creating...
                  </>
                ) : (
                  'Create & Assign Pipeline'
                )}
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

