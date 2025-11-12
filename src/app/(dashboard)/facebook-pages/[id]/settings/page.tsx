'use client';

import { useState, useEffect, useCallback } from 'react';
import { useParams } from 'next/navigation';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Button } from '@/components/ui/button';
import { toast } from 'sonner';
import Link from 'next/link';
import { ArrowLeft } from 'lucide-react';

interface Pipeline {
  id: string;
  name: string;
}

export default function FacebookPageSettingsPage() {
  const params = useParams();
  const [pipelines, setPipelines] = useState<Pipeline[]>([]);
  const [settings, setSettings] = useState({
    autoPipelineId: 'none',
    autoPipelineMode: 'SKIP_EXISTING'
  });
  const [loading, setLoading] = useState(false);

  const fetchPipelines = useCallback(async () => {
    try {
      const res = await fetch('/api/pipelines');
      if (!res.ok) {
        console.error('Failed to fetch pipelines:', res.status, res.statusText);
        toast.error('Failed to load pipelines');
        return;
      }
      const data = await res.json();
      console.log('Fetched pipelines:', data);
      setPipelines(data);
      
      if (data.length === 0) {
        toast.info('No pipelines found. Create a pipeline first at /pipelines');
      }
    } catch (error) {
      console.error('Failed to fetch pipelines:', error);
      toast.error('Failed to load pipelines');
    }
  }, []);

  const fetchPageSettings = useCallback(async () => {
    try {
      const res = await fetch(`/api/facebook/pages/${params.id}`);
      if (!res.ok) {
        console.error('Failed to fetch page settings:', res.status, res.statusText);
        toast.error('Failed to load page settings');
        return;
      }
      const data = await res.json();
      console.log('Fetched page settings:', data);
      setSettings({
        autoPipelineId: data.autoPipelineId || 'none',
        autoPipelineMode: data.autoPipelineMode || 'SKIP_EXISTING'
      });
    } catch (error) {
      console.error('Failed to fetch settings:', error);
      toast.error('Failed to load page settings');
    }
  }, [params.id]);

  useEffect(() => {
    fetchPipelines();
    fetchPageSettings();
  }, [fetchPipelines, fetchPageSettings]);

  async function saveSettings() {
    setLoading(true);
    try {
      // Convert "none" to null for database
      const settingsToSave = {
        autoPipelineId: settings.autoPipelineId === 'none' ? null : settings.autoPipelineId,
        autoPipelineMode: settings.autoPipelineMode
      };
      console.log('Saving settings:', settingsToSave);
      const res = await fetch(`/api/facebook/pages/${params.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settingsToSave)
      });
      
      if (res.ok) {
        const data = await res.json();
        console.log('Settings saved:', data);
        toast.success('Settings saved successfully! Auto-assignment will apply on next sync.');
      } else {
        const errorData = await res.json();
        console.error('Failed to save settings:', errorData);
        toast.error(errorData.error || 'Failed to save settings');
      }
    } catch (error) {
      console.error('Error saving settings:', error);
      toast.error('Error saving settings');
    } finally {
      setLoading(false);
    }
  }

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

