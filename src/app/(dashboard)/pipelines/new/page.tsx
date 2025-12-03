'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { PIPELINE_TEMPLATES } from '@/lib/pipelines/templates';
import { CheckCircle2, Sparkles, Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { useEffect } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';

type PipelineGenerationLogic = 'HYBRID' | 'CONSERVATIVE' | 'BALANCED' | 'DETAILED' | 'ADAPTIVE' | 'BUSINESS_FOCUSED' | 'CUSTOM';

interface SuggestedStage {
  name: string;
  description: string;
  color: string;
  type: 'LEAD' | 'IN_PROGRESS' | 'WON' | 'LOST' | 'ARCHIVED';
  leadScoreMin: number;
  leadScoreMax: number;
  expectedContacts?: number;
  characteristics?: string[];
}

interface PipelineSuggestion {
  name: string;
  description: string;
  stages: SuggestedStage[];
  totalContacts: number;
  confidence: number;
}

export default function NewPipelinePage() {
  const router = useRouter();
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [showAIGenerator, setShowAIGenerator] = useState(false);
  const [aiGenerating, setAiGenerating] = useState(false);
  const [aiStageCount, setAiStageCount] = useState<number | undefined>(undefined);
  const [useCustomStageCount, setUseCustomStageCount] = useState(false);
  const [aiSuggestion, setAiSuggestion] = useState<PipelineSuggestion | null>(null);
  // Chunk 9: New state variables
  const [selectedLogic, setSelectedLogic] = useState<PipelineGenerationLogic>('HYBRID');
  const [enableBusinessIntelligence, setEnableBusinessIntelligence] = useState(true);
  const [allowAIStageDecision, setAllowAIStageDecision] = useState(true);
  const [detailLevel, setDetailLevel] = useState(5);
  const [selectedPageId, setSelectedPageId] = useState<string | undefined>(undefined);
  const [customInstructions, setCustomInstructions] = useState<string>('');
  const [availablePages, setAvailablePages] = useState<Array<{ id: string; pageId: string; pageName: string }>>([]);
  const [loadingPages, setLoadingPages] = useState(false);

  // Fetch connected pages when dialog opens
  useEffect(() => {
    if (showAIGenerator) {
      fetchConnectedPages();
    }
  }, [showAIGenerator]);

  const fetchConnectedPages = async () => {
    setLoadingPages(true);
    try {
      const response = await fetch('/api/facebook/pages/connected', {
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const data = await response.json();
        const pages = data.pages || [];
        setAvailablePages(pages);
        
        if (pages.length === 0) {
          console.log('[Pipeline Generator] No connected Facebook pages found');
        } else {
          console.log(`[Pipeline Generator] Found ${pages.length} connected page(s)`);
        }
      } else {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
        console.error('Failed to fetch connected pages:', errorData.error);
        // Don't show toast for this - it's optional functionality
      }
    } catch (error) {
      console.error('Error fetching connected pages:', error);
      // Don't show toast for this - it's optional functionality
    } finally {
      setLoadingPages(false);
    }
  };

  const handleCreate = async () => {
    if (!selectedTemplate) return;

    setCreating(true);
    const template = PIPELINE_TEMPLATES[selectedTemplate as keyof typeof PIPELINE_TEMPLATES];

    try {
      const response = await fetch('/api/pipelines', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: template.name,
          description: template.description,
          color: template.color,
          stages: template.stages,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        toast.success('Pipeline created successfully');
        router.push(`/pipelines/${data.id}`);
      } else {
        toast.error('Failed to create pipeline');
      }
    } catch (error) {
      console.error('Create pipeline error:', error);
      toast.error('An error occurred');
    } finally {
      setCreating(false);
    }
  };

  const handleGenerateAI = async () => {
    setAiGenerating(true);
    try {
      const response = await fetch('/api/pipelines/generate-ai', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          facebookPageId: selectedPageId || undefined,
          stageCount: useCustomStageCount ? aiStageCount : undefined,
          logic: selectedLogic,
          enableBusinessIntelligence,
          allowAIStageDecision,
          detailLevel,
          customInstructions: customInstructions.trim() || undefined,
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

  const handleCreateAIPipeline = async () => {
    if (!aiSuggestion) return;

    setCreating(true);
    try {
      const response = await fetch('/api/pipelines', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: aiSuggestion.name,
          description: aiSuggestion.description,
          color: '#3b82f6',
          stages: aiSuggestion.stages.map((stage: SuggestedStage) => ({
            name: stage.name,
            description: stage.description,
            color: stage.color,
            type: stage.type,
          })),
        }),
      });

      if (response.ok) {
        const data = await response.json();
        toast.success('AI pipeline created successfully');
        router.push(`/pipelines/${data.id}`);
      } else {
        toast.error('Failed to create AI pipeline');
      }
    } catch (error) {
      console.error('Create AI pipeline error:', error);
      toast.error('An error occurred');
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      <div>
        <h1 className="text-3xl font-bold">Create Pipeline</h1>
        <p className="text-muted-foreground mt-2">
          Choose a template to get started
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        {Object.entries(PIPELINE_TEMPLATES).map(([key, template]) => (
          <Card
            key={key}
            className={`cursor-pointer transition-all ${
              selectedTemplate === key
                ? 'border-primary ring-2 ring-primary'
                : 'hover:border-primary/50'
            }`}
            onClick={() => setSelectedTemplate(key)}
          >
            <CardHeader>
              <div className="flex items-start justify-between">
                <div className="text-3xl">{template.icon}</div>
                {selectedTemplate === key && (
                  <CheckCircle2 className="h-5 w-5 text-primary" />
                )}
              </div>
              <CardTitle className="text-lg">{template.name}</CardTitle>
              <CardDescription>{template.description}</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">
                {template.stages.length} stages
              </p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* AI Generator Dialog */}
      <Dialog open={showAIGenerator} onOpenChange={setShowAIGenerator}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Sparkles className="h-5 w-5" />
              AI Pipeline Generator
            </DialogTitle>
            <DialogDescription>
              AI will analyze your contacts to create an optimal pipeline structure
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            {/* Page Selection */}
            <div>
              <Label htmlFor="page-selection">Select Facebook Page (Optional)</Label>
              <Select 
                value={selectedPageId || 'none'} 
                onValueChange={(value) => setSelectedPageId(value === 'none' ? undefined : value)}
                disabled={loadingPages}
              >
                <SelectTrigger id="page-selection" className="mt-2">
                  <SelectValue placeholder={loadingPages ? 'Loading pages...' : 'Select a page (optional)'} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">All Pages (No specific page)</SelectItem>
                  {availablePages.length === 0 && !loadingPages ? (
                    <SelectItem value="no-pages" disabled>
                      No connected pages found
                    </SelectItem>
                  ) : (
                    availablePages.map((page) => (
                      <SelectItem key={page.id} value={page.pageId}>
                        {page.pageName}
                      </SelectItem>
                    ))
                  )}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground mt-1">
                {availablePages.length === 0 && !loadingPages
                  ? 'No Facebook pages are connected. Connect pages in Settings → Integrations to filter by page.'
                  : 'Select a specific Facebook page to generate pipeline based on its contacts, or leave as "All Pages"'}
              </p>
            </div>

            {/* Custom Instructions */}
            <div>
              <Label htmlFor="custom-instructions">Custom Instructions (Optional)</Label>
              <Textarea
                id="custom-instructions"
                placeholder="E.g., 'Create a pipeline focused on B2B sales with stages for qualification, proposal, and negotiation. Use industry-specific terminology.'"
                value={customInstructions}
                onChange={(e) => setCustomInstructions(e.target.value)}
                className="mt-2 min-h-[100px]"
                rows={4}
              />
              <p className="text-xs text-muted-foreground mt-1">
                Provide specific instructions on how you'd like the pipeline to be structured. AI will use GPT-OSS-120B to generate a custom pipeline based on your requirements.
              </p>
            </div>

            {/* Chunk 10: Logic Selection */}
            <div>
              <Label htmlFor="generation-logic">Generation Logic</Label>
              <Select value={selectedLogic} onValueChange={(value) => setSelectedLogic(value as PipelineGenerationLogic)}>
                <SelectTrigger id="generation-logic" className="mt-2">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="HYBRID">Hybrid (Recommended - Combines all strategies)</SelectItem>
                  <SelectItem value="CONSERVATIVE">Conservative (3-8 stages, high confidence)</SelectItem>
                  <SelectItem value="BALANCED">Balanced (4-12 stages, moderate detail)</SelectItem>
                  <SelectItem value="DETAILED">Detailed (6-15 stages, granular)</SelectItem>
                  <SelectItem value="ADAPTIVE">Adaptive (AI decides, 3-20 stages)</SelectItem>
                  <SelectItem value="BUSINESS_FOCUSED">Business-Focused (5-10 stages, funnel-based)</SelectItem>
                  <SelectItem value="CUSTOM">Custom (User-specified count, 3-30 stages)</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground mt-1">
                {selectedLogic === 'HYBRID' && 'Intelligently combines multiple strategies based on your business needs'}
                {selectedLogic === 'CONSERVATIVE' && 'Creates fewer stages only when clear differentiation exists. Best for simple sales processes.'}
                {selectedLogic === 'BALANCED' && 'Balances detail with practicality. Good for most businesses.'}
                {selectedLogic === 'DETAILED' && 'Creates granular stages for complex sales processes. Best for detailed tracking.'}
                {selectedLogic === 'ADAPTIVE' && 'AI automatically determines optimal stage count based on your data. Recommended for most users.'}
                {selectedLogic === 'BUSINESS_FOCUSED' && 'Creates stages based on standard sales funnel (Awareness → Purchase). Best for traditional sales.'}
                {selectedLogic === 'CUSTOM' && 'You specify the exact number of stages. Maximum flexibility.'}
              </p>
            </div>

            {/* Chunk 10: Business Intelligence Toggle */}
            <div className="flex items-center justify-between">
              <div className="flex-1">
                <Label htmlFor="business-intelligence">Enable Business Intelligence</Label>
                <p className="text-xs text-muted-foreground">
                  AI analyzes your business type and creates stages based on your needs
                </p>
              </div>
              <Switch
                id="business-intelligence"
                checked={enableBusinessIntelligence}
                onCheckedChange={setEnableBusinessIntelligence}
              />
            </div>

            {/* Chunk 10: AI Stage Decision Toggle */}
            {enableBusinessIntelligence && (
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <Label htmlFor="ai-stage-decision">Let AI Decide Required Stages</Label>
                  <p className="text-xs text-muted-foreground">
                    AI automatically determines which stages your business needs
                  </p>
                </div>
                <Switch
                  id="ai-stage-decision"
                  checked={allowAIStageDecision}
                  onCheckedChange={setAllowAIStageDecision}
                />
              </div>
            )}

            {/* Chunk 10: Detail Level Slider */}
            <div>
              <Label htmlFor="detail-level">Detail Level: {detailLevel}/10</Label>
              <input
                id="detail-level"
                type="range"
                min={1}
                max={10}
                value={detailLevel}
                onChange={(e) => setDetailLevel(parseInt(e.target.value))}
                className="w-full mt-2"
              />
              <p className="text-xs text-muted-foreground mt-1">
                Higher values create more detailed pipelines with more stages
              </p>
            </div>

            {/* Custom Stage Count */}
            <div className="flex items-center justify-between">
              <Label htmlFor="custom-stage-count">Custom Stage Count</Label>
              <Switch
                id="custom-stage-count"
                checked={useCustomStageCount}
                onCheckedChange={setUseCustomStageCount}
              />
            </div>

            {useCustomStageCount && (
              <div>
                <Label htmlFor="stage-count">
                  Number of Stages 
                  {selectedLogic === 'CUSTOM' ? ' (3-30)' : ' (Optional)'}
                </Label>
                <Input
                  id="stage-count"
                  type="number"
                  min={3}
                  max={selectedLogic === 'CUSTOM' ? 30 : 20}
                  value={aiStageCount || ''}
                  onChange={(e) => setAiStageCount(parseInt(e.target.value) || undefined)}
                  className="mt-2"
                />
              </div>
            )}

            {!useCustomStageCount && (
              <p className="text-sm text-muted-foreground">
                AI will automatically determine the optimal number of stages based on your contact data
              </p>
            )}

            {aiSuggestion && (
              <div className="space-y-4 pt-4 border-t">
                <div>
                  <h3 className="font-semibold mb-2">{aiSuggestion.name}</h3>
                  <p className="text-sm text-muted-foreground mb-4">{aiSuggestion.description}</p>
                  <p className="text-xs text-muted-foreground">
                    Confidence: {aiSuggestion.confidence}% • Based on {aiSuggestion.totalContacts} contacts
                  </p>
                </div>

                <div className="space-y-2">
                  <h4 className="font-medium text-sm">Suggested Stages:</h4>
                  {aiSuggestion.stages.map((stage: SuggestedStage, index: number) => (
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
                          {stage.expectedContacts && stage.expectedContacts > 0 && (
                            <p className="text-xs text-muted-foreground">
                              Expected: ~{stage.expectedContacts} contacts
                            </p>
                          )}
                        </div>
                      </div>
                    </Card>
                  ))}
                </div>
              </div>
            )}
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowAIGenerator(false);
                setAiSuggestion(null);
                setSelectedPageId(undefined);
                setCustomInstructions('');
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
              <Button onClick={handleCreateAIPipeline} disabled={creating}>
                {creating ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Creating...
                  </>
                ) : (
                  'Create Pipeline'
                )}
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {selectedTemplate && (
        <Card>
          <CardHeader>
            <CardTitle>Pipeline Stages</CardTitle>
            <CardDescription>Preview of the stages in this pipeline</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {PIPELINE_TEMPLATES[selectedTemplate as keyof typeof PIPELINE_TEMPLATES].stages.map(
                (stage, index) => (
                  <div
                    key={index}
                    className="px-3 py-1 rounded-full text-sm font-medium"
                    style={{
                      backgroundColor: `${stage.color}20`,
                      color: stage.color,
                    }}
                  >
                    {stage.name}
                  </div>
                )
              )}
            </div>
          </CardContent>
        </Card>
      )}

      <div className="flex gap-3">
        <Button variant="outline" onClick={() => router.push('/pipelines')}>
          Cancel
        </Button>
        <Button
          variant="outline"
          onClick={() => setShowAIGenerator(true)}
          className="flex items-center gap-2"
        >
          <Sparkles className="h-4 w-4" />
          Generate with AI
        </Button>
        <Button
          onClick={handleCreate}
          disabled={!selectedTemplate || creating}
          className="flex-1"
        >
          {creating ? 'Creating...' : 'Create Pipeline'}
        </Button>
      </div>
    </div>
  );
}
