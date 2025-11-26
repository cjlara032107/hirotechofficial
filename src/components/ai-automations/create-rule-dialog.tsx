'use client';

import { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { toast } from 'sonner';
import { Loader2, X } from 'lucide-react';

interface FacebookPage {
  id: string;
  pageName: string;
  pageId: string;
}

interface Tag {
  id: string;
  name: string;
  color: string;
}

interface CreateRuleDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess: () => void;
}

export function CreateRuleDialog({ open, onOpenChange, onSuccess }: CreateRuleDialogProps) {
  const [loading, setLoading] = useState(false);
  const [facebookPages, setFacebookPages] = useState<FacebookPage[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [loadingData, setLoadingData] = useState(false);

  // Form state
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    customPrompt: '',
    languageStyle: 'taglish',
    facebookPageId: '',
    timeIntervalMinutes: '',
    timeIntervalHours: '24',
    timeIntervalDays: '',
    maxMessagesPerDay: '100',
    activeHoursStart: '9',
    activeHoursEnd: '21',
    run24_7: false,
    stopOnReply: true,
    removeTagOnReply: '',
    messageTag: 'ACCOUNT_UPDATE',
    enabled: true
  });

  const [includeTags, setIncludeTags] = useState<string[]>([]);
  const [excludeTags, setExcludeTags] = useState<string[]>([]);

  useEffect(() => {
    if (open) {
      fetchData();
    }
  }, [open]);

  const fetchData = async () => {
    setLoadingData(true);
    try {
      // Fetch Facebook pages
      const pagesRes = await fetch('/api/facebook/pages/connected');
      if (pagesRes.ok) {
        const pagesData = await pagesRes.json();
        setFacebookPages(pagesData.pages || []);
      }

      // Fetch tags
      const tagsRes = await fetch('/api/tags');
      if (tagsRes.ok) {
        const tagsData = await tagsRes.json();
        // Handle both response formats
        setTags(Array.isArray(tagsData) ? tagsData : (tagsData.tags || []));
      }
    } catch (error) {
      console.error('Error fetching data:', error);
    } finally {
      setLoadingData(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // Validation
    if (!formData.name.trim()) {
      toast.error('Please enter a rule name');
      return;
    }

    if (!formData.customPrompt.trim()) {
      toast.error('Please enter AI instructions');
      return;
    }

    // Ensure at least one time interval
    if (!formData.timeIntervalMinutes && !formData.timeIntervalHours && !formData.timeIntervalDays) {
      toast.error('Please set at least one time interval');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch('/api/ai-automations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: formData.name,
          description: formData.description || null,
          customPrompt: formData.customPrompt,
          languageStyle: formData.languageStyle,
          facebookPageId: formData.facebookPageId || null,
          timeIntervalMinutes: formData.timeIntervalMinutes ? parseInt(formData.timeIntervalMinutes) : null,
          timeIntervalHours: formData.timeIntervalHours ? parseInt(formData.timeIntervalHours) : null,
          timeIntervalDays: formData.timeIntervalDays ? parseInt(formData.timeIntervalDays) : null,
          maxMessagesPerDay: parseInt(formData.maxMessagesPerDay),
          activeHoursStart: parseInt(formData.activeHoursStart),
          activeHoursEnd: parseInt(formData.activeHoursEnd),
          run24_7: formData.run24_7,
          stopOnReply: formData.stopOnReply,
          removeTagOnReply: formData.removeTagOnReply || null,
          messageTag: formData.messageTag || null,
          enabled: formData.enabled,
          includeTags,
          excludeTags
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to create rule');
      }

      toast.success('AI automation rule created successfully!');
      onSuccess();
      onOpenChange(false);
      resetForm();
    } catch (error) {
      console.error('Error creating rule:', error);
      toast.error(error instanceof Error ? error.message : 'Failed to create rule');
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      customPrompt: '',
      languageStyle: 'taglish',
      facebookPageId: '',
      timeIntervalMinutes: '',
      timeIntervalHours: '24',
      timeIntervalDays: '',
      maxMessagesPerDay: '100',
      activeHoursStart: '9',
      activeHoursEnd: '21',
      run24_7: false,
      stopOnReply: true,
      removeTagOnReply: '',
      messageTag: 'ACCOUNT_UPDATE',
      enabled: true
    });
    setIncludeTags([]);
    setExcludeTags([]);
  };

  const addIncludeTag = (tagName: string) => {
    if (tagName && !includeTags.includes(tagName) && !excludeTags.includes(tagName)) {
      setIncludeTags([...includeTags, tagName]);
    }
  };

  const addExcludeTag = (tagName: string) => {
    if (tagName && !excludeTags.includes(tagName) && !includeTags.includes(tagName)) {
      setExcludeTags([...excludeTags, tagName]);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Create AI Automation Rule</DialogTitle>
          <DialogDescription>
            Set up an automated follow-up rule with AI-generated personalized messages
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Basic Information */}
          <div className="space-y-4">
            <h3 className="font-semibold text-sm">Basic Information</h3>
            
            <div className="space-y-2">
              <Label htmlFor="name">Rule Name *</Label>
              <Input
                id="name"
                placeholder="e.g., 24hr Hot Lead Follow-up"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="description">Description</Label>
              <Input
                id="description"
                placeholder="Brief description of this rule"
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="facebookPage">Facebook Page (Optional)</Label>
              <Select 
                value={formData.facebookPageId || 'all'} 
                onValueChange={(value) => setFormData({ ...formData, facebookPageId: value === 'all' ? '' : value })}
              >
                <SelectTrigger>
                  <SelectValue placeholder={loadingData ? "Loading pages..." : "All pages"} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Pages</SelectItem>
                  {facebookPages.map(page => (
                    <SelectItem key={page.id} value={page.id}>
                      {page.pageName}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* AI Configuration */}
          <div className="space-y-4">
            <h3 className="font-semibold text-sm">AI Configuration</h3>
            
            <div className="space-y-2">
              <Label htmlFor="customPrompt">AI Instructions *</Label>
              <Textarea
                id="customPrompt"
                placeholder="e.g., Remind them about their inquiry. Mention any products they asked about. Be friendly and helpful."
                value={formData.customPrompt}
                onChange={(e) => setFormData({ ...formData, customPrompt: e.target.value })}
                rows={4}
                required
              />
              <p className="text-xs text-muted-foreground">
                The AI will use these instructions along with conversation history to generate personalized messages
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="languageStyle">Language Style</Label>
              <Select 
                value={formData.languageStyle} 
                onValueChange={(value) => setFormData({ ...formData, languageStyle: value })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="taglish">Taglish (Filipino + English)</SelectItem>
                  <SelectItem value="english">English</SelectItem>
                  <SelectItem value="filipino">Filipino</SelectItem>
                  <SelectItem value="spanish">Spanish</SelectItem>
                  <SelectItem value="casual">Casual</SelectItem>
                  <SelectItem value="formal">Formal</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Time Settings */}
          <div className="space-y-4">
            <h3 className="font-semibold text-sm">Time Settings</h3>
            
            <div className="grid grid-cols-3 gap-4">
              <div className="space-y-2">
                <Label htmlFor="days">Days</Label>
                <Input
                  id="days"
                  type="number"
                  min="0"
                  placeholder="0"
                  value={formData.timeIntervalDays}
                  onChange={(e) => setFormData({ ...formData, timeIntervalDays: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="hours">Hours</Label>
                <Input
                  id="hours"
                  type="number"
                  min="0"
                  placeholder="24"
                  value={formData.timeIntervalHours}
                  onChange={(e) => setFormData({ ...formData, timeIntervalHours: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="minutes">Minutes</Label>
                <Input
                  id="minutes"
                  type="number"
                  min="0"
                  placeholder="0"
                  value={formData.timeIntervalMinutes}
                  onChange={(e) => setFormData({ ...formData, timeIntervalMinutes: e.target.value })}
                />
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              Send follow-up after contact has been inactive for this duration
            </p>
          </div>

          {/* Targeting */}
          <div className="space-y-4">
            <h3 className="font-semibold text-sm">Tag Filters</h3>
            
            <div className="space-y-2">
              <Label>Include Tags (Only send to contacts with these tags)</Label>
              <div className="flex gap-2">
                <Select onValueChange={addIncludeTag}>
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="Select tag to include" />
                  </SelectTrigger>
                  <SelectContent>
                    {tags.filter(t => !includeTags.includes(t.name)).map(tag => (
                      <SelectItem key={tag.id} value={tag.name}>
                        {tag.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="flex flex-wrap gap-2 mt-2">
                {includeTags.map(tag => (
                  <Badge key={tag} variant="default">
                    {tag}
                    <button
                      type="button"
                      onClick={() => setIncludeTags(includeTags.filter(t => t !== tag))}
                      className="ml-1 hover:text-destructive"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  </Badge>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <Label>Exclude Tags (Never send to contacts with these tags)</Label>
              <div className="flex gap-2">
                <Select onValueChange={addExcludeTag}>
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="Select tag to exclude" />
                  </SelectTrigger>
                  <SelectContent>
                    {tags.filter(t => !excludeTags.includes(t.name)).map(tag => (
                      <SelectItem key={tag.id} value={tag.name}>
                        {tag.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="flex flex-wrap gap-2 mt-2">
                {excludeTags.map(tag => (
                  <Badge key={tag} variant="outline">
                    {tag}
                    <button
                      type="button"
                      onClick={() => setExcludeTags(excludeTags.filter(t => t !== tag))}
                      className="ml-1 hover:text-destructive"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  </Badge>
                ))}
              </div>
            </div>
          </div>

          {/* Limits & Schedule */}
          <div className="space-y-4">
            <h3 className="font-semibold text-sm">Limits & Schedule</h3>
            
            <div className="space-y-2">
              <Label htmlFor="maxMessages">Max Messages Per Day</Label>
              <Input
                id="maxMessages"
                type="number"
                min="1"
                value={formData.maxMessagesPerDay}
                onChange={(e) => setFormData({ ...formData, maxMessagesPerDay: e.target.value })}
              />
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>Run 24/7</Label>
                <p className="text-xs text-muted-foreground">
                  Ignore active hours and run all day
                </p>
              </div>
              <Switch
                checked={formData.run24_7}
                onCheckedChange={(checked) => setFormData({ ...formData, run24_7: checked })}
              />
            </div>

            {!formData.run24_7 && (
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="startHour">Active Hours Start</Label>
                  <Input
                    id="startHour"
                    type="number"
                    min="0"
                    max="23"
                    value={formData.activeHoursStart}
                    onChange={(e) => setFormData({ ...formData, activeHoursStart: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="endHour">Active Hours End</Label>
                  <Input
                    id="endHour"
                    type="number"
                    min="0"
                    max="23"
                    value={formData.activeHoursEnd}
                    onChange={(e) => setFormData({ ...formData, activeHoursEnd: e.target.value })}
                  />
                </div>
              </div>
            )}
          </div>

          {/* Behavior */}
          <div className="space-y-4">
            <h3 className="font-semibold text-sm">Behavior</h3>
            
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>Stop on Reply</Label>
                <p className="text-xs text-muted-foreground">
                  Automatically stop sending when contact replies
                </p>
              </div>
              <Switch
                checked={formData.stopOnReply}
                onCheckedChange={(checked) => setFormData({ ...formData, stopOnReply: checked })}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="removeTag">Remove Tag on Reply (Optional)</Label>
              <Select 
                value={formData.removeTagOnReply || 'none'} 
                onValueChange={(value) => setFormData({ ...formData, removeTagOnReply: value === 'none' ? '' : value })}
              >
                <SelectTrigger>
                  <SelectValue placeholder="None" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">None</SelectItem>
                  {tags.map(tag => (
                    <SelectItem key={tag.id} value={tag.name}>
                      {tag.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="messageTag">Facebook Message Tag</Label>
              <Select 
                value={formData.messageTag} 
                onValueChange={(value) => setFormData({ ...formData, messageTag: value })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ACCOUNT_UPDATE">Account Update</SelectItem>
                  <SelectItem value="CONFIRMED_EVENT_UPDATE">Confirmed Event Update</SelectItem>
                  <SelectItem value="POST_PURCHASE_UPDATE">Post Purchase Update</SelectItem>
                  <SelectItem value="HUMAN_AGENT">Human Agent</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                Required by Facebook for messages outside 24-hour window
              </p>
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>Enable Rule</Label>
                <p className="text-xs text-muted-foreground">
                  Start automation immediately after creation
                </p>
              </div>
              <Switch
                checked={formData.enabled}
                onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
              />
            </div>
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={loading}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={loading}>
              {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              Create Rule
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

