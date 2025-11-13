'use client';

import { useState, useEffect, useMemo } from 'react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Plus, Play, Pause, Trash2, Clock, MessageSquare, TrendingUp, Edit2, Search, X } from 'lucide-react';
import { toast } from 'sonner';
import { CreateRuleDialog } from '@/components/ai-automations/create-rule-dialog';
import { EditRuleDialog } from '@/components/ai-automations/edit-rule-dialog';

interface Rule {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  customPrompt: string;
  languageStyle: string;
  timeIntervalMinutes?: number;
  timeIntervalHours?: number;
  timeIntervalDays?: number;
  includeTags: string[];
  excludeTags: string[];
  maxMessagesPerDay: number;
  activeHoursStart: number;
  activeHoursEnd: number;
  run24_7: boolean;
  stopOnReply: boolean;
  removeTagOnReply?: string;
  messageTag?: string;
  facebookPageId?: string;
  executionCount: number;
  successCount: number;
  failureCount: number;
  lastExecutedAt?: string;
  facebookPage?: {
    id: string;
    pageName: string;
    pageId: string;
  };
  _count: {
    executions: number;
    stops: number;
  };
}

export default function AIAutomationsPage() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<Rule | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRules, setSelectedRules] = useState<Set<string>>(new Set());

  useEffect(() => {
    fetchRules();
  }, []);

  const fetchRules = async () => {
    try {
      setError(null);
      const response = await fetch('/api/ai-automations');
      
      // Check if response is JSON before parsing
      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        // Not JSON - likely redirected to login page (HTML)
        console.log('[AI Automations] Not authenticated, redirecting to login');
        window.location.href = '/login';
        return;
      }
      
      const data = await response.json();
      
      if (!response.ok) {
        // 401 is expected when not logged in - will redirect to login
        if (response.status === 401) {
          console.log('[AI Automations] Not authenticated, redirecting to login');
          window.location.href = '/login';
          return;
        }
        throw new Error(data.error || 'Failed to load automation rules');
      }
      
      setRules(data.rules || []);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load automation rules';
      console.error('Error fetching rules:', err);
      setError(errorMessage);
      toast.error(errorMessage);
      setRules([]); // Ensure rules is always an array
    } finally {
      setLoading(false);
    }
  };

  const toggleRule = async (id: string, enabled: boolean) => {
    setActionLoading(id);
    try {
      const response = await fetch(`/api/ai-automations/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !enabled })
      });

      if (response.ok) {
        toast.success(!enabled ? 'Rule enabled' : 'Rule paused');
        fetchRules();
      } else {
        toast.error('Failed to update rule');
      }
    } catch {
      toast.error('Failed to update rule');
    } finally {
      setActionLoading(null);
    }
  };

  const deleteRule = async (id: string) => {
    if (!confirm('Are you sure you want to delete this automation rule?')) return;
    
    setActionLoading(id);
    try {
      const response = await fetch(`/api/ai-automations/${id}`, {
        method: 'DELETE'
      });

      if (response.ok) {
        toast.success('Rule deleted');
        setSelectedRules(prev => {
          const newSet = new Set(prev);
          newSet.delete(id);
          return newSet;
        });
        fetchRules();
      } else {
        toast.error('Failed to delete rule');
      }
    } catch {
      toast.error('Failed to delete rule');
    } finally {
      setActionLoading(null);
    }
  };

  const bulkDelete = async () => {
    if (selectedRules.size === 0) {
      toast.error('No rules selected');
      return;
    }

    if (!confirm(`Are you sure you want to delete ${selectedRules.size} automation rule(s)?`)) return;

    setLoading(true);
    try {
      const deletePromises = Array.from(selectedRules).map(id =>
        fetch(`/api/ai-automations/${id}`, { method: 'DELETE' })
      );

      const results = await Promise.all(deletePromises);
      const successCount = results.filter(r => r.ok).length;
      const failCount = results.filter(r => !r.ok).length;

      if (successCount > 0) {
        toast.success(`${successCount} rule(s) deleted successfully`);
      }
      if (failCount > 0) {
        toast.error(`Failed to delete ${failCount} rule(s)`);
      }

      setSelectedRules(new Set());
      fetchRules();
    } catch {
      toast.error('Failed to delete rules');
    } finally {
      setLoading(false);
    }
  };

  const testRule = async (id: string) => {
    setActionLoading(id);
    try {
      const response = await fetch('/api/ai-automations/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ruleId: id })
      });

      const data = await response.json();

      if (response.ok) {
        toast.success(`Test complete: ${data.sent} sent, ${data.failed} failed`);
        fetchRules();
      } else {
        toast.error(data.error || 'Test failed');
      }
    } catch {
      toast.error('Failed to execute test');
    } finally {
      setActionLoading(null);
    }
  };

  const handleEdit = (rule: Rule) => {
    setEditingRule(rule);
    setEditDialogOpen(true);
  };

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedRules(new Set(filteredRules.map(r => r.id)));
    } else {
      setSelectedRules(new Set());
    }
  };

  const handleSelectRule = (ruleId: string, checked: boolean) => {
    setSelectedRules(prev => {
      const newSet = new Set(prev);
      if (checked) {
        newSet.add(ruleId);
      } else {
        newSet.delete(ruleId);
      }
      return newSet;
    });
  };

  const getTimeIntervalText = (rule: Rule) => {
    const parts = [];
    if (rule.timeIntervalDays) parts.push(`${rule.timeIntervalDays}d`);
    if (rule.timeIntervalHours) parts.push(`${rule.timeIntervalHours}h`);
    if (rule.timeIntervalMinutes) parts.push(`${rule.timeIntervalMinutes}m`);
    return parts.join(' ') || 'Not set';
  };

  // Filtered rules based on search query
  const filteredRules = useMemo(() => {
    if (!searchQuery.trim()) return rules;
    
    const query = searchQuery.toLowerCase();
    return rules.filter(rule => 
      rule.name.toLowerCase().includes(query) ||
      rule.description?.toLowerCase().includes(query) ||
      rule.customPrompt.toLowerCase().includes(query) ||
      rule.facebookPage?.pageName.toLowerCase().includes(query) ||
      rule.includeTags.some(tag => tag.toLowerCase().includes(query)) ||
      rule.excludeTags.some(tag => tag.toLowerCase().includes(query))
    );
  }, [rules, searchQuery]);

  const allSelected = filteredRules.length > 0 && filteredRules.every(r => selectedRules.has(r.id));
  const someSelected = filteredRules.some(r => selectedRules.has(r.id)) && !allSelected;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-muted-foreground">Loading automation rules...</div>
      </div>
    );
  }

  if (error && rules.length === 0) {
    return (
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold">AI Automation Rules</h1>
            <p className="text-muted-foreground mt-1">
              Automatically send personalized follow-up messages powered by AI
            </p>
          </div>
        </div>
        <Card className="p-12 text-center">
          <div className="text-destructive mb-4">
            Error loading automation rules: {error}
          </div>
          <Button onClick={fetchRules}>
            Retry
          </Button>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold">AI Automation Rules</h1>
          <p className="text-muted-foreground mt-1">
            Automatically send personalized follow-up messages powered by AI
          </p>
        </div>
        <div className="flex gap-2">
          {selectedRules.size > 0 && (
            <Button 
              variant="destructive" 
              onClick={bulkDelete}
              disabled={loading}
            >
              <Trash2 className="w-4 h-4 mr-2" />
              Delete {selectedRules.size} Selected
            </Button>
          )}
          <Button onClick={() => setCreateDialogOpen(true)}>
            <Plus className="w-4 h-4 mr-2" />
            Create Rule
          </Button>
        </div>
      </div>

      {/* Search Bar */}
      <Card className="p-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search by name, description, prompt, tags, or page..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10 pr-10"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
        {searchQuery && (
          <p className="text-sm text-muted-foreground mt-2">
            Found {filteredRules.length} rule{filteredRules.length !== 1 ? 's' : ''}
          </p>
        )}
      </Card>
      
      <CreateRuleDialog 
        open={createDialogOpen}
        onOpenChange={setCreateDialogOpen}
        onSuccess={fetchRules}
      />

      {editingRule && (
        <EditRuleDialog
          open={editDialogOpen}
          onOpenChange={setEditDialogOpen}
          rule={editingRule}
          onSuccess={fetchRules}
        />
      )}

      {filteredRules.length === 0 && !searchQuery ? (
        <Card className="p-12 text-center">
          <div className="text-muted-foreground mb-4">
            No automation rules yet. Create your first rule to start automating follow-ups!
          </div>
          <Button onClick={() => setCreateDialogOpen(true)}>
            <Plus className="w-4 h-4 mr-2" />
            Create Your First Rule
          </Button>
        </Card>
      ) : filteredRules.length === 0 ? (
        <Card className="p-12 text-center">
          <div className="text-muted-foreground mb-4">
            No rules match your search query.
          </div>
          <Button onClick={() => setSearchQuery('')}>
            Clear Search
          </Button>
        </Card>
      ) : (
        <>
          {/* Select All */}
          <Card className="p-4 bg-muted/50 border-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Checkbox
                  checked={allSelected}
                  ref={(node: HTMLButtonElement | null) => {
                    if (node) {
                      const input = node.querySelector('input[type="checkbox"]') as HTMLInputElement | null;
                      if (input) {
                        input.indeterminate = someSelected;
                      }
                    }
                  }}
                  onCheckedChange={handleSelectAll}
                  className="data-[state=checked]:bg-primary data-[state=checked]:border-primary transition-all duration-200"
                />
                <span className="text-sm font-semibold">
                  {selectedRules.size > 0 
                    ? `${selectedRules.size} of ${filteredRules.length} selected`
                    : 'Select all automation rules'
                  }
                </span>
              </div>
              {selectedRules.size > 0 && (
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setSelectedRules(new Set())}
                  >
                    Clear Selection
                  </Button>
                </div>
              )}
            </div>
          </Card>

          <div className="grid gap-4">
            {filteredRules.map((rule) => (
              <Card key={rule.id} className="p-6">
                <div className="flex items-start gap-4">
                  {/* Checkbox */}
                  <div className="pt-1">
                    <Checkbox
                      checked={selectedRules.has(rule.id)}
                      onCheckedChange={(checked) => handleSelectRule(rule.id, checked as boolean)}
                      className="data-[state=checked]:bg-primary data-[state=checked]:border-primary transition-all duration-200 hover:border-primary/50"
                    />
                  </div>

                  {/* Content */}
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <h3 className="font-semibold text-lg">{rule.name}</h3>
                      <Badge variant={rule.enabled ? 'default' : 'secondary'}>
                        {rule.enabled ? 'Active' : 'Paused'}
                      </Badge>
                      {rule.facebookPage && (
                        <Badge variant="outline">{rule.facebookPage.pageName}</Badge>
                      )}
                    </div>

                    {rule.description && (
                      <p className="text-sm text-muted-foreground mb-3">
                        {rule.description}
                      </p>
                    )}

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
                      <div className="flex items-center gap-2">
                        <Clock className="w-4 h-4 text-muted-foreground" />
                        <div>
                          <div className="text-xs text-muted-foreground">Interval</div>
                          <div className="text-sm font-medium">{getTimeIntervalText(rule)}</div>
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        <MessageSquare className="w-4 h-4 text-muted-foreground" />
                        <div>
                          <div className="text-xs text-muted-foreground">Executions</div>
                          <div className="text-sm font-medium">{rule.executionCount}</div>
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        <TrendingUp className="w-4 h-4 text-green-600" />
                        <div>
                          <div className="text-xs text-muted-foreground">Success</div>
                          <div className="text-sm font-medium text-green-600">
                            {rule.successCount}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        <div>
                          <div className="text-xs text-muted-foreground">Stopped</div>
                          <div className="text-sm font-medium">
                            {rule._count.stops}
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="flex flex-wrap gap-2 mt-3">
                      {rule.includeTags.length > 0 && (
                        <div className="flex items-center gap-1 text-xs">
                          <span className="text-muted-foreground font-medium">Include:</span>
                          {rule.includeTags.map(tag => (
                            <Badge key={tag} variant="default" className="mr-1 bg-green-600 hover:bg-green-700">
                              {tag}
                            </Badge>
                          ))}
                        </div>
                      )}
                      {rule.excludeTags.length > 0 && (
                        <div className="flex items-center gap-1 text-xs">
                          <span className="text-muted-foreground font-medium">Exclude:</span>
                          {rule.excludeTags.map(tag => (
                            <Badge key={tag} variant="destructive" className="mr-1">
                              {tag}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>

                    {rule.lastExecutedAt && (
                      <div className="text-xs text-muted-foreground mt-2">
                        Last executed: {new Date(rule.lastExecutedAt).toLocaleString()}
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleEdit(rule)}
                      disabled={actionLoading === rule.id}
                      title="Edit rule"
                    >
                      <Edit2 className="w-4 h-4" />
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => testRule(rule.id)}
                      disabled={actionLoading === rule.id}
                      title="Test rule"
                    >
                      <Play className="w-4 h-4" />
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => toggleRule(rule.id, rule.enabled)}
                      disabled={actionLoading === rule.id}
                      title={rule.enabled ? 'Pause rule' : 'Resume rule'}
                    >
                      {rule.enabled ? (
                        <Pause className="w-4 h-4" />
                      ) : (
                        <Play className="w-4 h-4" />
                      )}
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => deleteRule(rule.id)}
                      disabled={actionLoading === rule.id}
                      title="Delete rule"
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </div>

                {rule.customPrompt && (
                  <details className="mt-4">
                    <summary className="text-sm text-muted-foreground cursor-pointer hover:text-foreground">
                      View AI Prompt
                    </summary>
                    <div className="mt-2 p-3 bg-muted rounded-md text-sm">
                      {rule.customPrompt}
                    </div>
                  </details>
                )}
              </Card>
            ))}
          </div>
        </>
      )}

      <Card className="p-6">
        <h3 className="font-semibold mb-2">💡 Quick Tips</h3>
        <ul className="text-sm text-muted-foreground space-y-1">
          <li>• Use the search bar to quickly find rules by name, tags, or content</li>
          <li>• Select multiple rules using checkboxes for bulk deletion</li>
          <li>• Click the edit button to modify rule settings</li>
          <li>• Automation runs every minute via Vercel Cron</li>
          <li>• Messages are personalized using conversation history</li>
          <li>• Automation stops automatically when users reply</li>
          <li>• Use the Play button to test a rule manually</li>
          <li>• Start with small time intervals (1-24 hours) for testing</li>
          <li>• Monitor execution stats to optimize your rules</li>
        </ul>
      </Card>
    </div>
  );
}
