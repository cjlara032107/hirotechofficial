'use client';

import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Settings, RefreshCw, CheckCircle2, XCircle } from 'lucide-react';
import { toast } from 'sonner';
import { LoadingSpinner } from '@/components/ui/loading-spinner';

interface PageAccess {
  id: string;
  pagePath: string;
  isEnabled: boolean;
  createdAt: string;
  updatedAt: string;
}

// Common pages in the application
const AVAILABLE_PAGES = [
  { path: '/dashboard', label: 'Dashboard', description: 'Main dashboard page' },
  { path: '/contacts', label: 'Contacts', description: 'Contact management' },
  { path: '/campaigns', label: 'Campaigns', description: 'Campaign management' },
  { path: '/pipelines', label: 'Pipelines', description: 'Sales pipelines' },
  { path: '/templates', label: 'Templates', description: 'Message templates' },
  { path: '/tags', label: 'Tags', description: 'Tag management' },
  { path: '/team', label: 'Team', description: 'Team management' },
  { path: '/ai-automations', label: 'AI Automations', description: 'AI automation rules' },
  { path: '/settings', label: 'Settings', description: 'Application settings' },
  { path: '/settings/profile', label: 'Profile Settings', description: 'User profile settings' },
  { path: '/settings/integrations', label: 'Integrations', description: 'Integration settings' },
  { path: '/settings/api-keys', label: 'API Keys', description: 'API key management' },
];

export function PageAccessClient() {
  const [pageAccesses, setPageAccesses] = useState<PageAccess[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [updatingPaths, setUpdatingPaths] = useState<Set<string>>(new Set());

  useEffect(() => {
    loadPageAccesses();
  }, []);

  async function loadPageAccesses() {
    try {
      setIsLoading(true);
      const response = await fetch('/api/developer/page-access');
      if (!response.ok) {
        if (response.status === 403) {
          toast.error('Developer access required');
          return;
        }
        throw new Error('Failed to load page access');
      }
      const data = await response.json();
      setPageAccesses(data);
    } catch (error) {
      console.error('Error loading page access:', error);
      toast.error('Failed to load page access');
    } finally {
      setIsLoading(false);
    }
  }

  async function togglePageAccess(pagePath: string, currentEnabled: boolean) {
    setUpdatingPaths(prev => new Set(prev).add(pagePath));

    try {
      const response = await fetch('/api/developer/page-access', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          pagePath,
          isEnabled: !currentEnabled,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to update page access');
      }

      const updated = await response.json();
      
      // Update local state
      setPageAccesses(prev => {
        const existing = prev.find(pa => pa.pagePath === pagePath);
        if (existing) {
          return prev.map(pa =>
            pa.pagePath === pagePath ? updated : pa
          );
        } else {
          return [...prev, updated];
        }
      });

      toast.success(
        `Page access ${!currentEnabled ? 'enabled' : 'disabled'} for ${pagePath}`
      );
    } catch (error) {
      console.error('Error updating page access:', error);
      toast.error('Failed to update page access');
    } finally {
      setUpdatingPaths(prev => {
        const next = new Set(prev);
        next.delete(pagePath);
        return next;
      });
    }
  }

  function getPageAccess(pagePath: string): PageAccess | null {
    return pageAccesses.find(pa => pa.pagePath === pagePath) || null;
  }

  function isPageEnabled(pagePath: string): boolean {
    const access = getPageAccess(pagePath);
    // Default to enabled if no setting exists
    return access ? access.isEnabled : true;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Page Access Management</h1>
          <p className="text-muted-foreground mt-1">
            Enable or disable access to specific pages for all users
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={loadPageAccesses}
          disabled={isLoading}
        >
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Available Pages</CardTitle>
          <CardDescription>
            Toggle access to specific pages for all users. When disabled, all users will see an &quot;Under Development&quot; message when trying to access the page.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <LoadingSpinner className="h-8 w-8" />
            </div>
          ) : (
            <div className="space-y-4">
              {AVAILABLE_PAGES.map((page) => {
                const enabled = isPageEnabled(page.path);
                const isUpdating = updatingPaths.has(page.path);

                return (
                  <div
                    key={page.path}
                    className="flex items-center justify-between p-4 border rounded-lg hover:bg-accent/50 transition-colors"
                  >
                    <div className="flex-1 space-y-1">
                      <div className="flex items-center gap-2">
                        <h3 className="font-medium">{page.label}</h3>
                        {enabled ? (
                          <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400">
                            <CheckCircle2 className="h-3 w-3" />
                            Enabled
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400">
                            <XCircle className="h-3 w-3" />
                            Disabled
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground">
                        {page.description}
                      </p>
                      <p className="text-xs text-muted-foreground font-mono">
                        {page.path}
                      </p>
                      {!enabled && (
                        <p className="text-xs text-red-600 dark:text-red-400 font-medium mt-1">
                          ⚠️ All users will see &quot;Under Development&quot; message
                        </p>
                      )}
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="flex items-center space-x-2">
                        <Switch
                          id={`page-${page.path}`}
                          checked={enabled}
                          onCheckedChange={() => togglePageAccess(page.path, enabled)}
                          disabled={isUpdating}
                        />
                        <Label
                          htmlFor={`page-${page.path}`}
                          className="cursor-pointer"
                        >
                          {enabled ? 'Enabled' : 'Disabled'}
                        </Label>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

