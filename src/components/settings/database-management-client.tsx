'use client';

import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { toast } from 'sonner';
import { Plus, Database, CheckCircle2, XCircle, AlertCircle } from 'lucide-react';

interface DatabaseInfo {
  index: number;
  projectRef: string;
  hasPooledUrl: boolean;
  hasDirectUrl: boolean;
  urlPreview: string;
}

interface DatabasesResponse {
  success: boolean;
  multiDbEnabled: boolean;
  dbCount: number;
  routingStrategy: string;
  databases: DatabaseInfo[];
  capacity?: {
    connectionsPerDatabase: number;
    totalConnectionCapacity: number;
    supabasePoolCapacity: number;
    environment: string;
  };
}

export function DatabaseManagementClient() {
  const [databases, setDatabases] = useState<DatabasesResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newDatabaseUrl, setNewDatabaseUrl] = useState('');
  const [newDirectUrl, setNewDirectUrl] = useState('');
  const [newDatabaseName, setNewDatabaseName] = useState('');
  const [isAdding, setIsAdding] = useState(false);

  useEffect(() => {
    loadDatabases();
  }, []);

  async function loadDatabases() {
    try {
      setIsLoading(true);
      const response = await fetch('/api/developer/databases');
      if (!response.ok) {
        throw new Error('Failed to load databases');
      }
      const data = await response.json();
      setDatabases(data);
    } catch (error) {
      console.error('Error loading databases:', error);
      toast.error('Failed to load databases');
    } finally {
      setIsLoading(false);
    }
  }

  async function handleAddDatabase() {
    if (!newDatabaseUrl.trim()) {
      toast.error('Database URL is required');
      return;
    }

    try {
      setIsAdding(true);
      const response = await fetch('/api/developer/databases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          databaseUrl: newDatabaseUrl.trim(),
          directUrl: newDirectUrl.trim() || null,
          name: newDatabaseName.trim() || null,
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to add database');
      }

      const result = await response.json();
      
      // Show capacity increase info
      const capacityInfo = result.capacity;
      const capacityMessage = capacityInfo 
        ? `Capacity will increase to ${capacityInfo.new} connections (+${capacityInfo.increase})`
        : 'Connection test passed!';
      
      toast.success(capacityMessage, {
        description: 'See instructions below to add to .env.local',
        duration: 10000,
      });

      // Display instructions
      const instructions = [
        result.instructions.step2,
        result.instructions.step3,
        result.instructions.step4,
        result.instructions.step5,
      ].filter(Boolean).join('\n');

      console.log('📝 Add these to .env.local:\n' + instructions);
      
      // Copy to clipboard if possible
      if (navigator.clipboard) {
        await navigator.clipboard.writeText(instructions);
        toast.info('Instructions copied to clipboard');
      }

      // Reset form
      setNewDatabaseUrl('');
      setNewDirectUrl('');
      setNewDatabaseName('');
      setShowAddForm(false);
      
      // Reload databases
      await loadDatabases();
    } catch (error) {
      console.error('Error adding database:', error);
      toast.error(error instanceof Error ? error.message : 'Failed to add database');
    } finally {
      setIsAdding(false);
    }
  }

  if (isLoading) {
    return <div className="p-6">Loading databases...</div>;
  }

  if (!databases) {
    return <div className="p-6 text-red-500">Failed to load databases</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Database Management</h2>
          <p className="text-muted-foreground mt-1">
            Manage multi-database configuration
          </p>
        </div>
        <Button onClick={() => setShowAddForm(!showAddForm)}>
          <Plus className="mr-2 h-4 w-4" />
          Add Database
        </Button>
      </div>

      {/* Status Card */}
      <Card>
        <CardHeader>
          <CardTitle>Multi-Database Status</CardTitle>
          <CardDescription>Current configuration</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Multi-DB Enabled</Label>
              <div className="flex items-center gap-2 mt-1">
                {databases.multiDbEnabled ? (
                  <CheckCircle2 className="h-5 w-5 text-green-500" />
                ) : (
                  <XCircle className="h-5 w-5 text-red-500" />
                )}
                <span>{databases.multiDbEnabled ? 'Yes' : 'No'}</span>
              </div>
            </div>
            <div>
              <Label>Database Count</Label>
              <div className="mt-1 text-lg font-semibold">{databases.dbCount}</div>
            </div>
            <div>
              <Label>Routing Strategy</Label>
              <div className="mt-1 capitalize">{databases.routingStrategy}</div>
            </div>
            <div>
              <Label>Total Capacity</Label>
              <div className="mt-1">
                {databases.capacity ? (
                  <div className="space-y-1">
                    <div className="font-semibold">{databases.capacity.totalConnectionCapacity} connections</div>
                    <div className="text-xs text-muted-foreground">
                      ({databases.dbCount} × {databases.capacity.connectionsPerDatabase} per DB)
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Supabase Pool: {databases.capacity.supabasePoolCapacity}
                    </div>
                  </div>
                ) : (
                  <div>{databases.dbCount * 200} connections</div>
                )}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Add Database Form */}
      {showAddForm && (
        <Card>
          <CardHeader>
            <CardTitle>Add New Database</CardTitle>
            <CardDescription>
              Test and add a new Supabase database to your multi-DB setup
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="databaseUrl">Pooled Connection URL *</Label>
              <Input
                id="databaseUrl"
                type="text"
                placeholder="postgresql://postgres.projectref:password@pooler.supabase.com:6543/postgres?pgbouncer=true"
                value={newDatabaseUrl}
                onChange={(e) => setNewDatabaseUrl(e.target.value)}
                className="mt-1 font-mono text-sm"
              />
              <p className="text-xs text-muted-foreground mt-1">
                Get this from Supabase Dashboard → Settings → Database → Connection Pooling
              </p>
            </div>

            <div>
              <Label htmlFor="directUrl">Direct Connection URL (Optional)</Label>
              <Input
                id="directUrl"
                type="text"
                placeholder="postgresql://postgres:password@db.supabase.co:5432/postgres"
                value={newDirectUrl}
                onChange={(e) => setNewDirectUrl(e.target.value)}
                className="mt-1 font-mono text-sm"
              />
              <p className="text-xs text-muted-foreground mt-1">
                Used for migrations. Get from Supabase Dashboard → Settings → Database → Direct Connection
              </p>
            </div>

            <div>
              <Label htmlFor="databaseName">Database Name (Optional)</Label>
              <Input
                id="databaseName"
                type="text"
                placeholder="Production DB 4"
                value={newDatabaseName}
                onChange={(e) => setNewDatabaseName(e.target.value)}
                className="mt-1"
              />
            </div>

            <div className="flex gap-2">
              <Button onClick={handleAddDatabase} disabled={isAdding}>
                {isAdding ? 'Testing...' : 'Test & Add Database'}
              </Button>
              <Button variant="outline" onClick={() => setShowAddForm(false)}>
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Databases List */}
      <div className="space-y-4">
        <h3 className="text-lg font-semibold">Configured Databases</h3>
        <div className="grid gap-4">
          {databases.databases.map((db) => (
            <Card key={db.index}>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Database className="h-5 w-5" />
                    <CardTitle>Database {db.index}</CardTitle>
                  </div>
                  <div className="flex items-center gap-2">
                    {db.hasPooledUrl && (
                      <span className="text-xs bg-green-100 text-green-800 px-2 py-1 rounded">
                        Pooled
                      </span>
                    )}
                    {db.hasDirectUrl && (
                      <span className="text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded">
                        Direct
                      </span>
                    )}
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div>
                    <Label className="text-xs">Project Reference</Label>
                    <div className="font-mono text-sm">{db.projectRef}</div>
                  </div>
                  <div>
                    <Label className="text-xs">Connection URL</Label>
                    <div className="font-mono text-xs text-muted-foreground break-all">
                      {db.urlPreview}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {databases.databases.length === 0 && (
          <Card>
            <CardContent className="py-8 text-center text-muted-foreground">
              <AlertCircle className="h-8 w-8 mx-auto mb-2" />
              <p>No databases configured</p>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}

