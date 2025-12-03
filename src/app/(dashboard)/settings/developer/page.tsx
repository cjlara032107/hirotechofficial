import { redirect } from 'next/navigation';
import { auth } from '@/auth';
import { PageAccessClient } from '@/components/settings/page-access-client';
import { DatabaseManagementClient } from '@/components/settings/database-management-client';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

// Force dynamic rendering since we use auth() which uses cookies
export const dynamic = 'force-dynamic';

export default async function DeveloperSettingsPage() {
  try {
    const session = await auth();
    
    if (!session?.user) {
      redirect('/login');
    }

    // Check developer role
    if (session.user.role !== 'DEVELOPER') {
      redirect('/settings');
    }

    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold">Developer Settings</h1>
          <p className="text-muted-foreground mt-1">
            Manage page access and database configuration
          </p>
        </div>

        <Tabs defaultValue="page-access" className="space-y-4">
          <TabsList>
            <TabsTrigger value="page-access">Page Access</TabsTrigger>
            <TabsTrigger value="databases">Databases</TabsTrigger>
          </TabsList>
          
          <TabsContent value="page-access" className="space-y-4">
            <PageAccessClient />
          </TabsContent>
          
          <TabsContent value="databases" className="space-y-4">
            <DatabaseManagementClient />
          </TabsContent>
        </Tabs>
      </div>
    );
  } catch (error) {
    console.error('Error in DeveloperSettingsPage:', error);
    redirect('/settings');
  }
}

