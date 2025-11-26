import { getPageAccessStatus } from '@/lib/developer/get-page-access';
import UnderDevelopmentPage from '../under-development/page';
import { auth } from '@/auth';
import { redirect } from 'next/navigation';

export default async function DashboardPage() {
  const session = await auth();
  if (!session?.user?.id) {
    redirect('/login');
  }

  const pageAccess = await getPageAccessStatus(session.user.id, '/dashboard');
  
  if (pageAccess === false) {
    return <UnderDevelopmentPage searchParams={Promise.resolve({ page: '/dashboard' })} />;
  }

  return (
    <div className="space-y-8">
      <div className="space-y-2">
        <h1 className="text-4xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground text-lg">
          Welcome to your business messaging platform
        </p>
      </div>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        {/* Placeholder cards - will be implemented in analytics phase */}
        <div className="rounded-xl border border-border/50 bg-card shadow-sm p-6 hover:shadow-md transition-all">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">Total Contacts</h3>
          <p className="mt-3 text-4xl font-bold tracking-tight">0</p>
        </div>
        <div className="rounded-xl border border-border/50 bg-card shadow-sm p-6 hover:shadow-md transition-all">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">Active Campaigns</h3>
          <p className="mt-3 text-4xl font-bold tracking-tight">0</p>
        </div>
        <div className="rounded-xl border border-border/50 bg-card shadow-sm p-6 hover:shadow-md transition-all">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">Messages Sent</h3>
          <p className="mt-3 text-4xl font-bold tracking-tight">0</p>
        </div>
        <div className="rounded-xl border border-border/50 bg-card shadow-sm p-6 hover:shadow-md transition-all">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">Conversion Rate</h3>
          <p className="mt-3 text-4xl font-bold tracking-tight">0%</p>
        </div>
      </div>
    </div>
  );
}

