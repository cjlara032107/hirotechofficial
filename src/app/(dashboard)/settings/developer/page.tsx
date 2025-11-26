import { redirect } from 'next/navigation';
import { auth } from '@/auth';
import { PageAccessClient } from '@/components/settings/page-access-client';

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

    return <PageAccessClient />;
  } catch (error) {
    console.error('Error in DeveloperSettingsPage:', error);
    redirect('/settings');
  }
}

