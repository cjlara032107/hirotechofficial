import { redirect } from 'next/navigation';
import { getPageAccessStatus } from '@/lib/developer/get-page-access';
import UnderDevelopmentPage from '@/app/(dashboard)/under-development/page';
import { auth } from '@/auth';

interface PageAccessGuardProps {
  pagePath: string;
  children: React.ReactNode;
}

/**
 * Server Component that checks if a page is enabled for the current user
 * If disabled, shows "under development" message
 */
export async function PageAccessGuard({ pagePath, children }: PageAccessGuardProps) {
  const session = await auth();
  if (!session?.user?.id) {
    redirect('/login');
  }

  const isEnabled = await getPageAccessStatus(session.user.id, pagePath);

  // If page is disabled, show under development page
  if (isEnabled === false) {
    return <UnderDevelopmentPage searchParams={Promise.resolve({ page: pagePath })} />;
  }

  // Page is enabled, render normally
  return <>{children}</>;
}



