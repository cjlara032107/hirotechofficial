import { getPageAccessStatus } from '@/lib/developer/get-page-access';
import UnderDevelopmentPage from '@/app/(dashboard)/under-development/page';
import { auth } from '@/auth';
import { redirect } from 'next/navigation';

/**
 * Higher-order component to protect pages with per-developer access control
 * Usage: Wrap your page component with this
 * Note: Requires userId from session, so pages using this must be server components
 */
export async function withPageAccess<T extends object>(
  pagePath: string,
  Component: React.ComponentType<T>
) {
  return async function ProtectedPage(props: T) {
    const session = await auth();
    if (!session?.user?.id) {
      redirect('/login');
    }

    const isEnabled = await getPageAccessStatus(session.user.id, pagePath);

    if (isEnabled === false) {
      return <UnderDevelopmentPage searchParams={Promise.resolve({ page: pagePath })} />;
    }

    return <Component {...props} />;
  };
}



