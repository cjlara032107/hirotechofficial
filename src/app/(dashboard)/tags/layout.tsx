import { getPageAccessStatus } from '@/lib/developer/get-page-access';
import UnderDevelopmentPage from '../under-development/page';
import { auth } from '@/auth';
import { redirect } from 'next/navigation';

export default async function TagsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await auth();
  if (!session?.user?.id) {
    redirect('/login');
  }

  const pageAccess = await getPageAccessStatus(session.user.id, '/tags');
  
  if (pageAccess === false) {
    return <UnderDevelopmentPage searchParams={Promise.resolve({ page: '/tags' })} />;
  }

  return <>{children}</>;
}



