import { auth } from '@/auth';
import { redirect } from 'next/navigation';
import { SettingsNav } from '@/components/settings/settings-nav';

export default async function SettingsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await auth();

  if (!session?.user) {
    redirect('/login');
  }

  return (
    <div className="container mx-auto py-6">
      <div className="grid gap-6 lg:grid-cols-[250px_1fr]">
        <aside className="lg:col-span-1">
          <div className="sticky top-6">
            <SettingsNav userRole={session.user.role} />
          </div>
        </aside>
        <main className="lg:col-span-1">
          {children}
        </main>
      </div>
    </div>
  );
}





