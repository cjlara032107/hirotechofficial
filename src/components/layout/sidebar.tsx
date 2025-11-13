'use client';

import Link from 'next/link';
import Image from 'next/image';
import { usePathname } from 'next/navigation';
import { cn } from '@/lib/utils';
import {
  LayoutDashboard,
  Users,
  Send,
  GitBranch,
  FileText,
  Tag,
  Settings,
  Users2,
  Bot,
  Calendar,
} from 'lucide-react';

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Contacts', href: '/contacts', icon: Users },
  { name: 'Campaigns', href: '/campaigns', icon: Send },
  { name: 'Scheduled', href: '/campaigns/scheduled', icon: Calendar },
  { name: 'Pipelines', href: '/pipelines', icon: GitBranch },
  { name: 'AI Automations', href: '/ai-automations', icon: Bot },
  { name: 'Templates', href: '/templates', icon: FileText },
  { name: 'Tags', href: '/tags', icon: Tag },
  { name: 'Team', href: '/team', icon: Users2 },
  { name: 'Settings', href: '/settings', icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <div className="flex h-full w-64 flex-col border-r bg-card/50 backdrop-blur-xl">
      {/* Logo */}
      <div className="flex h-16 items-center border-b px-6">
        <Link href="/dashboard" className="flex items-center gap-3 group">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl overflow-hidden shadow-sm group-hover:shadow-md transition-all duration-200">
            <Image 
              src="/logo.svg" 
              alt="Hiro Logo" 
              width={36} 
              height={36}
              className="object-cover"
              priority
            />
          </div>
          <div className="flex flex-col -space-y-0.5">
            <span className="text-lg font-semibold tracking-tight">Hiro<sup className="text-[0.6rem] font-medium">tech</sup></span>
          </div>
        </Link>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1.5 p-3">
        {navigation.map((item) => {
          const isActive = pathname === item.href || pathname.startsWith(item.href + '/');
          return (
            <Link
              key={item.name}
              href={item.href}
              className={cn(
                'flex items-center gap-3 rounded-xl px-3.5 py-2.5 text-sm font-medium transition-all duration-200',
                isActive
                  ? 'bg-primary text-primary-foreground shadow-sm'
                  : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground hover:shadow-sm'
              )}
            >
              <item.icon className="h-5 w-5" />
              {item.name}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="border-t p-4">
        <div className="text-xs text-muted-foreground">
          <p className="font-medium">Hiro<sup className="text-[0.5rem]">tech</sup> Platform</p>
          <p className="mt-1.5">© 2025 All rights reserved</p>
        </div>
      </div>
    </div>
  );
}

