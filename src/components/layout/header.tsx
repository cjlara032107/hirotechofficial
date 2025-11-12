'use client';

import { signOut, useSession } from 'next-auth/react';
import { useState, useEffect } from 'react';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { LogOut, Settings, User } from 'lucide-react';
import Link from 'next/link';

export function Header() {
  const { data: session } = useSession();
  const [isMounted, setIsMounted] = useState(false);

  // Mark as mounted after first render - this is intentional to avoid hydration mismatch
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setIsMounted(true);
  }, []);

  const getInitials = (name?: string | null) => {
    if (!name) return 'U';
    return name
      .split(' ')
      .map((n) => n[0])
      .join('')
      .toUpperCase()
      .slice(0, 2);
  };

  return (
    <header className="flex h-16 items-center justify-between border-b bg-card/50 backdrop-blur-xl px-8">
      <div className="flex-1">
        {/* Breadcrumb or search can go here */}
      </div>

      <div className="flex items-center gap-4">
        {/* User menu */}
        {isMounted ? (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" className="relative h-10 w-10 rounded-full hover:ring-2 hover:ring-primary/20 transition-all">
                <Avatar className="h-10 w-10 ring-2 ring-background">
                  <AvatarImage src={session?.user?.image || ''} alt={session?.user?.name || ''} />
                  <AvatarFallback className="bg-primary/10 text-primary font-semibold">{getInitials(session?.user?.name)}</AvatarFallback>
                </Avatar>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-64 shadow-lg border-border/50">
              <DropdownMenuLabel>
                <div className="flex flex-col space-y-1.5 py-1">
                  <p className="text-sm font-semibold">{session?.user?.name}</p>
                  <p className="text-xs text-muted-foreground">{session?.user?.email}</p>
                </div>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem asChild>
                <Link href="/settings/profile" className="cursor-pointer">
                  <User className="mr-2 h-4 w-4" />
                  Profile
                </Link>
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <Link href="/settings" className="cursor-pointer">
                  <Settings className="mr-2 h-4 w-4" />
                  Settings
                </Link>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                className="cursor-pointer text-red-600"
                onClick={() => signOut({ callbackUrl: '/login' })}
              >
                <LogOut className="mr-2 h-4 w-4" />
                Log out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        ) : (
          <Button variant="ghost" className="relative h-10 w-10 rounded-full">
            <Avatar className="h-10 w-10 ring-2 ring-background">
              <AvatarFallback className="bg-primary/10 text-primary font-semibold">{getInitials(session?.user?.name)}</AvatarFallback>
            </Avatar>
          </Button>
        )}
      </div>
    </header>
  );
}

