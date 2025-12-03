'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { createClient } from '@/lib/supabase/client';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { logger } from '@/lib/utils/logger';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      logger.debug('Starting Supabase login');
      
      const supabase = createClient();
      
      const { data, error: signInError } = await supabase.auth.signInWithPassword({
        email,
        password,
      });

      logger.debug('Supabase login response', {
        hasUser: !!data?.user,
        hasSession: !!data?.session,
      });

      if (signInError) {
        logger.error('Login error', signInError instanceof Error ? signInError : new Error(String(signInError)));
        
        // Provide user-friendly error messages
        if (signInError.message.includes('Invalid login credentials')) {
          setError('Invalid email or password. Please check your credentials and try again.');
        } else if (signInError.message.includes('Email not confirmed')) {
          setError('Please verify your email address before logging in.');
        } else {
          setError(signInError.message);
        }
        
        setIsLoading(false);
        return;
      }

      if (data?.user) {
        logger.info('Login successful', { userId: data.user.id });
        
        // Ensure user profile exists in database
        try {
          logger.debug('Checking user profile in database');
          const checkResponse = await fetch('/api/auth/check-profile', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ userId: data.user.id }),
          });

          if (!checkResponse.ok) {
            logger.warn('Profile check failed, but continuing');
          } else {
            logger.debug('Profile verified');
          }
        } catch (profileError) {
          logger.warn('Profile check error', { error: profileError });
          // Continue anyway - the auth-helpers will create the profile
        }
        
        logger.debug('Redirecting to dashboard');
        router.push('/dashboard');
        router.refresh();
      } else {
        logger.error('No user returned from login');
        setError('Login failed. Please try again.');
        setIsLoading(false);
      }
    } catch (error) {
      logger.error('Login exception', error instanceof Error ? error : new Error(String(error)));
      setError('An unexpected error occurred. Please try again or contact support.');
      setIsLoading(false);
    }
  };

  return (
    <Card className="border-border/50 shadow-xl backdrop-blur-sm">
      <CardHeader className="space-y-2 pb-6">
        <CardTitle className="text-3xl font-bold tracking-tight">Welcome back</CardTitle>
        <CardDescription className="text-base">
          Enter your credentials to access your account
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-5">
          {error && (
            <div className="rounded-xl bg-red-50 border border-red-200/50 p-4 text-sm text-red-800">
              {error}
            </div>
          )}

          <div className="space-y-2.5">
            <Label htmlFor="email" className="text-sm font-semibold">Email</Label>
            <Input
              id="email"
              type="email"
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              disabled={isLoading}
              className="h-11 rounded-xl border-border/50 focus-visible:ring-primary/30"
            />
          </div>

          <div className="space-y-2.5">
            <Label htmlFor="password" className="text-sm font-semibold">Password</Label>
            <Input
              id="password"
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={isLoading}
              className="h-11 rounded-xl border-border/50 focus-visible:ring-primary/30"
            />
          </div>

          <Button type="submit" className="w-full h-11 rounded-xl shadow-sm hover:shadow-md transition-all" disabled={isLoading}>
            {isLoading ? 'Signing in...' : 'Sign in'}
          </Button>
        </form>

        <div className="mt-6 text-center text-sm text-muted-foreground">
          Don&apos;t have an account?{' '}
          <Link href="/register" className="font-semibold text-primary hover:underline">
            Sign up
          </Link>
        </div>
      </CardContent>
    </Card>
  );
}

