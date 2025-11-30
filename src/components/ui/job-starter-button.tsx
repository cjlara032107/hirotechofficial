'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Loader2 } from 'lucide-react';
import type { VariantProps } from 'class-variance-authority';
import { buttonVariants } from '@/components/ui/button';

type ButtonProps = React.ComponentProps<'button'> & VariantProps<typeof buttonVariants> & {
  asChild?: boolean;
};

interface JobStarterButtonProps extends Omit<ButtonProps, 'onClick' | 'disabled' | 'onError'> {
  /**
   * Function that starts a job and returns a jobId
   * Should return a Promise that resolves to a jobId string
   */
  startJob: () => Promise<string>;
  
  /**
   * Callback called when job starts successfully with the jobId
   */
  onStart?: (jobId: string) => void;
  
  /**
   * Callback called when an error occurs
   */
  onError?: (error: Error) => void;
  
  /**
   * Whether the button should be disabled
   */
  disabled?: boolean;
  
  /**
   * Text to show when button is idle
   */
  children: React.ReactNode;
  
  /**
   * Text to show when job is starting
   */
  loadingText?: string;
}

/**
 * A button component that starts a job and handles callbacks
 * 
 * Features:
 * - Calls onStart callback with jobId when job starts successfully
 * - Calls onError callback when an error occurs
 * - Disables button when disabled prop is true
 * - Handles network errors gracefully
 */
export function JobStarterButton({
  startJob,
  onStart,
  onError,
  disabled = false,
  children,
  loadingText = 'Starting...',
  ...buttonProps
}: JobStarterButtonProps) {
  const [isLoading, setIsLoading] = useState(false);

  const handleClick = async () => {
    if (disabled || isLoading) {
      return;
    }

    setIsLoading(true);

    try {
      const jobId = await startJob();
      
      // Call onStart callback with jobId
      if (onStart) {
        onStart(jobId);
      }
    } catch (error) {
      const errorObj = error instanceof Error 
        ? error 
        : new Error(error ? String(error) : 'Unknown error occurred');
      
      // Call onError callback
      if (onError) {
        onError(errorObj);
      } else {
        // Default error handling if no callback provided
        console.error('Job starter error:', errorObj);
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Button
      {...buttonProps}
      onClick={handleClick}
      disabled={disabled || isLoading}
    >
      {isLoading ? (
        <>
          <Loader2 className="h-4 w-4 animate-spin" />
          {loadingText}
        </>
      ) : (
        children
      )}
    </Button>
  );
}

