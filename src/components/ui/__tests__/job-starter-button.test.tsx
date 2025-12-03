/**
 * Tests for JobStarterButton Component
 * 
 * Tests:
 * - Calls onStart callback with jobId
 * - Calls onError callback on error
 * - Disables button when disabled prop is true
 * - Handles network errors gracefully
 */

import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { JobStarterButton } from '../job-starter-button';

// Mock the Button component
jest.mock('../button', () => ({
  Button: ({ children, onClick, disabled, ...props }: React.ComponentProps<'button'>) => (
    <button onClick={onClick} disabled={disabled} {...props}>
      {children}
    </button>
  ),
  buttonVariants: jest.fn(),
}));

// Mock lucide-react
jest.mock('lucide-react', () => ({
  Loader2: ({ className }: { className?: string }) => (
    <span data-testid="loader" className={className}>Loading</span>
  ),
}));

describe('JobStarterButton', () => {
  const mockStartJob = jest.fn();
  const mockOnStart = jest.fn();
  const mockOnError = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Test: Calls onStart callback with jobId', () => {
    it('should call onStart callback with jobId when job starts successfully', async () => {
      const user = userEvent.setup();
      const testJobId = 'test-job-123';
      mockStartJob.mockResolvedValue(testJobId);

      render(
        <JobStarterButton
          startJob={mockStartJob}
          onStart={mockOnStart}
        >
          Start Job
        </JobStarterButton>
      );

      const button = screen.getByRole('button', { name: /start job/i });
      await user.click(button);

      await waitFor(() => {
        expect(mockStartJob).toHaveBeenCalledTimes(1);
      });

      await waitFor(() => {
        expect(mockOnStart).toHaveBeenCalledWith(testJobId);
      });
    });

    it('should call onStart callback with correct jobId when multiple jobs are started', async () => {
      const user = userEvent.setup();
      const jobIds = ['job-1', 'job-2', 'job-3'];
      let callCount = 0;
      
      mockStartJob.mockImplementation(() => {
        const jobId = jobIds[callCount];
        callCount++;
        return Promise.resolve(jobId);
      });

      render(
        <JobStarterButton
          startJob={mockStartJob}
          onStart={mockOnStart}
        >
          Start Job
        </JobStarterButton>
      );

      const button = screen.getByRole('button', { name: /start job/i });
      
      // Click multiple times
      await user.click(button);
      await user.click(button);
      await user.click(button);

      await waitFor(() => {
        expect(mockOnStart).toHaveBeenCalledTimes(3);
        expect(mockOnStart).toHaveBeenNthCalledWith(1, 'job-1');
        expect(mockOnStart).toHaveBeenNthCalledWith(2, 'job-2');
        expect(mockOnStart).toHaveBeenNthCalledWith(3, 'job-3');
      });
    });

    it('should not call onStart callback if it is not provided', async () => {
      const user = userEvent.setup();
      const testJobId = 'test-job-456';
      mockStartJob.mockResolvedValue(testJobId);

      render(
        <JobStarterButton startJob={mockStartJob}>
          Start Job
        </JobStarterButton>
      );

      const button = screen.getByRole('button', { name: /start job/i });
      await user.click(button);

      await waitFor(() => {
        expect(mockStartJob).toHaveBeenCalledTimes(1);
      });

      expect(mockOnStart).not.toHaveBeenCalled();
    });
  });

  describe('Test: Calls onError callback on error', () => {
    it('should call onError callback when startJob throws an error', async () => {
      const user = userEvent.setup();
      const testError = new Error('Failed to start job');
      mockStartJob.mockRejectedValue(testError);

      render(
        <JobStarterButton
          startJob={mockStartJob}
          onError={mockOnError}
        >
          Start Job
        </JobStarterButton>
      );

      const button = screen.getByRole('button', { name: /start job/i });
      await user.click(button);

      await waitFor(() => {
        expect(mockStartJob).toHaveBeenCalledTimes(1);
      });

      await waitFor(() => {
        expect(mockOnError).toHaveBeenCalledTimes(1);
        expect(mockOnError).toHaveBeenCalledWith(testError);
      });
    });

    it('should call onError with Error object when startJob throws a non-Error value', async () => {
      const user = userEvent.setup();
      const nonErrorValue = 'String error';
      mockStartJob.mockRejectedValue(nonErrorValue);

      render(
        <JobStarterButton
          startJob={mockStartJob}
          onError={mockOnError}
        >
          Start Job
        </JobStarterButton>
      );

      const button = screen.getByRole('button', { name: /start job/i });
      await user.click(button);

      await waitFor(() => {
        expect(mockOnError).toHaveBeenCalledTimes(1);
        const errorArg = mockOnError.mock.calls[0][0];
        expect(errorArg).toBeInstanceOf(Error);
        expect(errorArg.message).toBe('String error');
      });
    });

    it('should call onError with Error object when startJob throws null', async () => {
      const user = userEvent.setup();
      mockStartJob.mockRejectedValue(null);

      render(
        <JobStarterButton
          startJob={mockStartJob}
          onError={mockOnError}
        >
          Start Job
        </JobStarterButton>
      );

      const button = screen.getByRole('button', { name: /start job/i });
      await user.click(button);

      await waitFor(() => {
        expect(mockOnError).toHaveBeenCalledTimes(1);
        const errorArg = mockOnError.mock.calls[0][0];
        expect(errorArg).toBeInstanceOf(Error);
        expect(errorArg.message).toBe('Unknown error occurred');
      });
    });

    it('should handle error gracefully when onError is not provided', async () => {
      const user = userEvent.setup();
      const testError = new Error('Test error');
      mockStartJob.mockRejectedValue(testError);
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      render(
        <JobStarterButton startJob={mockStartJob}>
          Start Job
        </JobStarterButton>
      );

      const button = screen.getByRole('button', { name: /start job/i });
      await user.click(button);

      await waitFor(() => {
        expect(consoleErrorSpy).toHaveBeenCalledWith(
          'Job starter error:',
          expect.any(Error)
        );
      });

      consoleErrorSpy.mockRestore();
    });
  });

  describe('Test: Disables button when disabled prop is true', () => {
    it('should disable button when disabled prop is true', () => {
      render(
        <JobStarterButton
          startJob={mockStartJob}
          disabled={true}
        >
          Start Job
        </JobStarterButton>
      );

      const button = screen.getByRole('button', { name: /start job/i });
      expect(button).toBeDisabled();
    });

    it('should not call startJob when button is disabled and clicked', async () => {
      const user = userEvent.setup();
      mockStartJob.mockResolvedValue('job-id');

      render(
        <JobStarterButton
          startJob={mockStartJob}
          disabled={true}
        >
          Start Job
        </JobStarterButton>
      );

      const button = screen.getByRole('button', { name: /start job/i });
      await user.click(button);

      // Wait a bit to ensure startJob is not called
      await new Promise(resolve => setTimeout(resolve, 100));

      expect(mockStartJob).not.toHaveBeenCalled();
    });

    it('should enable button when disabled prop is false', () => {
      render(
        <JobStarterButton
          startJob={mockStartJob}
          disabled={false}
        >
          Start Job
        </JobStarterButton>
      );

      const button = screen.getByRole('button', { name: /start job/i });
      expect(button).not.toBeDisabled();
    });

    it('should disable button while loading', async () => {
      const user = userEvent.setup();
      mockStartJob.mockImplementation(() => new Promise(resolve => setTimeout(() => resolve('job-id'), 100)));

      render(
        <JobStarterButton
          startJob={mockStartJob}
        >
          Start Job
        </JobStarterButton>
      );

      const button = screen.getByRole('button', { name: /start job/i });
      await user.click(button);

      // Button should be disabled while loading
      await waitFor(() => {
        expect(button).toBeDisabled();
      });
    });
  });

  describe('Test: Handles network errors gracefully', () => {
    it('should handle network timeout errors', async () => {
      const user = userEvent.setup();
      const networkError = new Error('Network timeout') as Error & { code?: string };
      networkError.code = 'ETIMEDOUT';
      mockStartJob.mockRejectedValue(networkError);

      render(
        <JobStarterButton
          startJob={mockStartJob}
          onError={mockOnError}
        >
          Start Job
        </JobStarterButton>
      );

      const button = screen.getByRole('button', { name: /start job/i });
      await user.click(button);

      await waitFor(() => {
        expect(mockOnError).toHaveBeenCalledWith(networkError);
      });

      // Button should be re-enabled after error
      await waitFor(() => {
        expect(button).not.toBeDisabled();
      });
    });

    it('should handle fetch network errors', async () => {
      const user = userEvent.setup();
      const fetchError = new Error('Failed to fetch') as Error & { name?: string };
      fetchError.name = 'TypeError';
      mockStartJob.mockRejectedValue(fetchError);

      render(
        <JobStarterButton
          startJob={mockStartJob}
          onError={mockOnError}
        >
          Start Job
        </JobStarterButton>
      );

      const button = screen.getByRole('button', { name: /start job/i });
      await user.click(button);

      await waitFor(() => {
        expect(mockOnError).toHaveBeenCalledWith(fetchError);
      });
    });

    it('should handle connection refused errors', async () => {
      const user = userEvent.setup();
      const connectionError = new Error('ECONNREFUSED') as Error & { code?: string };
      connectionError.code = 'ECONNREFUSED';
      mockStartJob.mockRejectedValue(connectionError);

      render(
        <JobStarterButton
          startJob={mockStartJob}
          onError={mockOnError}
        >
          Start Job
        </JobStarterButton>
      );

      const button = screen.getByRole('button', { name: /start job/i });
      await user.click(button);

      await waitFor(() => {
        expect(mockOnError).toHaveBeenCalledWith(connectionError);
      });
    });

    it('should handle 500 server errors', async () => {
      const user = userEvent.setup();
      const serverError = new Error('Internal Server Error') as Error & { status?: number; statusText?: string };
      serverError.status = 500;
      serverError.statusText = 'Internal Server Error';
      mockStartJob.mockRejectedValue(serverError);

      render(
        <JobStarterButton
          startJob={mockStartJob}
          onError={mockOnError}
        >
          Start Job
        </JobStarterButton>
      );

      const button = screen.getByRole('button', { name: /start job/i });
      await user.click(button);

      await waitFor(() => {
        expect(mockOnError).toHaveBeenCalledWith(serverError);
      });
    });

    it('should handle 404 not found errors', async () => {
      const user = userEvent.setup();
      const notFoundError = new Error('Not Found') as Error & { status?: number; statusText?: string };
      notFoundError.status = 404;
      notFoundError.statusText = 'Not Found';
      mockStartJob.mockRejectedValue(notFoundError);

      render(
        <JobStarterButton
          startJob={mockStartJob}
          onError={mockOnError}
        >
          Start Job
        </JobStarterButton>
      );

      const button = screen.getByRole('button', { name: /start job/i });
      await user.click(button);

      await waitFor(() => {
        expect(mockOnError).toHaveBeenCalledWith(notFoundError);
      });
    });

    it('should re-enable button after network error', async () => {
      const user = userEvent.setup();
      const networkError = new Error('Network error');
      mockStartJob.mockRejectedValue(networkError);

      render(
        <JobStarterButton
          startJob={mockStartJob}
          onError={mockOnError}
        >
          Start Job
        </JobStarterButton>
      );

      const button = screen.getByRole('button', { name: /start job/i });
      await user.click(button);

      // Wait for error to be handled
      await waitFor(() => {
        expect(mockOnError).toHaveBeenCalled();
      });

      // Button should be re-enabled
      await waitFor(() => {
        expect(button).not.toBeDisabled();
      });

      // Should be able to click again
      expect(button).not.toBeDisabled();
    });

    it('should handle multiple consecutive network errors', async () => {
      const user = userEvent.setup();
      const networkError = new Error('Network error');
      mockStartJob.mockRejectedValue(networkError);

      render(
        <JobStarterButton
          startJob={mockStartJob}
          onError={mockOnError}
        >
          Start Job
        </JobStarterButton>
      );

      const button = screen.getByRole('button', { name: /start job/i });
      
      // Click multiple times
      await user.click(button);
      await waitFor(() => expect(mockOnError).toHaveBeenCalledTimes(1));
      
      await user.click(button);
      await waitFor(() => expect(mockOnError).toHaveBeenCalledTimes(2));
      
      await user.click(button);
      await waitFor(() => expect(mockOnError).toHaveBeenCalledTimes(3));

      // Each error should be handled independently
      expect(mockOnError).toHaveBeenCalledTimes(3);
    });
  });
});

