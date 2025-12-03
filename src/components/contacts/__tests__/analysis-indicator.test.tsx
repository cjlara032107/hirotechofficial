/**
 * Tests for AnalysisIndicator component
 * 
 * Tests for:
 * - Renders progress display correctly
 * - Polls status endpoint at interval (2 seconds)
 * - Displays progress metrics correctly (analyzed, failed, percentage)
 * - Displays job status badge
 * - Stops polling when job completes
 */

import React from 'react';
import { render, screen, waitFor, act } from '@testing-library/react';
import { AnalysisIndicator } from '../analysis-indicator';
import { toast } from 'sonner';

// Mock dependencies
jest.mock('sonner', () => ({
  toast: {
    success: jest.fn(),
    error: jest.fn(),
  },
}));

// Mock lucide-react icons
jest.mock('lucide-react', () => ({
  Sparkles: () => <div data-testid="sparkles-icon">Sparkles</div>,
  X: () => <div data-testid="x-icon">X</div>,
  CheckCircle2: () => <div data-testid="check-circle-icon">CheckCircle2</div>,
  AlertCircle: () => <div data-testid="alert-circle-icon">AlertCircle</div>,
  Loader2: () => <div data-testid="loader-icon">Loader2</div>,
}));

// Mock UI components
jest.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, ...props }: any) => (
    <button onClick={onClick} {...props}>
      {children}
    </button>
  ),
}));

jest.mock('@/components/ui/card', () => ({
  Card: ({ children, className }: any) => (
    <div className={className} data-testid="card">
      {children}
    </div>
  ),
  CardContent: ({ children, className }: any) => (
    <div className={className} data-testid="card-content">
      {children}
    </div>
  ),
}));

jest.mock('@/components/ui/progress', () => ({
  Progress: ({ value, className }: any) => (
    <div
      data-testid="progress-bar"
      className={className}
      role="progressbar"
      aria-valuenow={value}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      {value}%
    </div>
  ),
}));

// Mock window.dispatchEvent
const mockDispatchEvent = jest.fn();
Object.defineProperty(window, 'dispatchEvent', {
  value: mockDispatchEvent,
  writable: true,
  configurable: true,
});

// Mock document.hidden
Object.defineProperty(document, 'hidden', {
  writable: true,
  configurable: true,
  value: false,
});

describe('AnalysisIndicator', () => {
  const mockJobId = 'test-job-123';
  const mockOnComplete = jest.fn();
  const mockOnDismiss = jest.fn();
  const mockOnError = jest.fn();

  // Mock fetch globally
  const mockFetch = jest.fn();
  global.fetch = mockFetch;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
    mockFetch.mockClear();
    mockDispatchEvent.mockClear();
    mockOnComplete.mockClear();
    mockOnDismiss.mockClear();
    mockOnError.mockClear();
    document.hidden = false;
  });

  afterEach(() => {
    jest.runOnlyPendingTimers();
    jest.useRealTimers();
  });

  const createMockJobResponse = (overrides: Partial<any> = {}) => ({
    id: mockJobId,
    status: 'IN_PROGRESS',
    totalContacts: 100,
    analyzedContacts: 50,
    failedContacts: 2,
    startedAt: new Date('2024-01-01'),
    completedAt: null,
    ...overrides,
  });

  describe('Renders progress display correctly', () => {
    it('should render the component with initial job data', async () => {
      const mockJob = createMockJobResponse();
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      // Wait for fetch to complete and component to render
      await waitFor(
        () => {
          expect(screen.getByTestId('card')).toBeInTheDocument();
          expect(screen.getByText('Analyzing Contacts')).toBeInTheDocument();
        },
        { timeout: 3000 }
      );
    });

    it('should render progress bar when job is in progress', async () => {
      const mockJob = createMockJobResponse({
        status: 'IN_PROGRESS',
        analyzedContacts: 30,
        totalContacts: 100,
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      await waitFor(() => {
        const progressBar = screen.getByTestId('progress-bar');
        expect(progressBar).toBeInTheDocument();
        expect(progressBar).toHaveAttribute('aria-valuenow', '30');
      });
    });

    it('should not render when job is null', async () => {
      // Component returns null when job is null, so we can't test rendering
      // But we can test that fetch is called
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => null,
      });

      const { container } = render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      // Wait for fetch to be called
      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalled();
      }, { timeout: 2000 });

      // Component should not render anything when job is null
      expect(container.firstChild).toBeNull();
    }, 10000);
  });

  describe('Polls status endpoint at interval (2 seconds)', () => {
    it('should poll immediately on mount', async () => {
      const mockJob = createMockJobResponse();
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      // Wait for initial fetch
      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledWith(
          `/api/contacts/analysis-status/${mockJobId}`
        );
      });
    });

    it('should poll every 2 seconds when job is in progress', async () => {
      const mockJob = createMockJobResponse({ status: 'IN_PROGRESS' });
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      // Wait for initial poll
      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledTimes(1);
      });

      // Advance 2 seconds - should poll again
      act(() => {
        jest.advanceTimersByTime(2000);
      });

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledTimes(2);
      });

      // Advance another 2 seconds - should poll again
      act(() => {
        jest.advanceTimersByTime(2000);
      });

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledTimes(3);
      });
    });

    it('should not poll when document is hidden', async () => {
      document.hidden = true;
      const mockJob = createMockJobResponse({ status: 'IN_PROGRESS' });
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      // Wait for initial poll
      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledTimes(1);
      }, { timeout: 2000 });

      const initialCallCount = mockFetch.mock.calls.length;

      // Advance 2 seconds multiple times - should NOT poll because document is hidden
      act(() => {
        jest.advanceTimersByTime(2000);
      });
      
      act(() => {
        jest.advanceTimersByTime(2000);
      });

      // Should not have made additional calls beyond the initial one
      expect(mockFetch).toHaveBeenCalledTimes(initialCallCount);
    });

    it('should resume polling when document becomes visible', async () => {
      document.hidden = true;
      const mockJob = createMockJobResponse({ status: 'IN_PROGRESS' });
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledTimes(1);
      });

      const initialCallCount = mockFetch.mock.calls.length;

      // Simulate visibility change
      document.hidden = false;
      act(() => {
        const event = new Event('visibilitychange');
        document.dispatchEvent(event);
      });

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledTimes(initialCallCount + 1);
      });
    });
  });

  describe('Displays progress metrics correctly', () => {
    it('should display analyzed contacts count', async () => {
      const mockJob = createMockJobResponse({
        analyzedContacts: 45,
        totalContacts: 100,
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      await waitFor(() => {
        expect(screen.getByText(/45 of 100 contacts analyzed/i)).toBeInTheDocument();
      });
    });

    it('should display failed contacts count when > 0', async () => {
      const mockJob = createMockJobResponse({
        analyzedContacts: 50,
        totalContacts: 100,
        failedContacts: 5,
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      await waitFor(() => {
        expect(screen.getByText(/• 5 failed/i)).toBeInTheDocument();
      });
    });

    it('should not display failed contacts when count is 0', async () => {
      const mockJob = createMockJobResponse({
        analyzedContacts: 50,
        totalContacts: 100,
        failedContacts: 0,
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      await waitFor(() => {
        const text = screen.getByText(/50 of 100 contacts analyzed/i);
        expect(text).toBeInTheDocument();
        expect(text.textContent).not.toContain('failed');
      });
    });

    it('should calculate and display correct percentage', async () => {
      const mockJob = createMockJobResponse({
        analyzedContacts: 75,
        totalContacts: 100,
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      await waitFor(() => {
        const progressBar = screen.getByTestId('progress-bar');
        expect(progressBar).toHaveAttribute('aria-valuenow', '75');
      });
    });

    it('should handle zero total contacts gracefully', async () => {
      const mockJob = createMockJobResponse({
        analyzedContacts: 0,
        totalContacts: 0,
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      await waitFor(() => {
        const progressBar = screen.getByTestId('progress-bar');
        expect(progressBar).toHaveAttribute('aria-valuenow', '0');
      });
    });
  });

  describe('Displays job status badge', () => {
    it('should display IN_PROGRESS status with loader icon', async () => {
      const mockJob = createMockJobResponse({ status: 'IN_PROGRESS' });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      await waitFor(() => {
        expect(screen.getByTestId('loader-icon')).toBeInTheDocument();
        expect(screen.getByText('Analyzing Contacts')).toBeInTheDocument();
      });
    });

    it('should display COMPLETED status with check icon', async () => {
      const mockJob = createMockJobResponse({
        status: 'COMPLETED',
        analyzedContacts: 100,
        totalContacts: 100,
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      await waitFor(() => {
        expect(screen.getByTestId('check-circle-icon')).toBeInTheDocument();
        expect(screen.getByText('Analysis Complete')).toBeInTheDocument();
      });
    });

    it('should display FAILED status with alert icon', async () => {
      const mockJob = createMockJobResponse({
        status: 'FAILED',
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      await waitFor(() => {
        expect(screen.getByTestId('alert-circle-icon')).toBeInTheDocument();
        expect(screen.getByText('Analysis Failed')).toBeInTheDocument();
      });
    });

    it('should display CANCELLED status', async () => {
      const mockJob = createMockJobResponse({
        status: 'CANCELLED',
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      await waitFor(() => {
        expect(screen.getByText('Analysis Cancelled')).toBeInTheDocument();
      });
    });

    it('should apply correct border color for IN_PROGRESS status', async () => {
      const mockJob = createMockJobResponse({ status: 'IN_PROGRESS' });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      await waitFor(() => {
        const card = screen.getByTestId('card');
        expect(card.className).toContain('border-l-blue-500');
      });
    });

    it('should apply correct border color for COMPLETED status', async () => {
      const mockJob = createMockJobResponse({ status: 'COMPLETED' });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      await waitFor(() => {
        const card = screen.getByTestId('card');
        expect(card.className).toContain('border-l-green-500');
      });
    });

    it('should apply correct border color for FAILED status', async () => {
      const mockJob = createMockJobResponse({ status: 'FAILED' });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      await waitFor(() => {
        const card = screen.getByTestId('card');
        expect(card.className).toContain('border-l-red-500');
      });
    });
  });

  describe('Stops polling when job completes', () => {
    it('should stop polling when status is COMPLETED', async () => {
      const inProgressJob = createMockJobResponse({ status: 'IN_PROGRESS' });
      const completedJob = createMockJobResponse({
        status: 'COMPLETED',
        analyzedContacts: 100,
        totalContacts: 100,
      });

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => inProgressJob,
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => completedJob,
        });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      // Wait for initial poll
      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledTimes(1);
      });

      // Advance 2 seconds - should poll again and get completed status
      await act(async () => {
        jest.advanceTimersByTime(2000);
        await Promise.resolve();
      });

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledTimes(2);
      });

      // Advance another 2 seconds - should NOT poll because job is complete
      await act(async () => {
        jest.advanceTimersByTime(2000);
        await Promise.resolve();
      });

      // Should still be 2 calls, not 3
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should stop polling when status is FAILED', async () => {
      const inProgressJob = createMockJobResponse({ status: 'IN_PROGRESS' });
      const failedJob = createMockJobResponse({ status: 'FAILED' });

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => inProgressJob,
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => failedJob,
        });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      // Wait for initial poll
      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledTimes(1);
      });

      // Advance 2 seconds - should poll again and get failed status
      await act(async () => {
        jest.advanceTimersByTime(2000);
        await Promise.resolve();
      });

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledTimes(2);
      });

      // Advance another 2 seconds - should NOT poll because job is failed
      await act(async () => {
        jest.advanceTimersByTime(2000);
        await Promise.resolve();
      });

      // Should still be 2 calls, not 3
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should stop polling when status is CANCELLED', async () => {
      const inProgressJob = createMockJobResponse({ status: 'IN_PROGRESS' });
      const cancelledJob = createMockJobResponse({ status: 'CANCELLED' });

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => inProgressJob,
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => cancelledJob,
        });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      // Wait for initial poll
      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledTimes(1);
      });

      // Advance 2 seconds - should poll again and get cancelled status
      await act(async () => {
        jest.advanceTimersByTime(2000);
        await Promise.resolve();
      });

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledTimes(2);
      });

      // Advance another 2 seconds - should NOT poll because job is cancelled
      await act(async () => {
        jest.advanceTimersByTime(2000);
        await Promise.resolve();
      });

      // Should still be 2 calls, not 3
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should call onComplete callback when job completes', async () => {
      const completedJob = createMockJobResponse({
        status: 'COMPLETED',
        analyzedContacts: 100,
        totalContacts: 100,
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => completedJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      await waitFor(() => {
        expect(mockOnComplete).toHaveBeenCalledTimes(1);
      });
    });

    it('should show success toast when job completes successfully', async () => {
      const completedJob = createMockJobResponse({
        status: 'COMPLETED',
        analyzedContacts: 100,
        totalContacts: 100,
        failedContacts: 0,
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => completedJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      await waitFor(() => {
        expect(toast.success).toHaveBeenCalledWith(
          expect.stringContaining('Analysis complete!'),
          { duration: 5000 }
        );
      });
    });

    it('should dispatch analysisCompleted event when job completes', async () => {
      const completedJob = createMockJobResponse({
        status: 'COMPLETED',
        analyzedContacts: 95,
        totalContacts: 100,
        failedContacts: 5,
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => completedJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      await waitFor(() => {
        expect(mockDispatchEvent).toHaveBeenCalled();
      });

      // Find the analysisCompleted event
      const eventCall = mockDispatchEvent.mock.calls.find(
        (call) => call[0]?.type === 'analysisCompleted'
      );
      expect(eventCall).toBeDefined();
      if (eventCall) {
        const event = eventCall[0];
        expect(event.type).toBe('analysisCompleted');
        expect(event.detail).toEqual({
          jobId: mockJobId,
          analyzedContacts: 95,
          failedContacts: 5,
        });
      }
    });

    it('should show error toast when job fails', async () => {
      const failedJob = createMockJobResponse({
        status: 'FAILED',
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => failedJob,
      });

      render(
        <AnalysisIndicator
          jobId={mockJobId}
          onComplete={mockOnComplete}
          onDismiss={mockOnDismiss}
        />
      );

      await waitFor(() => {
        expect(toast.error).toHaveBeenCalledWith(
          'Analysis failed. Please try again.',
          { duration: 5000 }
        );
      });
    });
  });

  // Checklist-specific tests
  describe('Test: Calls onError callback', () => {
    it('should call onError when fetch throws an error', async () => {
      const onError = jest.fn();
      const networkError = new Error('Network request failed');
      
      mockFetch.mockRejectedValueOnce(networkError);

      render(<AnalysisIndicator jobId={mockJobId} onError={onError} />);

      await waitFor(() => {
        expect(onError).toHaveBeenCalledTimes(1);
        expect(onError).toHaveBeenCalledWith(networkError);
      }, { timeout: 3000 });
    });

    it('should call onError when fetch returns non-ok response', async () => {
      const onError = jest.fn();
      
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      });

      render(<AnalysisIndicator jobId={mockJobId} onError={onError} />);

      await waitFor(() => {
        expect(onError).toHaveBeenCalledTimes(1);
        expect(onError).toHaveBeenCalledWith(expect.any(Error));
      }, { timeout: 3000 });
    });

    it('should not call onError if not provided', async () => {
      const networkError = new Error('Network request failed');
      
      mockFetch.mockRejectedValueOnce(networkError);

      render(<AnalysisIndicator jobId={mockJobId} />);

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalled();
      }, { timeout: 3000 });

      // Should not throw - onError is optional
      expect(mockFetch).toHaveBeenCalled();
    });
  });

  describe('Test: Cleans up polling on unmount', () => {
    it('should clear polling interval on unmount', async () => {
      const clearIntervalSpy = jest.spyOn(global, 'clearInterval');
      
      const inProgressJob = createMockJobResponse({ status: 'IN_PROGRESS' });
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => inProgressJob,
      });

      const { unmount } = render(
        <AnalysisIndicator jobId={mockJobId} />
      );

      // Wait for initial poll
      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledTimes(1);
      });

      // Advance timer to trigger interval
      await act(async () => {
        jest.advanceTimersByTime(2000);
        await Promise.resolve();
      });

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledTimes(2);
      });

      // Unmount component
      unmount();

      // Verify clearInterval was called
      expect(clearIntervalSpy).toHaveBeenCalled();

      // Advance timer after unmount - should not trigger more polls
      const callCountBefore = mockFetch.mock.calls.length;
      await act(async () => {
        jest.advanceTimersByTime(10000);
        await Promise.resolve();
      });
      const callCountAfter = mockFetch.mock.calls.length;

      // Should not have made more fetch calls
      expect(callCountAfter).toBe(callCountBefore);

      clearIntervalSpy.mockRestore();
    });

    it('should remove visibility change event listener on unmount', async () => {
      const removeEventListenerSpy = jest.spyOn(document, 'removeEventListener');
      const inProgressJob = createMockJobResponse({ status: 'IN_PROGRESS' });
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => inProgressJob,
      });

      const { unmount } = render(
        <AnalysisIndicator jobId={mockJobId} />
      );

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalled();
      }, { timeout: 2000 });

      unmount();

      await waitFor(() => {
        expect(removeEventListenerSpy).toHaveBeenCalledWith(
          'visibilitychange',
          expect.any(Function)
        );
      }, { timeout: 2000 });

      removeEventListenerSpy.mockRestore();
    });
  });

  describe('Test: Handles network errors during polling', () => {
    it('should continue polling after a network error if job is still in progress', async () => {
      const onError = jest.fn();
      const networkError = new Error('Network request failed');
      
      // First poll fails
      mockFetch.mockRejectedValueOnce(networkError);
      
      // Second poll succeeds
      const inProgressJob = createMockJobResponse({ status: 'IN_PROGRESS' });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => inProgressJob,
      });

      render(<AnalysisIndicator jobId={mockJobId} onError={onError} />);

      // Wait for initial poll error
      await waitFor(() => {
        expect(onError).toHaveBeenCalledTimes(1);
      }, { timeout: 2000 });

      // Advance timer to trigger interval poll
      act(() => {
        jest.advanceTimersByTime(2000);
      });

      // Wait for second poll (should succeed)
      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledTimes(2);
      }, { timeout: 2000 });

      // Verify onError was only called once (for the first error)
      expect(onError).toHaveBeenCalledTimes(1);
    });

    it('should handle network error followed by successful completion', async () => {
      const onComplete = jest.fn();
      const onError = jest.fn();
      const networkError = new Error('Network request failed');
      
      // First poll fails
      mockFetch.mockRejectedValueOnce(networkError);
      
      // Second poll succeeds with completion
      const completedJob = createMockJobResponse({
        status: 'COMPLETED',
        analyzedContacts: 100,
        totalContacts: 100,
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => completedJob,
      });

      render(
        <AnalysisIndicator 
          jobId={mockJobId} 
          onComplete={onComplete} 
          onError={onError} 
        />
      );

      // Wait for initial poll error
      await waitFor(() => {
        expect(onError).toHaveBeenCalledTimes(1);
      }, { timeout: 3000 });

      // Advance timer to trigger interval poll
      await act(async () => {
        jest.advanceTimersByTime(2000);
        await Promise.resolve();
      });

      // Wait for completion - both callbacks should be called
      await waitFor(() => {
        expect(onComplete).toHaveBeenCalledTimes(1);
      }, { timeout: 3000 });

      // Verify both callbacks were called correctly
      expect(onError).toHaveBeenCalledTimes(1);
      expect(onComplete).toHaveBeenCalledTimes(1);
    });

    it('should handle fetch response that is not ok', async () => {
      const onError = jest.fn();
      
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      });

      render(<AnalysisIndicator jobId={mockJobId} onError={onError} />);

      await waitFor(() => {
        expect(onError).toHaveBeenCalledTimes(1);
        expect(onError).toHaveBeenCalledWith(
          expect.objectContaining({
            message: 'Failed to fetch status',
          })
        );
      }, { timeout: 3000 });
    });
  });
});
