/**
 * Tests for AnalyzeAllButton component
 * 
 * Tests:
 * - Renders button correctly
 * - Calls API on button click
 * - Shows loading state during API call
 * - Shows success toast on success
 * - Shows error toast on error
 */

import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AnalyzeAllButton } from '../analyze-all-button';
import { toast } from 'sonner';

// Mock sonner toast
jest.mock('sonner', () => ({
  toast: {
    success: jest.fn(),
    error: jest.fn(),
    info: jest.fn(),
    warning: jest.fn(),
  },
}));

// Mock fetch globally
global.fetch = jest.fn();

const mockedFetch = global.fetch as jest.MockedFunction<typeof fetch>;
const mockedToast = toast as jest.Mocked<typeof toast>;

describe('AnalyzeAllButton', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockedFetch.mockClear();
  });

  describe('Renders button correctly', () => {
    it('should render the button with correct text', () => {
      render(<AnalyzeAllButton />);
      
      const button = screen.getByRole('button', { name: /ai analyze all/i });
      expect(button).toBeInTheDocument();
    });

    it('should render the Sparkles icon', () => {
      render(<AnalyzeAllButton />);
      
      // The icon should be present (we can check by the button content)
      const button = screen.getByRole('button', { name: /ai analyze all/i });
      expect(button).toBeInTheDocument();
      // Icon is rendered as SVG, so we check the button contains the text
      expect(button.textContent).toContain('AI Analyze All');
    });

    it('should have correct button variant', () => {
      render(<AnalyzeAllButton />);
      
      const button = screen.getByRole('button', { name: /ai analyze all/i });
      // Check that button has outline variant styles (border class indicates outline variant)
      expect(button.className).toContain('border');
    });

    it('should not be disabled initially', () => {
      render(<AnalyzeAllButton />);
      
      const button = screen.getByRole('button', { name: /ai analyze all/i });
      expect(button).not.toBeDisabled();
    });
  });

  describe('Calls API on button click', () => {
    it('should call the API endpoint when button is clicked', async () => {
      const user = userEvent.setup();
      
      mockedFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ successCount: 5 }),
      } as Response);

      render(<AnalyzeAllButton />);
      
      const button = screen.getByRole('button', { name: /ai analyze all/i });
      await user.click(button);

      await waitFor(() => {
        expect(mockedFetch).toHaveBeenCalledTimes(1);
      });

      expect(mockedFetch).toHaveBeenCalledWith(
        '/api/contacts/analyze-all',
        expect.objectContaining({
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ limit: 100, skipIfHasContext: true }),
        })
      );
    });

    it('should call API with correct request body', async () => {
      const user = userEvent.setup();
      
      mockedFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ successCount: 3 }),
      } as Response);

      render(<AnalyzeAllButton />);
      
      const button = screen.getByRole('button', { name: /ai analyze all/i });
      await user.click(button);

      await waitFor(() => {
        expect(mockedFetch).toHaveBeenCalled();
      });

      const callArgs = mockedFetch.mock.calls[0];
      expect(callArgs[0]).toBe('/api/contacts/analyze-all');
      expect(callArgs[1]?.method).toBe('POST');
      expect(callArgs[1]?.headers).toEqual({
        'Content-Type': 'application/json',
      });
      expect(callArgs[1]?.body).toBe(
        JSON.stringify({ limit: 100, skipIfHasContext: true })
      );
    });
  });

  describe('Shows loading state during API call', () => {
    it('should show loading text when API call is in progress', async () => {
      const user = userEvent.setup();
      
      // Create a promise that we can control
      let resolvePromise: (value: Response) => void;
      const promise = new Promise<Response>((resolve) => {
        resolvePromise = resolve;
      });

      mockedFetch.mockReturnValueOnce(promise as Promise<Response>);

      render(<AnalyzeAllButton />);
      
      const button = screen.getByRole('button', { name: /ai analyze all/i });
      await user.click(button);

      // Check loading state
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /analyzing.../i })).toBeInTheDocument();
      });

      expect(screen.getByRole('button', { name: /analyzing.../i })).toBeDisabled();

      // Resolve the promise
      resolvePromise!({
        ok: true,
        json: async () => ({ successCount: 5 }),
      } as Response);
    });

    it('should disable button during API call', async () => {
      const user = userEvent.setup();
      
      let resolvePromise: (value: Response) => void;
      const promise = new Promise<Response>((resolve) => {
        resolvePromise = resolve;
      });

      mockedFetch.mockReturnValueOnce(promise as Promise<Response>);

      render(<AnalyzeAllButton />);
      
      const button = screen.getByRole('button', { name: /ai analyze all/i });
      await user.click(button);

      await waitFor(() => {
        const loadingButton = screen.getByRole('button', { name: /analyzing.../i });
        expect(loadingButton).toBeDisabled();
      });

      resolvePromise!({
        ok: true,
        json: async () => ({ successCount: 5 }),
      } as Response);
    });

    it('should restore button text after API call completes', async () => {
      const user = userEvent.setup();
      
      // Use a delayed promise to ensure loading state is visible
      let resolvePromise: (value: Response) => void;
      const promise = new Promise<Response>((resolve) => {
        resolvePromise = resolve;
      });

      mockedFetch.mockReturnValueOnce(promise as Promise<Response>);

      render(<AnalyzeAllButton />);
      
      const button = screen.getByRole('button', { name: /ai analyze all/i });
      await user.click(button);

      // Wait for loading state
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /analyzing.../i })).toBeInTheDocument();
      });

      // Resolve the promise
      resolvePromise!({
        ok: true,
        json: async () => ({ successCount: 5 }),
      } as Response);

      // Wait for completion
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /ai analyze all/i })).toBeInTheDocument();
      }, { timeout: 3000 });

      expect(screen.getByRole('button', { name: /ai analyze all/i })).not.toBeDisabled();
    });
  });

  describe('Shows success toast on success', () => {
    it('should show success toast when API call succeeds', async () => {
      const user = userEvent.setup();
      
      mockedFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ successCount: 5 }),
      } as Response);

      render(<AnalyzeAllButton />);
      
      const button = screen.getByRole('button', { name: /ai analyze all/i });
      await user.click(button);

      await waitFor(() => {
        expect(mockedToast.success).toHaveBeenCalled();
      });

      expect(mockedToast.success).toHaveBeenCalledWith(
        'Analyzed 5 contacts successfully'
      );
    });

    it('should show success toast with correct count', async () => {
      const user = userEvent.setup();
      
      mockedFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ successCount: 10 }),
      } as Response);

      render(<AnalyzeAllButton />);
      
      const button = screen.getByRole('button', { name: /ai analyze all/i });
      await user.click(button);

      await waitFor(() => {
        expect(mockedToast.success).toHaveBeenCalledWith(
          'Analyzed 10 contacts successfully'
        );
      });
    });

    it('should show success toast even with zero count', async () => {
      const user = userEvent.setup();
      
      mockedFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ successCount: 0 }),
      } as Response);

      render(<AnalyzeAllButton />);
      
      const button = screen.getByRole('button', { name: /ai analyze all/i });
      await user.click(button);

      await waitFor(() => {
        expect(mockedToast.success).toHaveBeenCalledWith(
          'Analyzed 0 contacts successfully'
        );
      });
    });
  });

  describe('Shows error toast on error', () => {
    it('should show error toast when API call fails', async () => {
      const user = userEvent.setup();
      
      mockedFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: async () => ({}),
      } as Response);

      render(<AnalyzeAllButton />);
      
      const button = screen.getByRole('button', { name: /ai analyze all/i });
      await user.click(button);

      await waitFor(() => {
        expect(mockedToast.error).toHaveBeenCalled();
      });

      expect(mockedToast.error).toHaveBeenCalledWith('Failed to analyze contacts');
    });

    it('should show error toast when fetch throws an error', async () => {
      const user = userEvent.setup();
      
      mockedFetch.mockRejectedValueOnce(new Error('Network error'));

      render(<AnalyzeAllButton />);
      
      const button = screen.getByRole('button', { name: /ai analyze all/i });
      await user.click(button);

      await waitFor(() => {
        expect(mockedToast.error).toHaveBeenCalled();
      });

      expect(mockedToast.error).toHaveBeenCalledWith('Failed to analyze contacts');
    });

    it('should show error toast when API returns non-ok response', async () => {
      const user = userEvent.setup();
      
      mockedFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({ error: 'Bad request' }),
      } as Response);

      render(<AnalyzeAllButton />);
      
      const button = screen.getByRole('button', { name: /ai analyze all/i });
      await user.click(button);

      await waitFor(() => {
        expect(mockedToast.error).toHaveBeenCalledWith('Failed to analyze contacts');
      });
    });

    it('should not show success toast when error occurs', async () => {
      const user = userEvent.setup();
      
      mockedFetch.mockRejectedValueOnce(new Error('Network error'));

      render(<AnalyzeAllButton />);
      
      const button = screen.getByRole('button', { name: /ai analyze all/i });
      await user.click(button);

      await waitFor(() => {
        expect(mockedToast.error).toHaveBeenCalled();
      });

      expect(mockedToast.success).not.toHaveBeenCalled();
    });

    it('should restore button state after error', async () => {
      const user = userEvent.setup();
      
      mockedFetch.mockRejectedValueOnce(new Error('Network error'));

      render(<AnalyzeAllButton />);
      
      const button = screen.getByRole('button', { name: /ai analyze all/i });
      await user.click(button);

      // Wait for error to be handled
      await waitFor(() => {
        expect(mockedToast.error).toHaveBeenCalled();
      });

      // Button should be enabled again
      await waitFor(() => {
        const restoredButton = screen.getByRole('button', { name: /ai analyze all/i });
        expect(restoredButton).not.toBeDisabled();
      });
    });
  });
});

