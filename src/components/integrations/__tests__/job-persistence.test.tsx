/**
 * Tests for Job Status Persistence After Page Refresh
 * 
 * Test cases:
 * 1. Job status is recovered from database after page refresh
 * 2. Polling resumes automatically for IN_PROGRESS jobs
 * 3. Polling resumes automatically for PENDING jobs
 * 4. Completed jobs are not resumed after refresh
 * 5. Failed jobs are not resumed after refresh
 * 6. Multiple jobs can be recovered simultaneously
 */

import { render, screen, waitFor } from '@testing-library/react';
import { ConnectedPagesList } from '../connected-pages-list';

// Mock fetch
global.fetch = jest.fn();

// Mock next/navigation
jest.mock('next/navigation', () => ({
  useRouter: () => ({
    push: jest.fn(),
    refresh: jest.fn(),
  }),
}));

// Mock sonner toast
jest.mock('sonner', () => ({
  toast: {
    success: jest.fn(),
    error: jest.fn(),
    info: jest.fn(),
  },
}));

describe('Job Status Persistence After Page Refresh', () => {
  const mockPageId = 'test-page-id';
  const mockJobId = 'test-job-id';
  const mockOrganizationId = 'test-org-id';

  const mockPage = {
    id: mockPageId,
    pageId: 'fb-page-id',
    pageName: 'Test Page',
    instagramAccountId: null,
    instagramUsername: null,
    isActive: true,
    lastSyncedAt: null,
    autoSync: true,
    autoPipelineId: null,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    (global.fetch as jest.Mock).mockClear();
  });

  describe('Test: Job status is recovered from database after page refresh', () => {
    it('should recover IN_PROGRESS job status after page refresh', async () => {
      // Mock initial page fetch
      (global.fetch as jest.Mock).mockImplementation((url: string) => {
        if (url.includes('/api/facebook/pages/connected')) {
          return Promise.resolve({
            ok: true,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({ pages: [mockPage] }),
          });
        }
        if (url.includes('/latest-sync')) {
          // Simulate finding an IN_PROGRESS job after refresh
          return Promise.resolve({
            ok: true,
            json: async () => ({
              job: {
                id: mockJobId,
                status: 'IN_PROGRESS',
                syncedContacts: 50,
                failedContacts: 2,
                totalContacts: 100,
                tokenExpired: false,
                startedAt: new Date().toISOString(),
                completedAt: null,
                createdAt: new Date().toISOString(),
              },
            }),
          });
        }
        if (url.includes('/sync-status')) {
          // Mock polling response
          return Promise.resolve({
            ok: true,
            json: async () => ({
              id: mockJobId,
              status: 'IN_PROGRESS',
              syncedContacts: 60,
              failedContacts: 2,
              totalContacts: 100,
              tokenExpired: false,
              startedAt: new Date().toISOString(),
              completedAt: null,
            }),
          });
        }
        if (url.includes('/contacts-count')) {
          // Mock contact count response
          return Promise.resolve({
            ok: true,
            json: async () => ({ count: 100 }),
          });
        }
        return Promise.reject(new Error('Unexpected URL'));
      });

      render(<ConnectedPagesList />);

      // Wait for initial fetch
      await waitFor(() => {
        expect(global.fetch).toHaveBeenCalledWith(
          expect.stringContaining('/api/facebook/pages/connected')
        );
      });

      // Wait for latest sync job check
      await waitFor(() => {
        expect(global.fetch).toHaveBeenCalledWith(
          expect.stringContaining('/latest-sync')
        );
      }, { timeout: 3000 });

      // Verify that polling was started for the recovered job
      await waitFor(() => {
        expect(global.fetch).toHaveBeenCalledWith(
          expect.stringContaining(`/sync-status/${mockJobId}`)
        );
      }, { timeout: 5000 });
    });

    it('should recover PENDING job status after page refresh', async () => {
      (global.fetch as jest.Mock).mockImplementation((url: string) => {
        if (url.includes('/api/facebook/pages/connected')) {
          return Promise.resolve({
            ok: true,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({ pages: [mockPage] }),
          });
        }
        if (url.includes('/latest-sync')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({
              job: {
                id: mockJobId,
                status: 'PENDING',
                syncedContacts: 0,
                failedContacts: 0,
                totalContacts: 100,
                tokenExpired: false,
                startedAt: null,
                completedAt: null,
                createdAt: new Date().toISOString(),
              },
            }),
          });
        }
        if (url.includes('/sync-status')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({
              id: mockJobId,
              status: 'PENDING',
              syncedContacts: 0,
              failedContacts: 0,
              totalContacts: 100,
              tokenExpired: false,
              startedAt: null,
              completedAt: null,
            }),
          });
        }
        if (url.includes('/contacts-count')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({ count: 0 }),
          });
        }
        return Promise.reject(new Error('Unexpected URL'));
      });

      render(<ConnectedPagesList />);

      await waitFor(() => {
        expect(global.fetch).toHaveBeenCalledWith(
          expect.stringContaining('/latest-sync')
        );
      }, { timeout: 3000 });

      // Verify polling was started for PENDING job
      await waitFor(() => {
        expect(global.fetch).toHaveBeenCalledWith(
          expect.stringContaining(`/sync-status/${mockJobId}`)
        );
      }, { timeout: 5000 });
    });
  });

  describe('Test: Completed jobs are not resumed after refresh', () => {
    it('should not resume polling for COMPLETED jobs', async () => {
      (global.fetch as jest.Mock).mockImplementation((url: string) => {
        if (url.includes('/api/facebook/pages/connected')) {
          return Promise.resolve({
            ok: true,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({ pages: [mockPage] }),
          });
        }
        if (url.includes('/latest-sync')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({
              job: {
                id: mockJobId,
                status: 'COMPLETED',
                syncedContacts: 100,
                failedContacts: 0,
                totalContacts: 100,
                tokenExpired: false,
                startedAt: new Date().toISOString(),
                completedAt: new Date().toISOString(),
                createdAt: new Date().toISOString(),
              },
            }),
          });
        }
        if (url.includes('/contacts-count')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({ count: 100 }),
          });
        }
        return Promise.reject(new Error('Unexpected URL'));
      });

      render(<ConnectedPagesList />);

      await waitFor(() => {
        expect(global.fetch).toHaveBeenCalledWith(
          expect.stringContaining('/latest-sync')
        );
      }, { timeout: 3000 });

      // Wait a bit to ensure polling doesn't start
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Verify that sync-status endpoint was NOT called (no polling)
      const syncStatusCalls = (global.fetch as jest.Mock).mock.calls.filter((call: any[]) =>
        call[0]?.includes('/sync-status')
      );
      expect(syncStatusCalls.length).toBe(0);
    });
  });

  describe('Test: Failed jobs are not resumed after refresh', () => {
    it('should not resume polling for FAILED jobs', async () => {
      (global.fetch as jest.Mock).mockImplementation((url: string) => {
        if (url.includes('/api/facebook/pages/connected')) {
          return Promise.resolve({
            ok: true,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({ pages: [mockPage] }),
          });
        }
        if (url.includes('/latest-sync')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({
              job: {
                id: mockJobId,
                status: 'FAILED',
                syncedContacts: 30,
                failedContacts: 70,
                totalContacts: 100,
                tokenExpired: false,
                startedAt: new Date().toISOString(),
                completedAt: new Date().toISOString(),
                createdAt: new Date().toISOString(),
              },
            }),
          });
        }
        if (url.includes('/contacts-count')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({ count: 30 }),
          });
        }
        return Promise.reject(new Error('Unexpected URL'));
      });

      render(<ConnectedPagesList />);

      await waitFor(() => {
        expect(global.fetch).toHaveBeenCalledWith(
          expect.stringContaining('/latest-sync')
        );
      }, { timeout: 3000 });

      // Wait to ensure polling doesn't start
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Verify that sync-status endpoint was NOT called
      const syncStatusCalls = (global.fetch as jest.Mock).mock.calls.filter((call: any[]) =>
        call[0]?.includes('/sync-status')
      );
      expect(syncStatusCalls.length).toBe(0);
    });
  });

  describe('Test: Multiple jobs can be recovered simultaneously', () => {
    it('should recover multiple IN_PROGRESS jobs from different pages', async () => {
      const mockPage1 = { ...mockPage, id: 'page-1', pageName: 'Page 1' };
      const mockPage2 = { ...mockPage, id: 'page-2', pageName: 'Page 2' };
      const jobId1 = 'job-1';
      const jobId2 = 'job-2';

      (global.fetch as jest.Mock).mockImplementation((url: string) => {
        if (url.includes('/api/facebook/pages/connected')) {
          return Promise.resolve({
            ok: true,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({ pages: [mockPage1, mockPage2] }),
          });
        }
        if (url.includes('/latest-sync')) {
          const pageId = url.includes('page-1') ? 'page-1' : 'page-2';
          const jobId = pageId === 'page-1' ? jobId1 : jobId2;
          return Promise.resolve({
            ok: true,
            json: async () => ({
              job: {
                id: jobId,
                status: 'IN_PROGRESS',
                syncedContacts: 50,
                failedContacts: 2,
                totalContacts: 100,
                tokenExpired: false,
                startedAt: new Date().toISOString(),
                completedAt: null,
                createdAt: new Date().toISOString(),
              },
            }),
          });
        }
        if (url.includes('/sync-status')) {
          const jobId = url.includes(jobId1) ? jobId1 : jobId2;
          return Promise.resolve({
            ok: true,
            json: async () => ({
              id: jobId,
              status: 'IN_PROGRESS',
              syncedContacts: 60,
              failedContacts: 2,
              totalContacts: 100,
              tokenExpired: false,
              startedAt: new Date().toISOString(),
              completedAt: null,
            }),
          });
        }
        if (url.includes('/contacts-count')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({ count: 50 }),
          });
        }
        return Promise.reject(new Error('Unexpected URL'));
      });

      render(<ConnectedPagesList />);

      await waitFor(() => {
        const latestSyncCalls = (global.fetch as jest.Mock).mock.calls.filter((call: any[]) =>
          call[0]?.includes('/latest-sync')
        );
        expect(latestSyncCalls.length).toBeGreaterThanOrEqual(2);
      }, { timeout: 3000 });

      // Verify both jobs are being polled
      await waitFor(() => {
        const syncStatusCalls = (global.fetch as jest.Mock).mock.calls.filter((call: any[]) =>
          call[0]?.includes('/sync-status')
        );
        expect(syncStatusCalls.length).toBeGreaterThanOrEqual(2);
      }, { timeout: 5000 });
    });
  });

  describe('Test: Job recovery handles errors gracefully', () => {
    it('should handle network errors when checking latest sync job', async () => {
      (global.fetch as jest.Mock).mockImplementation((url: string) => {
        if (url.includes('/api/facebook/pages/connected')) {
          return Promise.resolve({
            ok: true,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({ pages: [mockPage] }),
          });
        }
        if (url.includes('/latest-sync')) {
          return Promise.reject(new Error('Network error'));
        }
        if (url.includes('/contacts-count')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({ count: 0 }),
          });
        }
        return Promise.reject(new Error('Unexpected URL'));
      });

      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      render(<ConnectedPagesList />);

      await waitFor(() => {
        expect(global.fetch).toHaveBeenCalledWith(
          expect.stringContaining('/latest-sync')
        );
      }, { timeout: 3000 });

      // Verify error was logged but didn't crash the component
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Error checking latest sync job'),
        expect.anything()
      );

      consoleSpy.mockRestore();
    });

    it('should handle null job response gracefully', async () => {
      (global.fetch as jest.Mock).mockImplementation((url: string) => {
        if (url.includes('/api/facebook/pages/connected')) {
          return Promise.resolve({
            ok: true,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({ pages: [mockPage] }),
          });
        }
        if (url.includes('/latest-sync')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({ job: null }),
          });
        }
        if (url.includes('/contacts-count')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({ count: 0 }),
          });
        }
        return Promise.reject(new Error('Unexpected URL'));
      });

      render(<ConnectedPagesList />);

      await waitFor(() => {
        expect(global.fetch).toHaveBeenCalledWith(
          expect.stringContaining('/latest-sync')
        );
      }, { timeout: 3000 });

      // Verify no polling started when job is null
      await new Promise(resolve => setTimeout(resolve, 2000));

      const syncStatusCalls = (global.fetch as jest.Mock).mock.calls.filter((call: any[]) =>
        call[0]?.includes('/sync-status')
      );
      expect(syncStatusCalls.length).toBe(0);
    });
  });
});

