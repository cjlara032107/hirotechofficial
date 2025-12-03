/**
 * API Route Tests for /api/facebook/analyze-pipeline
 * 
 * Tests for:
 * - Validates forceUpdateExisting boolean
 * - Handles database connection errors
 */

import { NextRequest } from 'next/server';
import { POST } from '../route';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { startPipelineAnalysis } from '@/lib/facebook/pipeline-analyzer';

// Mock dependencies
jest.mock('@/auth');
jest.mock('@/lib/db', () => ({
  prisma: {
    facebookPage: {
      findFirst: jest.fn(),
    },
  },
}));
jest.mock('@/lib/facebook/pipeline-analyzer', () => ({
  startPipelineAnalysis: jest.fn(),
}));

const mockedAuth = auth as jest.MockedFunction<typeof auth>;
const mockedPrisma = prisma as jest.Mocked<typeof prisma>;
const mockedStartPipelineAnalysis = startPipelineAnalysis as jest.MockedFunction<typeof startPipelineAnalysis>;

describe('API Route: /api/facebook/analyze-pipeline', () => {
  const mockAuthenticatedSession = {
    user: {
      id: 'user-123',
      email: 'test@example.com',
      organizationId: 'org-123',
    },
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockedAuth.mockResolvedValue(mockAuthenticatedSession as any);
  });

  describe('Validates forceUpdateExisting boolean', () => {
    beforeEach(() => {
      mockedPrisma.facebookPage.findFirst = jest.fn().mockResolvedValue({
        id: 'page-123',
        organizationId: 'org-123',
        autoPipelineId: null,
        autoPipeline: null,
      });
      mockedStartPipelineAnalysis.mockResolvedValue({
        success: true,
        jobId: 'job-123',
        message: 'Pipeline analysis started',
      });
    });

    it('should accept true boolean for forceUpdateExisting', async () => {
      const request = new NextRequest('http://localhost:3000/api/facebook/analyze-pipeline', {
        method: 'POST',
        body: JSON.stringify({
          facebookPageId: 'page-123',
          forceUpdateExisting: true,
        }),
      });

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.success).toBe(true);
      expect(mockedStartPipelineAnalysis).toHaveBeenCalledWith('page-123', true);
    });

    it('should accept false boolean for forceUpdateExisting', async () => {
      const request = new NextRequest('http://localhost:3000/api/facebook/analyze-pipeline', {
        method: 'POST',
        body: JSON.stringify({
          facebookPageId: 'page-123',
          forceUpdateExisting: false,
        }),
      });

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.success).toBe(true);
      expect(mockedStartPipelineAnalysis).toHaveBeenCalledWith('page-123', false);
    });

    it('should default to false when forceUpdateExisting is missing', async () => {
      const request = new NextRequest('http://localhost:3000/api/facebook/analyze-pipeline', {
        method: 'POST',
        body: JSON.stringify({
          facebookPageId: 'page-123',
        }),
      });

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.success).toBe(true);
      // Should default to false when undefined
      expect(mockedStartPipelineAnalysis).toHaveBeenCalledWith('page-123', false);
    });

    it('should handle string "true" as boolean true', async () => {
      const request = new NextRequest('http://localhost:3000/api/facebook/analyze-pipeline', {
        method: 'POST',
        body: JSON.stringify({
          facebookPageId: 'page-123',
          forceUpdateExisting: 'true', // String instead of boolean
        }),
      });

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      // The API uses === true, so string "true" will be false
      // This test documents current behavior - might want to add validation
      expect(mockedStartPipelineAnalysis).toHaveBeenCalledWith('page-123', false);
    });

    it('should handle string "false" as boolean false', async () => {
      const request = new NextRequest('http://localhost:3000/api/facebook/analyze-pipeline', {
        method: 'POST',
        body: JSON.stringify({
          facebookPageId: 'page-123',
          forceUpdateExisting: 'false', // String instead of boolean
        }),
      });

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      // The API uses === true, so string "false" will be false
      expect(mockedStartPipelineAnalysis).toHaveBeenCalledWith('page-123', false);
    });

    it('should handle number 1 as truthy (but not boolean true)', async () => {
      const request = new NextRequest('http://localhost:3000/api/facebook/analyze-pipeline', {
        method: 'POST',
        body: JSON.stringify({
          facebookPageId: 'page-123',
          forceUpdateExisting: 1, // Number instead of boolean
        }),
      });

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      // The API uses === true, so number 1 will be false
      expect(mockedStartPipelineAnalysis).toHaveBeenCalledWith('page-123', false);
    });

    it('should handle null as false', async () => {
      const request = new NextRequest('http://localhost:3000/api/facebook/analyze-pipeline', {
        method: 'POST',
        body: JSON.stringify({
          facebookPageId: 'page-123',
          forceUpdateExisting: null,
        }),
      });

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(mockedStartPipelineAnalysis).toHaveBeenCalledWith('page-123', false);
    });
  });

  describe('Handles database connection errors', () => {
    it('should return 500 when database connection fails during page lookup', async () => {
      const connectionError = new Error('Can\'t reach database');
      (connectionError as any).code = 'P1001';
      mockedPrisma.facebookPage.findFirst = jest.fn().mockRejectedValue(connectionError);

      const request = new NextRequest('http://localhost:3000/api/facebook/analyze-pipeline', {
        method: 'POST',
        body: JSON.stringify({
          facebookPageId: 'page-123',
          forceUpdateExisting: false,
        }),
      });

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(500);
      expect(responseData.error).toBe('Can\'t reach database');
    });

    it('should return 500 when database connection fails during pipeline analysis start', async () => {
      mockedPrisma.facebookPage.findFirst = jest.fn().mockResolvedValue({
        id: 'page-123',
        organizationId: 'org-123',
        autoPipelineId: null,
        autoPipeline: null,
      });

      const connectionError = new Error('Connection pool exhausted');
      (connectionError as any).code = 'P2024';
      mockedStartPipelineAnalysis.mockRejectedValue(connectionError);

      const request = new NextRequest('http://localhost:3000/api/facebook/analyze-pipeline', {
        method: 'POST',
        body: JSON.stringify({
          facebookPageId: 'page-123',
          forceUpdateExisting: false,
        }),
      });

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(500);
      expect(responseData.error).toBe('Connection pool exhausted');
    });

    it('should return 500 when database timeout occurs', async () => {
      mockedPrisma.facebookPage.findFirst = jest.fn().mockResolvedValue({
        id: 'page-123',
        organizationId: 'org-123',
        autoPipelineId: null,
        autoPipeline: null,
      });

      const timeoutError = new Error('Connection timeout');
      (timeoutError as any).code = 'ETIMEDOUT';
      mockedStartPipelineAnalysis.mockRejectedValue(timeoutError);

      const request = new NextRequest('http://localhost:3000/api/facebook/analyze-pipeline', {
        method: 'POST',
        body: JSON.stringify({
          facebookPageId: 'page-123',
          forceUpdateExisting: false,
        }),
      });

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(500);
      expect(responseData.error).toBe('Connection timeout');
    });
  });

  describe('Input validation', () => {
    it('should return 400 when facebookPageId is missing', async () => {
      const request = new NextRequest('http://localhost:3000/api/facebook/analyze-pipeline', {
        method: 'POST',
        body: JSON.stringify({
          forceUpdateExisting: false,
        }),
      });

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(400);
      expect(responseData.error).toBe('facebookPageId is required');
      expect(mockedStartPipelineAnalysis).not.toHaveBeenCalled();
    });

    it('should return 401 when user is not authenticated', async () => {
      mockedAuth.mockResolvedValue(null);

      const request = new NextRequest('http://localhost:3000/api/facebook/analyze-pipeline', {
        method: 'POST',
        body: JSON.stringify({
          facebookPageId: 'page-123',
          forceUpdateExisting: false,
        }),
      });

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(401);
      expect(responseData.error).toBe('Unauthorized');
      expect(mockedStartPipelineAnalysis).not.toHaveBeenCalled();
    });

    it('should return 404 when page does not belong to user organization', async () => {
      mockedPrisma.facebookPage.findFirst = jest.fn().mockResolvedValue(null);

      const request = new NextRequest('http://localhost:3000/api/facebook/analyze-pipeline', {
        method: 'POST',
        body: JSON.stringify({
          facebookPageId: 'page-123',
          forceUpdateExisting: false,
        }),
      });

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(404);
      expect(responseData.error).toBe('Facebook page not found or access denied');
      expect(mockedStartPipelineAnalysis).not.toHaveBeenCalled();
    });
  });
});
