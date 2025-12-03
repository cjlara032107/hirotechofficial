/**
 * Tests for Enhanced Analysis with Fallback
 * 
 * Tests verify:
 * - usedFallback flag is included in result
 * - retryCount is included in result
 * - Analysis attempts are logged appropriately
 */

// Mock dependencies BEFORE imports to prevent OpenAI module loading issues
jest.mock('../google-ai-service', () => ({
  analyzeConversation: jest.fn(),
  analyzeConversationWithStageRecommendation: jest.fn(),
}));

jest.mock('../fallback-scoring', () => ({
  calculateFallbackScore: jest.fn(),
}));

import { analyzeWithFallback, batchAnalyzeWithFallback } from '../enhanced-analysis';
import * as googleAIService from '../google-ai-service';
import * as fallbackScoring from '../fallback-scoring';

const mockedGoogleAI = googleAIService as jest.Mocked<typeof googleAIService>;
const mockedFallback = fallbackScoring as jest.Mocked<typeof fallbackScoring>;

describe('analyzeWithFallback', () => {
  const mockMessages = [
    { from: 'user', text: 'Hello', timestamp: new Date() },
    { from: 'contact', text: 'Hi there!', timestamp: new Date() },
  ];

  const mockPipelineStages = [
    { name: 'New Lead', type: 'lead', leadScoreMin: 0, leadScoreMax: 30 },
    { name: 'Qualified', type: 'lead', leadScoreMin: 31, leadScoreMax: 70 },
    { name: 'Hot Lead', type: 'lead', leadScoreMin: 71, leadScoreMax: 100 },
  ];

  const mockFallbackScore = {
    leadScore: 25,
    leadStatus: 'NEW',
    reasoning: 'Test fallback reasoning',
    confidence: 50,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    // Suppress console logs during tests
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    
    // Default mock for fallback scoring
    mockedFallback.calculateFallbackScore.mockReturnValue(mockFallbackScore);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Test: Includes usedFallback flag in result', () => {
    it('should include usedFallback: false when AI analysis succeeds', async () => {
      const mockAnalysis = {
        summary: 'Test summary',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedGoogleAI.analyzeConversationWithStageRecommendation.mockResolvedValue(mockAnalysis);

      const result = await analyzeWithFallback(mockMessages, mockPipelineStages);

      expect(result).toHaveProperty('usedFallback');
      expect(result.usedFallback).toBe(false);
      expect(result.analysis).toEqual(mockAnalysis);
    });

    it('should include usedFallback: true when AI analysis fails and fallback is used', async () => {
      mockedGoogleAI.analyzeConversationWithStageRecommendation.mockResolvedValue(null);

      const result = await analyzeWithFallback(mockMessages, mockPipelineStages);

      expect(result).toHaveProperty('usedFallback');
      expect(result.usedFallback).toBe(true);
      expect(result.analysis.leadScore).toBe(mockFallbackScore.leadScore);
    });

    it('should include usedFallback: true when all retries are exhausted', async () => {
      mockedGoogleAI.analyzeConversationWithStageRecommendation
        .mockRejectedValueOnce(new Error('Error 1'))
        .mockRejectedValueOnce(new Error('Error 2'))
        .mockRejectedValueOnce(new Error('Error 3'));

      const result = await analyzeWithFallback(mockMessages, mockPipelineStages, undefined, 3);

      expect(result).toHaveProperty('usedFallback');
      expect(result.usedFallback).toBe(true);
    });

    it('should include usedFallback: true when summary-only analysis succeeds but uses fallback scoring', async () => {
      mockedGoogleAI.analyzeConversationWithStageRecommendation.mockResolvedValue(null);
      mockedGoogleAI.analyzeConversation.mockResolvedValue('Test summary');

      const result = await analyzeWithFallback(mockMessages, []); // No pipeline stages

      expect(result).toHaveProperty('usedFallback');
      expect(result.usedFallback).toBe(true);
      expect(result.analysis.summary).toBe('Test summary');
    });

    it('should include usedFallback flag in batchAnalyzeWithFallback results', async () => {
      const mockAnalysis = {
        summary: 'Test summary',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedGoogleAI.analyzeConversationWithStageRecommendation.mockResolvedValue(mockAnalysis);

      const contacts = [
        { contactId: 'contact-1', messages: mockMessages },
        { contactId: 'contact-2', messages: mockMessages },
      ];

      const results = await batchAnalyzeWithFallback(contacts, mockPipelineStages);

      results.forEach((result) => {
        expect(result).toHaveProperty('usedFallback');
      });
    });
  });

  describe('Test: Includes retryCount in result', () => {
    it('should include retryCount: 0 when AI analysis succeeds on first attempt', async () => {
      const mockAnalysis = {
        summary: 'Test summary',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedGoogleAI.analyzeConversationWithStageRecommendation.mockResolvedValue(mockAnalysis);

      const result = await analyzeWithFallback(mockMessages, mockPipelineStages);

      expect(result).toHaveProperty('retryCount');
      expect(result.retryCount).toBe(0);
    });

    it('should include retryCount: 1 when AI analysis succeeds on second attempt', async () => {
      const mockAnalysis = {
        summary: 'Test summary',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedGoogleAI.analyzeConversationWithStageRecommendation
        .mockRejectedValueOnce(new Error('First attempt failed'))
        .mockResolvedValueOnce(mockAnalysis);

      const result = await analyzeWithFallback(mockMessages, mockPipelineStages, undefined, 3);

      expect(result).toHaveProperty('retryCount');
      expect(result.retryCount).toBe(1);
      expect(result.usedFallback).toBe(false);
    });

    it('should include retryCount: 2 when AI analysis succeeds on third attempt', async () => {
      const mockAnalysis = {
        summary: 'Test summary',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedGoogleAI.analyzeConversationWithStageRecommendation
        .mockRejectedValueOnce(new Error('First attempt failed'))
        .mockRejectedValueOnce(new Error('Second attempt failed'))
        .mockResolvedValueOnce(mockAnalysis);

      const result = await analyzeWithFallback(mockMessages, mockPipelineStages, undefined, 3);

      expect(result).toHaveProperty('retryCount');
      expect(result.retryCount).toBe(2);
      expect(result.usedFallback).toBe(false);
    });

    it('should include retryCount equal to maxRetries when all attempts fail', async () => {
      mockedGoogleAI.analyzeConversationWithStageRecommendation
        .mockRejectedValue(new Error('All attempts failed'));

      const maxRetries = 3;
      const result = await analyzeWithFallback(mockMessages, mockPipelineStages, undefined, maxRetries);

      expect(result).toHaveProperty('retryCount');
      expect(result.retryCount).toBe(maxRetries);
      expect(result.usedFallback).toBe(true);
    });

    it('should include retryCount in batchAnalyzeWithFallback results', async () => {
      const mockAnalysis = {
        summary: 'Test summary',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedGoogleAI.analyzeConversationWithStageRecommendation.mockResolvedValue(mockAnalysis);

      const contacts = [
        { contactId: 'contact-1', messages: mockMessages },
      ];

      const results = await batchAnalyzeWithFallback(contacts, mockPipelineStages);

      results.forEach((result) => {
        expect(result).toHaveProperty('retryCount');
        expect(typeof result.retryCount).toBe('number');
        expect(result.retryCount).toBeGreaterThanOrEqual(0);
      });
    });

    it('should include retryCount in batchAnalyzeWithFallback when error occurs', async () => {
      mockedGoogleAI.analyzeConversationWithStageRecommendation.mockRejectedValue(new Error('Test error'));

      const contacts = [
        { contactId: 'contact-1', messages: mockMessages },
      ];

      const results = await batchAnalyzeWithFallback(contacts, mockPipelineStages);

      const result = results.get('contact-1');
      expect(result).toBeDefined();
      // When error occurs, analyzeWithFallback is called with maxRetries=2, so retryCount will be 2
      expect(result?.retryCount).toBeGreaterThanOrEqual(0);
      expect(result?.usedFallback).toBe(true);
    });
  });

  describe('Test: Logs analysis attempts appropriately', () => {
    it('should log success message when AI analysis succeeds', async () => {
      const mockAnalysis = {
        summary: 'Test summary',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedGoogleAI.analyzeConversationWithStageRecommendation.mockResolvedValue(mockAnalysis);

      await analyzeWithFallback(mockMessages, mockPipelineStages);

      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('[Enhanced Analysis] AI success on attempt')
      );
    });

    it('should log warning when an attempt fails', async () => {
      const mockAnalysis = {
        summary: 'Test summary',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedGoogleAI.analyzeConversationWithStageRecommendation
        .mockRejectedValueOnce(new Error('First attempt failed'))
        .mockResolvedValueOnce(mockAnalysis);

      await analyzeWithFallback(mockMessages, mockPipelineStages, undefined, 3);

      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('[Enhanced Analysis] Attempt'),
        expect.any(String)
      );
    });

    it('should log retry message when retrying after failure', async () => {
      const mockAnalysis = {
        summary: 'Test summary',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedGoogleAI.analyzeConversationWithStageRecommendation
        .mockRejectedValueOnce(new Error('First attempt failed'))
        .mockResolvedValueOnce(mockAnalysis);

      await analyzeWithFallback(mockMessages, mockPipelineStages, undefined, 3);

      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('[Enhanced Analysis] Retrying in')
      );
    });

    it('should log fallback message when all attempts fail', async () => {
      mockedGoogleAI.analyzeConversationWithStageRecommendation
        .mockRejectedValue(new Error('All attempts failed'));

      await analyzeWithFallback(mockMessages, mockPipelineStages, undefined, 3);

      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('[Enhanced Analysis] All AI attempts failed, using fallback scoring')
      );
    });

    it('should log last error when all attempts fail', async () => {
      const errorMessage = 'All attempts failed';
      mockedGoogleAI.analyzeConversationWithStageRecommendation
        .mockRejectedValue(new Error(errorMessage));

      await analyzeWithFallback(mockMessages, mockPipelineStages, undefined, 3);

      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('[Enhanced Analysis] Last error:'),
        errorMessage
      );
    });

    it('should log summary success message when summary-only analysis succeeds', async () => {
      mockedGoogleAI.analyzeConversationWithStageRecommendation.mockResolvedValue(null);
      mockedGoogleAI.analyzeConversation.mockResolvedValue('Test summary');

      await analyzeWithFallback(mockMessages, []); // No pipeline stages

      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('[Enhanced Analysis] Summary success on attempt')
      );
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('using fallback scoring')
      );
    });

    it('should log batch analysis start and completion', async () => {
      const mockAnalysis = {
        summary: 'Test summary',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedGoogleAI.analyzeConversationWithStageRecommendation.mockResolvedValue(mockAnalysis);

      const contacts = [
        { contactId: 'contact-1', messages: mockMessages },
      ];

      await batchAnalyzeWithFallback(contacts, mockPipelineStages);

      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('[Batch Analysis] Processing')
      );
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('[Batch Analysis] Complete:')
      );
    });

    it('should log fallback usage in batch analysis', async () => {
      mockedGoogleAI.analyzeConversationWithStageRecommendation.mockResolvedValue(null);

      const contacts = [
        { contactId: 'contact-1', messages: mockMessages },
      ];

      await batchAnalyzeWithFallback(contacts, mockPipelineStages);

      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('[Batch Analysis] Contact contact-1: Used fallback')
      );
    });

    it('should log AI success in batch analysis', async () => {
      const mockAnalysis = {
        summary: 'Test summary',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedGoogleAI.analyzeConversationWithStageRecommendation.mockResolvedValue(mockAnalysis);

      const contacts = [
        { contactId: 'contact-1', messages: mockMessages },
      ];

      await batchAnalyzeWithFallback(contacts, mockPipelineStages);

      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('[Batch Analysis] Contact contact-1: AI success')
      );
    });

    it('should handle errors gracefully in batch analysis', async () => {
      // When analyzeWithFallback encounters errors, it handles them internally
      // and returns a fallback result. The catch block in batchAnalyzeWithFallback
      // is a safety net for unexpected errors.
      // 
      // For this test, we verify that even when AI analysis fails,
      // the function returns a valid result with usedFallback: true
      mockedGoogleAI.analyzeConversationWithStageRecommendation.mockRejectedValue(new Error('Test error'));

      const contacts = [
        { contactId: 'contact-1', messages: mockMessages },
      ];

      const results = await batchAnalyzeWithFallback(contacts, mockPipelineStages);

      // Should return a result even when errors occur
      const result = results.get('contact-1');
      expect(result).toBeDefined();
      expect(result?.usedFallback).toBe(true);
      expect(result?.analysis).toBeDefined();
      expect(result?.analysis.leadScore).toBeGreaterThan(0);
    });
  });
});

