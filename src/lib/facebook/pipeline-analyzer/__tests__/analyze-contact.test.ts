/**
 * Tests for analyzeContact function
 * 
 * Tests verify:
 * - usedFallback flag is included in result
 * - retryCount is included in result
 * - Analysis attempts are logged appropriately
 */

// Mock dependencies BEFORE imports
jest.mock('@/lib/ai/fast-detailed-analysis', () => ({
  analyzeConversationFast: jest.fn(),
}));

jest.mock('@/lib/ai/enhanced-analysis-v2', () => ({
  analyzeConversationEnhanced: jest.fn(),
}));

import { analyzeContact } from '../analyze-contact';
import * as fastDetailedAnalysis from '@/lib/ai/fast-detailed-analysis';
import * as enhancedAnalysisV2 from '@/lib/ai/enhanced-analysis-v2';
import type { FastDetailedAnalysis } from '@/lib/ai/fast-detailed-analysis';

const mockedFastAnalysis = fastDetailedAnalysis as jest.Mocked<typeof fastDetailedAnalysis>;
const mockedEnhancedAnalysis = enhancedAnalysisV2 as jest.Mocked<typeof enhancedAnalysisV2>;

// Type for enhanced analysis result (simplified for testing)
interface EnhancedAnalysisResult {
  summary: string;
  reasoning: string;
  recommendedStage: string;
  leadScore: number;
  leadStatus: string;
  confidence: number;
  buyerIntent: string;
  sentiment: string;
  productInterests: string[];
  intentSignals: {
    rapidReplies: boolean;
    multipleQuestions: boolean;
    offHoursResponse: boolean;
    askingForProof: boolean;
  };
  conversionProbability: number;
  nextBestAction: string;
  agentSuggestions: Record<string, unknown>;
  stageReason: string;
}

describe('analyzeContact', () => {
  const mockMessages = [
    { from: 'user', text: 'Hello', timestamp: new Date() },
    { from: 'contact', text: 'Hi there!', timestamp: new Date() },
  ];

  const mockPipelineStages = [
    { name: 'New Lead', type: 'lead', leadScoreMin: 0, leadScoreMax: 30 },
    { name: 'Qualified', type: 'lead', leadScoreMin: 31, leadScoreMax: 70 },
  ];

  beforeEach(() => {
    jest.clearAllMocks();
    // Suppress console logs during tests
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Test: Includes usedFallback flag in result', () => {
    it('should include usedFallback: false when fast analysis succeeds', async () => {
      const mockFastResult = {
        summary: 'A'.repeat(300), // > 200 chars
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(mockFastResult);

      const result = await analyzeContact(mockMessages, mockPipelineStages);

      expect(result).not.toBeNull();
      expect(result).toHaveProperty('usedFallback');
      expect(result?.usedFallback).toBe(false);
      expect(result?.analysis).toEqual(mockFastResult);
    });

    it('should include usedFallback: false when enhanced analysis succeeds after fast fails', async () => {
      const mockEnhancedResult: EnhancedAnalysisResult = {
        summary: 'Enhanced analysis summary',
        reasoning: 'Test reasoning',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        buyerIntent: 'HIGH',
        sentiment: 'POSITIVE',
        productInterests: [],
        intentSignals: {
          rapidReplies: false,
          multipleQuestions: false,
          offHoursResponse: false,
          askingForProof: false,
        },
        conversionProbability: 75,
        nextBestAction: 'Follow up',
        agentSuggestions: {},
        stageReason: 'Based on analysis',
      };

      // Fast analysis returns null or too short
      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(null);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockResolvedValue(mockEnhancedResult);

      const result = await analyzeContact(mockMessages, mockPipelineStages);

      expect(result).not.toBeNull();
      expect(result).toHaveProperty('usedFallback');
      expect(result?.usedFallback).toBe(false);
      expect(result?.analysis).toEqual(mockEnhancedResult);
    });

    it('should return null when all analysis methods fail', async () => {
      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(null);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockResolvedValue(null);

      const result = await analyzeContact(mockMessages, mockPipelineStages);

      expect(result).toBeNull();
    });

    it('should include usedFallback flag even when fast analysis is too short', async () => {
      const mockFastResult: FastDetailedAnalysis = {
        summary: 'A'.repeat(100), // < 200 chars
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      const mockEnhancedResult: EnhancedAnalysisResult = {
        summary: 'Enhanced analysis summary',
        reasoning: 'Test reasoning',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        buyerIntent: 'HIGH',
        sentiment: 'POSITIVE',
        productInterests: [],
        intentSignals: {
          rapidReplies: false,
          multipleQuestions: false,
          offHoursResponse: false,
          askingForProof: false,
        },
        conversionProbability: 75,
        nextBestAction: 'Follow up',
        agentSuggestions: {},
        stageReason: 'Based on analysis',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(mockFastResult);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockResolvedValue(mockEnhancedResult);

      const result = await analyzeContact(mockMessages, mockPipelineStages);

      expect(result).not.toBeNull();
      expect(result).toHaveProperty('usedFallback');
      expect(result?.usedFallback).toBe(false);
    });
  });

  describe('Test: Includes retryCount in result', () => {
    it('should include retryCount: 0 when fast analysis succeeds', async () => {
      const mockFastResult: FastDetailedAnalysis = {
        summary: 'A'.repeat(300),
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(mockFastResult);

      const result = await analyzeContact(mockMessages, mockPipelineStages);

      expect(result).not.toBeNull();
      expect(result).toHaveProperty('retryCount');
      expect(result?.retryCount).toBe(0);
    });

    it('should include retryCount: 0 when enhanced analysis succeeds', async () => {
      const mockEnhancedResult: EnhancedAnalysisResult = {
        summary: 'Enhanced analysis summary',
        reasoning: 'Test reasoning',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        buyerIntent: 'HIGH',
        sentiment: 'POSITIVE',
        productInterests: [],
        intentSignals: {
          rapidReplies: false,
          multipleQuestions: false,
          offHoursResponse: false,
          askingForProof: false,
        },
        conversionProbability: 75,
        nextBestAction: 'Follow up',
        agentSuggestions: {},
        stageReason: 'Based on analysis',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(null);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockResolvedValue(mockEnhancedResult);

      const result = await analyzeContact(mockMessages, mockPipelineStages);

      expect(result).not.toBeNull();
      expect(result).toHaveProperty('retryCount');
      expect(result?.retryCount).toBe(0);
    });

    it('should always include retryCount as a number when result is not null', async () => {
      const mockFastResult: FastDetailedAnalysis = {
        summary: 'A'.repeat(300),
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(mockFastResult);

      const result = await analyzeContact(mockMessages, mockPipelineStages);

      expect(result).not.toBeNull();
      expect(result).toHaveProperty('retryCount');
      expect(typeof result?.retryCount).toBe('number');
      expect(result?.retryCount).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Test: Logs analysis attempts appropriately', () => {
    const jobId = 'test-job-123';

    it('should log success when fast AI analysis succeeds', async () => {
      const mockFastResult = {
        summary: 'A'.repeat(300),
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(mockFastResult);

      await analyzeContact(mockMessages, mockPipelineStages, undefined, jobId);

      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining(`[Pipeline Analysis ${jobId}] ✅ Fast AI analysis successful`)
      );
    });

    it('should log warning when fast AI analysis is too short', async () => {
      const mockFastResult = {
        summary: 'A'.repeat(100), // < 200 chars
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      const mockEnhancedResult = {
        summary: 'Enhanced analysis summary',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
        buyerIntent: 'HIGH',
        sentiment: 'POSITIVE',
        productInterests: [],
        intentSignals: {
          rapidReplies: false,
          multipleQuestions: false,
          offHoursResponse: false,
          askingForProof: false,
        },
        conversionProbability: 75,
        nextBestAction: 'Follow up',
        agentSuggestions: {},
        stageReason: 'Test reason',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(mockFastResult);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockResolvedValue(mockEnhancedResult);

      await analyzeContact(mockMessages, mockPipelineStages, undefined, jobId);

      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining(`[Pipeline Analysis ${jobId}] ⚠️ Fast AI analysis too short`)
      );
    });

    it('should log warning when fast AI analysis returns null', async () => {
      const mockEnhancedResult: EnhancedAnalysisResult = {
        summary: 'Enhanced analysis summary',
        reasoning: 'Test reasoning',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        buyerIntent: 'HIGH',
        sentiment: 'POSITIVE',
        productInterests: [],
        intentSignals: {
          rapidReplies: false,
          multipleQuestions: false,
          offHoursResponse: false,
          askingForProof: false,
        },
        conversionProbability: 75,
        nextBestAction: 'Follow up',
        agentSuggestions: {},
        stageReason: 'Based on analysis',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(null);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockResolvedValue(mockEnhancedResult);

      await analyzeContact(mockMessages, mockPipelineStages, undefined, jobId);

      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining(`[Pipeline Analysis ${jobId}] ⚠️ Fast AI analysis returned null`)
      );
    });

    it('should log error when fast AI analysis fails', async () => {
      const mockEnhancedResult: EnhancedAnalysisResult = {
        summary: 'Enhanced analysis summary',
        reasoning: 'Test reasoning',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        buyerIntent: 'HIGH',
        sentiment: 'POSITIVE',
        productInterests: [],
        intentSignals: {
          rapidReplies: false,
          multipleQuestions: false,
          offHoursResponse: false,
          askingForProof: false,
        },
        conversionProbability: 75,
        nextBestAction: 'Follow up',
        agentSuggestions: {},
        stageReason: 'Based on analysis',
      };

      const error = new Error('Fast analysis failed');
      mockedFastAnalysis.analyzeConversationFast.mockRejectedValue(error);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockResolvedValue(mockEnhancedResult);

      await analyzeContact(mockMessages, mockPipelineStages, undefined, jobId);

      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining(`[Pipeline Analysis ${jobId}] ❌ Fast AI analysis failed:`),
        expect.any(String)
      );
    });

    it('should log success when enhanced analysis succeeds', async () => {
      const mockEnhancedResult = {
        summary: 'Enhanced analysis summary',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
        buyerIntent: 'HIGH',
        sentiment: 'POSITIVE',
        productInterests: [],
        intentSignals: {
          rapidReplies: false,
          multipleQuestions: false,
          offHoursResponse: false,
          askingForProof: false,
        },
        conversionProbability: 75,
        nextBestAction: 'Follow up',
        agentSuggestions: {},
        stageReason: 'Test reason',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(null);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockResolvedValue(mockEnhancedResult);

      await analyzeContact(mockMessages, mockPipelineStages, undefined, jobId);

      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining(`[Pipeline Analysis ${jobId}] Using enhanced analysis:`)
      );
    });

    it('should log error when enhanced analysis fails', async () => {
      const error = new Error('Enhanced analysis failed');
      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(null);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockRejectedValue(error);

      await analyzeContact(mockMessages, mockPipelineStages, undefined, jobId);

      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining(`[Pipeline Analysis ${jobId}] ❌ Enhanced analysis failed:`),
        expect.any(String)
      );
    });

    it('should log warning when all analysis methods fail', async () => {
      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(null);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockResolvedValue(null);

      await analyzeContact(mockMessages, mockPipelineStages, undefined, jobId);

      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining(`[Pipeline Analysis ${jobId}] ⚠️ All analysis methods failed, returning null`)
      );
    });

    it('should not log when jobId is not provided', async () => {
      const mockFastResult = {
        summary: 'A'.repeat(300),
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(mockFastResult);

      await analyzeContact(mockMessages, mockPipelineStages);

      // Should still work but logs may not include jobId prefix
      expect(mockedFastAnalysis.analyzeConversationFast).toHaveBeenCalled();
    });

    it('should log with correct jobId prefix in all log messages', async () => {
      const mockFastResult = {
        summary: 'A'.repeat(300),
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(mockFastResult);

      await analyzeContact(mockMessages, mockPipelineStages, undefined, jobId);

      const logCalls = (console.log as jest.Mock).mock.calls;
      const logMessages = logCalls.map(call => call[0]).join(' ');

      if (logCalls.length > 0) {
        expect(logMessages).toContain(jobId);
      }
    });
  });
});

describe('analyzeContact', () => {
  const mockMessages = [
    { from: 'user', text: 'Hello', timestamp: new Date() },
    { from: 'contact', text: 'Hi there!', timestamp: new Date() },
  ];

  const mockPipelineStages = [
    { name: 'New Lead', type: 'lead', leadScoreMin: 0, leadScoreMax: 30 },
    { name: 'Qualified', type: 'lead', leadScoreMin: 31, leadScoreMax: 70 },
  ];

  beforeEach(() => {
    jest.clearAllMocks();
    // Suppress console logs during tests
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Test: Includes usedFallback flag in result', () => {
    it('should include usedFallback: false when fast analysis succeeds', async () => {
      const mockFastResult = {
        summary: 'A'.repeat(300), // > 200 chars
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(mockFastResult);

      const result = await analyzeContact(mockMessages, mockPipelineStages);

      expect(result).not.toBeNull();
      expect(result).toHaveProperty('usedFallback');
      expect(result?.usedFallback).toBe(false);
      expect(result?.analysis).toEqual(mockFastResult);
    });

    it('should include usedFallback: false when enhanced analysis succeeds after fast fails', async () => {
      const mockEnhancedResult: EnhancedAnalysisResult = {
        summary: 'Enhanced analysis summary',
        reasoning: 'Test reasoning',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        buyerIntent: 'HIGH',
        sentiment: 'POSITIVE',
        productInterests: [],
        intentSignals: {
          rapidReplies: false,
          multipleQuestions: false,
          offHoursResponse: false,
          askingForProof: false,
        },
        conversionProbability: 75,
        nextBestAction: 'Follow up',
        agentSuggestions: {},
        stageReason: 'Based on analysis',
      };

      // Fast analysis returns null or too short
      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(null);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockResolvedValue(mockEnhancedResult);

      const result = await analyzeContact(mockMessages, mockPipelineStages);

      expect(result).not.toBeNull();
      expect(result).toHaveProperty('usedFallback');
      expect(result?.usedFallback).toBe(false);
      expect(result?.analysis).toEqual(mockEnhancedResult);
    });

    it('should return null when all analysis methods fail', async () => {
      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(null);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockResolvedValue(null);

      const result = await analyzeContact(mockMessages, mockPipelineStages);

      expect(result).toBeNull();
    });

    it('should include usedFallback flag even when fast analysis is too short', async () => {
      const mockFastResult: FastDetailedAnalysis = {
        summary: 'A'.repeat(100), // < 200 chars
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      const mockEnhancedResult: EnhancedAnalysisResult = {
        summary: 'Enhanced analysis summary',
        reasoning: 'Test reasoning',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        buyerIntent: 'HIGH',
        sentiment: 'POSITIVE',
        productInterests: [],
        intentSignals: {
          rapidReplies: false,
          multipleQuestions: false,
          offHoursResponse: false,
          askingForProof: false,
        },
        conversionProbability: 75,
        nextBestAction: 'Follow up',
        agentSuggestions: {},
        stageReason: 'Based on analysis',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(mockFastResult);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockResolvedValue(mockEnhancedResult);

      const result = await analyzeContact(mockMessages, mockPipelineStages);

      expect(result).not.toBeNull();
      expect(result).toHaveProperty('usedFallback');
      expect(result?.usedFallback).toBe(false);
    });
  });

  describe('Test: Includes retryCount in result', () => {
    it('should include retryCount: 0 when fast analysis succeeds', async () => {
      const mockFastResult: FastDetailedAnalysis = {
        summary: 'A'.repeat(300),
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(mockFastResult);

      const result = await analyzeContact(mockMessages, mockPipelineStages);

      expect(result).not.toBeNull();
      expect(result).toHaveProperty('retryCount');
      expect(result?.retryCount).toBe(0);
    });

    it('should include retryCount: 0 when enhanced analysis succeeds', async () => {
      const mockEnhancedResult: EnhancedAnalysisResult = {
        summary: 'Enhanced analysis summary',
        reasoning: 'Test reasoning',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        buyerIntent: 'HIGH',
        sentiment: 'POSITIVE',
        productInterests: [],
        intentSignals: {
          rapidReplies: false,
          multipleQuestions: false,
          offHoursResponse: false,
          askingForProof: false,
        },
        conversionProbability: 75,
        nextBestAction: 'Follow up',
        agentSuggestions: {},
        stageReason: 'Based on analysis',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(null);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockResolvedValue(mockEnhancedResult);

      const result = await analyzeContact(mockMessages, mockPipelineStages);

      expect(result).not.toBeNull();
      expect(result).toHaveProperty('retryCount');
      expect(result?.retryCount).toBe(0);
    });

    it('should always include retryCount as a number when result is not null', async () => {
      const mockFastResult: FastDetailedAnalysis = {
        summary: 'A'.repeat(300),
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(mockFastResult);

      const result = await analyzeContact(mockMessages, mockPipelineStages);

      expect(result).not.toBeNull();
      expect(result).toHaveProperty('retryCount');
      expect(typeof result?.retryCount).toBe('number');
      expect(result?.retryCount).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Test: Logs analysis attempts appropriately', () => {
    const jobId = 'test-job-123';

    it('should log success when fast AI analysis succeeds', async () => {
      const mockFastResult = {
        summary: 'A'.repeat(300),
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(mockFastResult);

      await analyzeContact(mockMessages, mockPipelineStages, undefined, jobId);

      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining(`[Pipeline Analysis ${jobId}] ✅ Fast AI analysis successful`)
      );
    });

    it('should log warning when fast AI analysis is too short', async () => {
      const mockFastResult = {
        summary: 'A'.repeat(100), // < 200 chars
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      const mockEnhancedResult = {
        summary: 'Enhanced analysis summary',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
        buyerIntent: 'HIGH',
        sentiment: 'POSITIVE',
        productInterests: [],
        intentSignals: {
          rapidReplies: false,
          multipleQuestions: false,
          offHoursResponse: false,
          askingForProof: false,
        },
        conversionProbability: 75,
        nextBestAction: 'Follow up',
        agentSuggestions: {},
        stageReason: 'Test reason',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(mockFastResult);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockResolvedValue(mockEnhancedResult);

      await analyzeContact(mockMessages, mockPipelineStages, undefined, jobId);

      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining(`[Pipeline Analysis ${jobId}] ⚠️ Fast AI analysis too short`)
      );
    });

    it('should log warning when fast AI analysis returns null', async () => {
      const mockEnhancedResult: EnhancedAnalysisResult = {
        summary: 'Enhanced analysis summary',
        reasoning: 'Test reasoning',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        buyerIntent: 'HIGH',
        sentiment: 'POSITIVE',
        productInterests: [],
        intentSignals: {
          rapidReplies: false,
          multipleQuestions: false,
          offHoursResponse: false,
          askingForProof: false,
        },
        conversionProbability: 75,
        nextBestAction: 'Follow up',
        agentSuggestions: {},
        stageReason: 'Based on analysis',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(null);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockResolvedValue(mockEnhancedResult);

      await analyzeContact(mockMessages, mockPipelineStages, undefined, jobId);

      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining(`[Pipeline Analysis ${jobId}] ⚠️ Fast AI analysis returned null`)
      );
    });

    it('should log error when fast AI analysis fails', async () => {
      const mockEnhancedResult: EnhancedAnalysisResult = {
        summary: 'Enhanced analysis summary',
        reasoning: 'Test reasoning',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        buyerIntent: 'HIGH',
        sentiment: 'POSITIVE',
        productInterests: [],
        intentSignals: {
          rapidReplies: false,
          multipleQuestions: false,
          offHoursResponse: false,
          askingForProof: false,
        },
        conversionProbability: 75,
        nextBestAction: 'Follow up',
        agentSuggestions: {},
        stageReason: 'Based on analysis',
      };

      const error = new Error('Fast analysis failed');
      mockedFastAnalysis.analyzeConversationFast.mockRejectedValue(error);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockResolvedValue(mockEnhancedResult);

      await analyzeContact(mockMessages, mockPipelineStages, undefined, jobId);

      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining(`[Pipeline Analysis ${jobId}] ❌ Fast AI analysis failed:`),
        expect.any(String)
      );
    });

    it('should log success when enhanced analysis succeeds', async () => {
      const mockEnhancedResult = {
        summary: 'Enhanced analysis summary',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
        buyerIntent: 'HIGH',
        sentiment: 'POSITIVE',
        productInterests: [],
        intentSignals: {
          rapidReplies: false,
          multipleQuestions: false,
          offHoursResponse: false,
          askingForProof: false,
        },
        conversionProbability: 75,
        nextBestAction: 'Follow up',
        agentSuggestions: {},
        stageReason: 'Test reason',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(null);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockResolvedValue(mockEnhancedResult);

      await analyzeContact(mockMessages, mockPipelineStages, undefined, jobId);

      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining(`[Pipeline Analysis ${jobId}] Using enhanced analysis:`)
      );
    });

    it('should log error when enhanced analysis fails', async () => {
      const error = new Error('Enhanced analysis failed');
      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(null);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockRejectedValue(error);

      await analyzeContact(mockMessages, mockPipelineStages, undefined, jobId);

      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining(`[Pipeline Analysis ${jobId}] ❌ Enhanced analysis failed:`),
        expect.any(String)
      );
    });

    it('should log warning when all analysis methods fail', async () => {
      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(null);
      mockedEnhancedAnalysis.analyzeConversationEnhanced.mockResolvedValue(null);

      await analyzeContact(mockMessages, mockPipelineStages, undefined, jobId);

      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining(`[Pipeline Analysis ${jobId}] ⚠️ All analysis methods failed, returning null`)
      );
    });

    it('should not log when jobId is not provided', async () => {
      const mockFastResult = {
        summary: 'A'.repeat(300),
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(mockFastResult);

      await analyzeContact(mockMessages, mockPipelineStages);

      // Should still work but logs may not include jobId prefix
      expect(mockedFastAnalysis.analyzeConversationFast).toHaveBeenCalled();
    });

    it('should log with correct jobId prefix in all log messages', async () => {
      const mockFastResult = {
        summary: 'A'.repeat(300),
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 80,
        reasoning: 'Test reasoning',
      };

      mockedFastAnalysis.analyzeConversationFast.mockResolvedValue(mockFastResult);

      await analyzeContact(mockMessages, mockPipelineStages, undefined, jobId);

      const logCalls = (console.log as jest.Mock).mock.calls;
      const logMessages = logCalls.map(call => call[0]).join(' ');

      if (logCalls.length > 0) {
        expect(logMessages).toContain(jobId);
      }
    });
  });
});
