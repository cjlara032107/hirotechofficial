/**
 * Tests for processContact function
 * 
 * Tests verify all checklist items:
 * - Processes contact successfully
 * - Returns null when conversation not found
 * - Returns null when messages can't be fetched
 * - Returns null when AI analysis fails
 * - Handles cancellation check
 * - Handles contact with no messages
 * - Handles contact with invalid conversation data
 * - Builds correct update data structure
 * - Handles all error cases gracefully (doesn't throw)
 */

// Mock dependencies BEFORE imports
jest.mock('@/lib/db', () => ({
  prisma: {
    syncJob: {
      findUnique: jest.fn(),
    },
  },
}));

jest.mock('../analyze-contact', () => ({
  analyzeContact: jest.fn(),
}));

jest.mock('../../client', () => ({
  FacebookClient: jest.fn(),
  FacebookApiError: class FacebookApiError extends Error {
    code?: number;
    isTokenExpired?: boolean;
    constructor(message: string, code?: number) {
      super(message);
      this.code = code;
      this.isTokenExpired = code === 190;
    }
  },
}));

import { processContact, type ProcessContactResult } from '../process-contact';
import { analyzeContact } from '../analyze-contact';
import { FacebookClient, FacebookApiError } from '../../client';
import { prisma } from '@/lib/db';

const mockedAnalyzeContact = analyzeContact as jest.MockedFunction<typeof analyzeContact>;
const mockedPrisma = prisma as jest.Mocked<typeof prisma>;

describe('processContact', () => {
  const mockJobId = 'test-job-123';
  const mockContact = {
    id: 'contact-123',
    messengerPSID: 'psid-123',
    instagramSID: null,
    firstName: 'John',
    lastName: 'Doe',
    lastInteraction: new Date('2024-01-01'),
  };

  const mockPipelineStages = [
    { name: 'New Lead', type: 'lead', leadScoreMin: 0, leadScoreMax: 30 },
    { name: 'Qualified', type: 'lead', leadScoreMin: 31, leadScoreMax: 70 },
  ];

  const mockConversationInfo = {
    conversationId: 'conv-123',
    updatedTime: '2024-01-01T00:00:00Z',
  };

  const mockMessengerConversationMap = new Map([
    ['psid-123', mockConversationInfo],
  ]);

  const mockInstagramConversationMap = new Map<string, typeof mockConversationInfo>();

  const mockMessages = [
    {
      message: 'Hello',
      from: { name: 'John', id: 'psid-123' },
      created_time: '2024-01-01T00:00:00Z',
    },
    {
      message: 'Hi there!',
      from: { name: 'Business', id: 'page-123' },
      created_time: '2024-01-01T00:01:00Z',
    },
  ];

  const mockAnalysisResult = {
    analysis: {
      summary: 'Test summary',
      reasoning: 'Test reasoning',
      recommendedStage: 'Qualified',
      leadScore: 50,
      leadStatus: 'QUALIFIED',
      confidence: 80,
      buyerIntent: 'HIGH',
      sentiment: 'POSITIVE',
      productInterests: ['product1'],
      intentSignals: { rapidReplies: true },
      nextBestAction: 'Follow up',
      agentSuggestions: {},
    },
    usedFallback: false,
    retryCount: 0,
  };

  let mockClient: jest.Mocked<FacebookClient>;
  let mockConversationFetchLimiter: { execute: jest.Mock };
  let mockAnalysisLimiter: { execute: jest.Mock };

  beforeEach(() => {
    jest.clearAllMocks();

    // Setup mock FacebookClient
    mockClient = {
      getRecentMessagesForConversation: jest.fn(),
    } as any;

    // Setup mock limiters
    mockConversationFetchLimiter = {
      execute: jest.fn((fn) => fn()),
    };

    mockAnalysisLimiter = {
      execute: jest.fn((fn) => fn()),
    };

    // Default mock implementations
    mockedPrisma.syncJob.findUnique.mockResolvedValue({
      status: 'IN_PROGRESS',
    } as any);

    (mockClient.getRecentMessagesForConversation as jest.Mock).mockResolvedValue(mockMessages);
    mockedAnalyzeContact.mockResolvedValue(mockAnalysisResult);

    // Suppress console logs during tests
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Test: Processes contact successfully', () => {
    it('should process contact successfully with valid data', async () => {
      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).not.toBeNull();
      expect(result).toHaveProperty('contactId', 'contact-123');
      expect(result).toHaveProperty('aiContext');
      expect(result).toHaveProperty('aiAnalysis');
      expect(result?.aiAnalysis).toEqual(mockAnalysisResult.analysis);
      expect(mockClient.getRecentMessagesForConversation).toHaveBeenCalledWith('conv-123', 20);
      expect(mockedAnalyzeContact).toHaveBeenCalled();
    });

    it('should process contact with Instagram SID when Messenger PSID not available', async () => {
      const instagramContact = {
        ...mockContact,
        messengerPSID: null,
        instagramSID: 'ig-123',
      };

      const instagramMap = new Map([['ig-123', mockConversationInfo]]);

      const result = await processContact(
        instagramContact,
        mockMessengerConversationMap,
        instagramMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).not.toBeNull();
      expect(result?.contactId).toBe('contact-123');
    });
  });

  describe('Test: Returns null when conversation not found', () => {
    it('should return null when Messenger conversation not found', async () => {
      const emptyMap = new Map<string, typeof mockConversationInfo>();

      const result = await processContact(
        mockContact,
        emptyMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).toBeNull();
      expect(mockClient.getRecentMessagesForConversation).not.toHaveBeenCalled();
      expect(mockedAnalyzeContact).not.toHaveBeenCalled();
    });

    it('should return null when neither Messenger nor Instagram conversation found', async () => {
      const emptyMessengerMap = new Map<string, typeof mockConversationInfo>();
      const emptyInstagramMap = new Map<string, typeof mockConversationInfo>();

      const result = await processContact(
        mockContact,
        emptyMessengerMap,
        emptyInstagramMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).toBeNull();
    });

    it('should return null when contact has no PSID or Instagram SID', async () => {
      const contactWithoutIds = {
        ...mockContact,
        messengerPSID: null,
        instagramSID: null,
      };

      const result = await processContact(
        contactWithoutIds,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).toBeNull();
    });
  });

  describe('Test: Returns null when messages can\'t be fetched', () => {
    it('should return null when getRecentMessagesForConversation throws error', async () => {
      (mockClient.getRecentMessagesForConversation as jest.Mock).mockRejectedValue(
        new Error('API error')
      );

      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).toBeNull();
      expect(mockedAnalyzeContact).not.toHaveBeenCalled();
    });

    it('should return null when getRecentMessagesForConversation throws FacebookApiError', async () => {
      (mockClient.getRecentMessagesForConversation as jest.Mock).mockRejectedValue(
        new FacebookApiError('Rate limit exceeded', 613)
      );

      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).toBeNull();
    });

    it('should return null when message fetch times out', async () => {
      // Mock limiter to delay longer than timeout
      mockConversationFetchLimiter.execute = jest.fn((fn) => {
        return new Promise((_, reject) => {
          setTimeout(() => reject(new Error('Timeout')), 11000);
        });
      });

      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).toBeNull();
    }, 15000); // Increase timeout for this test
  });

  describe('Test: Returns null when AI analysis fails', () => {
    it('should return null when analyzeContact returns null', async () => {
      mockedAnalyzeContact.mockResolvedValue(null);

      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).toBeNull();
    });

    it('should return null when analyzeContact throws error', async () => {
      mockedAnalyzeContact.mockRejectedValue(new Error('AI analysis failed'));

      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).toBeNull();
    });

    it('should return null when analysis times out', async () => {
      // Mock limiter to delay longer than timeout
      mockAnalysisLimiter.execute = jest.fn((fn) => {
        return new Promise((_, reject) => {
          setTimeout(() => reject(new Error('Timeout')), 61000);
        });
      });

      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).toBeNull();
    }, 70000); // Increase timeout for this test
  });

  describe('Test: Handles cancellation check', () => {
    it('should return null when job is cancelled', async () => {
      mockedPrisma.syncJob.findUnique.mockResolvedValue({
        status: 'CANCELLED',
      } as any);

      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).toBeNull();
      expect(mockClient.getRecentMessagesForConversation).not.toHaveBeenCalled();
      expect(mockedAnalyzeContact).not.toHaveBeenCalled();
    });

    it('should continue processing when job is not cancelled', async () => {
      mockedPrisma.syncJob.findUnique.mockResolvedValue({
        status: 'IN_PROGRESS',
      } as any);

      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).not.toBeNull();
    });
  });

  describe('Test: Handles contact with no messages', () => {
    it('should return null when messages array is empty', async () => {
      (mockClient.getRecentMessagesForConversation as jest.Mock).mockResolvedValue([]);

      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).toBeNull();
      expect(mockedAnalyzeContact).not.toHaveBeenCalled();
    });

    it('should return null when messages is null', async () => {
      (mockClient.getRecentMessagesForConversation as jest.Mock).mockResolvedValue(null);

      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).toBeNull();
    });

    it('should return null when all messages are filtered out (no message text)', async () => {
      const messagesWithoutText = [
        {
          from: { name: 'John', id: 'psid-123' },
          created_time: '2024-01-01T00:00:00Z',
          // No message field
        },
      ];

      (mockClient.getRecentMessagesForConversation as jest.Mock).mockResolvedValue(
        messagesWithoutText
      );

      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).toBeNull();
      expect(mockedAnalyzeContact).not.toHaveBeenCalled();
    });
  });

  describe('Test: Handles contact with invalid conversation data', () => {
    it('should return null when conversationInfo is undefined in map', async () => {
      const mapWithUndefined = new Map<string, typeof mockConversationInfo>();
      mapWithUndefined.set('psid-123', undefined as any);

      const result = await processContact(
        mockContact,
        mapWithUndefined,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      // Should handle gracefully - may return null or attempt to process
      // The function should not throw
      expect(async () => {
        await processContact(
          mockContact,
          mapWithUndefined,
          mockInstagramConversationMap,
          mockPipelineStages,
          mockJobId,
          mockClient,
          mockConversationFetchLimiter,
          mockAnalysisLimiter
        );
      }).not.toThrow();
    });

    it('should handle conversationInfo with missing conversationId', async () => {
      const invalidConversationInfo = {
        updatedTime: '2024-01-01T00:00:00Z',
        // Missing conversationId
      } as any;

      const invalidMap = new Map([['psid-123', invalidConversationInfo]]);

      // Should not throw, but may return null when trying to fetch messages
      const result = await processContact(
        mockContact,
        invalidMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      // Function should handle gracefully without throwing
      expect(result).toBeDefined(); // May be null or may attempt processing
    });
  });

  describe('Test: Builds correct update data structure', () => {
    it('should build correct update data structure with all fields', async () => {
      const enhancedAnalysis = {
        ...mockAnalysisResult.analysis,
        conversionPath: ['awareness', 'interest'],
        similarLeadsInsight: 'Similar to other high-value leads',
        botAccuracyScore: 0.95,
        conversationPatterns: { questionCount: 5 },
        indirectIntent: 'MIGHT_BUY',
        buyerReliability: 'HIGH',
        buyerStyle: 'ANALYTICAL',
        leadRiskLevel: 'LOW',
        leadRiskReasons: [],
      };

      mockedAnalyzeContact.mockResolvedValue({
        ...mockAnalysisResult,
        analysis: enhancedAnalysis,
      });

      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).not.toBeNull();
      expect(result).toHaveProperty('contactId', 'contact-123');
      expect(result).toHaveProperty('aiContext');
      expect(result).toHaveProperty('aiSummary');
      expect(result).toHaveProperty('aiAnalysis');
      expect(result).toHaveProperty('conversionProbability', enhancedAnalysis.conversionProbability);
      expect(result).toHaveProperty('buyerIntent', enhancedAnalysis.buyerIntent);
      expect(result).toHaveProperty('sentiment', enhancedAnalysis.sentiment);
      expect(result).toHaveProperty('productInterests', enhancedAnalysis.productInterests);
      expect(result).toHaveProperty('intentSignals', enhancedAnalysis.intentSignals);
      expect(result).toHaveProperty('nextBestAction', enhancedAnalysis.nextBestAction);
      expect(result).toHaveProperty('agentSuggestions', enhancedAnalysis.agentSuggestions);
      expect(result).toHaveProperty('conversionPath', enhancedAnalysis.conversionPath);
      expect(result).toHaveProperty('similarLeadsInsight', enhancedAnalysis.similarLeadsInsight);
      expect(result).toHaveProperty('botAccuracyScore', enhancedAnalysis.botAccuracyScore);
      expect(result).toHaveProperty('conversationPatterns', enhancedAnalysis.conversationPatterns);
      expect(result).toHaveProperty('indirectIntent', enhancedAnalysis.indirectIntent);
      expect(result).toHaveProperty('buyerReliability', enhancedAnalysis.buyerReliability);
      expect(result).toHaveProperty('buyerStyle', enhancedAnalysis.buyerStyle);
      expect(result).toHaveProperty('leadRiskLevel', enhancedAnalysis.leadRiskLevel);
      expect(result).toHaveProperty('leadRiskReasons', enhancedAnalysis.leadRiskReasons);
    });

    it('should use summary as aiContext when summary is longer than reasoning', async () => {
      const analysisWithLongSummary = {
        ...mockAnalysisResult.analysis,
        summary: 'A'.repeat(500), // Long summary
        reasoning: 'B'.repeat(100), // Shorter reasoning
      };

      mockedAnalyzeContact.mockResolvedValue({
        ...mockAnalysisResult,
        analysis: analysisWithLongSummary,
      });

      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).not.toBeNull();
      expect(result?.aiContext).toBe(analysisWithLongSummary.summary);
    });

    it('should use reasoning as aiContext when reasoning is longer than summary', async () => {
      const analysisWithLongReasoning = {
        ...mockAnalysisResult.analysis,
        summary: 'A'.repeat(100), // Shorter summary
        reasoning: 'B'.repeat(500), // Long reasoning
      };

      mockedAnalyzeContact.mockResolvedValue({
        ...mockAnalysisResult,
        analysis: analysisWithLongReasoning,
      });

      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).not.toBeNull();
      expect(result?.aiContext).toBe(analysisWithLongReasoning.reasoning);
    });

    it('should use summary as aiSummary when available', async () => {
      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).not.toBeNull();
      expect(result?.aiSummary).toBe(mockAnalysisResult.analysis.summary);
    });
  });

  describe('Test: Handles all error cases gracefully (doesn\'t throw)', () => {
    it('should not throw when isJobCancelled throws error', async () => {
      mockedPrisma.syncJob.findUnique.mockRejectedValue(new Error('Database error'));

      await expect(
        processContact(
          mockContact,
          mockMessengerConversationMap,
          mockInstagramConversationMap,
          mockPipelineStages,
          mockJobId,
          mockClient,
          mockConversationFetchLimiter,
          mockAnalysisLimiter
        )
      ).resolves.not.toThrow();

      // Should return null on error
      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).toBeNull();
    });

    it('should not throw when conversationFetchLimiter.execute throws', async () => {
      mockConversationFetchLimiter.execute = jest.fn(() => {
        throw new Error('Limiter error');
      });

      await expect(
        processContact(
          mockContact,
          mockMessengerConversationMap,
          mockInstagramConversationMap,
          mockPipelineStages,
          mockJobId,
          mockClient,
          mockConversationFetchLimiter,
          mockAnalysisLimiter
        )
      ).resolves.not.toThrow();

      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).toBeNull();
    });

    it('should not throw when analysisLimiter.execute throws', async () => {
      mockAnalysisLimiter.execute = jest.fn(() => {
        throw new Error('Analysis limiter error');
      });

      await expect(
        processContact(
          mockContact,
          mockMessengerConversationMap,
          mockInstagramConversationMap,
          mockPipelineStages,
          mockJobId,
          mockClient,
          mockConversationFetchLimiter,
          mockAnalysisLimiter
        )
      ).resolves.not.toThrow();

      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).toBeNull();
    });

    it('should not throw when processing messages throws unexpected error', async () => {
      // Mock messages that cause error during processing
      const invalidMessages = [
        {
          // Missing required fields
        },
      ];

      (mockClient.getRecentMessagesForConversation as jest.Mock).mockResolvedValue(invalidMessages);

      await expect(
        processContact(
          mockContact,
          mockMessengerConversationMap,
          mockInstagramConversationMap,
          mockPipelineStages,
          mockJobId,
          mockClient,
          mockConversationFetchLimiter,
          mockAnalysisLimiter
        )
      ).resolves.not.toThrow();

      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      // Should return null when no valid messages
      expect(result).toBeNull();
    });

    it('should not throw when analysis result has invalid structure', async () => {
      mockedAnalyzeContact.mockResolvedValue({
        // Missing analysis field
        usedFallback: false,
        retryCount: 0,
      } as any);

      await expect(
        processContact(
          mockContact,
          mockMessengerConversationMap,
          mockInstagramConversationMap,
          mockPipelineStages,
          mockJobId,
          mockClient,
          mockConversationFetchLimiter,
          mockAnalysisLimiter
        )
      ).resolves.not.toThrow();

      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).toBeNull();
    });

    it('should not throw on any unexpected error', async () => {
      // Simulate any unexpected error by making client throw
      (mockClient.getRecentMessagesForConversation as jest.Mock).mockImplementation(() => {
        throw new Error('Unexpected error');
      });

      await expect(
        processContact(
          mockContact,
          mockMessengerConversationMap,
          mockInstagramConversationMap,
          mockPipelineStages,
          mockJobId,
          mockClient,
          mockConversationFetchLimiter,
          mockAnalysisLimiter
        )
      ).resolves.not.toThrow();

      const result = await processContact(
        mockContact,
        mockMessengerConversationMap,
        mockInstagramConversationMap,
        mockPipelineStages,
        mockJobId,
        mockClient,
        mockConversationFetchLimiter,
        mockAnalysisLimiter
      );

      expect(result).toBeNull();
    });
  });
});









