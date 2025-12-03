import axios from 'axios';
import { facebookRateLimiter } from './rate-limiter';

const FB_GRAPH_URL = 'https://graph.facebook.com/v19.0';

/**
 * Custom error class for Facebook API errors
 * 
 * Provides type-safe error handling for Facebook Graph API errors with:
 * - Error code and type information
 * - Helper methods for common error types
 * - Contextual error information
 * 
 * @example
 * ```typescript
 * try {
 *   await client.getConversations(pageId, 'messenger');
 * } catch (error) {
 *   if (error instanceof FacebookApiError) {
 *     if (error.isTokenExpired) {
 *       // Handle token expiration
 *     }
 *     if (error.isRateLimited) {
 *       // Handle rate limiting
 *     }
 *   }
 * }
 * ```
 */
export class FacebookApiError extends Error {
  constructor(
    public code: number,
    public type: string,
    message: string,
    public context?: string
  ) {
    super(message);
    this.name = 'FacebookApiError';
  }

  get isTokenExpired(): boolean {
    return this.code === 190;
  }

  get isRateLimited(): boolean {
    return this.code === 613 || this.code === 4 || this.code === 17;
  }

  get isPermissionError(): boolean {
    return this.code === 200 || this.code === 10;
  }

  get isInvalidParameter(): boolean {
    return this.code === 100;
  }
}

/**
 * Parses a Facebook API error response into a FacebookApiError
 * 
 * Extracts error information from Facebook Graph API error responses
 * and creates a typed error object for consistent error handling.
 * 
 * @param error - The error object from axios or Facebook API
 * @param context - Optional context string describing where the error occurred
 * @returns FacebookApiError instance with parsed error information
 * @throws The original error if it's not a Facebook API error
 */
function parseFacebookError(error: any, context?: string): FacebookApiError {
  if (error.response?.data?.error) {
    const fbError = error.response.data.error;
    return new FacebookApiError(
      fbError.code,
      fbError.type || 'OAuthException',
      fbError.message,
      context
    );
  }
  throw error;
}

export type MessageTag =
  | 'CONFIRMED_EVENT_UPDATE'
  | 'POST_PURCHASE_UPDATE'
  | 'ACCOUNT_UPDATE'
  | 'HUMAN_AGENT';

export interface SendMessageOptions {
  recipientId: string;
  message: string;
  messageTag?: MessageTag;
  notificationType?: 'REGULAR' | 'SILENT_PUSH' | 'NO_PUSH';
}

/**
 * Cache entry for conversations
 */
interface ConversationCacheEntry {
  data: any[];
  timestamp: number;
  ttl: number; // Time to live in milliseconds
}

/**
 * Cache entry for conversation chunks
 */
interface ConversationChunkCacheEntry {
  conversationIds: Set<string>;
  timestamp: number;
  ttl: number;
}

/**
 * Request deduplication: tracks in-flight requests to prevent duplicate API calls
 */
class RequestDeduplicator {
  private inFlightRequests = new Map<string, Promise<any>>();

  /**
   * Execute a request with deduplication
   * If the same request is already in-flight, returns the existing promise
   */
  async execute<T>(key: string, requestFn: () => Promise<T>): Promise<T> {
    // Check if request is already in-flight
    const existingRequest = this.inFlightRequests.get(key);
    if (existingRequest) {
      return existingRequest as Promise<T>;
    }

    // Create new request
    const requestPromise = requestFn()
      .then((result) => {
        // Remove from in-flight requests on success
        this.inFlightRequests.delete(key);
        return result;
      })
      .catch((error) => {
        // Remove from in-flight requests on error
        this.inFlightRequests.delete(key);
        throw error;
      });

    // Store in-flight request
    this.inFlightRequests.set(key, requestPromise);

    return requestPromise;
  }

  /**
   * Clear all in-flight requests (useful for testing or cleanup)
   */
  clear(): void {
    this.inFlightRequests.clear();
  }
}

/**
 * Facebook Graph API client with caching and request deduplication
 * 
 * Provides a high-level interface for interacting with Facebook Graph API:
 * - Conversation fetching (Messenger and Instagram)
 * - Message sending
 * - Page information retrieval
 * - Automatic request deduplication
 * - Response caching (5 minutes for conversations, 10 minutes for chunks)
 * - Comprehensive error handling with FacebookApiError
 * 
 * Features:
 * - Prevents duplicate API calls for the same request
 * - Caches conversation data to reduce API calls
 * - Handles pagination automatically
 * - Provides type-safe error handling
 * 
 * @example
 * ```typescript
 * const client = new FacebookClient(accessToken);
 * const conversations = await client.getConversations(pageId, 'messenger');
 * await client.sendMessengerMessage({
 *   recipientId: 'user_id',
 *   message: 'Hello!'
 * });
 * ```
 */
export class FacebookClient {
  private requestDeduplicator = new RequestDeduplicator();
  private conversationCache = new Map<string, ConversationCacheEntry>();
  private conversationChunkCache = new Map<string, ConversationChunkCacheEntry>();
  private readonly CONVERSATION_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
  private readonly CHUNK_CACHE_TTL = 10 * 60 * 1000; // 10 minutes for chunk cache

  /**
   * Creates a new FacebookClient instance
   * 
   * @param accessToken - Facebook page access token for API authentication
   */
  constructor(private accessToken: string) {}

  /**
   * Generate cache key for conversations
   */
  private getConversationCacheKey(pageId: string, platform: 'messenger' | 'instagram'): string {
    return `conversations:${platform}:${pageId}`;
  }

  /**
   * Generate cache key for conversation chunks
   */
  private getChunkCacheKey(pageId: string, platform: 'messenger' | 'instagram', chunkIndex: number): string {
    return `chunk:${platform}:${pageId}:${chunkIndex}`;
  }

  /**
   * Generate cache key for fetched conversation IDs
   */
  private getFetchedIdsCacheKey(pageId: string, platform: 'messenger' | 'instagram'): string {
    return `fetchedIds:${platform}:${pageId}`;
  }

  /**
   * Get cached conversations if available and not expired
   */
  private getCachedConversations(pageId: string, platform: 'messenger' | 'instagram'): any[] | null {
    const cacheKey = this.getConversationCacheKey(pageId, platform);
    const cached = this.conversationCache.get(cacheKey);

    if (!cached) {
      return null;
    }

    const now = Date.now();
    if (now - cached.timestamp > cached.ttl) {
      // Cache expired
      this.conversationCache.delete(cacheKey);
      return null;
    }

    return cached.data;
  }

  /**
   * Cache conversations
   */
  private setCachedConversations(
    pageId: string,
    platform: 'messenger' | 'instagram',
    data: any[],
    ttl: number = this.CONVERSATION_CACHE_TTL
  ): void {
    const cacheKey = this.getConversationCacheKey(pageId, platform);
    this.conversationCache.set(cacheKey, {
      data,
      timestamp: Date.now(),
      ttl,
    });
  }

  /**
   * Cache conversation chunk metadata (for debugging/monitoring)
   * Note: This is optional and mainly for tracking purposes
   */
  private setCachedChunk(
    pageId: string,
    platform: 'messenger' | 'instagram',
    chunkIndex: number,
    conversationIds: Set<string>,
    ttl: number = this.CHUNK_CACHE_TTL
  ): void {
    const cacheKey = this.getChunkCacheKey(pageId, platform, chunkIndex);
    this.conversationChunkCache.set(cacheKey, {
      conversationIds,
      timestamp: Date.now(),
      ttl,
    });
  }

  /**
   * Get set of already-fetched conversation IDs
   */
  private getFetchedConversationIds(pageId: string, platform: 'messenger' | 'instagram'): Set<string> {
    const cacheKey = this.getFetchedIdsCacheKey(pageId, platform);
    const cached = this.conversationChunkCache.get(cacheKey);
    
    if (!cached) {
      return new Set<string>();
    }
    
    const now = Date.now();
    if (now - cached.timestamp > cached.ttl) {
      this.conversationChunkCache.delete(cacheKey);
      return new Set<string>();
    }
    
    return cached.conversationIds;
  }

  /**
   * Mark conversation IDs as fetched
   */
  private markConversationsAsFetched(
    pageId: string,
    platform: 'messenger' | 'instagram',
    conversationIds: Set<string>
  ): void {
    const cacheKey = this.getFetchedIdsCacheKey(pageId, platform);
    const existing = this.getFetchedConversationIds(pageId, platform);
    
    // Merge with existing
    conversationIds.forEach(id => existing.add(id));
    
    this.conversationChunkCache.set(cacheKey, {
      conversationIds: existing,
      timestamp: Date.now(),
      ttl: this.CHUNK_CACHE_TTL,
    });
  }

  /**
   * Clear conversation cache (useful for testing or when data is stale)
   */
  clearConversationCache(pageId?: string, platform?: 'messenger' | 'instagram'): void {
    if (pageId && platform) {
      const cacheKey = this.getConversationCacheKey(pageId, platform);
      this.conversationCache.delete(cacheKey);
      
      // Clear chunk cache for this page/platform
      const fetchedIdsKey = this.getFetchedIdsCacheKey(pageId, platform);
      this.conversationChunkCache.delete(fetchedIdsKey);
      
      // Clear all chunk caches for this page/platform
      for (const key of this.conversationChunkCache.keys()) {
        if (key.startsWith(`chunk:${platform}:${pageId}:`)) {
          this.conversationChunkCache.delete(key);
        }
      }
    } else {
      this.conversationCache.clear();
      this.conversationChunkCache.clear();
    }
  }

  /**
   * Sends a message via Facebook Messenger
   * 
   * Sends a text message to a recipient with optional message tag and notification type.
   * Message tags allow sending messages outside the 24-hour messaging window for
   * specific use cases (e.g., post-purchase updates, account updates).
   * 
   * @param options - Message sending options
   * @param options.recipientId - Facebook user ID or page-scoped ID of the recipient
   * @param options.message - Text message to send
   * @param options.messageTag - Optional message tag for sending outside 24-hour window
   *   - `CONFIRMED_EVENT_UPDATE`: Event updates
   *   - `POST_PURCHASE_UPDATE`: Post-purchase messages
   *   - `ACCOUNT_UPDATE`: Account updates
   *   - `HUMAN_AGENT`: Human agent responses
   * @param options.notificationType - Notification type (default: 'REGULAR')
   *   - `REGULAR`: Full notification
   *   - `SILENT_PUSH`: Silent push notification
   *   - `NO_PUSH`: No notification
   * @returns Promise resolving to API response with message ID
   * @throws FacebookApiError if the API call fails
   * 
   * @example
   * ```typescript
   * await client.sendMessengerMessage({
   *   recipientId: 'user_123',
   *   message: 'Thank you for your order!',
   *   messageTag: 'POST_PURCHASE_UPDATE',
   *   notificationType: 'REGULAR'
   * });
   * ```
   */
  async sendMessengerMessage(options: SendMessageOptions) {
    const { recipientId, message, messageTag, notificationType = 'REGULAR' } = options;

    const payload: any = {
      recipient: { id: recipientId },
      message: { text: message },
      notification_type: notificationType,
    };

    if (messageTag) {
      payload.messaging_type = 'MESSAGE_TAG';
      payload.tag = messageTag;
    } else {
      payload.messaging_type = 'RESPONSE';
    }

    try {
      const response = await axios.post(
        `${FB_GRAPH_URL}/me/messages`,
        payload,
        {
          params: { access_token: this.accessToken },
        }
      );
      return { success: true, data: response.data };
    } catch (error: any) {
      if (error.response?.data?.error) {
        const fbError = error.response.data.error;

        if (fbError.code === 10903) {
          return {
            success: false,
            error: 'OUTSIDE_24HR_WINDOW',
            message: 'Cannot send message outside 24-hour window without appropriate message tag',
          };
        }

        if (fbError.code === 200) {
          return {
            success: false,
            error: 'INVALID_TAG_USAGE',
            message: 'Message tag usage does not match message content',
          };
        }

        // Check for rate limit errors (codes: 613, 4, 17)
        const isRateLimit = fbError.code === 613 || fbError.code === 4 || fbError.code === 17;
        
        // Log detailed error information for debugging
        if (isRateLimit) {
          console.warn(`[Facebook API] Rate limit detected:`, {
            code: fbError.code,
            type: fbError.type,
            message: fbError.message,
            recipientId: options.recipientId,
          });
        } else {
          console.error(`[Facebook API] Error sending message:`, {
            code: fbError.code,
            type: fbError.type,
            message: fbError.message,
            subcode: fbError.error_subcode,
            recipientId: options.recipientId,
          });
        }

        return {
          success: false,
          error: isRateLimit ? 'RATE_LIMIT' : 'FACEBOOK_API_ERROR',
          message: `Facebook API Error (${fbError.code}): ${fbError.message}`,
          code: fbError.code,
          type: fbError.type,
        };
      }

      throw error;
    }
  }

  /**
   * Send Instagram DM
   */
  async sendInstagramMessage(recipientIGID: string, message: string) {
    try {
      const response = await axios.post(
        `${FB_GRAPH_URL}/me/messages`,
        {
          recipient: { id: recipientIGID },
          message: { text: message },
        },
        {
          params: { access_token: this.accessToken },
        }
      );
      return { success: true, data: response.data };
    } catch (error: any) {
      if (error.response?.data?.error) {
        const fbError = error.response.data.error;
        // Check for rate limit errors (codes: 613, 4, 17)
        const isRateLimit = fbError.code === 613 || fbError.code === 4 || fbError.code === 17;
        
        if (isRateLimit) {
          console.warn(`[Facebook API] Rate limit detected for Instagram message:`, {
            code: fbError.code,
            message: fbError.message,
            recipientId: recipientIGID,
          });
        }
        
        return {
          success: false,
          error: isRateLimit ? 'RATE_LIMIT' : 'FACEBOOK_API_ERROR',
          message: `Facebook API Error (${fbError.code}): ${fbError.message}`,
          code: fbError.code,
          type: fbError.type,
        };
      }
      throw error;
    }
  }

  /**
   * Send a message with media attachment (image or video)
   * 
   * Sends a media message to a recipient with optional text caption.
   * Media URL must be publicly accessible for Facebook to fetch it.
   * 
   * @param options - Media message options
   * @param options.recipientId - Facebook user ID or page-scoped ID of the recipient
   * @param options.message - Optional text message/caption
   * @param options.mediaUrl - URL of the media file (must be publicly accessible)
   * @param options.mediaType - Type of media: 'image' or 'video'
   * @param options.messageTag - Optional message tag for sending outside 24-hour window
   * @param options.notificationType - Notification type (default: 'REGULAR')
   * @returns Promise resolving to API response with message ID
   * @throws FacebookApiError if the API call fails
   * 
   * @example
   * ```typescript
   * await client.sendMediaMessage({
   *   recipientId: 'user_123',
   *   message: 'Check out this image!',
   *   mediaUrl: 'https://example.com/image.jpg',
   *   mediaType: 'image',
   *   messageTag: 'POST_PURCHASE_UPDATE',
   * });
   * ```
   */
  async sendMediaMessage(options: {
    recipientId: string;
    message?: string;
    mediaUrl: string;
    mediaType: 'image' | 'video';
    messageTag?: string;
    notificationType?: 'REGULAR' | 'SILENT_PUSH' | 'NO_PUSH';
  }) {
    const { recipientId, message, mediaUrl, mediaType, messageTag, notificationType = 'REGULAR' } = options;

    const payload: any = {
      recipient: { id: recipientId },
      notification_type: notificationType,
    };

    if (messageTag) {
      payload.messaging_type = 'MESSAGE_TAG';
      payload.tag = messageTag;
    } else {
      payload.messaging_type = 'RESPONSE';
    }

    // Build message payload with media
    // Note: Facebook Messenger API doesn't support text and attachment in the same message
    // If text is provided, we'll send it as a separate message after the media
    if (mediaType === 'image') {
      payload.message = {
        attachment: {
          type: 'image',
          payload: {
            url: mediaUrl,
            is_reusable: false,
          },
        },
      };
    } else if (mediaType === 'video') {
      payload.message = {
        attachment: {
          type: 'video',
          payload: {
            url: mediaUrl,
            is_reusable: false,
          },
        },
      };
    }

    try {
      // Validate media URL is accessible before sending
      console.log(`[Facebook API] Sending media message:`, {
        recipientId,
        mediaUrl,
        mediaType,
        hasText: !!message,
      });
      
      // First, send the media attachment
      const mediaResponse = await axios.post(
        `${FB_GRAPH_URL}/me/messages`,
        payload,
        {
          params: { access_token: this.accessToken },
        }
      );
      
      console.log(`[Facebook API] Media message sent successfully:`, {
        messageId: mediaResponse.data?.message_id,
        recipientId,
      });
      
      // If text message is provided, send it as a separate message after the media
      // Facebook Messenger API doesn't support text and attachment in the same message
      if (message && message.trim()) {
        try {
          // Small delay to ensure media is processed
          await new Promise(resolve => setTimeout(resolve, 300));
          
          const textPayload: any = {
            recipient: { id: recipientId },
            message: { text: message },
            notification_type: notificationType,
          };
          
          if (messageTag) {
            textPayload.messaging_type = 'MESSAGE_TAG';
            textPayload.tag = messageTag;
          } else {
            textPayload.messaging_type = 'RESPONSE';
          }
          
          const textResponse = await axios.post(
            `${FB_GRAPH_URL}/me/messages`,
            textPayload,
            {
              params: { access_token: this.accessToken },
            }
          );
          
          console.log(`[Facebook API] Text message sent after media:`, {
            messageId: textResponse.data?.message_id,
            recipientId,
          });
        } catch (textError: any) {
          // Log but don't fail - media was sent successfully
          const textFbError = textError.response?.data?.error;
          console.warn(`[Facebook API] Failed to send text after media (media was sent):`, {
            error: textFbError?.message || textError.message,
            code: textFbError?.code,
            recipientId,
          });
        }
      }
      
      return { success: true, data: mediaResponse.data };
    } catch (error: any) {
      if (error.response?.data?.error) {
        const fbError = error.response.data.error;

        if (fbError.code === 10903) {
          return {
            success: false,
            error: 'OUTSIDE_24HR_WINDOW',
            message: 'Cannot send message outside 24-hour window without appropriate message tag',
          };
        }

        if (fbError.code === 200) {
          return {
            success: false,
            error: 'INVALID_TAG_USAGE',
            message: 'Message tag usage does not match message content',
          };
        }

        // Check for rate limit errors (codes: 613, 4, 17)
        const isRateLimit = fbError.code === 613 || fbError.code === 4 || fbError.code === 17;
        
        // Log detailed error information for debugging
        if (isRateLimit) {
          console.warn(`[Facebook API] Rate limit detected for media message:`, {
            code: fbError.code,
            type: fbError.type,
            message: fbError.message,
            recipientId: options.recipientId,
          });
        } else {
          console.error(`[Facebook API] Error sending media message:`, {
            code: fbError.code,
            type: fbError.type,
            message: fbError.message,
            subcode: fbError.error_subcode,
            recipientId: options.recipientId,
            mediaUrl: mediaUrl, // Add mediaUrl to error log
          });
        }

        return {
          success: false,
          error: isRateLimit ? 'RATE_LIMIT' : 'FACEBOOK_API_ERROR',
          message: `Facebook API Error (${fbError.code}): ${fbError.message}`,
          code: fbError.code,
          type: fbError.type,
        };
      }

      throw error;
    }
  }

  /**
   * Fetch Messenger conversations in chunks of 50
   * Returns conversations in chunks, skipping already-fetched ones
   * Uses chunk-level caching to avoid re-fetching
   */
  async *fetchMessengerConversationsInChunks(
    pageId: string,
    chunkSize: number = 50,
    useCache: boolean = true
  ): AsyncGenerator<any[], void, unknown> {
    const fetchedIds = useCache ? this.getFetchedConversationIds(pageId, 'messenger') : new Set<string>();
    let nextUrl: string | null = null;
    let hasMore = true;
    let chunkIndex = 0;
    let totalFetched = 0;

    try {
      // Fetch first page
      const response = await axios.get(
        `${FB_GRAPH_URL}/${pageId}/conversations`,
        {
          params: {
            access_token: this.accessToken,
            fields: 'id,participants,updated_time,message_count',
            limit: chunkSize,
          },
          timeout: 30000,
        }
      );

      if (response.data.data && response.data.data.length > 0) {
        // Filter out already-fetched conversations
        const newConversations = response.data.data.filter(
          (convo: any) => !fetchedIds.has(convo.id)
        );

        if (newConversations.length > 0) {
          // Mark as fetched and update local set
          const newIds = new Set<string>(newConversations.map((c: any) => c.id as string));
          newIds.forEach((id: string) => fetchedIds.add(id));
          this.markConversationsAsFetched(pageId, 'messenger', newIds);
          
          // Cache chunk metadata (optional, for tracking)
          if (useCache) {
            this.setCachedChunk(pageId, 'messenger', chunkIndex, newIds);
          }

          totalFetched += newConversations.length;
          yield newConversations;
          chunkIndex++;
        }
        // Note: Even if all conversations were already fetched, we continue to next page
      }

      // Check if there's a next page
      nextUrl = response.data.paging?.next || null;
      hasMore = !!nextUrl;

      // Fetch subsequent pages in chunks
      while (hasMore && nextUrl) {
        try {
          const nextResponse = await axios.get(nextUrl, {
            timeout: 30000,
          });

          if (nextResponse.data.data && nextResponse.data.data.length > 0) {
            // Filter out already-fetched conversations
            const newConversations = nextResponse.data.data.filter(
              (convo: any) => !fetchedIds.has(convo.id)
            );

            if (newConversations.length > 0) {
              // Mark as fetched and update local set
              const newIds = new Set<string>(newConversations.map((c: any) => c.id as string));
              newIds.forEach((id: string) => fetchedIds.add(id));
              this.markConversationsAsFetched(pageId, 'messenger', newIds);
              
              // Cache chunk metadata (optional, for tracking)
              if (useCache) {
                this.setCachedChunk(pageId, 'messenger', chunkIndex, newIds);
              }

              totalFetched += newConversations.length;
              yield newConversations;
              chunkIndex++;
            }
            // Note: Even if all conversations were already fetched, we continue to next page
          }

          // Update pagination info
          nextUrl = nextResponse.data.paging?.next || null;
          hasMore = !!nextUrl && nextResponse.data.data?.length > 0;
        } catch (paginationError: any) {
          const fbError = paginationError.response?.data?.error;
          if (fbError && (fbError.code === 613 || fbError.code === 4 || fbError.code === 17)) {
            throw parseFacebookError(paginationError, `Rate limited while paginating conversations for Page ID: ${pageId}`);
          }
          console.error(`[Facebook API] Error fetching chunk ${chunkIndex}:`, paginationError.message);
          break;
        }
      }

      console.log(`[Facebook API] Fetched ${totalFetched} Messenger conversations in ${chunkIndex} chunks`);
    } catch (error: any) {
      throw parseFacebookError(error, `Failed to fetch conversations in chunks for Page ID: ${pageId}`);
    }
  }

  /**
   * Fetch Instagram conversations in chunks of 50
   * Returns conversations in chunks, skipping already-fetched ones
   * Uses chunk-level caching to avoid re-fetching
   */
  async *fetchInstagramConversationsInChunks(
    instagramAccountId: string,
    chunkSize: number = 50,
    useCache: boolean = true
  ): AsyncGenerator<any[], void, unknown> {
    const fetchedIds = useCache ? this.getFetchedConversationIds(instagramAccountId, 'instagram') : new Set<string>();
    let nextUrl: string | null = null;
    let hasMore = true;
    let chunkIndex = 0;
    let totalFetched = 0;

    try {
      // Fetch first page
      const response = await axios.get(
        `${FB_GRAPH_URL}/${instagramAccountId}/conversations`,
        {
          params: {
            access_token: this.accessToken,
            fields: 'id,participants,updated_time,message_count',
            limit: chunkSize,
          },
          timeout: 30000,
        }
      );

      if (response.data.data && response.data.data.length > 0) {
        // Filter out already-fetched conversations
        const newConversations = response.data.data.filter(
          (convo: any) => !fetchedIds.has(convo.id)
        );

        if (newConversations.length > 0) {
          // Mark as fetched and update local set
          const newIds = new Set<string>(newConversations.map((c: any) => c.id as string));
          newIds.forEach((id: string) => fetchedIds.add(id));
          this.markConversationsAsFetched(instagramAccountId, 'instagram', newIds);
          
          // Cache chunk metadata (optional, for tracking)
          if (useCache) {
            this.setCachedChunk(instagramAccountId, 'instagram', chunkIndex, newIds);
          }

          totalFetched += newConversations.length;
          yield newConversations;
          chunkIndex++;
        }
        // Note: Even if all conversations were already fetched, we continue to next page
      }

      // Check if there's a next page
      nextUrl = response.data.paging?.next || null;
      hasMore = !!nextUrl;

      // Fetch subsequent pages in chunks
      while (hasMore && nextUrl) {
        try {
          const nextResponse = await axios.get(nextUrl, {
            timeout: 30000,
          });

          if (nextResponse.data.data && nextResponse.data.data.length > 0) {
            // Filter out already-fetched conversations
            const newConversations = nextResponse.data.data.filter(
              (convo: any) => !fetchedIds.has(convo.id)
            );

            if (newConversations.length > 0) {
              // Mark as fetched and update local set
              const newIds = new Set<string>(newConversations.map((c: any) => c.id as string));
              newIds.forEach((id: string) => fetchedIds.add(id));
              this.markConversationsAsFetched(instagramAccountId, 'instagram', newIds);
              
              // Cache chunk metadata (optional, for tracking)
              if (useCache) {
                this.setCachedChunk(instagramAccountId, 'instagram', chunkIndex, newIds);
              }

              totalFetched += newConversations.length;
              yield newConversations;
              chunkIndex++;
            }
            // Note: Even if all conversations were already fetched, we continue to next page
          }

          // Update pagination info
          nextUrl = nextResponse.data.paging?.next || null;
          hasMore = !!nextUrl && nextResponse.data.data?.length > 0;
        } catch (paginationError: any) {
          const fbError = paginationError.response?.data?.error;
          if (fbError && (fbError.code === 613 || fbError.code === 4 || fbError.code === 17)) {
            throw parseFacebookError(paginationError, `Rate limited while paginating conversations for Instagram Account ID: ${instagramAccountId}`);
          }
          console.error(`[Facebook API] Error fetching chunk ${chunkIndex}:`, paginationError.message);
          break;
        }
      }

      console.log(`[Facebook API] Fetched ${totalFetched} Instagram conversations in ${chunkIndex} chunks`);
    } catch (error: any) {
      throw parseFacebookError(error, `Failed to fetch Instagram conversations in chunks for Account ID: ${instagramAccountId}`);
    }
  }

  /**
   * Fetch Messenger conversations incrementally until all needed participants are found
   * Stops early to avoid fetching thousands of conversations
   * Uses caching and deduplication to avoid duplicate API calls
   */
  async getMessengerConversationsUntilFound(
    pageId: string,
    neededParticipantIds: Set<string>,
    limit = 100
  ): Promise<any[]> {
    // Use deduplication to prevent duplicate requests
    const cacheKey = `getMessengerConversationsUntilFound:${pageId}:${Array.from(neededParticipantIds).sort().join(',')}`;
    return this.requestDeduplicator.execute(cacheKey, async () => {
      const allConversations: any[] = [];
      const foundParticipants = new Set<string>();
      let nextUrl: string | null = null;
      let hasMore = true;
      let pageCount = 0;
      
      // Maximum time limit: 10 minutes (600 seconds) to allow fetching many conversations
      // For 1400+ contacts, we may need to fetch thousands of conversations to find all participants
      // Increased from 5 minutes to 10 minutes to reduce failures
      const MAX_TIME_MS = 10 * 60 * 1000;
      const startTime = Date.now();

      try {
        // Fetch first page
        // Use 20 second timeout to allow more pages to be fetched within the total time limit
        const response = await axios.get(
          `${FB_GRAPH_URL}/${pageId}/conversations`,
          {
            params: {
              access_token: this.accessToken,
              fields: 'id,participants,updated_time,message_count',
              limit,
            },
            timeout: 20000,
          }
        );

      if (response.data.data) {
        allConversations.push(...response.data.data);
        pageCount++;
        
        // Check if we found all needed participants in first page
        for (const convo of response.data.data) {
          if (!convo.participants?.data) continue;
          for (const participant of convo.participants.data) {
            if (neededParticipantIds.has(participant.id)) {
              foundParticipants.add(participant.id);
            }
          }
        }
      }

      // Check if we found all needed participants
      if (foundParticipants.size >= neededParticipantIds.size) {
        console.log(`[Facebook API] Found all ${foundParticipants.size}/${neededParticipantIds.size} participants in first ${pageCount} page(s), stopping early`);
        return allConversations;
      } else {
        console.log(`[Facebook API] Found ${foundParticipants.size}/${neededParticipantIds.size} participants in first page, continuing to fetch more...`);
      }

      // Check if there's a next page
      nextUrl = response.data.paging?.next || null;
      hasMore = !!nextUrl;

      // Fetch subsequent pages until we find all participants or hit time limit
      let consecutiveTimeouts = 0;
      const MAX_CONSECUTIVE_TIMEOUTS = 5; // Allow up to 5 consecutive timeouts before giving up
      
      while (hasMore && nextUrl && foundParticipants.size < neededParticipantIds.size) {
        // Check time limit
        if (Date.now() - startTime > MAX_TIME_MS) {
          console.warn(`[Facebook API] Time limit reached (${MAX_TIME_MS}ms), stopping pagination. Found ${foundParticipants.size}/${neededParticipantIds.size} participants so far.`);
          break;
        }
        
        try {
          // Reduce per-page timeout to 20 seconds to allow more pages to be fetched
          // This helps when Facebook API is slow but still responsive
          const nextResponse = await axios.get(nextUrl, {
            timeout: 20000,
          });
          
          // Reset timeout counter on success
          consecutiveTimeouts = 0;
          
          if (nextResponse.data.data && nextResponse.data.data.length > 0) {
            allConversations.push(...nextResponse.data.data);
            pageCount++;
            
            // Check if we found all needed participants
            for (const convo of nextResponse.data.data) {
              if (!convo.participants?.data) continue;
              for (const participant of convo.participants.data) {
                if (neededParticipantIds.has(participant.id)) {
                  foundParticipants.add(participant.id);
                }
              }
            }
            
            // Stop if we found all participants
            if (foundParticipants.size >= neededParticipantIds.size) {
              console.log(`[Facebook API] Found all ${foundParticipants.size}/${neededParticipantIds.size} participants after ${pageCount} pages, stopping early`);
              break;
            } else {
              // Log progress every 10 pages or when we find new participants
              if (pageCount % 10 === 0 || foundParticipants.size > 0) {
                console.log(`[Facebook API] Progress: Found ${foundParticipants.size}/${neededParticipantIds.size} participants after ${pageCount} pages (${allConversations.length} conversations fetched)...`);
              }
            }
          }

          // Update pagination info
          nextUrl = nextResponse.data.paging?.next || null;
          hasMore = !!nextUrl && nextResponse.data.data?.length > 0;

          // No delay - Facebook API can handle rapid pagination, and we have error handling for rate limits
        } catch (paginationError: any) {
          const errorMsg = paginationError.message || 'Unknown error';
          const isTimeout = errorMsg.includes('timeout') || errorMsg.includes('ECONNABORTED');
          
          console.error(`[Facebook API] Error fetching page ${pageCount + 1} of Messenger conversations:`, errorMsg);
          
          // If we get rate limited, throw the error
          const fbError = paginationError.response?.data?.error;
          if (fbError && (fbError.code === 613 || fbError.code === 4 || fbError.code === 17)) {
            throw parseFacebookError(paginationError, `Rate limited while paginating conversations for Page ID: ${pageId}`);
          }
          
          // For timeouts: Continue to next page if we haven't hit max consecutive timeouts
          if (isTimeout) {
            consecutiveTimeouts++;
            console.warn(`[Facebook API] Page ${pageCount + 1} timed out (${consecutiveTimeouts}/${MAX_CONSECUTIVE_TIMEOUTS} consecutive), found ${foundParticipants.size}/${neededParticipantIds.size} participants so far`);
            
            if (consecutiveTimeouts >= MAX_CONSECUTIVE_TIMEOUTS) {
              console.warn(`[Facebook API] Too many consecutive timeouts (${consecutiveTimeouts}), stopping pagination. Found ${foundParticipants.size}/${neededParticipantIds.size} participants so far.`);
              break;
            }
            
            // Try to continue - if we have a nextUrl from a previous successful page, we can try it
            // But if we don't have nextUrl, we'll break on next iteration
            // For now, we'll break and return what we have
            // The issue is that without the response, we don't have the next URL
            console.warn(`[Facebook API] Cannot continue without next URL after timeout. Returning ${allConversations.length} conversations fetched so far.`);
            break;
          }
          
          // For other pagination errors, log but continue with what we have
          console.warn(`[Facebook API] Failed to fetch page ${pageCount + 1}, stopping pagination. Found ${foundParticipants.size}/${neededParticipantIds.size} participants so far.`);
          break;
        }
      }

        console.log(`[Facebook API] Fetched ${pageCount} pages, found ${foundParticipants.size}/${neededParticipantIds.size} participants`);
        
        // Cache the results (even partial results are useful)
        this.setCachedConversations(pageId, 'messenger', allConversations);
        
        return allConversations;
      } catch (error: any) {
        // CRITICAL: Return partial results instead of throwing, so pipeline analysis can continue
        // This prevents all contacts from failing when conversation fetch has issues
        const errorMsg = error.message || 'Unknown error';
        console.error(`[Facebook API] Error in getMessengerConversationsUntilFound: ${errorMsg}`);
        console.warn(`[Facebook API] Returning ${allConversations.length} conversations already fetched (partial results)`);
        
        // Only throw for rate limits - for other errors, return partial results
        const fbError = error.response?.data?.error;
        if (fbError && (fbError.code === 613 || fbError.code === 4 || fbError.code === 17)) {
          throw parseFacebookError(error, `Rate limited while fetching conversations for Page ID: ${pageId}`);
        }
        
        // Cache partial results - better than nothing
        if (allConversations.length > 0) {
          this.setCachedConversations(pageId, 'messenger', allConversations, 2 * 60 * 1000); // Shorter TTL for partial results
        }
        
        // Return whatever we have - better than 0 conversations
        return allConversations;
      }
    });
  }

  /**
   * Fetch Messenger conversations with messages (includes sender names)
   * Automatically handles pagination to fetch ALL conversations
   * Uses caching and request deduplication to avoid duplicate API calls
   */
  async getMessengerConversations(pageId: string, limit = 100, useCache = true) {
    // Check cache first
    if (useCache) {
      const cached = this.getCachedConversations(pageId, 'messenger');
      if (cached) {
        console.log(`[Facebook API] Using cached conversations for page ${pageId} (${cached.length} conversations)`);
        return cached;
      }
    }

    // Use deduplication to prevent duplicate requests
    const cacheKey = `getMessengerConversations:${pageId}:${limit}`;
    return this.requestDeduplicator.execute(cacheKey, async () => {
      const allConversations: any[] = [];
      let nextUrl: string | null = null;
      let hasMore = true;

      try {
        // Fetch first page
        const response = await axios.get(
          `${FB_GRAPH_URL}/${pageId}/conversations`,
          {
            params: {
              access_token: this.accessToken,
              fields: 'id,participants,updated_time,message_count',
              limit,
            },
          }
        );

      if (response.data.data) {
        allConversations.push(...response.data.data);
      }

      // Check if there's a next page
      nextUrl = response.data.paging?.next || null;
      hasMore = !!nextUrl;

      // Fetch all subsequent pages with progress updates
      let pageCount = 1;
      // No limit - fetch all conversations
      while (hasMore && nextUrl) {
        try {
          if (pageCount % 10 === 0) {
            console.log(`[Facebook API] Fetched ${pageCount} pages, ${allConversations.length} Messenger conversations so far...`);
          }
          
          // Add timeout per page request (30 seconds - increased from 20 to handle slow Facebook API responses)
          const nextResponse = await Promise.race([
            axios.get(nextUrl, {
              timeout: 30000, // 30 second timeout per request (increased from 20)
            }),
            new Promise((_, reject) => 
              setTimeout(() => reject(new Error(`Page ${pageCount} request timed out after 30 seconds`)), 30000)
            )
          ]) as any;
          
          if (nextResponse.data.data && nextResponse.data.data.length > 0) {
            allConversations.push(...nextResponse.data.data);
          }

          // Update pagination info
          nextUrl = nextResponse.data.paging?.next || null;
          hasMore = !!nextUrl && nextResponse.data.data?.length > 0;
          pageCount++;

          // No delay - Facebook API can handle rapid pagination, and we have error handling for rate limits
        } catch (paginationError: any) {
          console.error(`[Facebook API] Error fetching page ${pageCount} of Messenger conversations:`, paginationError);
          
          // If we get rate limited, throw the error
          const fbError = paginationError.response?.data?.error;
          if (fbError && (fbError.code === 613 || fbError.code === 4 || fbError.code === 17)) {
            throw parseFacebookError(paginationError, `Rate limited while paginating conversations for Page ID: ${pageId}`);
          }
          
          // Retry logic: Try up to 2 retries for transient errors
          const MAX_RETRIES = 2;
          let retryCount = 0;
          let retrySuccess = false;
          
          // Only retry if we have a valid nextUrl
          if (!nextUrl) {
            console.warn(`[Facebook API] No nextUrl available for retry, breaking pagination`);
            break;
          }
          
          while (retryCount < MAX_RETRIES && !retrySuccess && nextUrl) {
            retryCount++;
            console.warn(`[Facebook API] Retrying page ${pageCount} (attempt ${retryCount}/${MAX_RETRIES})...`);
            
            try {
              await new Promise(resolve => setTimeout(resolve, 2000 * retryCount)); // Exponential backoff
              const retryResponse = await Promise.race([
                axios.get(nextUrl, {
                  timeout: 30000,
                }),
                new Promise((_, reject) => 
                  setTimeout(() => reject(new Error(`Retry ${retryCount} timed out`)), 30000)
                )
              ]) as any;
              
              if (retryResponse.data.data && retryResponse.data.data.length > 0) {
                allConversations.push(...retryResponse.data.data);
                retrySuccess = true;
                
                // Update pagination info for next iteration
                nextUrl = retryResponse.data.paging?.next || null;
                hasMore = !!nextUrl && retryResponse.data.data.length > 0;
                console.log(`[Facebook API] ✅ Retry successful for page ${pageCount}, continuing pagination...`);
                break; // Exit retry loop, continue with pagination
              }
            } catch (retryError: any) {
              console.warn(`[Facebook API] Retry ${retryCount} failed for page ${pageCount}:`, retryError.message || retryError);
              if (retryCount >= MAX_RETRIES) {
                // All retries exhausted
                const errorType = paginationError.message?.includes('timeout') || paginationError.code === 'ECONNABORTED' 
                  ? 'timeout' 
                  : 'error';
                console.warn(`[Facebook API] ⚠️ All retries exhausted for page ${pageCount} (${errorType}), continuing with ${allConversations.length} conversations already fetched`);
                console.warn(`[Facebook API] This may result in incomplete conversation coverage. Some contacts may fail analysis.`);
                break; // Exit pagination loop
              }
            }
          }
          
          // If retry failed, break out of pagination
          if (!retrySuccess) {
            break;
          }
        }
      }
      
      // All pages fetched

        // Cache the results
        if (useCache) {
          this.setCachedConversations(pageId, 'messenger', allConversations);
        }

        return allConversations;
      } catch (error: any) {
        throw parseFacebookError(error, `Failed to fetch conversations for Page ID: ${pageId}`);
      }
    });
  }

  /**
   * Stream Messenger conversations as they're fetched (yields conversations page by page)
   * This allows processing to start immediately instead of waiting for all conversations
   * @param pageId - Facebook page ID
   * @param limit - Number of conversations per page
   * @param signal - Optional AbortSignal for cancellation
   */
  async *fetchMessengerConversationsStream(
    pageId: string,
    limit = 500,
    signal?: AbortSignal
  ) {
    let nextUrl: string | null = null;
    let hasMore = true;
    let pageCount = 0;

    try {
      // Check if already cancelled
      if (signal?.aborted) {
        return;
      }

      // Fetch first page with timeout and cancellation support
      const response = await axios.get(
        `${FB_GRAPH_URL}/${pageId}/conversations`,
        {
          params: {
            access_token: this.accessToken,
            fields: 'id,participants,updated_time,message_count',
            limit,
          },
          timeout: 30000, // 30 second timeout for first request
          signal, // Support cancellation
        }
      );

      const conversations = response.data.data || [];
      
      // Yield each conversation immediately
      for (const convo of conversations) {
        yield convo;
      }

      // Check if there's a next page
      nextUrl = response.data.paging?.next || null;
      hasMore = !!nextUrl;
      pageCount = 1;

      // Fetch subsequent pages and yield conversations as they arrive
      while (hasMore && nextUrl) {
        // Check for cancellation before each request
        if (signal?.aborted) {
          console.log('[Facebook API] Messenger conversation stream cancelled');
          return;
        }

        try {
          if (pageCount % 10 === 0) {
            console.log(`[Facebook API] Streaming: Fetched ${pageCount} pages of Messenger conversations so far...`);
          }

          const nextResponse = await axios.get(nextUrl, {
            timeout: 30000, // 30 second timeout per request
            signal, // Support cancellation
          });

          const nextConversations = nextResponse.data.data || [];

          // Yield each conversation immediately
          for (const convo of nextConversations) {
            yield convo;
          }

          // Update pagination info
          nextUrl = nextResponse.data.paging?.next || null;
          hasMore = !!nextUrl && nextConversations.length > 0;
          pageCount++;

          // No delay - Facebook API can handle rapid pagination, and we have error handling for rate limits
        } catch (paginationError: any) {
          console.error('Error fetching next page of Messenger conversations:', paginationError);

          // If we get rate limited, throw the error
          const fbError = paginationError.response?.data?.error;
          if (fbError && (fbError.code === 613 || fbError.code === 4 || fbError.code === 17)) {
            throw parseFacebookError(paginationError, `Rate limited while paginating conversations for Page ID: ${pageId}`);
          }

          // For other pagination errors, log but continue with what we have
          // Retry once before giving up
          if (pageCount < 3) {
            console.warn(`[Facebook API] Retrying page ${pageCount + 1} after error...`);
            await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds before retry
            continue; // Retry the same page
          }
          console.warn(`[Facebook API] Failed to fetch page ${pageCount + 1} after retries, continuing with ${pageCount} pages already fetched`);
          break;
        }
      }
    } catch (error: any) {
      throw parseFacebookError(error, `Failed to fetch conversations for Page ID: ${pageId}`);
    }
  }

  /**
   * Fetch ALL messages for a specific conversation with pagination
   * This ensures we get the complete conversation history for accurate AI analysis
   * @param conversationId - Conversation ID
   * @param maxPages - Maximum number of pages to fetch
   * @param signal - Optional AbortSignal for cancellation
   */
  async getAllMessagesForConversation(
    conversationId: string,
    maxPages: number = 50,
    signal?: AbortSignal
  ): Promise<any[]> {
    const allMessages: any[] = [];
    let nextUrl: string | null = `${FB_GRAPH_URL}/${conversationId}/messages`;
    let hasMore = true;
    let pageCount = 0;
    const MAX_MESSAGE_PAGES = maxPages; // Safety limit

    try {
      while (hasMore && nextUrl && pageCount < MAX_MESSAGE_PAGES) {
        // Check for cancellation before each request
        if (signal?.aborted) {
          console.log(`[Facebook Client] Message fetch cancelled for conversation ${conversationId}`);
          break;
        }

        try {
          // Add timeout per page (30 seconds - increased from 15 for better reliability)
          const response: any = await Promise.race([
            axios.get(nextUrl, {
              params: {
                access_token: this.accessToken,
                fields: 'from,message,created_time',
                limit: 100, // 100 messages per page
              },
              timeout: 30000, // 30 second timeout per request (increased from 15)
              signal, // Support cancellation
            }),
            new Promise((_, reject) => {
              const timeoutId = setTimeout(() => reject(new Error(`Message page ${pageCount + 1} request timed out after 30 seconds`)), 30000);
              // Clear timeout if cancelled
              if (signal) {
                signal.addEventListener('abort', () => {
                  clearTimeout(timeoutId);
                  reject(new Error('Request cancelled'));
                });
              }
            })
          ]) as any;

          if (response.data.data?.length > 0) {
            allMessages.push(...response.data.data);
          }

          nextUrl = response.data.paging?.next || null;
          hasMore = !!nextUrl && response.data.data?.length > 0;
          pageCount++;

          // No delay - Facebook API can handle rapid pagination, and we have error handling for rate limits
        } catch (pageError: any) {
          console.error(`[Facebook Client] Error fetching message page ${pageCount + 1} for conversation ${conversationId}:`, pageError);
          
          // If timeout, continue with what we have
          if (pageError.message?.includes('timeout') || pageError.code === 'ECONNABORTED') {
            console.warn(`[Facebook Client] Message page ${pageCount + 1} timed out, continuing with ${allMessages.length} messages already fetched`);
            break;
          }
          
          // For other errors, return what we have
          break;
        }
      }

      if (pageCount >= MAX_MESSAGE_PAGES) {
        console.warn(`[Facebook Client] Reached maximum message page limit (${MAX_MESSAGE_PAGES}) for conversation ${conversationId}. Fetched ${allMessages.length} messages total.`);
      }

      console.log(`[Facebook Client] Fetched ${allMessages.length} total messages for conversation ${conversationId} (${pageCount} pages)`);
      return allMessages;
    } catch (error: any) {
      console.error(`[Facebook Client] Error fetching all messages for conversation ${conversationId}:`, error);
      return allMessages; // Return what we got so far
    }
  }

  /**
   * Fetch limited messages for a conversation (faster for analysis)
   * Fetches only the most recent messages up to the limit
   * @param conversationId - Conversation ID
   * @param limit - Maximum number of messages to fetch
   * @param signal - Optional AbortSignal for cancellation
   */
  async getRecentMessagesForConversation(
    conversationId: string,
    limit: number = 100,
    signal?: AbortSignal
  ): Promise<any[]> {
    try {
      // Check if already cancelled
      if (signal?.aborted) {
        return [];
      }

      const response: any = await axios.get(`${FB_GRAPH_URL}/${conversationId}/messages`, {
        params: {
          access_token: this.accessToken,
          fields: 'from,message,created_time',
          limit: Math.min(limit, 100), // Facebook API max is 100 per request
        },
        timeout: 15000, // Reduced to 15 second timeout for faster failure
        signal, // Support cancellation
      });

      const messages = response.data.data || [];
      console.log(`[Facebook Client] Fetched ${messages.length} recent messages for conversation ${conversationId}`);
      return messages;
    } catch (error: any) {
      console.error(`[Facebook Client] Error fetching recent messages for conversation ${conversationId}:`, error);
      return [];
    }
  }

  /**
   * Batch get Messenger profiles
   * Facebook Graph API supports batch requests up to 50 requests per batch
   */
  async batchGetMessengerProfiles(psids: string[]): Promise<Map<string, any>> {
    if (psids.length === 0) {
      return new Map();
    }

    // Facebook batch API limit is 50 requests per batch
    const BATCH_SIZE = 50;
    const results = new Map<string, any>();

    // Process in batches
    for (let i = 0; i < psids.length; i += BATCH_SIZE) {
      const batch = psids.slice(i, i + BATCH_SIZE);
      
      // Create batch requests - Facebook Graph API batch format
      const batchRequests = batch.map((psid) => ({
        method: 'GET',
        relative_url: `${psid}?fields=first_name,last_name,profile_pic,locale,timezone`,
      }));

      try {
        // Facebook Graph API batch endpoint format
        // Batch parameter must be a JSON string of request objects
        // Can be sent as query parameter or form data
        const response = await axios.post(
          `${FB_GRAPH_URL}/`,
          null,
          {
            params: {
              access_token: this.accessToken,
              batch: JSON.stringify(batchRequests),
            },
          }
        );

        // Parse batch response
        if (Array.isArray(response.data)) {
          response.data.forEach((item: any, index: number) => {
            if (item.code === 200 && item.body) {
              try {
                const profileData = typeof item.body === 'string' ? JSON.parse(item.body) : item.body;
                const psid = batch[index];
                results.set(psid, profileData);
              } catch (parseError) {
                console.error(`[Facebook API] Failed to parse profile response for ${batch[index]}:`, parseError);
              }
            } else {
              console.warn(`[Facebook API] Failed to get profile for ${batch[index]}:`, item.body || item.error);
            }
          });
        }
      } catch (error: any) {
        console.error(`[Facebook API] Batch profile request failed:`, error);
        // Continue with other batches even if one fails
      }
    }

    return results;
  }

  /**
   * Get user profile (Messenger)
   * Uses deduplication to prevent duplicate requests
   */
  async getMessengerProfile(psid: string) {
    const cacheKey = `getMessengerProfile:${psid}`;
    return this.requestDeduplicator.execute(cacheKey, async () => {
      try {
        const response = await axios.get(`${FB_GRAPH_URL}/${psid}`, {
          params: {
            access_token: this.accessToken,
            fields: 'first_name,last_name,profile_pic,locale,timezone',
          },
        });
        return response.data;
      } catch (error: any) {
        throw parseFacebookError(error, `Failed to get profile for PSID: ${psid}`);
      }
    });
  }

  /**
   * Get Instagram conversations with messages (includes sender names)
   * Automatically handles pagination to fetch ALL conversations
   */
  /**
   * Fetch Instagram conversations incrementally until all needed participants are found
   * Stops early to avoid fetching thousands of conversations
   * Uses caching and deduplication to avoid duplicate API calls
   */
  async getInstagramConversationsUntilFound(
    igAccountId: string,
    neededParticipantIds: Set<string>,
    limit = 100
  ): Promise<any[]> {
    // Use deduplication to prevent duplicate requests
    const cacheKey = `getInstagramConversationsUntilFound:${igAccountId}:${Array.from(neededParticipantIds).sort().join(',')}`;
    return this.requestDeduplicator.execute(cacheKey, async () => {
      const allConversations: any[] = [];
      const foundParticipants = new Set<string>();
      let nextUrl: string | null = null;
      let hasMore = true;
      let pageCount = 0;
      
      // Maximum time limit: 10 minutes (600 seconds) to allow fetching many conversations
      // For 1400+ contacts, we may need to fetch thousands of conversations to find all participants
      // Increased from 5 minutes to 10 minutes to reduce failures
      const MAX_TIME_MS = 10 * 60 * 1000;
      const startTime = Date.now();

      try {
        // Fetch first page
        // Use 20 second timeout to allow more pages to be fetched within the total time limit
        const response = await axios.get(
          `${FB_GRAPH_URL}/${igAccountId}/conversations`,
          {
            params: {
              access_token: this.accessToken,
              fields: 'id,participants,updated_time,message_count',
              limit,
            },
            timeout: 20000,
          }
        );

      if (response.data.data) {
        allConversations.push(...response.data.data);
        pageCount++;
        
        // Check if we found all needed participants in first page
        for (const convo of response.data.data) {
          if (!convo.participants?.data) continue;
          for (const participant of convo.participants.data) {
            if (neededParticipantIds.has(participant.id)) {
              foundParticipants.add(participant.id);
            }
          }
        }
      }

      // Check if we found all needed participants
      if (foundParticipants.size >= neededParticipantIds.size) {
        console.log(`[Facebook API] Found all ${foundParticipants.size} IG participants in first ${pageCount} page(s), stopping early`);
        return allConversations;
      }

      // Check if there's a next page
      nextUrl = response.data.paging?.next || null;
      hasMore = !!nextUrl;

      // Fetch subsequent pages until we find all participants or hit time limit
      while (hasMore && nextUrl && foundParticipants.size < neededParticipantIds.size) {
        // Check time limit
        if (Date.now() - startTime > MAX_TIME_MS) {
          console.warn(`[Facebook API] Time limit reached (${MAX_TIME_MS}ms), stopping Instagram pagination. Found ${foundParticipants.size}/${neededParticipantIds.size} participants so far.`);
          break;
        }
        
        try {
          // Reduce per-page timeout to 20 seconds to allow more pages to be fetched
          const nextResponse = await axios.get(nextUrl, {
            timeout: 20000,
          });
          
          if (nextResponse.data.data && nextResponse.data.data.length > 0) {
            allConversations.push(...nextResponse.data.data);
            pageCount++;
            
            // Check if we found all needed participants
            for (const convo of nextResponse.data.data) {
              if (!convo.participants?.data) continue;
              for (const participant of convo.participants.data) {
                if (neededParticipantIds.has(participant.id)) {
                  foundParticipants.add(participant.id);
                }
              }
            }
            
            // Stop if we found all participants
            if (foundParticipants.size >= neededParticipantIds.size) {
              console.log(`[Facebook API] Found all ${foundParticipants.size}/${neededParticipantIds.size} IG participants after ${pageCount} pages, stopping early`);
              break;
            } else {
              // Log progress every 10 pages
              if (pageCount % 10 === 0) {
                console.log(`[Facebook API] Instagram progress: Found ${foundParticipants.size}/${neededParticipantIds.size} participants after ${pageCount} pages...`);
              }
            }
          }

          // Update pagination info
          nextUrl = nextResponse.data.paging?.next || null;
          hasMore = !!nextUrl && nextResponse.data.data?.length > 0;

          // No delay - Facebook API can handle rapid pagination, and we have error handling for rate limits
        } catch (paginationError: any) {
          const errorMsg = paginationError.message || 'Unknown error';
          const isTimeout = errorMsg.includes('timeout') || errorMsg.includes('ECONNABORTED');
          
          console.error(`[Facebook API] Error fetching page ${pageCount + 1} of Instagram conversations:`, errorMsg);
          
          // If we get rate limited, throw the error
          const fbError = paginationError.response?.data?.error;
          if (fbError && (fbError.code === 613 || fbError.code === 4 || fbError.code === 17)) {
            throw parseFacebookError(paginationError, `Rate limited while paginating Instagram conversations for Account ID: ${igAccountId}`);
          }
          
          // For timeouts: Log but continue if we haven't hit max consecutive timeouts
          if (isTimeout) {
            console.warn(`[Facebook API] Instagram page ${pageCount + 1} timed out, found ${foundParticipants.size}/${neededParticipantIds.size} participants so far`);
            // Can't continue without nextUrl, so break
            break;
          }
          
          // For other pagination errors, log but continue with what we have
          console.warn(`[Facebook API] Failed to fetch Instagram page ${pageCount + 1}, stopping pagination. Found ${foundParticipants.size}/${neededParticipantIds.size} participants so far.`);
          break;
        }
      }

        console.log(`[Facebook API] Fetched ${pageCount} IG pages, found ${foundParticipants.size}/${neededParticipantIds.size} participants`);
        
        // Cache the results (even partial results are useful)
        this.setCachedConversations(igAccountId, 'instagram', allConversations);
        
        return allConversations;
      } catch (error: any) {
        // CRITICAL: Return partial results instead of throwing, so pipeline analysis can continue
        // This prevents all contacts from failing when conversation fetch has issues
        const errorMsg = error.message || 'Unknown error';
        console.error(`[Facebook API] Error in getInstagramConversationsUntilFound: ${errorMsg}`);
        console.warn(`[Facebook API] Returning ${allConversations.length} Instagram conversations already fetched (partial results)`);
        
        // Only throw for rate limits - for other errors, return partial results
        const fbError = error.response?.data?.error;
        if (fbError && (fbError.code === 613 || fbError.code === 4 || fbError.code === 17)) {
          throw parseFacebookError(error, `Rate limited while fetching Instagram conversations for Account ID: ${igAccountId}`);
        }
        
        // Cache partial results - better than nothing
        if (allConversations.length > 0) {
          this.setCachedConversations(igAccountId, 'instagram', allConversations, 2 * 60 * 1000); // Shorter TTL for partial results
        }
        
        // Return whatever we have - better than 0 conversations
        return allConversations;
      }
    });
  }

  async getInstagramConversations(igAccountId: string, limit = 100, useCache = true) {
    // Check cache first
    if (useCache) {
      const cached = this.getCachedConversations(igAccountId, 'instagram');
      if (cached) {
        console.log(`[Facebook API] Using cached Instagram conversations for account ${igAccountId} (${cached.length} conversations)`);
        return cached;
      }
    }

    // Use deduplication to prevent duplicate requests
    const cacheKey = `getInstagramConversations:${igAccountId}:${limit}`;
    return this.requestDeduplicator.execute(cacheKey, async () => {
      const allConversations: any[] = [];
      let nextUrl: string | null = null;
      let hasMore = true;

      try {
        // Fetch first page
        const response = await axios.get(
          `${FB_GRAPH_URL}/${igAccountId}/conversations`,
          {
            params: {
              access_token: this.accessToken,
              fields: 'id,participants,updated_time,message_count',
              limit,
            },
          }
        );

      if (response.data.data) {
        allConversations.push(...response.data.data);
      }

      // Check if there's a next page
      nextUrl = response.data.paging?.next || null;
      hasMore = !!nextUrl;

      // Fetch all subsequent pages with progress updates
      let pageCount = 1;
      while (hasMore && nextUrl) {
        try {
          if (pageCount % 10 === 0) {
            console.log(`[Facebook API] Fetched ${pageCount} pages, ${allConversations.length} Instagram conversations so far...`);
          }
          
          // Add timeout per page request (30 seconds)
          const nextResponse = await Promise.race([
            axios.get(nextUrl, {
              timeout: 30000, // 30 second timeout per request
            }),
            new Promise((_, reject) => 
              setTimeout(() => reject(new Error(`Page ${pageCount} request timed out after 30 seconds`)), 30000)
            )
          ]) as any;
          
          if (nextResponse.data.data && nextResponse.data.data.length > 0) {
            allConversations.push(...nextResponse.data.data);
          }

          // Update pagination info
          nextUrl = nextResponse.data.paging?.next || null;
          hasMore = !!nextUrl && nextResponse.data.data?.length > 0;
          pageCount++;

          // No delay - Facebook API can handle rapid pagination, and we have error handling for rate limits
        } catch (paginationError: any) {
          console.error(`[Facebook API] Error fetching page ${pageCount} of Instagram conversations:`, paginationError);
          
          // If we get rate limited, throw the error
          const fbError = paginationError.response?.data?.error;
          if (fbError && (fbError.code === 613 || fbError.code === 4 || fbError.code === 17)) {
            throw parseFacebookError(paginationError, `Rate limited while paginating Instagram conversations for Account ID: ${igAccountId}`);
          }
          
          // Retry logic: Try up to 2 retries for transient errors
          const MAX_RETRIES = 2;
          let retryCount = 0;
          let retrySuccess = false;
          
          // Only retry if we have a valid nextUrl
          if (!nextUrl) {
            console.warn(`[Facebook API] No nextUrl available for Instagram retry, breaking pagination`);
            break;
          }
          
          while (retryCount < MAX_RETRIES && !retrySuccess && nextUrl) {
            retryCount++;
            console.warn(`[Facebook API] Retrying Instagram page ${pageCount} (attempt ${retryCount}/${MAX_RETRIES})...`);
            
            try {
              await new Promise(resolve => setTimeout(resolve, 2000 * retryCount)); // Exponential backoff
              const retryResponse = await Promise.race([
                axios.get(nextUrl, {
                  timeout: 30000,
                }),
                new Promise((_, reject) => 
                  setTimeout(() => reject(new Error(`Retry ${retryCount} timed out`)), 30000)
                )
              ]) as any;
              
              if (retryResponse.data.data && retryResponse.data.data.length > 0) {
                allConversations.push(...retryResponse.data.data);
                retrySuccess = true;
                
                // Update pagination info for next iteration
                nextUrl = retryResponse.data.paging?.next || null;
                hasMore = !!nextUrl && retryResponse.data.data.length > 0;
                console.log(`[Facebook API] ✅ Retry successful for Instagram page ${pageCount}, continuing pagination...`);
                break; // Exit retry loop, continue with pagination
              }
            } catch (retryError: any) {
              console.warn(`[Facebook API] Retry ${retryCount} failed for Instagram page ${pageCount}:`, retryError.message || retryError);
              if (retryCount >= MAX_RETRIES) {
                // All retries exhausted
                const errorType = paginationError.message?.includes('timeout') || paginationError.code === 'ECONNABORTED' 
                  ? 'timeout' 
                  : 'error';
                console.warn(`[Facebook API] ⚠️ All retries exhausted for Instagram page ${pageCount} (${errorType}), continuing with ${allConversations.length} conversations already fetched`);
                console.warn(`[Facebook API] This may result in incomplete conversation coverage. Some contacts may fail analysis.`);
                break; // Exit pagination loop
              }
            }
          }
          
          // If retry failed, break out of pagination
          if (!retrySuccess) {
            break;
          }
        }
      }

        // Cache the results
        if (useCache) {
          this.setCachedConversations(igAccountId, 'instagram', allConversations);
        }

        return allConversations;
      } catch (error: any) {
        throw parseFacebookError(error, `Failed to fetch Instagram conversations for Account ID: ${igAccountId}`);
      }
    });
  }

  /**
   * Stream Instagram conversations as they're fetched (yields conversations page by page)
   * This allows processing to start immediately instead of waiting for all conversations
   * @param igAccountId - Instagram account ID
   * @param limit - Number of conversations per page
   * @param signal - Optional AbortSignal for cancellation
   */
  async *fetchInstagramConversationsStream(
    igAccountId: string,
    limit = 500,
    signal?: AbortSignal
  ) {
    let nextUrl: string | null = null;
    let hasMore = true;
    let pageCount = 0;

    try {
      // Check if already cancelled
      if (signal?.aborted) {
        return;
      }

      // Fetch first page with timeout and cancellation support
      const response = await axios.get(
        `${FB_GRAPH_URL}/${igAccountId}/conversations`,
        {
          params: {
            access_token: this.accessToken,
            fields: 'id,participants,updated_time,message_count',
            limit,
          },
          timeout: 30000, // 30 second timeout for first request
          signal, // Support cancellation
        }
      );

      const conversations = response.data.data || [];

      // Yield each conversation immediately
      for (const convo of conversations) {
        yield convo;
      }

      // Check if there's a next page
      nextUrl = response.data.paging?.next || null;
      hasMore = !!nextUrl;
      pageCount = 1;

      // Fetch subsequent pages and yield conversations as they arrive
      while (hasMore && nextUrl) {
        // Check for cancellation before each request
        if (signal?.aborted) {
          console.log('[Facebook API] Instagram conversation stream cancelled');
          return;
        }

        try {
          if (pageCount % 10 === 0) {
            console.log(`[Facebook API] Streaming: Fetched ${pageCount} pages of Instagram conversations so far...`);
          }

          const nextResponse = await axios.get(nextUrl, {
            timeout: 30000, // 30 second timeout per request
            signal, // Support cancellation
          });

          const nextConversations = nextResponse.data.data || [];

          // Yield each conversation immediately
          for (const convo of nextConversations) {
            yield convo;
          }

          // Update pagination info
          nextUrl = nextResponse.data.paging?.next || null;
          hasMore = !!nextUrl && nextConversations.length > 0;
          pageCount++;

          // No delay - Facebook API can handle rapid pagination, and we have error handling for rate limits
        } catch (paginationError: any) {
          console.error('Error fetching next page of Instagram conversations:', paginationError);

          // If we get rate limited, throw the error
          const fbError = paginationError.response?.data?.error;
          if (fbError && (fbError.code === 613 || fbError.code === 4 || fbError.code === 17)) {
            throw parseFacebookError(paginationError, `Rate limited while paginating Instagram conversations for Account ID: ${igAccountId}`);
          }

          // For other pagination errors, log but continue with what we have
          console.warn(`Failed to fetch Instagram page, continuing with conversations already fetched`);
          break;
        }
      }
    } catch (error: any) {
      throw parseFacebookError(error, `Failed to fetch Instagram conversations for Account ID: ${igAccountId}`);
    }
  }

  /**
   * Batch get Instagram profiles
   * Facebook Graph API supports batch requests up to 50 requests per batch
   */
  async batchGetInstagramProfiles(igUserIds: string[]): Promise<Map<string, any>> {
    if (igUserIds.length === 0) {
      return new Map();
    }

    // Facebook batch API limit is 50 requests per batch
    const BATCH_SIZE = 50;
    const results = new Map<string, any>();

    // Process in batches
    for (let i = 0; i < igUserIds.length; i += BATCH_SIZE) {
      const batch = igUserIds.slice(i, i + BATCH_SIZE);
      
      // Create batch requests - Facebook Graph API batch format
      const batchRequests = batch.map((igUserId) => ({
        method: 'GET',
        relative_url: `${igUserId}?fields=name,username,profile_picture_url`,
      }));

      try {
        // Facebook Graph API batch endpoint format
        // Batch parameter must be a JSON string of request objects
        // Can be sent as query parameter or form data
        const response = await axios.post(
          `${FB_GRAPH_URL}/`,
          null,
          {
            params: {
              access_token: this.accessToken,
              batch: JSON.stringify(batchRequests),
            },
          }
        );

        // Parse batch response
        if (Array.isArray(response.data)) {
          response.data.forEach((item: any, index: number) => {
            if (item.code === 200 && item.body) {
              try {
                const profileData = typeof item.body === 'string' ? JSON.parse(item.body) : item.body;
                const igUserId = batch[index];
                results.set(igUserId, profileData);
              } catch (parseError) {
                console.error(`[Facebook API] Failed to parse Instagram profile response for ${batch[index]}:`, parseError);
              }
            } else {
              console.warn(`[Facebook API] Failed to get Instagram profile for ${batch[index]}:`, item.body || item.error);
            }
          });
        }
      } catch (error: any) {
        console.error(`[Facebook API] Batch Instagram profile request failed:`, error);
        // Continue with other batches even if one fails
      }
    }

    return results;
  }

  /**
   * Get Instagram user profile
   * Uses deduplication to prevent duplicate requests
   */
  async getInstagramProfile(igUserId: string) {
    const cacheKey = `getInstagramProfile:${igUserId}`;
    return this.requestDeduplicator.execute(cacheKey, async () => {
      try {
        const response = await axios.get(`${FB_GRAPH_URL}/${igUserId}`, {
          params: {
            access_token: this.accessToken,
            fields: 'name,username,profile_picture_url',
          },
        });
        return response.data;
      } catch (error: any) {
        throw parseFacebookError(error, `Failed to get Instagram profile for User ID: ${igUserId}`);
      }
    });
  }

  /**
   * Generic method to get conversations (automatically detects platform)
   */
  async getConversations(pageIdOrIgId: string, limit = 100, useCache = true) {
    // Try Messenger first (most common)
    try {
      return await this.getMessengerConversations(pageIdOrIgId, limit, useCache);
    } catch (error: any) {
      // If Messenger fails, try Instagram
      console.warn('[Facebook Client] Messenger fetch failed, trying Instagram...');
      return await this.getInstagramConversations(pageIdOrIgId, limit, useCache);
    }
  }
}

