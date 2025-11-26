import axios from 'axios';

const FB_GRAPH_URL = 'https://graph.facebook.com/v19.0';

/**
 * Custom error class for Facebook API errors
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
 * Parse Facebook API error response
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

export class FacebookClient {
  constructor(private accessToken: string) {}

  /**
   * Send Messenger message with optional message tag
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

        return {
          success: false,
          error: 'FACEBOOK_API_ERROR',
          message: fbError.message,
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
        return {
          success: false,
          error: 'FACEBOOK_API_ERROR',
          message: `Facebook API Error (${fbError.code}): ${fbError.message}`,
        };
      }
      throw error;
    }
  }

  /**
   * Fetch Messenger conversations incrementally until all needed participants are found
   * Stops early to avoid fetching thousands of conversations
   */
  async getMessengerConversationsUntilFound(
    pageId: string,
    neededParticipantIds: Set<string>,
    limit = 100
  ): Promise<any[]> {
    const allConversations: any[] = [];
    const foundParticipants = new Set<string>();
    let nextUrl: string | null = null;
    let hasMore = true;
    let pageCount = 0;

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
          timeout: 30000,
        }
      );

      if (response.data.data) {
        allConversations.push(...response.data.data);
        pageCount++;
        
        // Check if we found all needed participants in first page
        for (const convo of response.data.data) {
          for (const participant of convo.participants.data) {
            if (neededParticipantIds.has(participant.id)) {
              foundParticipants.add(participant.id);
            }
          }
        }
      }

      // Check if we found all needed participants
      if (foundParticipants.size >= neededParticipantIds.size) {
        console.log(`[Facebook API] Found all ${foundParticipants.size} participants in first ${pageCount} page(s), stopping early`);
        return allConversations;
      }

      // Check if there's a next page
      nextUrl = response.data.paging?.next || null;
      hasMore = !!nextUrl;

      // Fetch subsequent pages until we find all participants
      while (hasMore && nextUrl && foundParticipants.size < neededParticipantIds.size) {
        try {
          const nextResponse = await axios.get(nextUrl, {
            timeout: 30000,
          });
          
          if (nextResponse.data.data && nextResponse.data.data.length > 0) {
            allConversations.push(...nextResponse.data.data);
            pageCount++;
            
            // Check if we found all needed participants
            for (const convo of nextResponse.data.data) {
              for (const participant of convo.participants.data) {
                if (neededParticipantIds.has(participant.id)) {
                  foundParticipants.add(participant.id);
                }
              }
            }
            
            // Stop if we found all participants
            if (foundParticipants.size >= neededParticipantIds.size) {
              console.log(`[Facebook API] Found all ${foundParticipants.size} participants after ${pageCount} pages, stopping early`);
              break;
            }
          }

          // Update pagination info
          nextUrl = nextResponse.data.paging?.next || null;
          hasMore = !!nextUrl && nextResponse.data.data?.length > 0;

          // Add small delay to avoid rate limiting
          if (hasMore) {
            await new Promise(resolve => setTimeout(resolve, 50));
          }
        } catch (paginationError: any) {
          console.error('Error fetching next page of Messenger conversations:', paginationError);
          
          // If we get rate limited, throw the error
          const fbError = paginationError.response?.data?.error;
          if (fbError && (fbError.code === 613 || fbError.code === 4 || fbError.code === 17)) {
            throw parseFacebookError(paginationError, `Rate limited while paginating conversations for Page ID: ${pageId}`);
          }
          
          // For other pagination errors, log but continue with what we have
          console.warn(`Failed to fetch page, continuing with ${allConversations.length} conversations already fetched`);
          break;
        }
      }

      console.log(`[Facebook API] Fetched ${pageCount} pages, found ${foundParticipants.size}/${neededParticipantIds.size} participants`);
      return allConversations;
    } catch (error: any) {
      throw parseFacebookError(error, `Failed to fetch conversations for Page ID: ${pageId}`);
    }
  }

  /**
   * Fetch Messenger conversations with messages (includes sender names)
   * Automatically handles pagination to fetch ALL conversations
   */
  async getMessengerConversations(pageId: string, limit = 100) {
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

          // Add small delay to avoid rate limiting
          if (hasMore) {
            await new Promise(resolve => setTimeout(resolve, 100));
          }
        } catch (paginationError: any) {
          console.error(`[Facebook API] Error fetching page ${pageCount} of Messenger conversations:`, paginationError);
          
          // If we get rate limited, throw the error
          const fbError = paginationError.response?.data?.error;
          if (fbError && (fbError.code === 613 || fbError.code === 4 || fbError.code === 17)) {
            throw parseFacebookError(paginationError, `Rate limited while paginating conversations for Page ID: ${pageId}`);
          }
          
          // For timeout or other pagination errors, log but continue with what we have
          if (paginationError.message?.includes('timeout') || paginationError.code === 'ECONNABORTED') {
            console.warn(`[Facebook API] Page ${pageCount} timed out, continuing with ${allConversations.length} conversations already fetched`);
            // Log warning for monitoring
            console.warn(`[Facebook API] Failed to fetch page ${pageCount}, continuing with ${allConversations.length} conversations already fetched`);
          } else {
            console.warn(`[Facebook API] Failed to fetch page ${pageCount}, continuing with ${allConversations.length} conversations already fetched`);
          }
          break;
        }
      }
      
      // All pages fetched

      return allConversations;
    } catch (error: any) {
      throw parseFacebookError(error, `Failed to fetch conversations for Page ID: ${pageId}`);
    }
  }

  /**
   * Stream Messenger conversations as they're fetched (yields conversations page by page)
   * This allows processing to start immediately instead of waiting for all conversations
   */
  async *fetchMessengerConversationsStream(pageId: string, limit = 100) {
    let nextUrl: string | null = null;
    let hasMore = true;
    let pageCount = 0;

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
        try {
          if (pageCount % 10 === 0) {
            console.log(`[Facebook API] Streaming: Fetched ${pageCount} pages of Messenger conversations so far...`);
          }

          const nextResponse = await axios.get(nextUrl, {
            timeout: 30000, // 30 second timeout per request
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

          // Add small delay to avoid rate limiting
          if (hasMore) {
            await new Promise(resolve => setTimeout(resolve, 100));
          }
        } catch (paginationError: any) {
          console.error('Error fetching next page of Messenger conversations:', paginationError);

          // If we get rate limited, throw the error
          const fbError = paginationError.response?.data?.error;
          if (fbError && (fbError.code === 613 || fbError.code === 4 || fbError.code === 17)) {
            throw parseFacebookError(paginationError, `Rate limited while paginating conversations for Page ID: ${pageId}`);
          }

          // For other pagination errors, log but continue with what we have
          console.warn(`Failed to fetch page, continuing with conversations already fetched`);
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
   */
  async getAllMessagesForConversation(conversationId: string, maxPages: number = 50): Promise<any[]> {
    const allMessages: any[] = [];
    let nextUrl: string | null = `${FB_GRAPH_URL}/${conversationId}/messages`;
    let hasMore = true;
    let pageCount = 0;
    const MAX_MESSAGE_PAGES = maxPages; // Safety limit

    try {
      while (hasMore && nextUrl && pageCount < MAX_MESSAGE_PAGES) {
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
            }),
            new Promise((_, reject) => 
              setTimeout(() => reject(new Error(`Message page ${pageCount + 1} request timed out after 30 seconds`)), 30000)
            )
          ]) as any;

          if (response.data.data?.length > 0) {
            allMessages.push(...response.data.data);
          }

          nextUrl = response.data.paging?.next || null;
          hasMore = !!nextUrl && response.data.data?.length > 0;
          pageCount++;

          // Small delay to avoid rate limiting
          if (hasMore) {
            await new Promise(resolve => setTimeout(resolve, 50)); // 50ms delay
          }
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
   */
  async getRecentMessagesForConversation(conversationId: string, limit: number = 100): Promise<any[]> {
    try {
      const response: any = await axios.get(`${FB_GRAPH_URL}/${conversationId}/messages`, {
        params: {
          access_token: this.accessToken,
          fields: 'from,message,created_time',
          limit: Math.min(limit, 100), // Facebook API max is 100 per request
        },
        timeout: 15000, // Reduced to 15 second timeout for faster failure
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
   * Get user profile (Messenger)
   */
  async getMessengerProfile(psid: string) {
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
  }

  /**
   * Get Instagram conversations with messages (includes sender names)
   * Automatically handles pagination to fetch ALL conversations
   */
  /**
   * Fetch Instagram conversations incrementally until all needed participants are found
   * Stops early to avoid fetching thousands of conversations
   */
  async getInstagramConversationsUntilFound(
    igAccountId: string,
    neededParticipantIds: Set<string>,
    limit = 100
  ): Promise<any[]> {
    const allConversations: any[] = [];
    const foundParticipants = new Set<string>();
    let nextUrl: string | null = null;
    let hasMore = true;
    let pageCount = 0;

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
          timeout: 30000,
        }
      );

      if (response.data.data) {
        allConversations.push(...response.data.data);
        pageCount++;
        
        // Check if we found all needed participants in first page
        for (const convo of response.data.data) {
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

      // Fetch subsequent pages until we find all participants
      while (hasMore && nextUrl && foundParticipants.size < neededParticipantIds.size) {
        try {
          const nextResponse = await axios.get(nextUrl, {
            timeout: 30000,
          });
          
          if (nextResponse.data.data && nextResponse.data.data.length > 0) {
            allConversations.push(...nextResponse.data.data);
            pageCount++;
            
            // Check if we found all needed participants
            for (const convo of nextResponse.data.data) {
              for (const participant of convo.participants.data) {
                if (neededParticipantIds.has(participant.id)) {
                  foundParticipants.add(participant.id);
                }
              }
            }
            
            // Stop if we found all participants
            if (foundParticipants.size >= neededParticipantIds.size) {
              console.log(`[Facebook API] Found all ${foundParticipants.size} IG participants after ${pageCount} pages, stopping early`);
              break;
            }
          }

          // Update pagination info
          nextUrl = nextResponse.data.paging?.next || null;
          hasMore = !!nextUrl && nextResponse.data.data?.length > 0;

          // Add small delay to avoid rate limiting
          if (hasMore) {
            await new Promise(resolve => setTimeout(resolve, 50));
          }
        } catch (paginationError: any) {
          console.error('Error fetching next page of Instagram conversations:', paginationError);
          break;
        }
      }

      console.log(`[Facebook API] Fetched ${pageCount} IG pages, found ${foundParticipants.size}/${neededParticipantIds.size} participants`);
      return allConversations;
    } catch (error: any) {
      throw parseFacebookError(error, `Failed to fetch Instagram conversations for Account ID: ${igAccountId}`);
    }
  }

  async getInstagramConversations(igAccountId: string, limit = 100) {
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

      // Fetch all subsequent pages
      while (hasMore && nextUrl) {
        try {
          const nextResponse = await axios.get(nextUrl);
          
          if (nextResponse.data.data && nextResponse.data.data.length > 0) {
            allConversations.push(...nextResponse.data.data);
          }

          // Update pagination info
          nextUrl = nextResponse.data.paging?.next || null;
          hasMore = !!nextUrl && nextResponse.data.data?.length > 0;

          // Add small delay to avoid rate limiting
          if (hasMore) {
            await new Promise(resolve => setTimeout(resolve, 100));
          }
        } catch (paginationError: any) {
          console.error('Error fetching next page of Instagram conversations:', paginationError);
          
          // If we get rate limited, throw the error
          const fbError = paginationError.response?.data?.error;
          if (fbError && (fbError.code === 613 || fbError.code === 4 || fbError.code === 17)) {
            throw parseFacebookError(paginationError, `Rate limited while paginating Instagram conversations for Account ID: ${igAccountId}`);
          }
          
          // For other pagination errors, log but continue with what we have
          console.warn(`Failed to fetch Instagram page, continuing with ${allConversations.length} conversations already fetched`);
          break;
        }
      }

      return allConversations;
    } catch (error: any) {
      throw parseFacebookError(error, `Failed to fetch Instagram conversations for Account ID: ${igAccountId}`);
    }
  }

  /**
   * Stream Instagram conversations as they're fetched (yields conversations page by page)
   * This allows processing to start immediately instead of waiting for all conversations
   */
  async *fetchInstagramConversationsStream(igAccountId: string, limit = 100) {
    let nextUrl: string | null = null;
    let hasMore = true;
    let pageCount = 0;

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
        try {
          if (pageCount % 10 === 0) {
            console.log(`[Facebook API] Streaming: Fetched ${pageCount} pages of Instagram conversations so far...`);
          }

          const nextResponse = await axios.get(nextUrl, {
            timeout: 30000, // 30 second timeout per request
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

          // Add small delay to avoid rate limiting
          if (hasMore) {
            await new Promise(resolve => setTimeout(resolve, 100));
          }
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
   * Get Instagram user profile
   */
  async getInstagramProfile(igUserId: string) {
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
  }

  /**
   * Generic method to get conversations (automatically detects platform)
   */
  async getConversations(pageIdOrIgId: string, limit = 100) {
    // Try Messenger first (most common)
    try {
      return await this.getMessengerConversations(pageIdOrIgId, limit);
    } catch (error: any) {
      // If Messenger fails, try Instagram
      console.warn('[Facebook Client] Messenger fetch failed, trying Instagram...');
      return await this.getInstagramConversations(pageIdOrIgId, limit);
    }
  }
}

