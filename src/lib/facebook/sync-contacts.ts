import { prisma } from '@/lib/db';
import { FacebookClient, FacebookApiError } from './client';
import { analyzeConversation } from '@/lib/ai/google-ai-service';

interface SyncResult {
  success: boolean;
  synced: number;
  failed: number;
  errors: Array<{ platform: string; id: string; error: string; code?: number }>;
  tokenExpired?: boolean;
}

export async function syncContacts(facebookPageId: string): Promise<SyncResult> {
  const page = await prisma.facebookPage.findUnique({
    where: { id: facebookPageId },
  });

  if (!page) throw new Error('Facebook page not found');

  const client = new FacebookClient(page.pageAccessToken);
  let syncedCount = 0;
  let failedCount = 0;
  let tokenExpired = false;
  const errors: Array<{ platform: string; id: string; error: string; code?: number }> = [];

  console.log(`[Sync] Starting contact sync for Facebook Page: ${page.pageId}`);

  // Sync Messenger contacts
  try {
    console.log('[Sync] Fetching Messenger conversations (with pagination)...');
    const messengerConvos = await client.getMessengerConversations(page.pageId);
    console.log(`[Sync] Fetched ${messengerConvos.length} Messenger conversations`);

    for (const convo of messengerConvos) {
      for (const participant of convo.participants.data) {
        if (participant.id === page.pageId) continue; // Skip page itself

        try {
          // Extract name from conversation messages (if available)
          // Messages include sender information with names
          let firstName = `User ${participant.id.slice(-6)}`; // Fallback name
          let lastName: string | null = null;
          
          if (convo.messages?.data) {
            // Find a message from this participant
            const userMessage = convo.messages.data.find(
              (msg: any) => msg.from?.id === participant.id
            );
            
            if (userMessage?.from?.name) {
              // Split name into first and last
              const nameParts = userMessage.from.name.trim().split(' ');
              firstName = nameParts[0] || firstName;
              
              // Get last name (everything after first name)
              if (nameParts.length > 1) {
                lastName = nameParts.slice(1).join(' ');
              }
            }
          }
          
          // Analyze conversation with AI if messages exist
          let aiContext: string | null = null;
          
          if (convo.messages?.data && convo.messages.data.length > 0) {
            try {
              const messagesToAnalyze = convo.messages.data
                .filter((msg: any) => msg.message)
                .map((msg: any) => ({
                  from: msg.from?.name || msg.from?.id || 'Unknown',
                  text: msg.message,
                }));

              if (messagesToAnalyze.length > 0) {
                aiContext = await analyzeConversation(messagesToAnalyze);
              }
            } catch (error) {
              console.error(`[Sync] Failed to analyze conversation for ${participant.id}:`, error);
            }
          }
          
          await prisma.contact.upsert({
            where: {
              messengerPSID_facebookPageId: {
                messengerPSID: participant.id,
                facebookPageId: page.id,
              },
            },
            create: {
              messengerPSID: participant.id,
              firstName: firstName,
              lastName: lastName,
              hasMessenger: true,
              organizationId: page.organizationId,
              facebookPageId: page.id,
              lastInteraction: new Date(convo.updated_time),
              aiContext: aiContext,
              aiContextUpdatedAt: aiContext ? new Date() : null,
            },
            update: {
              firstName: firstName,
              lastName: lastName,
              lastInteraction: new Date(convo.updated_time),
              hasMessenger: true,
              aiContext: aiContext,
              aiContextUpdatedAt: aiContext ? new Date() : null,
            },
          });
          syncedCount++;
        } catch (error: any) {
          failedCount++;
          const errorMessage = error.message || 'Unknown error';
          const errorCode = error instanceof FacebookApiError ? error.code : undefined;
          
          // Check if token is expired
          if (error instanceof FacebookApiError && error.isTokenExpired) {
            tokenExpired = true;
          }
          
          console.error(`Failed to sync Messenger contact ${participant.id}:`, errorMessage);
          errors.push({
            platform: 'Messenger',
            id: participant.id,
            error: errorMessage,
            code: errorCode,
          });
        }
      }
    }
  } catch (error: any) {
    const errorCode = error instanceof FacebookApiError ? error.code : undefined;
    
    // Check if token is expired
    if (error instanceof FacebookApiError && error.isTokenExpired) {
      tokenExpired = true;
    }
    
    console.error('Failed to fetch Messenger conversations:', error);
    errors.push({
      platform: 'Messenger',
      id: 'conversations',
      error: error.message || 'Failed to fetch conversations',
      code: errorCode,
    });
  }

  // Sync Instagram contacts (if connected)
  if (page.instagramAccountId) {
    try {
      console.log('[Sync] Fetching Instagram conversations (with pagination)...');
      const igConvos = await client.getInstagramConversations(page.instagramAccountId);
      console.log(`[Sync] Fetched ${igConvos.length} Instagram conversations`);

      for (const convo of igConvos) {
        for (const participant of convo.participants.data) {
          if (participant.id === page.instagramAccountId) continue;

          try {
            // Extract name from conversation messages (if available)
            let firstName = `IG User ${participant.id.slice(-6)}`; // Fallback name
            let lastName: string | null = null;
            
            if (convo.messages?.data) {
              // Find a message from this participant
              const userMessage = convo.messages.data.find(
                (msg: any) => msg.from?.id === participant.id
              );
              
              if (userMessage?.from?.name) {
                // Split name into first and last
                const nameParts = userMessage.from.name.trim().split(' ');
                firstName = nameParts[0] || firstName;
                
                // Get last name (everything after first name)
                if (nameParts.length > 1) {
                  lastName = nameParts.slice(1).join(' ');
                }
              } else if (userMessage?.from?.username) {
                // Fallback to username if name not available
                firstName = userMessage.from.username;
              }
            }
            
            // Analyze conversation with AI if messages exist
            let aiContext: string | null = null;
            
            if (convo.messages?.data && convo.messages.data.length > 0) {
              try {
                const messagesToAnalyze = convo.messages.data
                  .filter((msg: any) => msg.message)
                  .map((msg: any) => ({
                    from: msg.from?.name || msg.from?.username || msg.from?.id || 'Unknown',
                    text: msg.message,
                  }));

                if (messagesToAnalyze.length > 0) {
                  aiContext = await analyzeConversation(messagesToAnalyze);
                }
              } catch (error) {
                console.error(`[Sync] Failed to analyze IG conversation for ${participant.id}:`, error);
              }
            }
            
            // Check if contact exists by Instagram ID or Messenger PSID
            const existingContact = await prisma.contact.findFirst({
              where: {
                OR: [
                  { instagramSID: participant.id, facebookPageId: page.id },
                  {
                    messengerPSID: participant.id,
                    facebookPageId: page.id,
                  },
                ],
              },
            });

            if (existingContact) {
              // Update existing contact
              await prisma.contact.update({
                where: { id: existingContact.id },
                data: {
                  instagramSID: participant.id,
                  firstName: firstName,
                  lastName: lastName,
                  hasInstagram: true,
                  lastInteraction: new Date(convo.updated_time),
                  aiContext: aiContext,
                  aiContextUpdatedAt: aiContext ? new Date() : null,
                },
              });
            } else {
              // Create new contact with full name from messages
              await prisma.contact.create({
                data: {
                  instagramSID: participant.id,
                  firstName: firstName,
                  lastName: lastName,
                  hasInstagram: true,
                  organizationId: page.organizationId,
                  facebookPageId: page.id,
                  lastInteraction: new Date(convo.updated_time),
                  aiContext: aiContext,
                  aiContextUpdatedAt: aiContext ? new Date() : null,
                },
              });
            }
            syncedCount++;
          } catch (error: any) {
            failedCount++;
            const errorMessage = error.message || 'Unknown error';
            const errorCode = error instanceof FacebookApiError ? error.code : undefined;
            
            // Check if token is expired
            if (error instanceof FacebookApiError && error.isTokenExpired) {
              tokenExpired = true;
            }
            
            console.error(`Failed to sync IG contact ${participant.id}:`, errorMessage);
            errors.push({
              platform: 'Instagram',
              id: participant.id,
              error: errorMessage,
              code: errorCode,
            });
          }
        }
      }
    } catch (error: any) {
      const errorCode = error instanceof FacebookApiError ? error.code : undefined;
      
      // Check if token is expired
      if (error instanceof FacebookApiError && error.isTokenExpired) {
        tokenExpired = true;
      }
      
      console.error('Failed to fetch Instagram conversations:', error);
      errors.push({
        platform: 'Instagram',
        id: 'conversations',
        error: error.message || 'Failed to fetch conversations',
        code: errorCode,
      });
    }
  }

  // Update last synced time only if sync was at least partially successful
  if (syncedCount > 0 || !tokenExpired) {
    await prisma.facebookPage.update({
      where: { id: page.id },
      data: { lastSyncedAt: new Date() },
    });
  }

  console.log(`[Sync] Sync completed: ${syncedCount} synced, ${failedCount} failed${tokenExpired ? ' (Token expired)' : ''}`);

  return {
    success: true,
    synced: syncedCount,
    failed: failedCount,
    errors,
    tokenExpired,
  };
}


