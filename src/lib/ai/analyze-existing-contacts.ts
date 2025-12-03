import { prisma } from '@/lib/db';
import { FacebookClient } from '@/lib/facebook/client';
import { analyzeConversation } from './google-ai-service';
import { FacebookConversation, FacebookMessage } from '@/types/api';

/**
 * Concurrency limiter utility for parallel operations
 */
class ConcurrencyLimiter {
  private queue: Array<{ 
    fn: () => Promise<unknown>; 
    resolve: (value: unknown) => void; 
    reject: (error: unknown) => void 
  }> = [];
  private running = 0;

  constructor(private limit: number) {}

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.queue.push({ 
        fn: fn as () => Promise<unknown>, 
        resolve: resolve as (value: unknown) => void, 
        reject 
      });
      this.process();
    });
  }

  private process() {
    if (this.running >= this.limit || this.queue.length === 0) {
      return;
    }

    this.running++;
    const { fn, resolve, reject } = this.queue.shift()!;

    fn()
      .then(resolve)
      .catch(reject)
      .finally(() => {
        this.running--;
        this.process();
      });
  }
}

export async function analyzeExistingContacts(options: {
  organizationId?: string;
  facebookPageId?: string;
  limit?: number;
  skipIfHasContext?: boolean;
}) {
  const { organizationId, facebookPageId, limit, skipIfHasContext = true } = options;

  const whereClause: {
    organizationId?: string;
    facebookPageId?: string;
    aiContext?: null;
  } = {};
  if (organizationId) whereClause.organizationId = organizationId;
  if (facebookPageId) whereClause.facebookPageId = facebookPageId;
  if (skipIfHasContext) whereClause.aiContext = null;

  const contacts = await prisma.contact.findMany({
    where: whereClause,
    include: { facebookPage: true },
    take: limit,
  });

  console.log(`[AI Analysis] Found ${contacts.length} contacts to analyze`);

  let successCount = 0;
  let failedCount = 0;

  // Use concurrency limiter for parallel processing
  const analysisLimiter = new ConcurrencyLimiter(50); // 50 concurrent analysis jobs

  await Promise.all(
    contacts.map(contact =>
      analysisLimiter.execute(async () => {
        try {
          const client = new FacebookClient(contact.facebookPage.pageAccessToken);
          
          // Fetch conversation messages
          const psid = contact.messengerPSID || contact.instagramSID;
          if (!psid) {
            failedCount++;
            return { success: false, contactId: contact.id };
          }

          // Get conversation via Graph API
          const conversations = await client.getMessengerConversations(contact.facebookPage.pageId);
          const userConvo = conversations.find((c: FacebookConversation) => 
            c.participants?.data?.some((p) => p.id === psid)
          );

          if (!userConvo?.messages?.data || userConvo.messages.data.length === 0) {
            failedCount++;
            return { success: false, contactId: contact.id };
          }

          // Analyze conversation
          const messagesToAnalyze = userConvo.messages.data
            .filter((msg: FacebookMessage) => msg.message)
            .map((msg: FacebookMessage) => ({
              from: msg.from?.name || msg.from?.id || 'Unknown',
              text: msg.message || '',
            }));

          // Request comprehensive format to get full JSON structure
          const aiContextResult = await analyzeConversation(messagesToAnalyze, 2, { contactId: contact.id }, true);

          if (aiContextResult) {
            let aiContext: string;
            
            if (typeof aiContextResult === 'string') {
              // If it's a string, check if it's valid JSON
              try {
                const parsed = JSON.parse(aiContextResult);
                // If it parses and has expected structure, use it
                if (parsed && typeof parsed === 'object' && (parsed.executiveSummary || parsed.summary)) {
                  aiContext = aiContextResult;
                } else {
                  // Invalid JSON structure, build comprehensive format from string
                  aiContext = JSON.stringify({
                    executiveSummary: aiContextResult,
                    summary: aiContextResult,
                  });
                }
              } catch {
                // Not JSON, wrap in comprehensive format
                aiContext = JSON.stringify({
                  executiveSummary: aiContextResult,
                  summary: aiContextResult,
                });
              }
            } else if (aiContextResult.comprehensiveAnalysis) {
              // Use comprehensive analysis if available
              aiContext = JSON.stringify(aiContextResult.comprehensiveAnalysis);
            } else {
              // Fallback: build comprehensive format from summary
              aiContext = JSON.stringify({
                executiveSummary: aiContextResult.summary || '',
                summary: aiContextResult.summary || '',
              });
            }
            
            await prisma.contact.update({
              where: { id: contact.id },
              data: {
                aiContext,
                aiContextUpdatedAt: new Date(),
              },
            });
            successCount++;
            console.log(`[AI Analysis] ✓ ${contact.firstName} ${contact.lastName || ''}`);
            return { success: true, contactId: contact.id };
          } else {
            failedCount++;
            return { success: false, contactId: contact.id };
          }
        } catch (error) {
          console.error(`[AI Analysis] Failed for contact ${contact.id}:`, error);
          failedCount++;
          return { success: false, contactId: contact.id, error };
        }
      })
    )
  );

  console.log(`[AI Analysis] Complete: ${successCount} analyzed, ${failedCount} failed`);
  return { successCount, failedCount, total: contacts.length };
}

