import { prisma } from '@/lib/db';
import { FacebookClient } from '@/lib/facebook/client';
import { analyzeConversation } from './google-ai-service';

export async function analyzeExistingContacts(options: {
  organizationId?: string;
  facebookPageId?: string;
  limit?: number;
  skipIfHasContext?: boolean;
}) {
  const { organizationId, facebookPageId, limit, skipIfHasContext = true } = options;

  const whereClause: any = {};
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

  for (const contact of contacts) {
    try {
      const client = new FacebookClient(contact.facebookPage.pageAccessToken);
      
      // Fetch conversation messages
      const psid = contact.messengerPSID || contact.instagramSID;
      if (!psid) {
        failedCount++;
        continue;
      }

      // Get conversation via Graph API
      const conversations = await client.getMessengerConversations(contact.facebookPage.pageId);
      const userConvo = conversations.find((c: any) => 
        c.participants?.data?.some((p: any) => p.id === psid)
      );

      if (!userConvo?.messages?.data || userConvo.messages.data.length === 0) {
        failedCount++;
        continue;
      }

      // Analyze conversation
      const messagesToAnalyze = userConvo.messages.data
        .filter((msg: any) => msg.message)
        .map((msg: any) => ({
          from: msg.from?.name || msg.from?.id || 'Unknown',
          text: msg.message,
        }));

      const aiContext = await analyzeConversation(messagesToAnalyze);

      if (aiContext) {
        await prisma.contact.update({
          where: { id: contact.id },
          data: {
            aiContext,
            aiContextUpdatedAt: new Date(),
          },
        });
        successCount++;
        console.log(`[AI Analysis] ✓ ${contact.firstName} ${contact.lastName || ''}`);
      } else {
        failedCount++;
      }

      // Small delay to avoid rate limiting
      await new Promise(resolve => setTimeout(resolve, 500));
    } catch (error) {
      console.error(`[AI Analysis] Failed for contact ${contact.id}:`, error);
      failedCount++;
    }
  }

  console.log(`[AI Analysis] Complete: ${successCount} analyzed, ${failedCount} failed`);
  return { successCount, failedCount, total: contacts.length };
}

