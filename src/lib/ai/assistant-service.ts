import OpenAI from 'openai';
import { prisma } from '@/lib/db';
import apiKeyManager from './api-key-manager';
import { executeAIRequest, getTimeoutForOperation, getPriorityForOperation } from './ai-request-wrapper';

const MODEL = 'openai/gpt-oss-120b'; // 120B parameters for better reasoning
const BASE_URL = 'https://integrate.api.nvidia.com/v1';

// Get API key from database first, then fall back to environment variables
async function getApiKey(requestContext?: { operation?: string; userId?: string }): Promise<string | null> {
  // Try database first (preferred method - can be managed through UI)
  const dbKey = await apiKeyManager.getNextKey(requestContext);
  if (dbKey) {
    return dbKey;
  }
  
  // Fall back to environment variables if no database keys available
  const envKey = process.env.NVIDIA_API_KEY || process.env.GOOGLE_AI_API_KEY || null;
  if (envKey) {
    console.warn('[Assistant] ⚠️ Using environment variable API key (database keys not available)');
  }
  return envKey;
}

function createNvidiaClient(apiKey: string): OpenAI {
  return new OpenAI({
    baseURL: BASE_URL,
    apiKey: apiKey,
  });
}

interface UserDataContext {
  contacts: {
    total: number;
    recent: Array<{
      id: string;
      name: string;
      leadScore: number;
      stage?: string;
      lastInteraction?: Date;
    }>;
  };
  pipelines: Array<{
    id: string;
    name: string;
    stages: Array<{ id: string; name: string; contactCount: number }>;
  }>;
  campaigns: {
    total: number;
    active: number;
    recent: Array<{
      id: string;
      name: string;
      status: string;
      sentCount: number;
    }>;
  };
  conversations: {
    open: number;
    recent: Array<{
      id: string;
      contactName: string;
      lastMessageAt: Date;
      platform: string;
    }>;
  };
  pages: Array<{
    id: string;
    name: string;
    contactCount: number;
  }>;
  teams: Array<{
    id: string;
    name: string;
    memberCount: number;
  }>;
}

/**
 * Build comprehensive context from all user data
 */
async function buildUserDataContext(
  organizationId: string,
  userId: string
): Promise<UserDataContext> {
  // Fetch contacts (top 50 most recent)
  const contacts = await prisma.contact.findMany({
    where: { organizationId },
    take: 50,
    orderBy: { lastInteraction: 'desc' },
    select: {
      id: true,
      firstName: true,
      lastName: true,
      leadScore: true,
      lastInteraction: true,
      stage: {
        select: { name: true },
      },
    },
  });

  const totalContacts = await prisma.contact.count({
    where: { organizationId },
  });

  // Fetch pipelines with stages
  const pipelines = await prisma.pipeline.findMany({
    where: {
      organizationId,
      isArchived: false,
    },
    include: {
      stages: {
        include: {
          _count: {
            select: { contacts: true },
          },
        },
      },
    },
  });

  // Fetch campaigns
  const campaigns = await prisma.campaign.findMany({
    where: { organizationId },
    take: 10,
    orderBy: { createdAt: 'desc' },
    select: {
      id: true,
      name: true,
      status: true,
      sentCount: true,
    },
  });

  const activeCampaigns = campaigns.filter(
    (c) => c.status === 'SENDING' || c.status === 'SCHEDULED'
  ).length;

  // Fetch conversations
  const conversations = await prisma.conversation.findMany({
    where: {
      facebookPage: { organizationId },
      status: 'OPEN',
    },
    take: 10,
    orderBy: { lastMessageAt: 'desc' },
    include: {
      contact: {
        select: {
          firstName: true,
          lastName: true,
        },
      },
    },
  });

  const openConversations = await prisma.conversation.count({
    where: {
      facebookPage: { organizationId },
      status: 'OPEN',
    },
  });

  // Fetch pages
  const pages = await prisma.facebookPage.findMany({
    where: { organizationId, isActive: true },
    include: {
      _count: {
        select: { contacts: true },
      },
    },
  });

  // Fetch teams
  const teams = await prisma.team.findMany({
    where: { organizationId, status: 'ACTIVE' },
    include: {
      _count: {
        select: { members: true },
      },
    },
  });

  return {
    contacts: {
      total: totalContacts,
      recent: contacts.map((c) => ({
        id: c.id,
        name: `${c.firstName} ${c.lastName || ''}`.trim(),
        leadScore: c.leadScore,
        stage: c.stage?.name,
        lastInteraction: c.lastInteraction || undefined,
      })),
    },
    pipelines: pipelines.map((p) => ({
      id: p.id,
      name: p.name,
      stages: p.stages.map((s) => ({
        id: s.id,
        name: s.name,
        contactCount: s._count.contacts,
      })),
    })),
    campaigns: {
      total: campaigns.length,
      active: activeCampaigns,
      recent: campaigns.map((c) => ({
        id: c.id,
        name: c.name,
        status: c.status,
        sentCount: c.sentCount,
      })),
    },
    conversations: {
      open: openConversations,
      recent: conversations.map((c) => ({
        id: c.id,
        contactName: `${c.contact.firstName} ${c.contact.lastName || ''}`.trim(),
        lastMessageAt: c.lastMessageAt,
        platform: c.platform,
      })),
    },
    pages: pages.map((p) => ({
      id: p.id,
      name: p.pageName,
      contactCount: p._count.contacts,
    })),
    teams: teams.map((t) => ({
      id: t.id,
      name: t.name,
      memberCount: t._count.members,
    })),
  };
}

/**
 * Format user data context into a prompt-friendly string
 */
function formatContextForPrompt(context: UserDataContext): string {
  const sections: string[] = [];

  sections.push(`## Contacts Summary
- Total Contacts: ${context.contacts.total}
- Recent Contacts (showing ${context.contacts.recent.length}):
${context.contacts.recent
  .map(
    (c) =>
      `  - ${c.name} (ID: ${c.id}) - Lead Score: ${c.leadScore}${c.stage ? `, Stage: ${c.stage}` : ''}${c.lastInteraction ? `, Last Interaction: ${c.lastInteraction.toLocaleDateString()}` : ''}`
  )
  .join('\n')}`);

  sections.push(`## Pipelines
${context.pipelines
  .map(
    (p) =>
      `- ${p.name} (ID: ${p.id}) with ${p.stages.length} stages:\n${p.stages.map((s) => `  - ${s.name} (${s.contactCount} contacts)`).join('\n')}`
  )
  .join('\n\n')}`);

  sections.push(`## Campaigns
- Total: ${context.campaigns.total}
- Active: ${context.campaigns.active}
- Recent Campaigns:
${context.campaigns.recent
  .map((c) => `  - ${c.name} (${c.status}) - ${c.sentCount} sent`)
  .join('\n')}`);

  sections.push(`## Conversations
- Open Conversations: ${context.conversations.open}
- Recent Open Conversations:
${context.conversations.recent
  .map(
    (c) =>
      `  - ${c.contactName} (${c.platform}) - Last message: ${c.lastMessageAt.toLocaleDateString()}`
  )
  .join('\n')}`);

  sections.push(`## Facebook Pages
${context.pages.map((p) => `- ${p.name} (${p.contactCount} contacts)`).join('\n')}`);

  sections.push(`## Teams
${context.teams.map((t) => `- ${t.name} (${t.memberCount} members)`).join('\n')}`);

  return sections.join('\n\n');
}

/**
 * Get detailed information about a specific entity
 */
async function getEntityDetails(
  organizationId: string,
  entityType: string,
  entityId: string
): Promise<string> {
  switch (entityType.toLowerCase()) {
    case 'contact': {
      const contact = await prisma.contact.findFirst({
        where: { id: entityId, organizationId },
        include: {
          stage: true,
          pipeline: true,
          facebookPage: true,
          conversations: {
            take: 5,
            orderBy: { lastMessageAt: 'desc' },
            include: {
              messages: {
                take: 10,
                orderBy: { createdAt: 'desc' },
              },
            },
          },
        },
      });

      if (!contact) return 'Contact not found.';

      return `Contact Details:
- Name: ${contact.firstName} ${contact.lastName || ''}
- Lead Score: ${contact.leadScore}
- Status: ${contact.leadStatus}
- Stage: ${contact.stage?.name || 'None'}
- Pipeline: ${contact.pipeline?.name || 'None'}
- Tags: ${contact.tags.join(', ') || 'None'}
- AI Context: ${contact.aiContext || 'Not analyzed yet'}
- Last Interaction: ${contact.lastInteraction?.toLocaleString() || 'Never'}
- Recent Conversations: ${contact.conversations.length}
${contact.conversations
  .map(
    (c) =>
      `  - ${c.platform} conversation (${c.messages.length} messages, last: ${c.lastMessageAt.toLocaleString()})`
  )
  .join('\n')}`;
    }

    case 'campaign': {
      const campaign = await prisma.campaign.findFirst({
        where: { id: entityId, organizationId },
        include: {
          facebookPage: true,
          template: true,
        },
      });

      if (!campaign) return 'Campaign not found.';

      return `Campaign Details:
- Name: ${campaign.name}
- Status: ${campaign.status}
- Platform: ${campaign.platform}
- Sent: ${campaign.sentCount} / ${campaign.totalRecipients}
- Delivered: ${campaign.deliveredCount}
- Read: ${campaign.readCount}
- Replied: ${campaign.repliedCount}
- Failed: ${campaign.failedCount}`;
    }

    case 'pipeline': {
      const pipeline = await prisma.pipeline.findFirst({
        where: { id: entityId, organizationId },
        include: {
          stages: {
            include: {
              _count: {
                select: { contacts: true },
              },
            },
            orderBy: { order: 'asc' },
          },
          _count: {
            select: { contacts: true },
          },
        },
      });

      if (!pipeline) return 'Pipeline not found.';

      return `Pipeline Details:
- Name: ${pipeline.name}
- Total Contacts: ${pipeline._count.contacts}
- Stages:
${pipeline.stages
  .map((s) => `  - ${s.name} (${s._count.contacts} contacts, Score Range: ${s.leadScoreMin}-${s.leadScoreMax})`)
  .join('\n')}`;
    }

    default:
      return `Entity type "${entityType}" not supported. Supported types: contact, campaign, pipeline.`;
  }
}

/**
 * Process a user message and generate AI assistant response
 */
export async function processAssistantMessage(
  userMessage: string,
  organizationId: string,
  userId: string,
  chatHistory: Array<{ role: 'user' | 'assistant'; content: string }> = []
): Promise<{ response: string; sources?: string[] }> {
  const operation = 'processAssistantMessage';
  const apiKey = await getApiKey({ operation, userId });
  if (!apiKey) {
    throw new Error('No NVIDIA API key available. Please configure an API key in Settings → API Keys or set NVIDIA_API_KEY environment variable.');
  }

  // Build user data context
  const context = await buildUserDataContext(organizationId, userId);
  const contextText = formatContextForPrompt(context);

  // Check if user is asking about a specific entity
  const entityMatch = userMessage.match(/(contact|campaign|pipeline)\s+([a-z0-9]+)/i);
  let entityDetails = '';
  if (entityMatch) {
    const [, entityType, entityId] = entityMatch;
    entityDetails = await getEntityDetails(organizationId, entityType, entityId);
  }

  // Build system prompt
  const systemPrompt = `You are an AI assistant for a CRM system called HIRO. You have access to all user data including contacts, pipelines, campaigns, conversations, Facebook pages, and teams.

Your role is to:
1. Answer questions about the user's data
2. Provide insights and recommendations
3. Help users understand their business metrics
4. Suggest actions based on data patterns

You have access to the following data:
${contextText}

${entityDetails ? `\n## Additional Details for Query:\n${entityDetails}` : ''}

Important guidelines:
- Always be accurate and cite specific data when possible
- If you don't have enough information, say so
- Be concise but helpful
- Use the data provided to give actionable insights
- When mentioning contacts, campaigns, or other entities, include their IDs when relevant`;

  // Build messages array
  const messages: Array<{ role: 'user' | 'assistant' | 'system'; content: string }> = [
    { role: 'system', content: systemPrompt },
    ...chatHistory.map((msg) => ({
      role: msg.role,
      content: msg.content,
    })),
    { role: 'user', content: userMessage },
  ];

  const client = createNvidiaClient(apiKey);

  try {
    const result = await executeAIRequest(
      async () => {
        const completion = await client.chat.completions.create({
          model: MODEL,
          messages: messages as any,
          temperature: 0.7,
          max_tokens: 2000,
        });

        const response = completion.choices[0]?.message?.content;
        if (!response) {
          throw new Error('No response from AI model');
        }

        // Extract sources from context
        const sources: string[] = [];
        if (context.contacts.recent.length > 0) sources.push('contacts');
        if (context.pipelines.length > 0) sources.push('pipelines');
        if (context.campaigns.recent.length > 0) sources.push('campaigns');
        if (context.conversations.recent.length > 0) sources.push('conversations');

        return {
          response,
          sources,
        };
      },
      {
        operation,
        priority: getPriorityForOperation(operation, true), // User-initiated = high priority
        timeout: getTimeoutForOperation(operation),
        circuitBreaker: 'assistantMessage',
        apiKeyId: apiKey.substring(0, 16),
      }
    );

    // Record success
    await apiKeyManager.recordSuccess(apiKey, { 
      operation,
    }).catch(() => {
      // Non-critical if recording fails
    });

    return result;
  } catch (error) {
    // Error already logged by performance monitor
    console.error('[Assistant] Error processing message:', error);
    throw error;
  }
}

