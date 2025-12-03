/**
 * Database Cleanup Script
 * 
 * Keeps:
 * - Users
 * - AnalysisJobs
 * - Organizations (required for Users)
 * - API Keys (system credentials)
 * 
 * Deletes:
 * - Contacts (and all related data)
 * - Everything else
 */

// CRITICAL: Load environment variables BEFORE importing Prisma
import { config } from 'dotenv';
import { resolve } from 'path';

// Load environment variables from .env.local (must be first!)
const envResult = config({ path: resolve(process.cwd(), '.env.local') });

// Also try .env if .env.local doesn't exist
if (envResult.error && !process.env.DATABASE_URL) {
  config({ path: resolve(process.cwd(), '.env') });
}

// Verify DATABASE_URL is loaded
if (!process.env.DATABASE_URL) {
  console.error('❌ ERROR: DATABASE_URL not found in environment variables!');
  console.error('   Make sure .env.local or .env exists and contains DATABASE_URL');
  console.error(`   Current working directory: ${process.cwd()}`);
  console.error(`   Looking for: ${resolve(process.cwd(), '.env.local')}`);
  process.exit(1);
}

// Debug: Check if DATABASE_URL is actually set (without exposing the value)
const dbUrlLength = process.env.DATABASE_URL?.length || 0;
console.log(`✅ Environment variables loaded (DATABASE_URL length: ${dbUrlLength} chars)`);

// Now import Prisma (after env vars are loaded)
// We need to create a fresh Prisma client instance to ensure it reads the loaded env vars
import { PrismaClient } from '@prisma/client';

// Create a new Prisma client instance with the loaded DATABASE_URL
const prisma = new PrismaClient({
  log: process.env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error'],
  datasources: {
    db: {
      url: process.env.DATABASE_URL,
    },
  },
});

// Helper to ensure connection
async function connectPrisma() {
  await prisma.$connect();
  console.log('[Prisma] ✅ Connected to database');
}

async function cleanupDatabase() {
  console.log('🧹 Starting database cleanup...\n');
  console.log('⚠️  WARNING: This will delete Contacts and most data except Users, AnalysisJobs, and API Keys!\n');

  // Ensure database connection is established
  console.log('🔌 Connecting to database...\n');
  await connectPrisma();
  console.log('✅ Database connected\n');

  try {
    // Step 1: Delete child records first (respecting foreign keys)
    console.log('1️⃣  Deleting child records...\n');

    // Delete messages (depends on conversations, campaigns, contacts)
    const messagesDeleted = await prisma.message.deleteMany({});
    console.log(`   ✅ Deleted ${messagesDeleted.count} messages`);

    // Delete conversations (depends on contacts, facebookPages, users)
    const conversationsDeleted = await prisma.conversation.deleteMany({});
    console.log(`   ✅ Deleted ${conversationsDeleted.count} conversations`);

    // Delete contact activities (depends on contacts, users, pipeline stages)
    const activitiesDeleted = await prisma.contactActivity.deleteMany({});
    console.log(`   ✅ Deleted ${activitiesDeleted.count} contact activities`);

    // Delete AI automation executions (depends on contacts, conversations, rules, users)
    const aiExecutionsDeleted = await prisma.aIAutomationExecution.deleteMany({});
    console.log(`   ✅ Deleted ${aiExecutionsDeleted.count} AI automation executions`);

    // Delete AI automation stops (depends on contacts, rules)
    const aiStopsDeleted = await prisma.aIAutomationStop.deleteMany({});
    console.log(`   ✅ Deleted ${aiStopsDeleted.count} AI automation stops`);

    // Delete AI automation rules (depends on users, facebookPages)
    const aiRulesDeleted = await prisma.aIAutomationRule.deleteMany({});
    console.log(`   ✅ Deleted ${aiRulesDeleted.count} AI automation rules`);

    // Delete campaigns (depends on users, facebookPages, organizations, templates)
    const campaignsDeleted = await prisma.campaign.deleteMany({});
    console.log(`   ✅ Deleted ${campaignsDeleted.count} campaigns`);

    // Delete templates (depends on organizations)
    const templatesDeleted = await prisma.template.deleteMany({});
    console.log(`   ✅ Deleted ${templatesDeleted.count} templates`);

    // Delete pipeline automations (depends on pipelines)
    const pipelineAutomationsDeleted = await prisma.pipelineAutomation.deleteMany({});
    console.log(`   ✅ Deleted ${pipelineAutomationsDeleted.count} pipeline automations`);

    // Delete pipeline stages (depends on pipelines)
    const pipelineStagesDeleted = await prisma.pipelineStage.deleteMany({});
    console.log(`   ✅ Deleted ${pipelineStagesDeleted.count} pipeline stages`);

    // Delete pipelines (depends on organizations)
    const pipelinesDeleted = await prisma.pipeline.deleteMany({});
    console.log(`   ✅ Deleted ${pipelinesDeleted.count} pipelines`);

    // Delete tags (depends on organizations)
    const tagsDeleted = await prisma.tag.deleteMany({});
    console.log(`   ✅ Deleted ${tagsDeleted.count} tags`);

    // Delete contact groups
    const contactGroupsDeleted = await prisma.contactGroup.deleteMany({});
    console.log(`   ✅ Deleted ${contactGroupsDeleted.count} contact groups`);

    // Delete sync jobs (depends on facebookPages)
    const syncJobsDeleted = await prisma.syncJob.deleteMany({});
    console.log(`   ✅ Deleted ${syncJobsDeleted.count} sync jobs`);

    // Delete webhook events
    const webhookEventsDeleted = await prisma.webhookEvent.deleteMany({});
    console.log(`   ✅ Deleted ${webhookEventsDeleted.count} webhook events`);

    // Delete team-related data
    const teamNotificationsDeleted = await prisma.teamNotification.deleteMany({});
    console.log(`   ✅ Deleted ${teamNotificationsDeleted.count} team notifications`);

    const teamTopicsDeleted = await prisma.teamTopic.deleteMany({});
    console.log(`   ✅ Deleted ${teamTopicsDeleted.count} team topics`);

    const teamMessagesDeleted = await prisma.teamMessage.deleteMany({});
    console.log(`   ✅ Deleted ${teamMessagesDeleted.count} team messages`);

    const teamThreadsDeleted = await prisma.teamThread.deleteMany({});
    console.log(`   ✅ Deleted ${teamThreadsDeleted.count} team threads`);

    const teamTasksDeleted = await prisma.teamTask.deleteMany({});
    console.log(`   ✅ Deleted ${teamTasksDeleted.count} team tasks`);

    const teamBroadcastsDeleted = await prisma.teamBroadcast.deleteMany({});
    console.log(`   ✅ Deleted ${teamBroadcastsDeleted.count} team broadcasts`);

    const teamActivitiesDeleted = await prisma.teamActivity.deleteMany({});
    console.log(`   ✅ Deleted ${teamActivitiesDeleted.count} team activities`);

    const teamJoinRequestsDeleted = await prisma.teamJoinRequest.deleteMany({});
    console.log(`   ✅ Deleted ${teamJoinRequestsDeleted.count} team join requests`);

    const teamInvitesDeleted = await prisma.teamInvite.deleteMany({});
    console.log(`   ✅ Deleted ${teamInvitesDeleted.count} team invites`);

    const teamMemberPermissionsDeleted = await prisma.teamMemberPermission.deleteMany({});
    console.log(`   ✅ Deleted ${teamMemberPermissionsDeleted.count} team member permissions`);

    const teamMembersDeleted = await prisma.teamMember.deleteMany({});
    console.log(`   ✅ Deleted ${teamMembersDeleted.count} team members`);

    const teamsDeleted = await prisma.team.deleteMany({});
    console.log(`   ✅ Deleted ${teamsDeleted.count} teams`);

    // Delete assistant-related data
    const assistantMessagesDeleted = await prisma.assistantMessage.deleteMany({});
    console.log(`   ✅ Deleted ${assistantMessagesDeleted.count} assistant messages`);

    const assistantChatsDeleted = await prisma.assistantChat.deleteMany({});
    console.log(`   ✅ Deleted ${assistantChatsDeleted.count} assistant chats`);

    // Delete page accesses (depends on users)
    const pageAccessesDeleted = await prisma.pageAccess.deleteMany({});
    console.log(`   ✅ Deleted ${pageAccessesDeleted.count} page accesses`);

    // Delete system/monitoring data (handle tables that might not exist)
    try {
      const systemAlertsDeleted = await prisma.systemAlert.deleteMany({});
      console.log(`   ✅ Deleted ${systemAlertsDeleted.count} system alerts`);
    } catch (error: any) {
      if (error?.code === 'P2021') {
        console.log(`   ⏭️  SystemAlert table does not exist (skipped)`);
      } else {
        throw error;
      }
    }

    try {
      const jobLogsDeleted = await prisma.jobLog.deleteMany({});
      console.log(`   ✅ Deleted ${jobLogsDeleted.count} job logs`);
    } catch (error: any) {
      if (error?.code === 'P2021') {
        console.log(`   ⏭️  JobLog table does not exist (skipped)`);
      } else {
        throw error;
      }
    }

    try {
      const errorLogsDeleted = await prisma.errorLog.deleteMany({});
      console.log(`   ✅ Deleted ${errorLogsDeleted.count} error logs`);
    } catch (error: any) {
      if (error?.code === 'P2021') {
        console.log(`   ⏭️  ErrorLog table does not exist (skipped)`);
      } else {
        throw error;
      }
    }

    try {
      const performanceMetricsDeleted = await prisma.performanceMetric.deleteMany({});
      console.log(`   ✅ Deleted ${performanceMetricsDeleted.count} performance metrics`);
    } catch (error: any) {
      if (error?.code === 'P2021') {
        console.log(`   ⏭️  PerformanceMetric table does not exist (skipped)`);
      } else {
        throw error;
      }
    }

    try {
      const conversationCachesDeleted = await prisma.conversationCache.deleteMany({});
      console.log(`   ✅ Deleted ${conversationCachesDeleted.count} conversation caches`);
    } catch (error: any) {
      if (error?.code === 'P2021') {
        console.log(`   ⏭️  ConversationCache table does not exist (skipped)`);
      } else {
        throw error;
      }
    }

    // SKIP: Don't delete API keys - they're important system credentials
    console.log(`   ⏭️  Skipped API keys (preserved for system use)`);

    // Step 2: Delete Contacts (this will cascade delete related data)
    console.log('\n2️⃣  Deleting contacts...\n');
    const contactsDeleted = await prisma.contact.deleteMany({});
    console.log(`   ✅ Deleted ${contactsDeleted.count} contacts`);

    // Step 2.5: Clean up AnalysisJobs - clear orphaned contactIds
    console.log('\n2️⃣.5️⃣  Cleaning up AnalysisJobs...\n');
    const analysisJobsUpdated = await prisma.analysisJob.updateMany({
      data: {
        contactIds: [],
      },
    });
    console.log(`   ✅ Cleared contactIds from ${analysisJobsUpdated.count} analysis jobs`);

    // Step 3: Delete FacebookPages (no longer needed without contacts)
    console.log('\n3️⃣  Deleting Facebook pages...\n');
    const facebookPagesDeleted = await prisma.facebookPage.deleteMany({});
    console.log(`   ✅ Deleted ${facebookPagesDeleted.count} Facebook pages`);

    // Step 4: Show what's kept
    console.log('\n4️⃣  Summary of kept data...\n');

    const orgCount = await prisma.organization.count();
    const userCount = await prisma.user.count();
    const analysisJobCount = await prisma.analysisJob.count();
    const apiKeyCount = await prisma.apiKey.count();

    console.log(`   ✅ Organizations: ${orgCount}`);
    console.log(`   ✅ Users: ${userCount}`);
    console.log(`   ✅ Analysis Jobs: ${analysisJobCount}`);
    console.log(`   ✅ API Keys: ${apiKeyCount}`);

    console.log('\n' + '='.repeat(60));
    console.log('✅ Database cleanup completed successfully!');
    console.log('='.repeat(60) + '\n');

  } catch (error) {
    console.error('\n❌ Error during cleanup:', error);
    if (error instanceof Error) {
      console.error('Error message:', error.message);
      console.error('Stack trace:', error.stack);
    }
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

// Run the cleanup
cleanupDatabase()
  .then(() => {
    console.log('Cleanup script finished.');
    process.exit(0);
  })
  .catch((error) => {
    console.error('Cleanup script failed:', error);
    process.exit(1);
  });

