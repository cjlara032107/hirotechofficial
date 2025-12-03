/**
 * Diagnostic script to check AI analysis logs and status
 * Run with: npx tsx scripts/check-ai-analysis-logs.ts
 */

import { prisma } from '../src/lib/db';

async function checkAIAnalysisStatus() {
  console.log('🔍 Checking AI Analysis Status...\n');

  // Check for recent sync jobs (pipeline analysis)
  const recentJobs = await prisma.syncJob.findMany({
    take: 10,
    orderBy: { createdAt: 'desc' },
    where: {
      type: 'PIPELINE_ANALYSIS'
    },
    select: {
      id: true,
      status: true,
      createdAt: true,
      completedAt: true,
      errors: true,
      metadata: true,
    }
  });

  console.log(`📊 Recent Pipeline Analysis Jobs (${recentJobs.length}):`);
  if (recentJobs.length === 0) {
    console.log('   No pipeline analysis jobs found.');
  } else {
    recentJobs.forEach((job, i) => {
      console.log(`\n${i + 1}. Job ${job.id}`);
      console.log(`   Status: ${job.status}`);
      console.log(`   Created: ${job.createdAt.toISOString()}`);
      if (job.completedAt) {
        const duration = (job.completedAt.getTime() - job.createdAt.getTime()) / 1000;
        console.log(`   Completed: ${job.completedAt.toISOString()} (${duration.toFixed(1)}s)`);
      } else {
        const running = (Date.now() - job.createdAt.getTime()) / 1000;
        console.log(`   Running for: ${running.toFixed(1)}s`);
      }
      if (job.errors && job.errors.length > 0) {
        console.log(`   ❌ Errors (${job.errors.length}):`);
        job.errors.forEach((err: any, idx: number) => {
          console.log(`      ${idx + 1}. ${err.error || JSON.stringify(err)}`);
        });
      }
      if (job.metadata) {
        console.log(`   Metadata:`, JSON.stringify(job.metadata, null, 2));
      }
    });
  }

  // Check for contacts with recent AI analysis
  const recentContacts = await prisma.contact.findMany({
    take: 10,
    orderBy: { aiContextUpdatedAt: 'desc' },
    where: {
      OR: [
        { aiContext: { not: null } },
        { aiSummary: { not: null } },
        { aiContextUpdatedAt: { not: null } }
      ]
    },
    select: {
      id: true,
      firstName: true,
      lastName: true,
      aiContext: true,
      aiSummary: true,
      aiContextUpdatedAt: true,
      leadScore: true,
      messengerPSID: true,
      instagramSID: true,
    }
  });

  console.log(`\n\n📝 Recent AI Analysis Results (${recentContacts.length}):`);
  if (recentContacts.length === 0) {
    console.log('   No contacts with AI analysis found.');
  } else {
    recentContacts.forEach((contact, i) => {
      console.log(`\n${i + 1}. ${contact.firstName || ''} ${contact.lastName || ''} (${contact.id.substring(0, 8)}...)`);
      console.log(`   Lead Score: ${contact.leadScore || 'N/A'}`);
      console.log(`   Updated: ${contact.aiContextUpdatedAt?.toISOString() || 'Never'}`);
      if (contact.messengerPSID) {
        console.log(`   Platform: Messenger`);
      } else if (contact.instagramSID) {
        console.log(`   Platform: Instagram`);
      }
      if (contact.aiContext) {
        const contextLength = contact.aiContext.length;
        const preview = contact.aiContext.substring(0, 200);
        console.log(`   AI Context: ${contextLength} chars`);
        console.log(`   Preview: ${preview}${contextLength > 200 ? '...' : ''}`);
        if (contextLength < 200) {
          console.log(`   ⚠️ WARNING: AI context is very short (${contextLength} chars) - likely using fallback`);
        } else if (contextLength < 500) {
          console.log(`   ⚠️ WARNING: AI context is short (${contextLength} chars) - may not be detailed enough`);
        } else {
          console.log(`   ✅ AI context length looks good`);
        }
      } else {
        console.log(`   ⚠️ No AI Context`);
      }
      if (contact.aiSummary) {
        const summaryLength = contact.aiSummary.length;
        const preview = contact.aiSummary.substring(0, 150);
        console.log(`   AI Summary: ${summaryLength} chars`);
        console.log(`   Preview: ${preview}${summaryLength > 150 ? '...' : ''}`);
        if (summaryLength < 200) {
          console.log(`   ⚠️ WARNING: AI summary is very short (${summaryLength} chars) - likely using fallback`);
        }
      } else {
        console.log(`   ⚠️ No AI Summary`);
      }
    });
  }

  // Check API keys
  const apiKeys = await prisma.apiKey.findMany({
    where: {
      service: 'NVIDIA',
      isActive: true
    },
    select: {
      id: true,
      keyPrefix: true,
      lastUsedAt: true,
      consecutiveFailures: true,
      isRateLimited: true,
      createdAt: true,
    },
    orderBy: { lastUsedAt: 'desc' }
  });

  console.log(`\n\n🔑 NVIDIA API Keys (${apiKeys.length} active):`);
  if (apiKeys.length === 0) {
    console.log('   ❌ NO ACTIVE API KEYS FOUND!');
    console.log('   → Add API keys in Settings → API Keys');
    console.log('   → Or set NVIDIA_API_KEY environment variable');
  } else {
    apiKeys.forEach((key, i) => {
      console.log(`\n${i + 1}. Key ${key.id}`);
      console.log(`   Prefix: ${key.keyPrefix}`);
      console.log(`   Created: ${key.createdAt.toISOString()}`);
      console.log(`   Last Used: ${key.lastUsedAt?.toISOString() || 'Never'}`);
      console.log(`   Failures: ${key.consecutiveFailures || 0}`);
      if (key.isRateLimited) {
        console.log(`   ⚠️ RATE LIMITED`);
      }
      if (key.consecutiveFailures && key.consecutiveFailures > 5) {
        console.log(`   ⚠️ HIGH FAILURE COUNT - may need attention`);
      }
    });
  }

  // Check environment variable
  const envKey = process.env.NVIDIA_API_KEY || process.env.GOOGLE_AI_API_KEY;
  if (envKey) {
    console.log(`\n\n🌍 Environment Variable:`);
    console.log(`   Found: ${envKey.substring(0, 12)}... (${envKey.length} chars)`);
  } else {
    console.log(`\n\n🌍 Environment Variable: Not set`);
  }

  // Check recent activity logs related to AI
  const recentActivity = await prisma.contactActivity.findMany({
    take: 10,
    orderBy: { createdAt: 'desc' },
    where: {
      OR: [
        { type: 'STAGE_CHANGED' },
        { description: { contains: 'AI' } }
      ]
    },
    select: {
      id: true,
      contactId: true,
      type: true,
      title: true,
      description: true,
      createdAt: true,
      metadata: true,
    }
  });

  console.log(`\n\n📋 Recent AI-Related Activity (${recentActivity.length}):`);
  if (recentActivity.length > 0) {
    recentActivity.forEach((activity, i) => {
      console.log(`\n${i + 1}. ${activity.type} - ${activity.title || 'N/A'}`);
      console.log(`   Contact: ${activity.contactId.substring(0, 8)}...`);
      console.log(`   Time: ${activity.createdAt.toISOString()}`);
      if (activity.description) {
        const desc = activity.description.substring(0, 150);
        console.log(`   Description: ${desc}${activity.description.length > 150 ? '...' : ''}`);
      }
      if (activity.metadata) {
        console.log(`   Metadata:`, JSON.stringify(activity.metadata, null, 2));
      }
    });
  }

  // Summary statistics
  const totalContacts = await prisma.contact.count();
  const contactsWithAI = await prisma.contact.count({
    where: {
      aiContext: { not: null }
    }
  });
  const contactsWithShortAI = await prisma.contact.count({
    where: {
      aiContext: { not: null },
      OR: [
        { aiContext: { lt: '200' } }
      ]
    }
  });

  console.log(`\n\n📈 Summary Statistics:`);
  console.log(`   Total Contacts: ${totalContacts}`);
  console.log(`   Contacts with AI Context: ${contactsWithAI} (${((contactsWithAI / totalContacts) * 100).toFixed(1)}%)`);
  console.log(`   Contacts with Short AI Context (<200 chars): ${contactsWithShortAI}`);
  if (contactsWithShortAI > 0 && contactsWithAI > 0) {
    console.log(`   ⚠️ ${((contactsWithShortAI / contactsWithAI) * 100).toFixed(1)}% of AI analyses are very short (likely fallback)`);
  }

  console.log('\n\n✅ Diagnostic complete!');
}

checkAIAnalysisStatus().catch((error) => {
  console.error('❌ Error running diagnostic:', error);
  process.exit(1);
});
