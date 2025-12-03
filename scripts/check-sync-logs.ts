/**
 * Script to check sync logs and recent sync activity
 * Run with: npx tsx scripts/check-sync-logs.ts
 */

import { prisma, connectPrisma } from '../src/lib/db';

async function checkSyncLogs() {
  try {
    await connectPrisma();

    console.log('🔍 Checking recent sync jobs...\n');

    // Get recent sync jobs (last 10)
    const recentJobs = await prisma.syncJob.findMany({
      take: 10,
      orderBy: {
        createdAt: 'desc',
      },
      include: {
        facebookPage: {
          select: {
            pageName: true,
            pageId: true,
          },
        },
      },
    });

    if (recentJobs.length === 0) {
      console.log('❌ No sync jobs found in database\n');
      return;
    }

    console.log(`📊 Found ${recentJobs.length} recent sync job(s):\n`);

    for (const job of recentJobs) {
      const createdAt = new Date(job.createdAt);
      const startedAt = job.startedAt ? new Date(job.startedAt) : null;
      const completedAt = job.completedAt ? new Date(job.completedAt) : null;
      
      const duration = startedAt && completedAt
        ? `${Math.round((completedAt.getTime() - startedAt.getTime()) / 1000)}s`
        : startedAt
          ? `${Math.round((Date.now() - startedAt.getTime()) / 1000)}s (running)`
          : 'not started';

      const statusEmoji = {
        PENDING: '⏳',
        IN_PROGRESS: '🔄',
        COMPLETED: '✅',
        FAILED: '❌',
        CANCELLED: '🚫',
      }[job.status] || '❓';

      console.log(`${statusEmoji} Job: ${job.id}`);
      console.log(`   Page: ${job.facebookPage?.pageName || 'Unknown'} (${job.facebookPage?.pageId || 'N/A'})`);
      console.log(`   Status: ${job.status}`);
      console.log(`   Created: ${createdAt.toLocaleString()}`);
      if (startedAt) {
        console.log(`   Started: ${startedAt.toLocaleString()}`);
      }
      if (completedAt) {
        console.log(`   Completed: ${completedAt.toLocaleString()}`);
      }
      console.log(`   Duration: ${duration}`);
      console.log(`   Progress: ${job.syncedContacts}/${job.totalContacts} synced, ${job.failedContacts} failed`);
      
      if (job.tokenExpired) {
        console.log(`   ⚠️  Token expired!`);
      }
      
      if (job.errors && Array.isArray(job.errors) && job.errors.length > 0) {
        console.log(`   Errors: ${job.errors.length} error(s)`);
        job.errors.slice(0, 3).forEach((error: any, index: number) => {
          console.log(`      ${index + 1}. ${error.error || error.message || JSON.stringify(error)}`);
        });
        if (job.errors.length > 3) {
          console.log(`      ... and ${job.errors.length - 3} more`);
        }
      }
      
      console.log('');
    }

    // Check for active sync jobs
    const activeJobs = recentJobs.filter(job => 
      job.status === 'PENDING' || job.status === 'IN_PROGRESS'
    );

    if (activeJobs.length > 0) {
      console.log(`\n🔄 Active sync jobs: ${activeJobs.length}`);
      activeJobs.forEach(job => {
        console.log(`   - ${job.id} (${job.facebookPage?.pageName || 'Unknown'}) - ${job.status}`);
        if (job.startedAt) {
          const runningTime = Math.round((Date.now() - new Date(job.startedAt).getTime()) / 1000);
          console.log(`     Running for: ${runningTime}s`);
        }
      });
    } else {
      console.log('\n✅ No active sync jobs');
    }

    // Summary
    const completed = recentJobs.filter(j => j.status === 'COMPLETED').length;
    const failed = recentJobs.filter(j => j.status === 'FAILED').length;
    const inProgress = recentJobs.filter(j => j.status === 'IN_PROGRESS' || j.status === 'PENDING').length;

    console.log('\n📈 Summary:');
    console.log(`   ✅ Completed: ${completed}`);
    console.log(`   ❌ Failed: ${failed}`);
    console.log(`   🔄 In Progress: ${inProgress}`);

  } catch (error) {
    console.error('❌ Error checking sync logs:', error);
    if (error instanceof Error) {
      console.error('   Message:', error.message);
      console.error('   Stack:', error.stack);
    }
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

checkSyncLogs();









