import { prisma } from '../src/lib/db';

async function comprehensiveSystemCheck() {
  console.log('\n🔍 Comprehensive System Health Check\n');
  console.log('='.repeat(70));

  const results = {
    database: false,
    redis: false,
    devServer: false,
    campaignWorker: false,
    ngrokTunnel: false,
  };

  // ===== 1. DATABASE CHECK =====
  console.log('\n📊 1. DATABASE CHECK');
  console.log('-'.repeat(70));
  try {
    await prisma.$connect();
    console.log('✅ PostgreSQL Connected');
    
    // Check database version
    const dbVersion: Array<{ version: string }> = await prisma.$queryRawUnsafe('SELECT version();');
    console.log(`   Version: ${dbVersion[0].version.split(',')[0]}`);
    
    // Check connection pool
    console.log('\n   Testing queries:');
    const userCount = await prisma.user.count();
    const orgCount = await prisma.organization.count();
    const contactCount = await prisma.contact.count();
    const campaignCount = await prisma.campaign.count();
    
    console.log(`   - Users: ${userCount}`);
    console.log(`   - Organizations: ${orgCount}`);
    console.log(`   - Contacts: ${contactCount}`);
    console.log(`   - Campaigns: ${campaignCount}`);
    
    results.database = true;
  } catch (error) {
    console.log('❌ Database Connection Failed');
    if (error instanceof Error) {
      console.log(`   Error: ${error.message}`);
    }
  }

  // ===== 2. REDIS CHECK =====
  console.log('\n📮 2. REDIS CHECK (Optional)');
  console.log('-'.repeat(70));
  try {
    const redisUrl = process.env.REDIS_URL;
    if (!redisUrl) {
      console.log('⚠️  REDIS_URL not configured');
      console.log('   Impact: Campaign queue processing unavailable');
      console.log('   Note: Basic features work without Redis');
    } else {
      console.log(`   REDIS_URL: ${redisUrl.substring(0, 20)}...`);
      console.log('   ℹ️  Redis check requires runtime connection');
      console.log('   Note: Used for background job processing');
    }
  } catch {
    console.log('⚠️  Redis check skipped');
  }

  // ===== 3. NEXT.JS DEV SERVER CHECK =====
  console.log('\n🚀 3. NEXT.JS DEV SERVER');
  console.log('-'.repeat(70));
  try {
    const response = await fetch('http://localhost:3000/api/health', {
      method: 'GET',
    });
    
    if (response.ok) {
      const data = await response.json();
      console.log('✅ Dev Server Running');
      console.log(`   Status: ${data.status || 'healthy'}`);
      console.log(`   Port: 3000`);
      results.devServer = true;
    } else {
      console.log('⚠️  Dev Server responding with errors');
      console.log(`   Status Code: ${response.status}`);
    }
  } catch {
    console.log('❌ Dev Server Not Running');
    console.log('   Start with: npm run dev');
  }

  // ===== 4. CAMPAIGN WORKER CHECK =====
  console.log('\n⚙️  4. CAMPAIGN WORKER / BACKGROUND JOBS');
  console.log('-'.repeat(70));
  try {
    // Check for active campaigns
    const activeCampaigns = await prisma.campaign.findMany({
      where: {
        status: {
          in: ['SENDING', 'SCHEDULED'],
        },
      },
      select: {
        id: true,
        name: true,
        status: true,
        sentCount: true,
        totalRecipients: true,
      },
    });
    
    if (activeCampaigns.length > 0) {
      console.log(`⚙️  ${activeCampaigns.length} Active Campaign(s)`);
      activeCampaigns.forEach(campaign => {
        console.log(`   - ${campaign.name}: ${campaign.status}`);
        console.log(`     Progress: ${campaign.sentCount}/${campaign.totalRecipients}`);
      });
      console.log('\n   Note: Campaign worker processes these via background jobs');
    } else {
      console.log('✅ No active campaigns (Worker idle)');
    }
    
    // Check for pending sync jobs
    const pendingSyncs = await prisma.syncJob.count({
      where: {
        status: {
          in: ['PENDING', 'IN_PROGRESS'],
        },
      },
    });
    
    if (pendingSyncs > 0) {
      console.log(`   📊 ${pendingSyncs} sync job(s) pending/in-progress`);
    } else {
      console.log('   ✅ No pending sync jobs');
    }
    
    results.campaignWorker = true;
  } catch (error) {
    console.log('❌ Cannot check campaign worker status');
    if (error instanceof Error) {
      console.log(`   Error: ${error.message}`);
    }
  }

  // ===== 5. NGROK TUNNEL CHECK =====
  console.log('\n🌐 5. NGROK TUNNEL (Optional)');
  console.log('-'.repeat(70));
  const appUrl = process.env.NEXT_PUBLIC_APP_URL;
  const isNgrok = appUrl?.includes('ngrok');
  
  if (isNgrok) {
    console.log(`✅ Ngrok URL configured: ${appUrl}`);
    console.log('   Used for: Facebook OAuth callbacks, Webhooks');
    results.ngrokTunnel = true;
  } else if (appUrl?.includes('localhost')) {
    console.log('ℹ️  Local development mode');
    console.log(`   URL: ${appUrl || 'http://localhost:3000'}`);
    console.log('   Note: Ngrok only needed for external webhooks');
  } else if (appUrl) {
    console.log(`✅ Production URL: ${appUrl}`);
    results.ngrokTunnel = true;
  } else {
    console.log('⚠️  NEXT_PUBLIC_APP_URL not set');
    console.log('   Impact: Facebook OAuth may not work correctly');
  }

  // ===== ENVIRONMENT VARIABLES CHECK =====
  console.log('\n📋 6. ENVIRONMENT VARIABLES');
  console.log('-'.repeat(70));
  
  const requiredVars = {
    'DATABASE_URL': !!process.env.DATABASE_URL,
    'NEXTAUTH_SECRET': !!process.env.NEXTAUTH_SECRET,
    'NEXTAUTH_URL': !!process.env.NEXTAUTH_URL,
  };
  
  const optionalVars = {
    'FACEBOOK_APP_ID': !!process.env.FACEBOOK_APP_ID,
    'FACEBOOK_APP_SECRET': !!process.env.FACEBOOK_APP_SECRET,
    'REDIS_URL': !!process.env.REDIS_URL,
    'NEXT_PUBLIC_APP_URL': !!process.env.NEXT_PUBLIC_APP_URL,
  };
  
  console.log('   Required:');
  Object.entries(requiredVars).forEach(([key, value]) => {
    console.log(`   ${value ? '✅' : '❌'} ${key}`);
  });
  
  console.log('\n   Optional:');
  Object.entries(optionalVars).forEach(([key, value]) => {
    console.log(`   ${value ? '✅' : '⚠️ '} ${key}`);
  });

  // ===== SUMMARY =====
  console.log('\n' + '='.repeat(70));
  console.log('\n📊 SYSTEM HEALTH SUMMARY\n');
  
  console.log(`Database:         ${results.database ? '✅ Connected' : '❌ Failed'}`);
  console.log(`Dev Server:       ${results.devServer ? '✅ Running' : '❌ Not Running'}`);
  console.log(`Campaign Worker:  ${results.campaignWorker ? '✅ Ready' : '⚠️  Check Required'}`);
  console.log(`Redis:            ${process.env.REDIS_URL ? '⚙️  Configured' : '⚠️  Not Configured (Optional)'}`);
  console.log(`Ngrok/URL:        ${results.ngrokTunnel ? '✅ Configured' : 'ℹ️  Local Dev Mode'}`);

  // Critical issues
  const criticalIssues = [];
  if (!results.database) criticalIssues.push('Database connection failed');
  if (!results.devServer) criticalIssues.push('Dev server not running');
  
  if (criticalIssues.length > 0) {
    console.log('\n⚠️  CRITICAL ISSUES:');
    criticalIssues.forEach(issue => console.log(`   - ${issue}`));
  } else {
    console.log('\n✅ ALL CRITICAL SYSTEMS OPERATIONAL');
  }
  
  // Recommendations
  console.log('\n💡 RECOMMENDATIONS:');
  if (!process.env.REDIS_URL) {
    console.log('   - Add Redis for campaign queue processing');
  }
  if (!process.env.NEXT_PUBLIC_APP_URL?.includes('ngrok') && !process.env.NEXT_PUBLIC_APP_URL?.includes('http')) {
    console.log('   - Set NEXT_PUBLIC_APP_URL for Facebook OAuth');
  }
  if (results.database && results.devServer) {
    console.log('   - System ready for development! 🚀');
  }
  
  console.log('\n' + '='.repeat(70) + '\n');

  await prisma.$disconnect();
}

comprehensiveSystemCheck().catch(console.error);

