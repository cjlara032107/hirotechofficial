import { prisma } from '../src/lib/db';

async function checkSystemServices() {
  console.log('\n🔍 System Services Health Check\n');
  console.log('='.repeat(60));
  
  const results = {
    database: false,
    redis: false,
    nextjs: false,
    environment: false,
  };

  // 1. Check Database (PostgreSQL via Prisma)
  console.log('\n1️⃣  Database (PostgreSQL) Check...');
  try {
    await prisma.$connect();
    const userCount = await prisma.user.count();
    const orgCount = await prisma.organization.count();
    const pageCount = await prisma.facebookPage.count();
    const contactCount = await prisma.contact.count();
    
    console.log('   ✅ Database: CONNECTED');
    console.log(`   📊 Users: ${userCount}`);
    console.log(`   📊 Organizations: ${orgCount}`);
    console.log(`   📊 Facebook Pages: ${pageCount}`);
    console.log(`   📊 Contacts: ${contactCount}`);
    results.database = true;
  } catch (error) {
    console.log('   ❌ Database: DISCONNECTED');
    console.log(`   ⚠️  Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }

  // 2. Check Redis (Optional for campaign worker)
  console.log('\n2️⃣  Redis Check...');
  const redisUrl = process.env.REDIS_URL;
  if (redisUrl) {
    console.log('   ✅ REDIS_URL configured');
    console.log('   ℹ️  Note: Redis is used for campaign queue processing');
    console.log('   💡 Campaign worker requires Redis to be running');
    results.redis = true;
  } else {
    console.log('   ⚠️  REDIS_URL not configured');
    console.log('   ℹ️  Basic features work without Redis');
    console.log('   ⚠️  Campaign processing will be limited');
  }

  // 3. Check Environment Variables
  console.log('\n3️⃣  Environment Variables Check...');
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

  let allRequired = true;
  Object.entries(requiredVars).forEach(([key, value]) => {
    if (value) {
      console.log(`   ✅ ${key}: Set`);
    } else {
      console.log(`   ❌ ${key}: Missing`);
      allRequired = false;
    }
  });

  console.log('\n   Optional Variables:');
  Object.entries(optionalVars).forEach(([key, value]) => {
    console.log(`   ${value ? '✅' : '⚠️ '} ${key}: ${value ? 'Set' : 'Not set'}`);
  });

  results.environment = allRequired;

  // 4. Check Next.js Dev Server (if running)
  console.log('\n4️⃣  Next.js Dev Server Check...');
  try {
    const response = await fetch('http://localhost:3000/api/health', {
      signal: AbortSignal.timeout(5000),
    });
    
    if (response.ok) {
      const data = await response.json();
      console.log('   ✅ Next.js Dev Server: RUNNING');
      console.log(`   📊 Status: ${data.status || 'healthy'}`);
      results.nextjs = true;
    } else {
      console.log('   ⚠️  Dev server responded but not healthy');
    }
  } catch {
    console.log('   ⚠️  Next.js Dev Server: NOT DETECTED');
    console.log('   💡 Start with: npm run dev');
  }

  // 5. Check Ngrok Tunnel
  console.log('\n5️⃣  Ngrok Tunnel Check...');
  const nextPublicAppUrl = process.env.NEXT_PUBLIC_APP_URL;
  if (nextPublicAppUrl && nextPublicAppUrl.includes('ngrok')) {
    console.log('   ✅ Ngrok URL configured');
    console.log(`   🌐 URL: ${nextPublicAppUrl}`);
    console.log('   ℹ️  Used for Facebook OAuth callbacks');
  } else {
    console.log('   ℹ️  No Ngrok tunnel detected');
    console.log('   💡 Ngrok only needed for:');
    console.log('      - Facebook OAuth testing');
    console.log('      - External webhook testing');
    console.log('      - Production preview');
  }

  // 6. Campaign Worker Status
  console.log('\n6️⃣  Campaign Worker Status...');
  if (results.redis && results.database) {
    console.log('   ✅ Prerequisites met for campaign worker');
    console.log('   💡 Campaign worker can process queued messages');
    console.log('   ℹ️  Worker runs automatically when campaigns are sent');
  } else {
    console.log('   ⚠️  Campaign worker prerequisites not met');
    if (!results.redis) {
      console.log('   ❌ Redis not configured');
    }
    if (!results.database) {
      console.log('   ❌ Database not connected');
    }
  }

  // Summary
  console.log('\n' + '='.repeat(60));
  console.log('\n📊 Summary:');
  console.log(`   Database: ${results.database ? '✅ Connected' : '❌ Disconnected'}`);
  console.log(`   Environment: ${results.environment ? '✅ All required vars set' : '⚠️  Missing vars'}`);
  console.log(`   Next.js Dev: ${results.nextjs ? '✅ Running' : '⚠️  Not detected'}`);
  console.log(`   Redis: ${results.redis ? '✅ Configured' : '⚠️  Not configured'}`);

  console.log('\n💡 Overall Status:');
  if (results.database && results.environment) {
    console.log('   ✅ Core systems operational');
    console.log('   ✅ Authentication and basic features available');
    if (results.redis) {
      console.log('   ✅ Campaign processing available');
    } else {
      console.log('   ⚠️  Campaign processing limited (no Redis)');
    }
  } else {
    console.log('   ⚠️  Some core systems need attention');
  }

  console.log('\n');
  await prisma.$disconnect();
}

checkSystemServices().catch(console.error);

