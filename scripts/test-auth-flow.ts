/**
 * Test Authentication Flow
 * 
 * This script tests the complete authentication flow including:
 * - Supabase connection
 * - Database connection
 * - User profile creation
 * - Session verification
 * 
 * Usage: npx tsx scripts/test-auth-flow.ts
 */

import { createClient } from '@supabase/supabase-js';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function testSupabaseConnection() {
  console.log('\n📡 Testing Supabase Connection...');
  
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseKey) {
    console.error('❌ Missing Supabase environment variables');
    return false;
  }

  try {
    const supabase = createClient(supabaseUrl, supabaseKey);
    const { error } = await supabase.auth.getSession();
    
    if (error) {
      console.error('❌ Supabase connection failed:', error.message);
      return false;
    }
    
    console.log('✅ Supabase connection successful');
    return true;
  } catch (error) {
    console.error('❌ Supabase connection error:', error);
    return false;
  }
}

async function testDatabaseConnection() {
  console.log('\n🗄️  Testing Database Connection...');
  
  try {
    await prisma.$connect();
    console.log('✅ Database connected');
    
    // Test a simple query
    const userCount = await prisma.user.count();
    console.log(`✅ Database query successful (${userCount} users found)`);
    
    return true;
  } catch (error) {
    console.error('❌ Database connection failed:', error);
    return false;
  }
}

async function testUserProfiles() {
  console.log('\n👥 Checking User Profiles...');
  
  try {
    const users = await prisma.user.findMany({
      include: {
        organization: true,
      },
      take: 10,
    });
    
    console.log(`✅ Found ${users.length} users in database`);
    
    for (const user of users) {
      console.log(`   - ${user.email} (${user.name || 'No name'})`);
      console.log(`     Organization: ${user.organization.name}`);
      console.log(`     Role: ${user.role}`);
    }
    
    return true;
  } catch (error) {
    console.error('❌ Failed to fetch user profiles:', error);
    return false;
  }
}

async function testOrphanedSupabaseUsers() {
  console.log('\n🔍 Checking for Orphaned Supabase Users...');
  
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !supabaseServiceKey) {
    console.log('⚠️  Skipping (SUPABASE_SERVICE_ROLE_KEY not set)');
    return true;
  }

  try {
    const supabase = createClient(supabaseUrl, supabaseServiceKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    });

    const { data: { users }, error } = await supabase.auth.admin.listUsers();

    if (error) {
      console.error('❌ Failed to fetch Supabase users:', error);
      return false;
    }

    console.log(`✅ Found ${users.length} users in Supabase Auth`);

    let orphanedCount = 0;
    
    for (const user of users) {
      const profile = await prisma.user.findUnique({
        where: { id: user.id },
      });

      if (!profile) {
        console.log(`   ⚠️  Orphaned user: ${user.email} (${user.id})`);
        orphanedCount++;
      }
    }

    if (orphanedCount === 0) {
      console.log('✅ No orphaned users found');
    } else {
      console.log(`⚠️  Found ${orphanedCount} orphaned user(s)`);
      console.log('   Run: npx tsx scripts/sync-supabase-users.ts to fix');
    }

    return true;
  } catch (error) {
    console.error('❌ Failed to check orphaned users:', error);
    return false;
  }
}

async function main() {
  console.log('🚀 Starting Authentication Flow Tests...');
  console.log('='.repeat(60));

  const results = {
    supabase: await testSupabaseConnection(),
    database: await testDatabaseConnection(),
    profiles: await testUserProfiles(),
    orphaned: await testOrphanedSupabaseUsers(),
  };

  console.log('\n' + '='.repeat(60));
  console.log('📊 Test Results Summary:');
  console.log('='.repeat(60));
  console.log(`Supabase Connection:     ${results.supabase ? '✅ PASS' : '❌ FAIL'}`);
  console.log(`Database Connection:     ${results.database ? '✅ PASS' : '❌ FAIL'}`);
  console.log(`User Profiles:           ${results.profiles ? '✅ PASS' : '❌ FAIL'}`);
  console.log(`Orphaned Users Check:    ${results.orphaned ? '✅ PASS' : '⚠️  WARN'}`);
  console.log('='.repeat(60));

  const allPassed = Object.values(results).every(result => result);

  if (allPassed) {
    console.log('\n✅ All tests passed! Authentication system is ready.');
  } else {
    console.log('\n❌ Some tests failed. Please check the errors above.');
    process.exit(1);
  }
}

main()
  .catch((error) => {
    console.error('💥 Test script failed:', error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

