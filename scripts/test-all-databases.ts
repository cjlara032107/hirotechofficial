/**
 * Test All Database Connections
 * Verifies all configured databases are accessible and working
 */

import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';

dotenv.config({ path: '.env.local' });
dotenv.config({ path: '.env' });

interface DatabaseTestResult {
  index: number;
  url: string;
  accessible: boolean;
  error?: string;
  responseTime?: number;
}

async function testDatabaseConnection(index: number, url: string): Promise<DatabaseTestResult> {
  const startTime = Date.now();
  
  try {
    const client = new PrismaClient({
      datasources: {
        db: {
          url: url,
        },
      },
      log: [], // Suppress logs during test
    });

    // Test connection with a simple query
    await Promise.race([
      client.$queryRaw`SELECT 1 as test`,
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Connection timeout after 10 seconds')), 10000)
      )
    ]);

    const responseTime = Date.now() - startTime;
    
    await client.$disconnect();
    
    return {
      index,
      url: url.replace(/:[^:@]+@/, ':****@'), // Hide password
      accessible: true,
      responseTime,
    };
  } catch (error: any) {
    const responseTime = Date.now() - startTime;
    const errorMessage = error?.message || String(error);
    
    return {
      index,
      url: url.replace(/:[^:@]+@/, ':****@'), // Hide password
      accessible: false,
      error: errorMessage,
      responseTime,
    };
  }
}

async function testAllDatabases() {
  console.log('🔍 Testing All Database Connections\n');
  console.log('='.repeat(80));

  const dbCount = parseInt(process.env.DB_COUNT || '3', 10);
  const results: DatabaseTestResult[] = [];

  console.log(`\n📊 Testing ${dbCount} databases...\n`);

  // Test each database
  for (let i = 0; i < dbCount; i++) {
    const dbUrl = process.env[`DATABASE_URL_${i}`];
    
    if (!dbUrl) {
      console.log(`⚠️  DATABASE_URL_${i}: Not configured`);
      results.push({
        index: i,
        url: 'Not configured',
        accessible: false,
        error: 'Environment variable not set',
      });
      continue;
    }

    console.log(`Testing Database ${i}...`);
    const result = await testDatabaseConnection(i, dbUrl);
    results.push(result);

    if (result.accessible) {
      console.log(`  ✅ Database ${i}: Accessible (${result.responseTime}ms)`);
    } else {
      console.log(`  ❌ Database ${i}: Failed - ${result.error}`);
    }
  }

  // Summary
  console.log('\n' + '='.repeat(80));
  console.log('📊 SUMMARY\n');

  const accessible = results.filter(r => r.accessible).length;
  const failed = results.filter(r => !r.accessible).length;

  results.forEach(result => {
    const status = result.accessible ? '✅' : '❌';
    const time = result.responseTime ? ` (${result.responseTime}ms)` : '';
    const error = result.error ? ` - ${result.error}` : '';
    console.log(`${status} Database ${result.index}: ${result.accessible ? 'Accessible' : 'Failed'}${time}${error}`);
  });

  console.log(`\n✅ Accessible: ${accessible}/${results.length}`);
  console.log(`❌ Failed: ${failed}/${results.length}`);

  if (failed > 0) {
    console.log('\n⚠️  ISSUES FOUND:\n');
    
    results.filter(r => !r.accessible).forEach(result => {
      console.log(`Database ${result.index}:`);
      console.log(`  URL: ${result.url}`);
      console.log(`  Error: ${result.error}`);
      console.log('');
    });

    console.log('💡 POSSIBLE FIXES:');
    console.log('  1. Check if Supabase projects are paused (free tier pauses after inactivity)');
    console.log('  2. Verify connection strings are correct');
    console.log('  3. Check network/firewall settings');
    console.log('  4. Ensure databases are not deleted or suspended');
    console.log('  5. Try restarting Supabase projects in dashboard');
  } else {
    console.log('\n✅ All databases are accessible!');
  }

  console.log('\n' + '='.repeat(80));
}

testAllDatabases().catch(console.error);




