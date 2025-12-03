#!/usr/bin/env tsx
/**
 * Verify database connection strings for all configured databases
 * Tests both pooled and direct connections
 */

import { PrismaClient } from '@prisma/client';
import * as dotenv from 'dotenv';

dotenv.config({ path: '.env.local' });
dotenv.config();

const DB_COUNT = parseInt(process.env.DB_COUNT || '3', 10);

interface ConnectionTest {
  database: number;
  type: 'pooled' | 'direct';
  url: string;
  success: boolean;
  error?: string;
  responseTime?: number;
}

const results: ConnectionTest[] = [];

async function testConnection(url: string, type: 'pooled' | 'direct', dbIndex: number): Promise<ConnectionTest> {
  const startTime = Date.now();
  
  try {
    const client = new PrismaClient({
      datasources: {
        db: {
          url: url,
        },
      },
      log: [],
    });

    // Test connection with a simple query
    await client.$queryRaw`SELECT 1 as test`;
    await client.$disconnect();

    const responseTime = Date.now() - startTime;
    
    return {
      database: dbIndex,
      type,
      url: url.replace(/:[^:@]+@/, ':****@'), // Hide password
      success: true,
      responseTime,
    };
  } catch (error) {
    const responseTime = Date.now() - startTime;
    const errorMsg = error instanceof Error ? error.message : String(error);
    
    return {
      database: dbIndex,
      type,
      url: url.replace(/:[^:@]+@/, ':****@'), // Hide password
      success: false,
      error: errorMsg.substring(0, 200), // Limit error length
      responseTime,
    };
  }
}

async function runTests() {
  console.log('🔍 Verifying Database Connection Strings...\n');
  console.log('='.repeat(80));

  for (let i = 0; i < DB_COUNT; i++) {
    const dbUrl = process.env[`DATABASE_URL_${i}`];
    const directUrl = process.env[`DIRECT_URL_${i}`];

    if (!dbUrl) {
      console.log(`\n⚠️  Database ${i + 1}: DATABASE_URL_${i} not set`);
      continue;
    }

    console.log(`\n📦 Testing Database ${i + 1}/${DB_COUNT}`);
    console.log('-'.repeat(80));

    // Test pooled connection
    console.log(`   🔄 Testing pooled connection (port 6543)...`);
    const pooledResult = await testConnection(dbUrl, 'pooled', i);
    results.push(pooledResult);
    
    if (pooledResult.success) {
      console.log(`   ✅ Pooled connection: SUCCESS (${pooledResult.responseTime}ms)`);
    } else {
      console.log(`   ❌ Pooled connection: FAILED`);
      console.log(`      Error: ${pooledResult.error}`);
    }

    // Test direct connection
    if (directUrl) {
      console.log(`   🔄 Testing direct connection (port 5432)...`);
      const directResult = await testConnection(directUrl, 'direct', i);
      results.push(directResult);
      
      if (directResult.success) {
        console.log(`   ✅ Direct connection: SUCCESS (${directResult.responseTime}ms)`);
      } else {
        console.log(`   ❌ Direct connection: FAILED`);
        console.log(`      Error: ${directResult.error}`);
      }
    } else {
      console.log(`   ⚠️  DIRECT_URL_${i} not set, skipping direct connection test`);
    }

    // Show connection strings (with password hidden)
    console.log(`\n   📋 Connection Strings:`);
    console.log(`      Pooled:  ${dbUrl.replace(/:[^:@]+@/, ':****@')}`);
    if (directUrl) {
      console.log(`      Direct:  ${directUrl.replace(/:[^:@]+@/, ':****@')}`);
    }
  }

  // Summary
  console.log('\n' + '='.repeat(80));
  console.log('📊 Summary\n');

  const successful = results.filter(r => r.success).length;
  const failed = results.filter(r => !r.success).length;

  console.log(`✅ Successful connections: ${successful}`);
  console.log(`❌ Failed connections: ${failed}\n`);

  if (failed > 0) {
    console.log('🔧 Issues Found:\n');
    
    results.filter(r => !r.success).forEach(result => {
      console.log(`   Database ${result.database + 1} (${result.type}):`);
      console.log(`      URL: ${result.url}`);
      console.log(`      Error: ${result.error}\n`);
    });

    console.log('💡 Recommendations:');
    console.log('   1. Verify Supabase projects are active and running');
    console.log('   2. Check connection strings in Supabase Dashboard → Settings → Database');
    console.log('   3. Ensure you\'re using the correct project reference and password');
    console.log('   4. For direct connections, use port 5432 (not 6543)');
    console.log('   5. For pooled connections, use port 6543 with ?pgbouncer=true');
  } else {
    console.log('🎉 All database connections are working!');
  }

  console.log('\n' + '='.repeat(80));
}

runTests().catch(console.error);

