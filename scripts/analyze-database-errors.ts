/**
 * Deep Analysis of Database Connection Errors
 * Identifies root cause of connection failures
 */

import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';
import * as dns from 'dns';
import { promisify } from 'util';

dotenv.config({ path: '.env.local' });
dotenv.config({ path: '.env' });

const dnsLookup = promisify(dns.lookup);

interface ErrorAnalysis {
  database: number;
  url: string;
  hostname: string;
  port: number;
  dnsResolvable: boolean;
  dnsError?: string;
  connectionError: string;
  errorCode?: string;
  errorType: 'dns' | 'connection' | 'auth' | 'timeout' | 'unknown';
  recommendations: string[];
}

async function analyzeDatabaseError(index: number, url: string): Promise<ErrorAnalysis> {
  const urlObj = new URL(url);
  const hostname = urlObj.hostname;
  const port = parseInt(urlObj.port || '6543', 10);

  const analysis: ErrorAnalysis = {
    database: index,
    url: url.replace(/:[^:@]+@/, ':****@'),
    hostname,
    port,
    dnsResolvable: false,
    connectionError: '',
    errorType: 'unknown',
    recommendations: [],
  };

  // Step 1: Test DNS resolution
  console.log(`\n🔍 Analyzing Database ${index}...`);
  console.log(`   Hostname: ${hostname}`);
  console.log(`   Port: ${port}`);

  try {
    const dnsResult = await dnsLookup(hostname);
    analysis.dnsResolvable = true;
    console.log(`   ✅ DNS Resolution: ${dnsResult.address} (${dnsResult.family === 4 ? 'IPv4' : 'IPv6'})`);
  } catch (dnsError: any) {
    analysis.dnsResolvable = false;
    analysis.dnsError = dnsError.message || String(dnsError);
    analysis.errorType = 'dns';
    console.log(`   ❌ DNS Resolution: Failed - ${analysis.dnsError}`);
    analysis.recommendations.push('DNS resolution failed - hostname may not exist or be unreachable');
    analysis.recommendations.push('Check if Supabase project exists and is active');
    return analysis;
  }

  // Step 2: Test connection
  console.log(`   🔄 Testing connection...`);
  try {
    const client = new PrismaClient({
      datasources: { db: { url } },
      log: [],
    });

    const startTime = Date.now();
    await Promise.race([
      client.$queryRaw`SELECT 1`,
      new Promise((_, reject) => setTimeout(() => reject(new Error('Connection timeout')), 10000))
    ]);
    const responseTime = Date.now() - startTime;

    await client.$disconnect();
    console.log(`   ✅ Connection: Success (${responseTime}ms)`);
    analysis.connectionError = 'Success';
    analysis.errorType = 'unknown';
    return analysis;
  } catch (error: any) {
    const errorMessage = error?.message || String(error);
    analysis.connectionError = errorMessage;

    // Analyze error type
    if (errorMessage.includes("Can't reach database") || errorMessage.includes('ECONNREFUSED')) {
      analysis.errorType = 'connection';
      analysis.recommendations.push('Connection refused - server may be down or port blocked');
      analysis.recommendations.push('Check if Supabase project is paused (free tier pauses after inactivity)');
      analysis.recommendations.push('Verify port 6543 is not blocked by firewall');
    } else if (errorMessage.includes('timeout') || errorMessage.includes('ETIMEDOUT')) {
      analysis.errorType = 'timeout';
      analysis.recommendations.push('Connection timeout - server may be slow or unreachable');
      analysis.recommendations.push('Check network connectivity');
    } else if (errorMessage.includes('FATAL') || errorMessage.includes('authentication') || errorMessage.includes('password')) {
      analysis.errorType = 'auth';
      analysis.recommendations.push('Authentication failed - check username and password');
      analysis.recommendations.push('Verify connection string from Supabase dashboard');
    } else if (errorMessage.includes('Tenant') || errorMessage.includes('not found')) {
      analysis.errorType = 'connection';
      analysis.recommendations.push('Project reference may be incorrect');
      analysis.recommendations.push('Verify project reference in Supabase dashboard');
    } else {
      analysis.errorType = 'unknown';
      analysis.recommendations.push('Unknown error - check Supabase project status');
    }

    // Extract error code if available
    if (error?.code) {
      analysis.errorCode = error.code;
    }

    console.log(`   ❌ Connection: Failed`);
    console.log(`      Error: ${errorMessage.substring(0, 150)}`);
  }

  // Step 3: Compare with working database format
  const db0Url = process.env.DATABASE_URL_0 || '';
  if (db0Url) {
    const db0UrlObj = new URL(db0Url);
    const db0Hostname = db0UrlObj.hostname;
    
    console.log(`   📊 Comparison with Database 0:`);
    console.log(`      DB 0 hostname: ${db0Hostname}`);
    console.log(`      DB ${index} hostname: ${hostname}`);
    
    // Check if format is different
    const db0UsesAws = db0Hostname.includes('aws-');
    const currentUsesAws = hostname.includes('aws-');
    
    if (db0UsesAws && !currentUsesAws) {
      analysis.recommendations.push('Database 0 uses AWS format (aws-1-ap-southeast-1.pooler.supabase.com)');
      analysis.recommendations.push('Database ' + index + ' uses standard format (pooler.[ref].supabase.co)');
      analysis.recommendations.push('Try using AWS format: aws-1-ap-southeast-1.pooler.supabase.com');
    }
  }

  return analysis;
}

async function main() {
  console.log('🔬 Deep Analysis of Database Connection Errors\n');
  console.log('='.repeat(80));

  const analyses: ErrorAnalysis[] = [];

  // Analyze Database 1
  const db1Url = process.env.DATABASE_URL_1;
  if (db1Url) {
    const analysis = await analyzeDatabaseError(1, db1Url);
    analyses.push(analysis);
  }

  // Analyze Database 2
  const db2Url = process.env.DATABASE_URL_2;
  if (db2Url) {
    const analysis = await analyzeDatabaseError(2, db2Url);
    analyses.push(analysis);
  }

  // Summary
  console.log('\n' + '='.repeat(80));
  console.log('📊 ERROR ANALYSIS SUMMARY\n');

  analyses.forEach(analysis => {
    console.log(`\n🔍 Database ${analysis.database}:`);
    console.log(`   Hostname: ${analysis.hostname}`);
    console.log(`   DNS Resolvable: ${analysis.dnsResolvable ? '✅ Yes' : '❌ No'}`);
    console.log(`   Error Type: ${analysis.errorType}`);
    if (analysis.errorCode) {
      console.log(`   Error Code: ${analysis.errorCode}`);
    }
    console.log(`   Connection Error: ${analysis.connectionError.substring(0, 100)}`);
    
    if (analysis.recommendations.length > 0) {
      console.log(`\n   💡 Recommendations:`);
      analysis.recommendations.forEach(rec => {
        console.log(`      - ${rec}`);
      });
    }
  });

  // Root Cause Analysis
  console.log('\n' + '='.repeat(80));
  console.log('🎯 ROOT CAUSE ANALYSIS\n');

  const dnsFailures = analyses.filter(a => !a.dnsResolvable);
  const connectionFailures = analyses.filter(a => a.dnsResolvable && a.errorType === 'connection');
  const authFailures = analyses.filter(a => a.errorType === 'auth');

  if (dnsFailures.length > 0) {
    console.log('❌ DNS Resolution Failures:');
    dnsFailures.forEach(a => {
      console.log(`   - Database ${a.database}: ${a.hostname} cannot be resolved`);
      console.log(`     → Most likely: Supabase project doesn't exist or is deleted`);
      console.log(`     → Or: Project reference is incorrect`);
    });
  }

  if (connectionFailures.length > 0) {
    console.log('\n❌ Connection Failures:');
    connectionFailures.forEach(a => {
      console.log(`   - Database ${a.database}: Can reach hostname but connection refused`);
      console.log(`     → Most likely: Supabase project is PAUSED (free tier pauses after inactivity)`);
      console.log(`     → Solution: Go to Supabase dashboard and unpause the project`);
    });
  }

  if (authFailures.length > 0) {
    console.log('\n❌ Authentication Failures:');
    authFailures.forEach(a => {
      console.log(`   - Database ${a.database}: Connection works but authentication fails`);
      console.log(`     → Most likely: Wrong password or username format`);
      console.log(`     → Solution: Get fresh connection string from Supabase dashboard`);
    });
  }

  // Compare with working database
  const db0Url = process.env.DATABASE_URL_0;
  if (db0Url) {
    const db0UrlObj = new URL(db0Url);
    const db0Hostname = db0UrlObj.hostname;
    
    console.log('\n📊 Format Comparison:');
    console.log(`   Database 0 (Working): ${db0Hostname}`);
    analyses.forEach(a => {
      const usesDifferentFormat = !a.hostname.includes('aws-') && db0Hostname.includes('aws-');
      if (usesDifferentFormat) {
        console.log(`   ⚠️  Database ${a.database} uses different hostname format`);
        console.log(`      → Try using AWS format like Database 0`);
      }
    });
  }

  console.log('\n' + '='.repeat(80));
}

main().catch(console.error);


 * Deep Analysis of Database Connection Errors
 * Identifies root cause of connection failures
 */

import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';
import * as dns from 'dns';
import { promisify } from 'util';

dotenv.config({ path: '.env.local' });
dotenv.config({ path: '.env' });

const dnsLookup = promisify(dns.lookup);

interface ErrorAnalysis {
  database: number;
  url: string;
  hostname: string;
  port: number;
  dnsResolvable: boolean;
  dnsError?: string;
  connectionError: string;
  errorCode?: string;
  errorType: 'dns' | 'connection' | 'auth' | 'timeout' | 'unknown';
  recommendations: string[];
}

async function analyzeDatabaseError(index: number, url: string): Promise<ErrorAnalysis> {
  const urlObj = new URL(url);
  const hostname = urlObj.hostname;
  const port = parseInt(urlObj.port || '6543', 10);

  const analysis: ErrorAnalysis = {
    database: index,
    url: url.replace(/:[^:@]+@/, ':****@'),
    hostname,
    port,
    dnsResolvable: false,
    connectionError: '',
    errorType: 'unknown',
    recommendations: [],
  };

  // Step 1: Test DNS resolution
  console.log(`\n🔍 Analyzing Database ${index}...`);
  console.log(`   Hostname: ${hostname}`);
  console.log(`   Port: ${port}`);

  try {
    const dnsResult = await dnsLookup(hostname);
    analysis.dnsResolvable = true;
    console.log(`   ✅ DNS Resolution: ${dnsResult.address} (${dnsResult.family === 4 ? 'IPv4' : 'IPv6'})`);
  } catch (dnsError: any) {
    analysis.dnsResolvable = false;
    analysis.dnsError = dnsError.message || String(dnsError);
    analysis.errorType = 'dns';
    console.log(`   ❌ DNS Resolution: Failed - ${analysis.dnsError}`);
    analysis.recommendations.push('DNS resolution failed - hostname may not exist or be unreachable');
    analysis.recommendations.push('Check if Supabase project exists and is active');
    return analysis;
  }

  // Step 2: Test connection
  console.log(`   🔄 Testing connection...`);
  try {
    const client = new PrismaClient({
      datasources: { db: { url } },
      log: [],
    });

    const startTime = Date.now();
    await Promise.race([
      client.$queryRaw`SELECT 1`,
      new Promise((_, reject) => setTimeout(() => reject(new Error('Connection timeout')), 10000))
    ]);
    const responseTime = Date.now() - startTime;

    await client.$disconnect();
    console.log(`   ✅ Connection: Success (${responseTime}ms)`);
    analysis.connectionError = 'Success';
    analysis.errorType = 'unknown';
    return analysis;
  } catch (error: any) {
    const errorMessage = error?.message || String(error);
    analysis.connectionError = errorMessage;

    // Analyze error type
    if (errorMessage.includes("Can't reach database") || errorMessage.includes('ECONNREFUSED')) {
      analysis.errorType = 'connection';
      analysis.recommendations.push('Connection refused - server may be down or port blocked');
      analysis.recommendations.push('Check if Supabase project is paused (free tier pauses after inactivity)');
      analysis.recommendations.push('Verify port 6543 is not blocked by firewall');
    } else if (errorMessage.includes('timeout') || errorMessage.includes('ETIMEDOUT')) {
      analysis.errorType = 'timeout';
      analysis.recommendations.push('Connection timeout - server may be slow or unreachable');
      analysis.recommendations.push('Check network connectivity');
    } else if (errorMessage.includes('FATAL') || errorMessage.includes('authentication') || errorMessage.includes('password')) {
      analysis.errorType = 'auth';
      analysis.recommendations.push('Authentication failed - check username and password');
      analysis.recommendations.push('Verify connection string from Supabase dashboard');
    } else if (errorMessage.includes('Tenant') || errorMessage.includes('not found')) {
      analysis.errorType = 'connection';
      analysis.recommendations.push('Project reference may be incorrect');
      analysis.recommendations.push('Verify project reference in Supabase dashboard');
    } else {
      analysis.errorType = 'unknown';
      analysis.recommendations.push('Unknown error - check Supabase project status');
    }

    // Extract error code if available
    if (error?.code) {
      analysis.errorCode = error.code;
    }

    console.log(`   ❌ Connection: Failed`);
    console.log(`      Error: ${errorMessage.substring(0, 150)}`);
  }

  // Step 3: Compare with working database format
  const db0Url = process.env.DATABASE_URL_0 || '';
  if (db0Url) {
    const db0UrlObj = new URL(db0Url);
    const db0Hostname = db0UrlObj.hostname;
    
    console.log(`   📊 Comparison with Database 0:`);
    console.log(`      DB 0 hostname: ${db0Hostname}`);
    console.log(`      DB ${index} hostname: ${hostname}`);
    
    // Check if format is different
    const db0UsesAws = db0Hostname.includes('aws-');
    const currentUsesAws = hostname.includes('aws-');
    
    if (db0UsesAws && !currentUsesAws) {
      analysis.recommendations.push('Database 0 uses AWS format (aws-1-ap-southeast-1.pooler.supabase.com)');
      analysis.recommendations.push('Database ' + index + ' uses standard format (pooler.[ref].supabase.co)');
      analysis.recommendations.push('Try using AWS format: aws-1-ap-southeast-1.pooler.supabase.com');
    }
  }

  return analysis;
}

async function main() {
  console.log('🔬 Deep Analysis of Database Connection Errors\n');
  console.log('='.repeat(80));

  const analyses: ErrorAnalysis[] = [];

  // Analyze Database 1
  const db1Url = process.env.DATABASE_URL_1;
  if (db1Url) {
    const analysis = await analyzeDatabaseError(1, db1Url);
    analyses.push(analysis);
  }

  // Analyze Database 2
  const db2Url = process.env.DATABASE_URL_2;
  if (db2Url) {
    const analysis = await analyzeDatabaseError(2, db2Url);
    analyses.push(analysis);
  }

  // Summary
  console.log('\n' + '='.repeat(80));
  console.log('📊 ERROR ANALYSIS SUMMARY\n');

  analyses.forEach(analysis => {
    console.log(`\n🔍 Database ${analysis.database}:`);
    console.log(`   Hostname: ${analysis.hostname}`);
    console.log(`   DNS Resolvable: ${analysis.dnsResolvable ? '✅ Yes' : '❌ No'}`);
    console.log(`   Error Type: ${analysis.errorType}`);
    if (analysis.errorCode) {
      console.log(`   Error Code: ${analysis.errorCode}`);
    }
    console.log(`   Connection Error: ${analysis.connectionError.substring(0, 100)}`);
    
    if (analysis.recommendations.length > 0) {
      console.log(`\n   💡 Recommendations:`);
      analysis.recommendations.forEach(rec => {
        console.log(`      - ${rec}`);
      });
    }
  });

  // Root Cause Analysis
  console.log('\n' + '='.repeat(80));
  console.log('🎯 ROOT CAUSE ANALYSIS\n');

  const dnsFailures = analyses.filter(a => !a.dnsResolvable);
  const connectionFailures = analyses.filter(a => a.dnsResolvable && a.errorType === 'connection');
  const authFailures = analyses.filter(a => a.errorType === 'auth');

  if (dnsFailures.length > 0) {
    console.log('❌ DNS Resolution Failures:');
    dnsFailures.forEach(a => {
      console.log(`   - Database ${a.database}: ${a.hostname} cannot be resolved`);
      console.log(`     → Most likely: Supabase project doesn't exist or is deleted`);
      console.log(`     → Or: Project reference is incorrect`);
    });
  }

  if (connectionFailures.length > 0) {
    console.log('\n❌ Connection Failures:');
    connectionFailures.forEach(a => {
      console.log(`   - Database ${a.database}: Can reach hostname but connection refused`);
      console.log(`     → Most likely: Supabase project is PAUSED (free tier pauses after inactivity)`);
      console.log(`     → Solution: Go to Supabase dashboard and unpause the project`);
    });
  }

  if (authFailures.length > 0) {
    console.log('\n❌ Authentication Failures:');
    authFailures.forEach(a => {
      console.log(`   - Database ${a.database}: Connection works but authentication fails`);
      console.log(`     → Most likely: Wrong password or username format`);
      console.log(`     → Solution: Get fresh connection string from Supabase dashboard`);
    });
  }

  // Compare with working database
  const db0Url = process.env.DATABASE_URL_0;
  if (db0Url) {
    const db0UrlObj = new URL(db0Url);
    const db0Hostname = db0UrlObj.hostname;
    
    console.log('\n📊 Format Comparison:');
    console.log(`   Database 0 (Working): ${db0Hostname}`);
    analyses.forEach(a => {
      const usesDifferentFormat = !a.hostname.includes('aws-') && db0Hostname.includes('aws-');
      if (usesDifferentFormat) {
        console.log(`   ⚠️  Database ${a.database} uses different hostname format`);
        console.log(`      → Try using AWS format like Database 0`);
      }
    });
  }

  console.log('\n' + '='.repeat(80));
}

main().catch(console.error);




