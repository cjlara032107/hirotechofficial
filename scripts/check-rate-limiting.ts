/**
 * Check Rate Limiting Configuration
 * 
 * This script checks:
 * 1. Rate limiting implementations in the codebase
 * 2. Rate limit configurations
 * 3. API endpoint protection
 * 4. Campaign rate limiting settings
 */

import { readFileSync, existsSync, readdirSync, statSync } from 'fs';
import { join } from 'path';

interface RateLimitConfig {
  file: string;
  type: 'middleware' | 'campaign' | 'api' | 'ai';
  config: string;
  status: 'found' | 'missing' | 'needs-review';
}

const results: RateLimitConfig[] = [];

function addResult(file: string, type: RateLimitConfig['type'], config: string, status: RateLimitConfig['status']) {
  results.push({ file, type, config, status });
}

async function checkRateLimiting() {
  console.log('\n🔍 Checking Rate Limiting Configuration...\n');

  // Check for rate limiting middleware
  console.log('📊 Checking Rate Limiting Middleware...\n');
  
  function findFiles(dir: string, pattern: RegExp): string[] {
    const files: string[] = [];
    try {
      const entries = readdirSync(dir);
      for (const entry of entries) {
        const fullPath = join(dir, entry);
        const stat = statSync(fullPath);
        if (stat.isDirectory()) {
          files.push(...findFiles(fullPath, pattern));
        } else if (stat.isFile() && pattern.test(entry)) {
          files.push(fullPath);
        }
      }
    } catch {
      // Directory doesn't exist or can't be read
    }
    return files;
  }
  
  const middlewareDir = join(process.cwd(), 'src', 'middleware');
  const middlewareFiles = existsSync(middlewareDir) ? findFiles(middlewareDir, /\.ts$/) : [];
  const rateLimitMiddleware = middlewareFiles.find(file => {
    try {
      const content = readFileSync(file, 'utf-8').toLowerCase();
      return content.includes('ratelimit') || content.includes('rate-limit');
    } catch {
      return false;
    }
  });

  if (rateLimitMiddleware) {
    const content = readFileSync(rateLimitMiddleware, 'utf-8');
    addResult(
      rateLimitMiddleware,
      'middleware',
      'Rate limiting middleware found',
      'found'
    );
    console.log(`✅ Found rate limiting middleware: ${rateLimitMiddleware}`);
    
    // Extract rate limit values
    const windowMatch = content.match(/windowMs[:\s]*(\d+)/i);
    const maxMatch = content.match(/max[:\s]*(\d+)/i);
    if (windowMatch && maxMatch) {
      console.log(`   Window: ${windowMatch[1]}ms, Max: ${maxMatch[1]} requests`);
    }
  } else {
    addResult(
      'src/middleware/rate-limit.ts',
      'middleware',
      'Rate limiting middleware not found',
      'missing'
    );
    console.log('⚠️  Rate limiting middleware not found');
    console.log('   Recommendation: Create rate limiting middleware for API protection');
  }

  // Check campaign rate limiting
  console.log('\n📊 Checking Campaign Rate Limiting...\n');
  
  const campaignSendFile = 'src/lib/campaigns/send.ts';
  if (existsSync(campaignSendFile)) {
    const content = readFileSync(campaignSendFile, 'utf-8');
    
    // Check for rate limit usage
    if (content.includes('rateLimit') || content.includes('rate_limit')) {
      addResult(
        campaignSendFile,
        'campaign',
        'Campaign rate limiting found',
        'found'
      );
      console.log(`✅ Campaign rate limiting found in: ${campaignSendFile}`);
      
      // Check for rate limit configuration
      const rateLimitMatch = content.match(/rateLimit[:\s]*(\d+)/i);
      if (rateLimitMatch) {
        const limit = parseInt(rateLimitMatch[1], 10);
        console.log(`   Rate limit: ${limit} messages per hour`);
        if (limit < 100) {
          console.log('   ⚠️  Rate limit is very low - may cause slow campaign sending');
        } else if (limit >= 3600) {
          console.log('   ✅ Rate limit is reasonable for fast sending');
        }
      }
    } else {
      addResult(
        campaignSendFile,
        'campaign',
        'Campaign rate limiting not found',
        'needs-review'
      );
      console.log('⚠️  Campaign rate limiting not found');
      console.log('   Note: Campaigns may send without rate limiting');
    }
  }

  // Check API rate limiting
  console.log('\n📊 Checking API Endpoint Rate Limiting...\n');
  
  const apiDir = join(process.cwd(), 'src', 'app', 'api');
  const apiRoutes = existsSync(apiDir) ? findFiles(apiDir, /route\.ts$/) : [];
  let protectedRoutes = 0;
  let unprotectedRoutes = 0;

  for (const route of apiRoutes.slice(0, 20)) { // Check first 20 routes
    try {
      const content = readFileSync(route, 'utf-8');
      const hasRateLimit = content.includes('rateLimit') || 
                           content.includes('rate-limit') ||
                           content.includes('ratelimit');
      
      if (hasRateLimit) {
        protectedRoutes++;
      } else {
        unprotectedRoutes++;
      }
    } catch {
      // Skip files that can't be read
    }
  }

  addResult(
    'API Routes',
    'api',
    `${protectedRoutes} protected, ${unprotectedRoutes} unprotected routes checked`,
    unprotectedRoutes > protectedRoutes ? 'needs-review' : 'found'
  );
  
  console.log(`📊 API Routes Check:`);
  console.log(`   ✅ Protected: ${protectedRoutes}`);
  console.log(`   ⚠️  Unprotected: ${unprotectedRoutes}`);
  
  if (unprotectedRoutes > protectedRoutes) {
    console.log('   Recommendation: Add rate limiting to more API endpoints');
  }

  // Check AI API rate limiting
  console.log('\n📊 Checking AI API Rate Limiting...\n');
  
  const aiDir = join(process.cwd(), 'src', 'lib', 'ai');
  const aiFiles = existsSync(aiDir) ? findFiles(aiDir, /\.ts$/) : [];
  let aiRateLimitFound = false;

  for (const file of aiFiles) {
    try {
      const content = readFileSync(file, 'utf-8');
      if (content.includes('rateLimit') || 
          content.includes('rate_limit') ||
          content.includes('markRateLimited')) {
        aiRateLimitFound = true;
        addResult(
          file,
          'ai',
          'AI rate limiting found',
          'found'
        );
        console.log(`✅ AI rate limiting found in: ${file}`);
        break;
      }
    } catch {
      // Skip files that can't be read
    }
  }

  if (!aiRateLimitFound) {
    addResult(
      'src/lib/ai',
      'ai',
      'AI rate limiting not found',
      'needs-review'
    );
    console.log('⚠️  AI rate limiting not found');
    console.log('   Note: AI API calls may not have rate limiting protection');
  }

  // Check Facebook API rate limiting
  console.log('\n📊 Checking Facebook API Rate Limiting...\n');
  
  const facebookClientFile = 'src/lib/facebook/client.ts';
  if (existsSync(facebookClientFile)) {
    const content = readFileSync(facebookClientFile, 'utf-8');
    
    if (content.includes('isRateLimited') || content.includes('rate limit')) {
      addResult(
        facebookClientFile,
        'api',
        'Facebook API rate limiting detection found',
        'found'
      );
      console.log(`✅ Facebook API rate limiting detection found`);
    } else {
      addResult(
        facebookClientFile,
        'api',
        'Facebook API rate limiting detection not found',
        'needs-review'
      );
      console.log('⚠️  Facebook API rate limiting detection not found');
    }
  }

  // Check database schema for rate limit defaults
  console.log('\n📊 Checking Database Schema for Rate Limits...\n');
  
  const schemaFile = 'prisma/schema.prisma';
  if (existsSync(schemaFile)) {
    const content = readFileSync(schemaFile, 'utf-8');
    const rateLimitMatch = content.match(/rateLimit\s+Int\s+@default\((\d+)\)/);
    
    if (rateLimitMatch) {
      const defaultLimit = parseInt(rateLimitMatch[1], 10);
      addResult(
        schemaFile,
        'campaign',
        `Default rate limit: ${defaultLimit} messages/hour`,
        defaultLimit < 100 ? 'needs-review' : 'found'
      );
      console.log(`✅ Default rate limit in schema: ${defaultLimit} messages/hour`);
      if (defaultLimit < 100) {
        console.log('   ⚠️  Default rate limit is very low - campaigns will be slow');
      }
    } else {
      addResult(
        schemaFile,
        'campaign',
        'Rate limit field not found in schema',
        'needs-review'
      );
      console.log('⚠️  Rate limit field not found in schema');
    }
  }
}

async function main() {
  console.log('🚀 Rate Limiting Configuration Check\n');
  console.log('='.repeat(60));

  await checkRateLimiting();

  console.log('\n' + '='.repeat(60));
  console.log('\n📊 Summary:\n');

  const found = results.filter(r => r.status === 'found').length;
  const missing = results.filter(r => r.status === 'missing').length;
  const needsReview = results.filter(r => r.status === 'needs-review').length;

  console.log(`✅ Found: ${found}`);
  console.log(`❌ Missing: ${missing}`);
  console.log(`⚠️  Needs Review: ${needsReview}`);

  if (missing > 0 || needsReview > 0) {
    console.log('\n⚠️  Some rate limiting configurations need attention.');
    console.log('   Review the recommendations above.');
    process.exit(0);
  } else {
    console.log('\n✅ Rate limiting is properly configured!');
    process.exit(0);
  }
}

main().catch((error) => {
  console.error('❌ Check script error:', error);
  process.exit(1);
});

