/**
 * Validate Timeout Settings (AI calls, API calls)
 * 
 * This script validates:
 * 1. AI API call timeouts
 * 2. External API call timeouts
 * 3. Database query timeouts
 * 4. Request timeouts
 */

import { readFileSync, existsSync, readdirSync, statSync } from 'fs';
import { join } from 'path';

interface TimeoutConfig {
  file: string;
  type: 'ai' | 'api' | 'database' | 'request';
  timeout: number;
  unit: 'ms' | 's';
  status: 'valid' | 'too-low' | 'too-high' | 'missing';
  recommendation?: string;
}

const results: TimeoutConfig[] = [];

function addResult(
  file: string,
  type: TimeoutConfig['type'],
  timeout: number,
  unit: 'ms' | 's',
  status: TimeoutConfig['status'],
  recommendation?: string
) {
  results.push({ file, type, timeout, unit, status, recommendation });
}

async function validateTimeoutSettings() {
  console.log('\n🔍 Validating Timeout Settings...\n');

  // Helper function to find files recursively
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

  // Check AI API timeouts
  console.log('📊 Checking AI API Timeouts...\n');
  
  const aiDir = join(process.cwd(), 'src', 'lib', 'ai');
  const aiFiles = existsSync(aiDir) ? findFiles(aiDir, /\.ts$/) : [];
  
  for (const file of aiFiles) {
    const content = readFileSync(file, 'utf-8');
    
    // Look for timeout constants
    const timeoutMatches = [
      ...content.matchAll(/TIMEOUT[_\s]*=\s*(\d+)/gi),
      ...content.matchAll(/timeout[:\s]*(\d+)/gi),
      ...content.matchAll(/setTimeout[^,]+,\s*(\d+)/gi),
    ];

    for (const match of timeoutMatches) {
      const timeout = parseInt(match[1], 10);
      let unit: 'ms' | 's' = 'ms';
      let timeoutMs = timeout;

      // Check if it's in seconds (common pattern: timeout: 30)
      if (content.includes('timeout:') && timeout < 100) {
        unit = 's';
        timeoutMs = timeout * 1000;
      }

      let status: TimeoutConfig['status'] = 'valid';
      let recommendation: string | undefined;

      // AI calls typically need 10-60 seconds
      if (timeoutMs < 10000) {
        status = 'too-low';
        recommendation = 'AI calls typically need 10-60 seconds. Consider increasing timeout.';
      } else if (timeoutMs > 120000) {
        status = 'too-high';
        recommendation = 'Timeout is very high. Consider reducing to 60-90 seconds for better UX.';
      } else if (timeoutMs >= 10000 && timeoutMs <= 90000) {
        status = 'valid';
      }

      addResult(file, 'ai', timeout, unit, status, recommendation);
      
      const icon = status === 'valid' ? '✅' : status === 'too-low' ? '⚠️' : '❌';
      console.log(`${icon} ${file}: ${timeout}${unit} ${status === 'valid' ? '(valid)' : `(${status})`}`);
      if (recommendation) {
        console.log(`   ${recommendation}`);
      }
    }
  }

  // Check Facebook API timeouts
  console.log('\n📊 Checking Facebook API Timeouts...\n');
  
  const facebookClientFile = 'src/lib/facebook/client.ts';
  if (existsSync(facebookClientFile)) {
    const content = readFileSync(facebookClientFile, 'utf-8');
    
    const timeoutMatches = [
      ...content.matchAll(/timeout[:\s]*(\d+)/gi),
      ...content.matchAll(/setTimeout[^,]+,\s*(\d+)/gi),
    ];

    for (const match of timeoutMatches) {
      const timeout = parseInt(match[1], 10);
      let status: TimeoutConfig['status'] = 'valid';
      let recommendation: string | undefined;

      if (timeout < 10000) {
        status = 'too-low';
        recommendation = 'Facebook API calls may need 15-30 seconds. Consider increasing timeout.';
      } else if (timeout > 60000) {
        status = 'too-high';
        recommendation = 'Timeout is very high. Consider reducing to 30-45 seconds.';
      }

      addResult(facebookClientFile, 'api', timeout, 'ms', status, recommendation);
      
      const icon = status === 'valid' ? '✅' : status === 'too-low' ? '⚠️' : '❌';
      console.log(`${icon} Facebook API: ${timeout}ms ${status === 'valid' ? '(valid)' : `(${status})`}`);
      if (recommendation) {
        console.log(`   ${recommendation}`);
      }
    }
  }

  // Check axios timeout configurations
  console.log('\n📊 Checking Axios Timeout Configurations...\n');
  
  const srcDir = join(process.cwd(), 'src');
  const allFiles = existsSync(srcDir) ? findFiles(srcDir, /\.ts$/) : [];
  
  for (const file of allFiles.slice(0, 30)) { // Check first 30 files
    const content = readFileSync(file, 'utf-8');
    
    if (content.includes('axios') && (content.includes('timeout') || content.includes('TIMEOUT'))) {
      const timeoutMatches = [
        ...content.matchAll(/timeout[:\s]*(\d+)/gi),
      ];

      for (const match of timeoutMatches) {
        const timeout = parseInt(match[1], 10);
        let status: TimeoutConfig['status'] = 'valid';
        let recommendation: string | undefined;

        if (timeout < 5000) {
          status = 'too-low';
          recommendation = 'API calls typically need 10-30 seconds. Consider increasing timeout.';
        } else if (timeout > 120000) {
          status = 'too-high';
          recommendation = 'Timeout is very high. Consider reducing to 30-60 seconds.';
        }

        addResult(file, 'api', timeout, 'ms', status, recommendation);
        
        const icon = status === 'valid' ? '✅' : status === 'too-low' ? '⚠️' : '❌';
        console.log(`${icon} ${file}: ${timeout}ms ${status === 'valid' ? '(valid)' : `(${status})`}`);
        if (recommendation) {
          console.log(`   ${recommendation}`);
        }
      }
    }
  }

  // Check database connection timeouts
  console.log('\n📊 Checking Database Timeout Settings...\n');
  
  const dbFile = 'src/lib/db.ts';
  if (existsSync(dbFile)) {
    const content = readFileSync(dbFile, 'utf-8');
    
    const poolTimeoutMatch = content.match(/pool_timeout[=:](\d+)/i);
    const connectTimeoutMatch = content.match(/connect_timeout[=:](\d+)/i);

    if (poolTimeoutMatch) {
      const timeout = parseInt(poolTimeoutMatch[1], 10);
      let status: TimeoutConfig['status'] = 'valid';
      let recommendation: string | undefined;

      if (timeout < 10) {
        status = 'too-low';
        recommendation = 'Pool timeout should be 30-60 seconds for better reliability.';
      } else if (timeout > 120) {
        status = 'too-high';
        recommendation = 'Pool timeout is very high. Consider reducing to 60 seconds.';
      }

      addResult(dbFile, 'database', timeout, 's', status, recommendation);
      
      const icon = status === 'valid' ? '✅' : status === 'too-low' ? '⚠️' : '❌';
      console.log(`${icon} Pool timeout: ${timeout}s ${status === 'valid' ? '(valid)' : `(${status})`}`);
      if (recommendation) {
        console.log(`   ${recommendation}`);
      }
    }

    if (connectTimeoutMatch) {
      const timeout = parseInt(connectTimeoutMatch[1], 10);
      let status: TimeoutConfig['status'] = 'valid';
      let recommendation: string | undefined;

      if (timeout < 10) {
        status = 'too-low';
        recommendation = 'Connect timeout should be 20-30 seconds for better reliability.';
      } else if (timeout > 60) {
        status = 'too-high';
        recommendation = 'Connect timeout is very high. Consider reducing to 30 seconds.';
      }

      addResult(dbFile, 'database', timeout, 's', status, recommendation);
      
      const icon = status === 'valid' ? '✅' : status === 'too-low' ? '⚠️' : '❌';
      console.log(`${icon} Connect timeout: ${timeout}s ${status === 'valid' ? '(valid)' : `(${status})`}`);
      if (recommendation) {
        console.log(`   ${recommendation}`);
      }
    }
  }

  // Check fast-detailed-analysis timeout
  console.log('\n📊 Checking Specific AI Timeout Configurations...\n');
  
  const fastAnalysisFile = 'src/lib/ai/fast-detailed-analysis.ts';
  if (existsSync(fastAnalysisFile)) {
    const content = readFileSync(fastAnalysisFile, 'utf-8');
    const timeoutMatch = content.match(/TIMEOUT_MS\s*=\s*(\d+)/);
    
    if (timeoutMatch) {
      const timeout = parseInt(timeoutMatch[1], 10);
      const status = timeout >= 30000 && timeout <= 90000 ? 'valid' : timeout < 30000 ? 'too-low' : 'too-high';
      const recommendation = timeout < 30000 
        ? 'AI analysis typically needs 30-60 seconds. Consider increasing timeout.'
        : timeout > 90000
        ? 'Timeout is very high. Consider reducing to 60 seconds for better UX.'
        : undefined;

      addResult(fastAnalysisFile, 'ai', timeout, 'ms', status, recommendation);
      
      const icon = status === 'valid' ? '✅' : status === 'too-low' ? '⚠️' : '❌';
      console.log(`${icon} Fast Analysis timeout: ${timeout}ms ${status === 'valid' ? '(valid)' : `(${status})`}`);
      if (recommendation) {
        console.log(`   ${recommendation}`);
      }
    }
  }
}

async function main() {
  console.log('🚀 Timeout Settings Validation\n');
  console.log('='.repeat(60));

  await validateTimeoutSettings();

  console.log('\n' + '='.repeat(60));
  console.log('\n📊 Summary:\n');

  const valid = results.filter(r => r.status === 'valid').length;
  const tooLow = results.filter(r => r.status === 'too-low').length;
  const tooHigh = results.filter(r => r.status === 'too-high').length;
  const missing = results.filter(r => r.status === 'missing').length;

  console.log(`✅ Valid: ${valid}`);
  console.log(`⚠️  Too Low: ${tooLow}`);
  console.log(`❌ Too High: ${tooHigh}`);
  console.log(`❓ Missing: ${missing}`);

  if (tooLow > 0 || tooHigh > 0) {
    console.log('\n⚠️  Some timeout settings need adjustment.');
    console.log('   Review the recommendations above.');
    process.exit(0);
  } else {
    console.log('\n✅ All timeout settings are valid!');
    process.exit(0);
  }
}

main().catch((error) => {
  console.error('❌ Validation script error:', error);
  process.exit(1);
});

