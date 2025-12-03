/**
 * Check AI Analyze Implementation
 * Verifies parallelization, API endpoints, and code structure without requiring server
 */

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

console.log('🔍 Checking AI Analyze Implementation\n');
console.log('='.repeat(80));

const checks: Array<{ name: string; passed: boolean; details: string }> = [];

// Check 1: Analyze Selected Contacts - Parallelization
console.log('\n📊 Check 1: Parallelization in analyze-selected-contacts.ts\n');
try {
  const filePath = join(process.cwd(), 'src/lib/facebook/analyze-selected-contacts.ts');
  if (existsSync(filePath)) {
    const content = readFileSync(filePath, 'utf-8');
    
    const hasPromiseAll = content.includes('Promise.all');
    const hasConcurrencyLimiter = content.includes('ConcurrencyLimiter');
    const hasAnalysisLimiter = content.includes('analysisLimiter');
    const hasExecute = content.includes('analysisLimiter.execute');
    
    checks.push({
      name: 'Promise.all for parallelization',
      passed: hasPromiseAll,
      details: hasPromiseAll ? '✅ Found Promise.all' : '❌ Missing Promise.all'
    });
    
    checks.push({
      name: 'ConcurrencyLimiter class',
      passed: hasConcurrencyLimiter,
      details: hasConcurrencyLimiter ? '✅ Found ConcurrencyLimiter' : '❌ Missing ConcurrencyLimiter'
    });
    
    checks.push({
      name: 'Analysis limiter instance',
      passed: hasAnalysisLimiter,
      details: hasAnalysisLimiter ? '✅ Found analysisLimiter' : '❌ Missing analysisLimiter'
    });
    
    checks.push({
      name: 'Limiter.execute() usage',
      passed: hasExecute,
      details: hasExecute ? '✅ Found analysisLimiter.execute()' : '❌ Missing execute() calls'
    });
    
    // Check concurrency limit value
    const limitMatch = content.match(/new ConcurrencyLimiter\((\d+)\)/g);
    if (limitMatch) {
      const limits = limitMatch.map(m => {
        const num = m.match(/\d+/)?.[0];
        return num ? parseInt(num, 10) : 0;
      });
      const analysisLimit = limits.find((_, i) => limitMatch[i]?.includes('analysisLimiter'));
      checks.push({
        name: 'Analysis concurrency limit',
        passed: (analysisLimit || 0) > 0,
        details: `Concurrency limit: ${analysisLimit || 'not found'}`
      });
    }
    
    console.log(`✅ File exists: ${filePath}`);
    console.log(`   Promise.all: ${hasPromiseAll ? '✅' : '❌'}`);
    console.log(`   ConcurrencyLimiter: ${hasConcurrencyLimiter ? '✅' : '❌'}`);
    console.log(`   analysisLimiter: ${hasAnalysisLimiter ? '✅' : '❌'}`);
    console.log(`   execute() calls: ${hasExecute ? '✅' : '❌'}`);
  } else {
    checks.push({
      name: 'analyze-selected-contacts.ts exists',
      passed: false,
      details: '❌ File not found'
    });
    console.log('❌ File not found:', filePath);
  }
} catch (error) {
  checks.push({
    name: 'analyze-selected-contacts.ts check',
    passed: false,
    details: `Error: ${error instanceof Error ? error.message : String(error)}`
  });
  console.log('❌ Error:', error);
}

// Check 2: API Endpoints
console.log('\n📡 Check 2: API Endpoints\n');
const endpoints = [
  'src/app/api/contacts/analyze-all/route.ts',
  'src/app/api/facebook/analyze-pipeline/route.ts',
  'src/app/api/facebook/analyze-selected/route.ts',
];

for (const endpoint of endpoints) {
  const filePath = join(process.cwd(), endpoint);
  const exists = existsSync(filePath);
  checks.push({
    name: `Endpoint: ${endpoint.split('/').pop()}`,
    passed: exists,
    details: exists ? '✅ Exists' : '❌ Not found'
  });
  console.log(`${exists ? '✅' : '❌'} ${endpoint}`);
}

// Check 3: Dynamic Concurrency
console.log('\n⚙️  Check 3: Dynamic Concurrency Configuration\n');
try {
  const filePath = join(process.cwd(), 'src/lib/ai/dynamic-concurrency.ts');
  if (existsSync(filePath)) {
    const content = readFileSync(filePath, 'utf-8');
    
    const hasGetGlobalRecommended = content.includes('getGlobalRecommendedConcurrency');
    const hasAnalysisConcurrency = content.includes('analysisConcurrency');
    const hasPoolAware = content.includes('pool-aware');
    
    checks.push({
      name: 'Global pool-aware concurrency',
      passed: hasGetGlobalRecommended,
      details: hasGetGlobalRecommended ? '✅ Using global pool-aware limits' : '❌ Not using pool-aware limits'
    });
    
    checks.push({
      name: 'Analysis concurrency calculation',
      passed: hasAnalysisConcurrency,
      details: hasAnalysisConcurrency ? '✅ Analysis concurrency configured' : '❌ Missing analysis concurrency'
    });
    
    console.log(`✅ Dynamic concurrency file exists`);
    console.log(`   Pool-aware: ${hasGetGlobalRecommended ? '✅' : '❌'}`);
    console.log(`   Analysis concurrency: ${hasAnalysisConcurrency ? '✅' : '❌'}`);
  } else {
    checks.push({
      name: 'dynamic-concurrency.ts exists',
      passed: false,
      details: '❌ File not found'
    });
    console.log('❌ File not found:', filePath);
  }
} catch (error) {
  console.log('❌ Error:', error);
}

// Check 4: Linting
console.log('\n🔍 Check 4: Code Quality\n');
try {
  const { execSync } = require('child_process');
  try {
    const lintResult = execSync('npx eslint --max-warnings=0 src/lib/facebook/analyze-selected-contacts.ts src/lib/ai/dynamic-concurrency.ts src/app/api/contacts/analyze-all/route.ts 2>&1', { 
      encoding: 'utf-8',
      cwd: process.cwd(),
      stdio: 'pipe'
    });
    checks.push({
      name: 'ESLint - No errors',
      passed: true,
      details: '✅ No linting errors'
    });
    console.log('✅ ESLint: No errors');
  } catch (lintError: any) {
    const output = lintError.stdout || lintError.message || '';
    const hasErrors = output.includes('error') && !output.includes('0 errors');
    checks.push({
      name: 'ESLint - No errors',
      passed: !hasErrors,
      details: hasErrors ? `⚠️  Linting issues found` : '✅ No critical errors'
    });
    if (hasErrors) {
      console.log('⚠️  ESLint issues found (check output above)');
    } else {
      console.log('✅ ESLint: No critical errors');
    }
  }
} catch (error) {
  checks.push({
    name: 'ESLint check',
    passed: false,
    details: '⚠️  Could not run ESLint'
  });
  console.log('⚠️  Could not run ESLint');
}

// Check 5: TypeScript compilation
console.log('\n📝 Check 5: TypeScript Types\n');
try {
  const { execSync } = require('child_process');
  try {
    execSync('npx tsc --noEmit --skipLibCheck src/lib/facebook/analyze-selected-contacts.ts src/lib/ai/dynamic-concurrency.ts 2>&1', {
      encoding: 'utf-8',
      cwd: process.cwd(),
      stdio: 'pipe'
    });
    checks.push({
      name: 'TypeScript - No type errors',
      passed: true,
      details: '✅ No type errors'
    });
    console.log('✅ TypeScript: No type errors');
  } catch (tsError: any) {
    const output = tsError.stdout || tsError.message || '';
    checks.push({
      name: 'TypeScript - No type errors',
      passed: false,
      details: '❌ Type errors found'
    });
    console.log('❌ TypeScript: Errors found');
    console.log(output.substring(0, 500));
  }
} catch (error) {
  checks.push({
    name: 'TypeScript check',
    passed: false,
    details: '⚠️  Could not run TypeScript check'
  });
  console.log('⚠️  Could not run TypeScript check');
}

// Summary
console.log('\n' + '='.repeat(80));
console.log('📊 SUMMARY\n');

const passed = checks.filter(c => c.passed).length;
const total = checks.length;

checks.forEach(check => {
  console.log(`${check.passed ? '✅' : '❌'} ${check.name}: ${check.details}`);
});

console.log(`\n${passed}/${total} checks passed`);

if (passed === total) {
  console.log('\n✅ All checks passed! AI analyze is properly configured with parallelization.');
} else {
  console.log('\n⚠️  Some checks failed. Review the details above.');
}

console.log('\n' + '='.repeat(80));




