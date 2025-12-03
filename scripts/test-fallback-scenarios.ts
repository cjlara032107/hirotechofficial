/**
 * Test Fallback Scenarios
 * 
 * Tests fallback scoring, emergency fallback, and error recovery
 */

// Load environment variables
import { config } from 'dotenv';
import { resolve } from 'path';
config({ path: resolve(process.cwd(), '.env.local') });
config({ path: resolve(process.cwd(), '.env') });

import { analyzeWithFallback } from '../src/lib/ai/enhanced-analysis';
import { calculateFallbackScore } from '../src/lib/ai/fallback-scoring';

interface TestResult {
  testName: string;
  passed: boolean;
  error?: string;
  details?: string;
}

const testResults: TestResult[] = [];

function logTest(testName: string, passed: boolean, error?: string, details?: string) {
  testResults.push({ testName, passed, error, details });
  const icon = passed ? '✅' : '❌';
  console.log(`${icon} ${testName}`);
  if (error) {
    console.log(`   Error: ${error}`);
  }
  if (details) {
    console.log(`   Details: ${details}`);
  }
  console.log('');
}

async function testFallbackScoring() {
  console.log('🧪 Test 1: Fallback Scoring\n');
  
  try {
    const messages = [
      { from: 'contact', text: 'Hello' },
      { from: 'business', text: 'Hi!' },
    ];
    
    const fallback = calculateFallbackScore(messages);
    
    // Should return valid fallback score
    if (fallback && typeof fallback.leadScore === 'number' && fallback.leadScore >= 0 && fallback.leadScore <= 100) {
      logTest('Fallback Scoring - Valid Score', true, undefined, `Score: ${fallback.leadScore}, Status: ${fallback.leadStatus}, Confidence: ${fallback.confidence}`);
    } else {
      logTest('Fallback Scoring - Valid Score', false, 'Invalid fallback score');
    }
    
    // Should have required fields
    if (fallback.reasoning && fallback.leadStatus) {
      logTest('Fallback Scoring - Required Fields', true, undefined, `Has reasoning: ${!!fallback.reasoning}, Has status: ${!!fallback.leadStatus}`);
    } else {
      logTest('Fallback Scoring - Required Fields', false, 'Missing required fields');
    }
  } catch (error) {
    logTest('Fallback Scoring - No Exception', false, error instanceof Error ? error.message : String(error));
  }
}

async function testEmergencyFallback() {
  console.log('🧪 Test 2: Emergency Fallback\n');
  
  try {
    // Test with empty messages to trigger emergency fallback
    const messages: Array<{ from: string; text: string }> = [];
    
    const result = await analyzeWithFallback(messages);
    
    // Should return result with emergency fallback, not throw
    if (result && result.analysis) {
      const hasValidScore = typeof result.analysis.leadScore === 'number' && result.analysis.leadScore >= 0;
      logTest('Emergency Fallback - Returns Result', hasValidScore, undefined, `Score: ${result.analysis.leadScore}, Used Fallback: ${result.usedFallback}`);
    } else {
      logTest('Emergency Fallback - Returns Result', false, 'Result is null or missing analysis');
    }
  } catch (error) {
    logTest('Emergency Fallback - No Exception', false, error instanceof Error ? error.message : String(error));
  }
}

async function testErrorRecovery() {
  console.log('🧪 Test 3: Error Recovery\n');
  
  try {
    // Test with messages that might cause errors
    const messages = [
      { from: 'contact', text: 'Hello, I need help with my order #12345' },
      { from: 'business', text: 'Hi! I can help you with that.' },
      { from: 'contact', text: 'Great! When will it arrive?' },
      { from: 'business', text: 'It should arrive in 2-3 business days.' },
    ];
    
    const result = await analyzeWithFallback(messages);
    
    // Should recover from any errors and return result
    if (result && result.analysis) {
      logTest('Error Recovery - Returns Result', true, undefined, `Score: ${result.analysis.leadScore}, Used Fallback: ${result.usedFallback}, Retries: ${result.retryCount}`);
    } else {
      logTest('Error Recovery - Returns Result', false, 'Result is null or missing analysis');
    }
  } catch (error) {
    logTest('Error Recovery - No Exception', false, error instanceof Error ? error.message : String(error));
  }
}

async function testMultipleRetries() {
  console.log('🧪 Test 4: Multiple Retries\n');
  
  try {
    const messages = [
      { from: 'contact', text: 'Hello' },
      { from: 'business', text: 'Hi!' },
    ];
    
    // Test with maxRetries = 3
    const result = await analyzeWithFallback(messages, undefined, undefined, 3);
    
    // Should handle retries and return result
    if (result && result.analysis) {
      const retriesWorked = result.retryCount >= 0 && result.retryCount <= 3;
      logTest('Multiple Retries - Handles Retries', retriesWorked, undefined, `Retries: ${result.retryCount}, Score: ${result.analysis.leadScore}`);
    } else {
      logTest('Multiple Retries - Handles Retries', false, 'Result is null or missing analysis');
    }
  } catch (error) {
    logTest('Multiple Retries - No Exception', false, error instanceof Error ? error.message : String(error));
  }
}

async function testFallbackAlwaysWorks() {
  console.log('🧪 Test 5: Fallback Always Works\n');
  
  try {
    // Test various scenarios that should all return fallback
    const scenarios = [
      { name: 'Empty messages', messages: [] },
      { name: 'Single message', messages: [{ from: 'contact', text: 'Hello' }] },
      { name: 'Multiple messages', messages: [
        { from: 'contact', text: 'Hello' },
        { from: 'business', text: 'Hi!' },
        { from: 'contact', text: 'Thanks' },
      ]},
    ];
    
    let allPassed = true;
    for (const scenario of scenarios) {
      try {
        const result = await analyzeWithFallback(scenario.messages);
        if (!result || !result.analysis) {
          allPassed = false;
          logTest(`Fallback Always Works - ${scenario.name}`, false, 'Result is null');
        } else {
          logTest(`Fallback Always Works - ${scenario.name}`, true, undefined, `Score: ${result.analysis.leadScore}`);
        }
      } catch (error) {
        allPassed = false;
        logTest(`Fallback Always Works - ${scenario.name}`, false, error instanceof Error ? error.message : String(error));
      }
    }
    
    return allPassed;
  } catch (error) {
    logTest('Fallback Always Works - No Exception', false, error instanceof Error ? error.message : String(error));
    return false;
  }
}

async function runAllTests() {
  console.log('='.repeat(60));
  console.log('🧪 Testing Fallback Scenarios');
  console.log('='.repeat(60));
  console.log('');
  
  await testFallbackScoring();
  await testEmergencyFallback();
  await testErrorRecovery();
  await testMultipleRetries();
  await testFallbackAlwaysWorks();
  
  // Summary
  console.log('='.repeat(60));
  console.log('📋 Test Summary');
  console.log('='.repeat(60));
  const passed = testResults.filter(r => r.passed).length;
  const failed = testResults.filter(r => !r.passed).length;
  console.log(`Total Tests: ${testResults.length}`);
  console.log(`✅ Passed: ${passed}`);
  console.log(`❌ Failed: ${failed}`);
  console.log('');
  
  if (failed > 0) {
    console.log('Failed Tests:');
    testResults.filter(r => !r.passed).forEach(r => {
      console.log(`  - ${r.testName}: ${r.error || 'Unknown error'}`);
    });
  }
  
  console.log('='.repeat(60));
  console.log('');
  
  return failed === 0;
}

// Run tests
runAllTests()
  .then((allPassed) => {
    if (allPassed) {
      console.log('✨ All fallback scenario tests passed!');
      process.exit(0);
    } else {
      console.log('⚠️  Some tests failed. Review the output above.');
      process.exit(1);
    }
  })
  .catch((error) => {
    console.error('💥 Test execution failed:', error);
    process.exit(1);
  });








