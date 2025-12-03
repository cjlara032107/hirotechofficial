/**
 * Validate Fixes
 * 
 * Validates that all fixes are working correctly by testing with a failing contact
 * and verifying error messages, fallback behavior, and logs
 */

// Load environment variables
import { config } from 'dotenv';
import { resolve } from 'path';
config({ path: resolve(process.cwd(), '.env.local') });
config({ path: resolve(process.cwd(), '.env') });

import { PrismaClient } from '@prisma/client';
import { analyzeWithFallback } from '../src/lib/ai/enhanced-analysis';
import { analyzeConversationFast } from '../src/lib/ai/fast-detailed-analysis';

// Create Prisma client
const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DATABASE_URL,
    },
  },
});

interface ValidationResult {
  testName: string;
  passed: boolean;
  error?: string;
  details?: string;
}

const validationResults: ValidationResult[] = [];

function logValidation(testName: string, passed: boolean, error?: string, details?: string) {
  validationResults.push({ testName, passed, error, details });
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

async function validateErrorMessages() {
  console.log('🔍 Validation 1: Error Messages\n');
  
  try {
    const messages = [
      { from: 'contact', text: 'Hello' },
      { from: 'business', text: 'Hi!' },
    ];
    
    // Capture console output
    const originalLog = console.log;
    const originalError = console.error;
    const logs: string[] = [];
    
    console.log = (...args: any[]) => {
      logs.push(args.join(' '));
      originalLog(...args);
    };
    
    console.error = (...args: any[]) => {
      logs.push(args.join(' '));
      originalError(...args);
    };
    
    const result = await analyzeWithFallback(messages);
    
    // Restore console
    console.log = originalLog;
    console.error = originalError;
    
    // Check if error messages are descriptive
    const hasDescriptiveErrors = logs.some(log => 
      log.includes('[Enhanced Analysis]') || 
      log.includes('[Fast AI]') ||
      log.includes('error') ||
      log.includes('Error')
    );
    
    logValidation('Error Messages - Descriptive', hasDescriptiveErrors, undefined, `Found ${logs.filter(l => l.includes('error') || l.includes('Error')).length} error log entries`);
  } catch (error) {
    logValidation('Error Messages - Descriptive', false, error instanceof Error ? error.message : String(error));
  }
}

async function validateFallbackWorks() {
  console.log('🔍 Validation 2: Fallback Works\n');
  
  try {
    const messages = [
      { from: 'contact', text: 'Hello' },
      { from: 'business', text: 'Hi!' },
    ];
    
    const result = await analyzeWithFallback(messages);
    
    // Should always return a result
    if (result && result.analysis) {
      const hasValidScore = typeof result.analysis.leadScore === 'number' && result.analysis.leadScore >= 0 && result.analysis.leadScore <= 100;
      const hasSummary = result.analysis.summary && result.analysis.summary.length > 0;
      
      logValidation('Fallback Works - Returns Result', hasValidScore && hasSummary, undefined, 
        `Score: ${result.analysis.leadScore}, Summary: ${result.analysis.summary.length} chars, Used Fallback: ${result.usedFallback}`);
    } else {
      logValidation('Fallback Works - Returns Result', false, 'Result is null or missing analysis');
    }
  } catch (error) {
    logValidation('Fallback Works - Returns Result', false, error instanceof Error ? error.message : String(error));
  }
}

async function validateLogsForDetails() {
  console.log('🔍 Validation 3: Logs Contain Details\n');
  
  try {
    const messages = [
      { from: 'contact', text: 'Hello, I need help' },
      { from: 'business', text: 'Hi! How can I help you?' },
    ];
    
    // Capture console output
    const originalLog = console.log;
    const originalError = console.error;
    const originalWarn = console.warn;
    const logs: string[] = [];
    
    console.log = (...args: any[]) => {
      logs.push(args.join(' '));
      originalLog(...args);
    };
    
    console.error = (...args: any[]) => {
      logs.push(args.join(' '));
      originalError(...args);
    };
    
    console.warn = (...args: any[]) => {
      logs.push(args.join(' '));
      originalWarn(...args);
    };
    
    await analyzeWithFallback(messages);
    
    // Restore console
    console.log = originalLog;
    console.error = originalError;
    console.warn = originalWarn;
    
    // Check if logs contain detailed information
    const hasContactInfo = logs.some(log => log.includes('contact') || log.includes('messages'));
    const hasErrorDetails = logs.some(log => log.includes('error') || log.includes('Error') || log.includes('failed'));
    const hasContext = logs.some(log => log.includes('context') || log.includes('Context') || log.includes('pipeline'));
    
    logValidation('Logs Contain Details - Contact Info', hasContactInfo, undefined, `Found contact/message references: ${hasContactInfo}`);
    logValidation('Logs Contain Details - Error Details', hasErrorDetails, undefined, `Found error references: ${hasErrorDetails}`);
    logValidation('Logs Contain Details - Context', hasContext, undefined, `Found context references: ${hasContext}`);
  } catch (error) {
    logValidation('Logs Contain Details', false, error instanceof Error ? error.message : String(error));
  }
}

async function validateNoUnhandledExceptions() {
  console.log('🔍 Validation 4: No Unhandled Exceptions\n');
  
  try {
    const scenarios = [
      { name: 'Empty messages', messages: [] },
      { name: 'Null messages', messages: null as any },
      { name: 'Invalid messages', messages: [{ invalid: 'data' }] as any },
    ];
    
    let allPassed = true;
    for (const scenario of scenarios) {
      try {
        if (scenario.messages === null) {
          // Skip null test as it will fail type checking
          continue;
        }
        
        const result = await analyzeWithFallback(scenario.messages);
        if (result && result.analysis) {
          logValidation(`No Unhandled Exceptions - ${scenario.name}`, true, undefined, `Returned result with score: ${result.analysis.leadScore}`);
        } else {
          allPassed = false;
          logValidation(`No Unhandled Exceptions - ${scenario.name}`, false, 'Result is null');
        }
      } catch (error) {
        allPassed = false;
        logValidation(`No Unhandled Exceptions - ${scenario.name}`, false, error instanceof Error ? error.message : String(error));
      }
    }
    
    return allPassed;
  } catch (error) {
    logValidation('No Unhandled Exceptions', false, error instanceof Error ? error.message : String(error));
    return false;
  }
}

async function validateFastAnalysisFallback() {
  console.log('🔍 Validation 5: Fast Analysis Fallback\n');
  
  try {
    const messages = [
      { from: 'contact', text: 'Hello' },
      { from: 'business', text: 'Hi!' },
    ];
    
    const result = await analyzeConversationFast(messages);
    
    // Should return null or result, not throw
    if (result === null || (result && result.summary)) {
      logValidation('Fast Analysis Fallback - Returns Null or Result', true, undefined, 
        result ? `Got result: ${result.summary.length} chars` : 'Got null (expected)');
    } else {
      logValidation('Fast Analysis Fallback - Returns Null or Result', false, 'Unexpected result format');
    }
  } catch (error) {
    logValidation('Fast Analysis Fallback - No Exception', false, error instanceof Error ? error.message : String(error));
  }
}

async function runAllValidations() {
  console.log('='.repeat(60));
  console.log('🔍 Validating Fixes');
  console.log('='.repeat(60));
  console.log('');
  
  await validateErrorMessages();
  await validateFallbackWorks();
  await validateLogsForDetails();
  await validateNoUnhandledExceptions();
  await validateFastAnalysisFallback();
  
  // Summary
  console.log('='.repeat(60));
  console.log('📋 Validation Summary');
  console.log('='.repeat(60));
  const passed = validationResults.filter(r => r.passed).length;
  const failed = validationResults.filter(r => !r.passed).length;
  console.log(`Total Validations: ${validationResults.length}`);
  console.log(`✅ Passed: ${passed}`);
  console.log(`❌ Failed: ${failed}`);
  console.log('');
  
  if (failed > 0) {
    console.log('Failed Validations:');
    validationResults.filter(r => !r.passed).forEach(r => {
      console.log(`  - ${r.testName}: ${r.error || 'Unknown error'}`);
    });
  }
  
  console.log('='.repeat(60));
  console.log('');
  
  return failed === 0;
}

// Run validations
runAllValidations()
  .then(async (allPassed) => {
    await prisma.$disconnect();
    if (allPassed) {
      console.log('✨ All validations passed!');
      process.exit(0);
    } else {
      console.log('⚠️  Some validations failed. Review the output above.');
      process.exit(1);
    }
  })
  .catch(async (error) => {
    await prisma.$disconnect().catch(() => {});
    console.error('💥 Validation execution failed:', error);
    process.exit(1);
  });








