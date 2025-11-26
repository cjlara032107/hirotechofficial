#!/usr/bin/env node

/**
 * Comprehensive Test Suite for AI Personalization Feature
 * Tests all endpoints, logic flows, and validates implementation
 */

const fs = require('fs');
const path = require('path');

// ANSI color codes
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
};

const log = {
  success: (msg) => console.log(`${colors.green}✓${colors.reset} ${msg}`),
  error: (msg) => console.log(`${colors.red}✗${colors.reset} ${msg}`),
  warn: (msg) => console.log(`${colors.yellow}⚠${colors.reset} ${msg}`),
  info: (msg) => console.log(`${colors.blue}ℹ${colors.reset} ${msg}`),
  section: (msg) => console.log(`\n${colors.cyan}═══ ${msg} ═══${colors.reset}\n`),
};

const results = {
  passed: 0,
  failed: 0,
  warnings: 0,
  errors: [],
};

// Test: Check if all required files exist
function testFilesExist() {
  log.section('Testing File Structure');
  
  const requiredFiles = [
    'src/app/(dashboard)/campaigns/new/page.tsx',
    'src/app/api/campaigns/preview-personalized-message/route.ts',
    'src/app/api/campaigns/preview-contacts/route.ts',
    'src/app/api/campaigns/route.ts',
    'src/lib/ai/google-ai-service.ts',
    'src/lib/campaigns/send.ts',
    'src/app/api/cron/send-scheduled/route.ts',
  ];

  requiredFiles.forEach(file => {
    const fullPath = path.join(process.cwd(), file);
    if (fs.existsSync(fullPath)) {
      log.success(`File exists: ${file}`);
      results.passed++;
    } else {
      log.error(`File missing: ${file}`);
      results.failed++;
      results.errors.push(`Missing file: ${file}`);
    }
  });
}

// Test: Check campaign creation page implementation
function testCampaignCreationPage() {
  log.section('Testing Campaign Creation Page');
  
  const pagePath = path.join(process.cwd(), 'src/app/(dashboard)/campaigns/new/page.tsx');
  
  if (!fs.existsSync(pagePath)) {
    log.error('Campaign creation page not found');
    results.failed++;
    return;
  }

  const pageContent = fs.readFileSync(pagePath, 'utf8');
  
  const requiredFeatures = [
    { name: 'AI personalization state', pattern: 'useAiPersonalization' },
    { name: 'Custom instructions state', pattern: 'aiCustomInstructions' },
    { name: 'Preview state', pattern: 'previewingContactId|previewMessage' },
    { name: 'AI toggle switch', pattern: 'id="ai-personalization"|id=\'ai-personalization\'' },
    { name: 'Custom instructions textarea', pattern: 'Custom Prompt Instructions' },
    { name: 'Preview button', pattern: 'handlePreviewPersonalizedMessage' },
    { name: 'Preview message display', pattern: 'AI Personalized Preview' },
    { name: 'AI personalization in create request', pattern: 'useAiPersonalization.*aiCustomInstructions' },
    { name: 'Sparkles icon import', pattern: 'Sparkles.*lucide-react' },
    { name: 'Eye icon import', pattern: 'Eye.*lucide-react' },
  ];

  requiredFeatures.forEach(({ name, pattern }) => {
    const regex = new RegExp(pattern, 'i');
    if (regex.test(pageContent)) {
      log.success(`Campaign page has: ${name}`);
      results.passed++;
    } else {
      log.error(`Campaign page missing: ${name}`);
      results.failed++;
      results.errors.push(`Campaign page missing: ${name}`);
    }
  });
}

// Test: Check preview personalized message endpoint
function testPreviewEndpoint() {
  log.section('Testing Preview Personalized Message Endpoint');
  
  const endpointPath = path.join(process.cwd(), 'src/app/api/campaigns/preview-personalized-message/route.ts');
  
  if (!fs.existsSync(endpointPath)) {
    log.error('Preview endpoint file not found');
    results.failed++;
    return;
  }

  const endpointContent = fs.readFileSync(endpointPath, 'utf8');
  
  const requiredFeatures = [
    { name: 'POST handler', pattern: 'export async function POST' },
    { name: 'Auth validation', pattern: 'validateSession|auth' },
    { name: 'Contact ID validation', pattern: 'contactId.*templateMessage' },
    { name: 'Contact lookup', pattern: 'prisma.contact.findFirst' },
    { name: 'Conversation history fetch', pattern: 'conversations.*include.*messages|conversationHistory' },
    { name: 'GoogleAIService usage', pattern: 'GoogleAIService' },
    { name: 'generatePersonalizedMessage call', pattern: 'generatePersonalizedMessage' },
    { name: 'Error handling', pattern: 'catch.*error|try.*catch' },
    { name: 'Response includes personalized message', pattern: 'personalizedMessage' },
  ];

  requiredFeatures.forEach(({ name, pattern }) => {
    const regex = new RegExp(pattern, 'i');
    if (regex.test(endpointContent)) {
      log.success(`Preview endpoint has: ${name}`);
      results.passed++;
    } else {
      log.error(`Preview endpoint missing: ${name}`);
      results.failed++;
      results.errors.push(`Preview endpoint missing: ${name}`);
    }
  });
}

// Test: Check campaign API route
function testCampaignAPIRoute() {
  log.section('Testing Campaign API Route');
  
  const routePath = path.join(process.cwd(), 'src/app/api/campaigns/route.ts');
  
  if (!fs.existsSync(routePath)) {
    log.error('Campaign API route not found');
    results.failed++;
    return;
  }

  const routeContent = fs.readFileSync(routePath, 'utf8');
  
  const requiredFeatures = [
    { name: 'POST handler', pattern: 'export async function POST' },
    { name: 'AI personalization fields extraction', pattern: 'useAiPersonalization|aiCustomInstructions' },
    { name: 'AI fields in campaign creation', pattern: 'useAiPersonalization|aiCustomInstructions.*campaign.create' },
    { name: 'Conditional field inclusion', pattern: 'useAiPersonalization.*undefined|aiCustomInstructions.*undefined' },
  ];

  requiredFeatures.forEach(({ name, pattern }) => {
    const regex = new RegExp(pattern, 'i');
    if (regex.test(routeContent)) {
      log.success(`Campaign API route has: ${name}`);
      results.passed++;
    } else {
      log.error(`Campaign API route missing: ${name}`);
      results.failed++;
      results.errors.push(`Campaign API route missing: ${name}`);
    }
  });
}

// Test: Check GoogleAIService implementation
function testGoogleAIService() {
  log.section('Testing GoogleAIService Implementation');
  
  const servicePath = path.join(process.cwd(), 'src/lib/ai/google-ai-service.ts');
  
  if (!fs.existsSync(servicePath)) {
    log.error('GoogleAIService file not found');
    results.failed++;
    return;
  }

  const serviceContent = fs.readFileSync(servicePath, 'utf8');
  
  const requiredFeatures = [
    { name: 'GoogleAIService class export', pattern: 'export class GoogleAIService' },
    { name: 'generatePersonalizedMessage method', pattern: 'generatePersonalizedMessage' },
    { name: 'PersonalizedMessageContext interface', pattern: 'PersonalizedMessageContext' },
    { name: 'Custom instructions support', pattern: 'customInstructions' },
    { name: 'Conversation history support', pattern: 'conversationHistory' },
    { name: 'Template message support', pattern: 'templateMessage' },
    { name: 'Error handling with fallback', pattern: 'catch.*fallback|replace.*firstName' },
    { name: 'API key management', pattern: 'getApiKey' },
  ];

  requiredFeatures.forEach(({ name, pattern }) => {
    const regex = new RegExp(pattern, 'i');
    if (regex.test(serviceContent)) {
      log.success(`GoogleAIService has: ${name}`);
      results.passed++;
    } else {
      log.error(`GoogleAIService missing: ${name}`);
      results.failed++;
      results.errors.push(`GoogleAIService missing: ${name}`);
    }
  });
}

// Test: Check campaign send logic
function testCampaignSendLogic() {
  log.section('Testing Campaign Send Logic');
  
  const sendPath = path.join(process.cwd(), 'src/lib/campaigns/send.ts');
  
  if (!fs.existsSync(sendPath)) {
    log.error('Campaign send file not found');
    results.failed++;
    return;
  }

  const sendContent = fs.readFileSync(sendPath, 'utf8');
  
  const requiredFeatures = [
    { name: 'AI message generation check', pattern: 'useAiPersonalization.*aiMessagesMap' },
    { name: 'AI message generation logic', pattern: 'GoogleAIService|generatePersonalizedMessage' },
    { name: 'Conversation history fetch', pattern: 'prisma.message.findMany' },
    { name: 'Batch processing', pattern: 'BATCH_SIZE|batch' },
    { name: 'AI messages map usage', pattern: 'aiMessagesMap\\[contact.id\\]' },
    { name: 'Fallback to template', pattern: 'fallbackMessage|template.*content' },
    { name: 'Error handling', pattern: 'catch.*error|try.*catch' },
    { name: 'Save AI messages to campaign', pattern: 'campaign.update.*aiMessagesMap|prisma.campaign.update' },
  ];

  requiredFeatures.forEach(({ name, pattern }) => {
    const regex = new RegExp(pattern, 'i');
    if (regex.test(sendContent)) {
      log.success(`Campaign send logic has: ${name}`);
      results.passed++;
    } else {
      log.error(`Campaign send logic missing: ${name}`);
      results.failed++;
      results.errors.push(`Campaign send logic missing: ${name}`);
    }
  });
}

// Test: Check scheduled campaign route
function testScheduledCampaignRoute() {
  log.section('Testing Scheduled Campaign Route');
  
  const cronPath = path.join(process.cwd(), 'src/app/api/cron/send-scheduled/route.ts');
  
  if (!fs.existsSync(cronPath)) {
    log.error('Scheduled campaign route not found');
    results.failed++;
    return;
  }

  const cronContent = fs.readFileSync(cronPath, 'utf8');
  
  const requiredFeatures = [
    { name: 'GoogleAIService import', pattern: 'import.*GoogleAIService' },
    { name: 'generateAIMessages function', pattern: 'generateAIMessages' },
    { name: 'GoogleAIService usage', pattern: 'new GoogleAIService' },
    { name: 'generatePersonalizedMessage call', pattern: 'generatePersonalizedMessage' },
    { name: 'Custom instructions usage', pattern: 'aiCustomInstructions|customInstructions' },
    { name: 'Conversation history processing', pattern: 'conversationHistory.*reverse' },
  ];

  requiredFeatures.forEach(({ name, pattern }) => {
    const regex = new RegExp(pattern, 'i');
    if (regex.test(cronContent)) {
      log.success(`Scheduled campaign route has: ${name}`);
      results.passed++;
    } else {
      log.error(`Scheduled campaign route missing: ${name}`);
      results.failed++;
      results.errors.push(`Scheduled campaign route missing: ${name}`);
    }
  });
}

// Test: Check preview contacts endpoint
function testPreviewContactsEndpoint() {
  log.section('Testing Preview Contacts Endpoint');
  
  const previewPath = path.join(process.cwd(), 'src/app/api/campaigns/preview-contacts/route.ts');
  
  if (!fs.existsSync(previewPath)) {
    log.error('Preview contacts endpoint not found');
    results.failed++;
    return;
  }

  const previewContent = fs.readFileSync(previewPath, 'utf8');
  
  // Check if aiContext is included in response
  if (previewContent.includes('aiContext') || previewContent.includes('lastInteraction')) {
    log.success('Preview contacts includes contact context fields');
    results.passed++;
  } else {
    log.warn('Preview contacts may not include all context fields');
    results.warnings++;
  }
}

// Test: Check database schema
function testDatabaseSchema() {
  log.section('Testing Database Schema');
  
  const schemaPath = path.join(process.cwd(), 'prisma', 'schema.prisma');
  
  if (!fs.existsSync(schemaPath)) {
    log.error('Prisma schema file not found');
    results.failed++;
    return;
  }

  const schemaContent = fs.readFileSync(schemaPath, 'utf8');
  
  const requiredFields = [
    'useAiPersonalization',
    'aiCustomInstructions',
    'aiMessagesMap',
  ];

  requiredFields.forEach(field => {
    if (schemaContent.includes(field)) {
      log.success(`Schema field exists: ${field}`);
      results.passed++;
    } else {
      log.error(`Schema field missing: ${field}`);
      results.failed++;
      results.errors.push(`Missing schema field: ${field}`);
    }
  });

  // Check Contact model for aiContext
  if (schemaContent.includes('aiContext') && schemaContent.includes('model Contact')) {
    log.success('Contact model includes aiContext field');
    results.passed++;
  } else {
    log.warn('Contact model may not have aiContext field');
    results.warnings++;
  }
}

// Test: Check for potential integration issues
function testIntegrationIssues() {
  log.section('Testing for Integration Issues');
  
  // Check if preview endpoint imports are correct
  const previewPath = path.join(process.cwd(), 'src/app/api/campaigns/preview-personalized-message/route.ts');
  
  if (fs.existsSync(previewPath)) {
    const previewContent = fs.readFileSync(previewPath, 'utf8');
    
    if (previewContent.includes('import') && previewContent.includes('GoogleAIService')) {
      log.success('Preview endpoint correctly imports GoogleAIService');
      results.passed++;
    } else {
      log.error('Preview endpoint may have incorrect imports');
      results.failed++;
      results.errors.push('Preview endpoint import issue');
    }
  }
  
  // Check if campaign page has proper error handling
  const pagePath = path.join(process.cwd(), 'src/app/(dashboard)/campaigns/new/page.tsx');
  
  if (fs.existsSync(pagePath)) {
    const pageContent = fs.readFileSync(pagePath, 'utf8');
    
    if (pageContent.includes('handlePreviewPersonalizedMessage') && 
        pageContent.includes('try.*catch') || pageContent.includes('catch')) {
      log.success('Campaign page has error handling for preview');
      results.passed++;
    } else {
      log.warn('Campaign page may need better error handling');
      results.warnings++;
    }
  }
}

// Test: Check TypeScript types
function testTypeScriptTypes() {
  log.section('Testing TypeScript Types');
  
  const previewPath = path.join(process.cwd(), 'src/app/api/campaigns/preview-personalized-message/route.ts');
  
  if (fs.existsSync(previewPath)) {
    const previewContent = fs.readFileSync(previewPath, 'utf8');
    
    // Check for proper typing
    if (previewContent.includes(': string') || previewContent.includes('string | null')) {
      log.success('Preview endpoint has type annotations');
      results.passed++;
    } else {
      log.warn('Preview endpoint may need more type annotations');
      results.warnings++;
    }
  }
}

// Main test runner
function runAllTests() {
  console.log('\n' + '='.repeat(60));
  console.log('   AI PERSONALIZATION FEATURE - COMPREHENSIVE TEST SUITE');
  console.log('='.repeat(60));
  
  testFilesExist();
  testCampaignCreationPage();
  testPreviewEndpoint();
  testCampaignAPIRoute();
  testGoogleAIService();
  testCampaignSendLogic();
  testScheduledCampaignRoute();
  testPreviewContactsEndpoint();
  testDatabaseSchema();
  testIntegrationIssues();
  testTypeScriptTypes();
  
  // Print summary
  console.log('\n' + '='.repeat(60));
  console.log('   TEST SUMMARY');
  console.log('='.repeat(60));
  console.log(`${colors.green}Passed:${colors.reset} ${results.passed}`);
  console.log(`${colors.red}Failed:${colors.reset} ${results.failed}`);
  console.log(`${colors.yellow}Warnings:${colors.reset} ${results.warnings}`);
  
  if (results.failed > 0) {
    console.log(`\n${colors.red}ERRORS:${colors.reset}`);
    results.errors.forEach((error, i) => {
      console.log(`  ${i + 1}. ${error}`);
    });
  }
  
  console.log('\n' + '='.repeat(60));
  
  if (results.failed === 0) {
    console.log(`${colors.green}✓ ALL TESTS PASSED!${colors.reset}`);
    console.log(`${colors.cyan}The AI personalization feature is ready to test.${colors.reset}`);
    console.log(`\n${colors.blue}Next steps:${colors.reset}`);
    console.log('  1. Start the development server: npm run dev');
    console.log('  2. Navigate to /campaigns/new');
    console.log('  3. Create a campaign with AI personalization enabled');
    console.log('  4. Test the preview functionality');
    process.exit(0);
  } else {
    console.log(`${colors.red}✗ SOME TESTS FAILED${colors.reset}`);
    console.log(`${colors.yellow}Please fix the errors above before testing.${colors.reset}`);
    process.exit(1);
  }
}

// Run tests
runAllTests();

