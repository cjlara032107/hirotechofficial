/**
 * Test AI Analyze API Endpoints
 * Checks if analyze endpoints are working and if parallelization is functioning
 */

import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });
dotenv.config({ path: '.env' });

async function testAnalyzeEndpoints() {
  console.log('🧪 Testing AI Analyze Endpoints\n');
  console.log('='.repeat(80));

  const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';

  // Test 1: Check if endpoints exist
  console.log('\n📋 Test 1: Endpoint Availability\n');
  
  const endpoints = [
    { name: 'Analyze All Contacts', path: '/api/contacts/analyze-all', method: 'POST' },
    { name: 'Analyze Pipeline', path: '/api/facebook/analyze-pipeline', method: 'POST' },
    { name: 'Analyze Selected', path: '/api/facebook/analyze-selected', method: 'POST' },
  ];

  for (const endpoint of endpoints) {
    try {
      const response = await fetch(`${baseUrl}${endpoint.path}`, {
        method: endpoint.method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      
      const status = response.status;
      const isAvailable = status !== 404;
      
      console.log(
        `${isAvailable ? '✅' : '❌'} ${endpoint.name}: ${endpoint.path} - Status: ${status}`
      );
      
      if (status === 401) {
        console.log('   ⚠️  Requires authentication (expected)');
      } else if (status === 400) {
        console.log('   ⚠️  Bad request (endpoint exists, needs valid data)');
      } else if (status === 404) {
        console.log('   ❌ Endpoint not found');
      }
    } catch (error) {
      console.log(`❌ ${endpoint.name}: ${endpoint.path} - Error: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // Test 2: Check concurrency limits
  console.log('\n📊 Test 2: Concurrency Limits\n');
  
  try {
    const { getCachedConcurrencyLimits } = await import('../src/lib/ai/dynamic-concurrency');
    const limits = await getCachedConcurrencyLimits();
    
    console.log(`✅ Concurrency limits loaded:`);
    console.log(`   - Analysis: ${limits.analysisConcurrency} concurrent operations`);
    console.log(`   - API Keys: ${limits.keyCount}`);
    console.log(`   - Message Generation: ${limits.messageGenerationConcurrency}`);
    console.log(`   - Automation: ${limits.automationConcurrency}`);
    
    if (limits.analysisConcurrency > 0) {
      console.log(`   ✅ Parallelization is ENABLED (${limits.analysisConcurrency} concurrent)`);
    } else {
      console.log(`   ❌ Parallelization is DISABLED (0 concurrent)`);
    }
  } catch (error) {
    console.log(`❌ Failed to load concurrency limits: ${error instanceof Error ? error.message : String(error)}`);
  }

  // Test 3: Check API key availability
  console.log('\n🔑 Test 3: API Key Availability\n');
  
  try {
    const apiKeyManager = (await import('../src/lib/ai/api-key-manager')).default;
    const keyCount = await apiKeyManager.getKeyCount();
    const hasKeys = keyCount > 0;
    
    console.log(`${hasKeys ? '✅' : '❌'} API Keys: ${keyCount} available`);
    
    if (!hasKeys) {
      console.log('   ⚠️  No API keys found - analysis will fail');
    }
  } catch (error) {
    console.log(`❌ Failed to check API keys: ${error instanceof Error ? error.message : String(error)}`);
  }

  // Test 4: Check analyze-selected-contacts implementation
  console.log('\n🔍 Test 4: Analyze Implementation Check\n');
  
  try {
    const analyzeModule = await import('../src/lib/facebook/analyze-selected-contacts');
    
    if (analyzeModule.analyzeSelectedContacts) {
      console.log('✅ analyzeSelectedContacts function exists');
      
      // Check if it uses Promise.all for parallelization
      const fs = await import('fs');
      const path = await import('path');
      const filePath = path.join(process.cwd(), 'src/lib/facebook/analyze-selected-contacts.ts');
      const content = fs.readFileSync(filePath, 'utf-8');
      
      const hasPromiseAll = content.includes('Promise.all');
      const hasConcurrencyLimiter = content.includes('ConcurrencyLimiter');
      const hasAnalysisLimiter = content.includes('analysisLimiter');
      
      console.log(`   ${hasPromiseAll ? '✅' : '❌'} Uses Promise.all for parallelization`);
      console.log(`   ${hasConcurrencyLimiter ? '✅' : '❌'} Uses ConcurrencyLimiter`);
      console.log(`   ${hasAnalysisLimiter ? '✅' : '❌'} Has analysis limiter`);
      
      if (hasPromiseAll && hasConcurrencyLimiter && hasAnalysisLimiter) {
        console.log('   ✅ Parallelization is properly implemented');
      } else {
        console.log('   ⚠️  Parallelization may not be fully implemented');
      }
    } else {
      console.log('❌ analyzeSelectedContacts function not found');
    }
  } catch (error) {
    console.log(`❌ Failed to check implementation: ${error instanceof Error ? error.message : String(error)}`);
  }

  console.log('\n' + '='.repeat(80));
  console.log('✅ Test Complete\n');
}

testAnalyzeEndpoints().catch(console.error);




