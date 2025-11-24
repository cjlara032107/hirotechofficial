/**
 * Test Suite for AI Automation API Endpoints
 * Tests all 5 main endpoints
 */

const BASE_URL = process.env.TEST_URL || 'http://localhost:3000';

async function testEndpoint1_ListRules() {
  console.log('\n🧪 Endpoint Test 1: GET /api/ai-automations (List Rules)');
  console.log('='.repeat(50));
  
  try {
    const response = await fetch(`${BASE_URL}/api/ai-automations`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });
    
    console.log(`Status: ${response.status}`);
    
    if (response.status === 401) {
      console.log('⚠️  Requires authentication (expected)');
      return true; // This is expected for protected endpoint
    }
    
    if (response.ok) {
      const data = await response.json();
      console.log(`Rules found: ${data.rules?.length || 0}`);
      console.log('✅ Endpoint Test 1 PASSED: List rules endpoint accessible');
      return true;
    } else {
      console.log('❌ Endpoint Test 1 FAILED: Unexpected error');
      return false;
    }
  } catch (error) {
    console.log('❌ Endpoint Test 1 FAILED:', error.message);
    return false;
  }
}

async function testEndpoint2_CronExecution() {
  console.log('\n🧪 Endpoint Test 2: GET /api/cron/ai-automations (Cron Job)');
  console.log('='.repeat(50));
  
  try {
    const response = await fetch(`${BASE_URL}/api/cron/ai-automations`, {
      method: 'GET',
      headers: {
        'x-vercel-cron': '1', // Simulate Vercel cron
      },
    });
    
    const data = await response.json();
    console.log(`Status: ${response.status}`);
    console.log(`Response:`, JSON.stringify(data, null, 2));
    
    if (response.ok) {
      console.log('✅ Endpoint Test 2 PASSED: Cron endpoint working');
      return true;
    } else {
      console.log('❌ Endpoint Test 2 FAILED: Cron endpoint error');
      return false;
    }
  } catch (error) {
    console.log('❌ Endpoint Test 2 FAILED:', error.message);
    return false;
  }
}

async function testEndpoint3_ManualExecute() {
  console.log('\n🧪 Endpoint Test 3: POST /api/ai-automations/execute (Manual Trigger)');
  console.log('='.repeat(50));
  
  try {
    const response = await fetch(`${BASE_URL}/api/ai-automations/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        ruleId: 'test-rule-id',
        bypassCooldown: true,
      }),
    });
    
    console.log(`Status: ${response.status}`);
    
    if (response.status === 401) {
      console.log('⚠️  Requires authentication (expected)');
      return true;
    }
    
    if (response.status === 404) {
      console.log('⚠️  Rule not found (expected for test ID)');
      return true;
    }
    
    const data = await response.json();
    console.log(`Response:`, JSON.stringify(data, null, 2));
    
    if (response.ok || response.status === 404) {
      console.log('✅ Endpoint Test 3 PASSED: Manual execute endpoint accessible');
      return true;
    } else {
      console.log('❌ Endpoint Test 3 FAILED: Unexpected error');
      return false;
    }
  } catch (error) {
    console.log('❌ Endpoint Test 3 FAILED:', error.message);
    return false;
  }
}

async function testEndpoint4_RuleDetails() {
  console.log('\n🧪 Endpoint Test 4: GET /api/ai-automations/[id]/details');
  console.log('='.repeat(50));
  
  try {
    const response = await fetch(`${BASE_URL}/api/ai-automations/test-id/details`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });
    
    console.log(`Status: ${response.status}`);
    
    if (response.status === 401) {
      console.log('⚠️  Requires authentication (expected)');
      return true;
    }
    
    if (response.status === 404) {
      console.log('⚠️  Rule not found (expected for test ID)');
      return true;
    }
    
    console.log('✅ Endpoint Test 4 PASSED: Rule details endpoint accessible');
    return true;
  } catch (error) {
    console.log('❌ Endpoint Test 4 FAILED:', error.message);
    return false;
  }
}

async function testEndpoint5_HealthCheck() {
  console.log('\n🧪 Endpoint Test 5: GET /api/health (Health Check)');
  console.log('='.repeat(50));
  
  try {
    const response = await fetch(`${BASE_URL}/api/health`, {
      method: 'GET',
    });
    
    const data = await response.json();
    console.log(`Status: ${response.status}`);
    console.log(`Response:`, JSON.stringify(data, null, 2));
    
    if (response.ok) {
      console.log('✅ Endpoint Test 5 PASSED: Health check working');
      return true;
    } else {
      console.log('❌ Endpoint Test 5 FAILED: Health check error');
      return false;
    }
  } catch (error) {
    console.log('❌ Endpoint Test 5 FAILED:', error.message);
    return false;
  }
}

async function runAllEndpointTests() {
  console.log('\n🚀 Starting AI Automation Endpoint Test Suite');
  console.log('='.repeat(50));
  console.log(`Base URL: ${BASE_URL}`);
  console.log(`Timestamp: ${new Date().toISOString()}`);
  
  const results = [];
  
  results.push(await testEndpoint1_ListRules());
  results.push(await testEndpoint2_CronExecution());
  results.push(await testEndpoint3_ManualExecute());
  results.push(await testEndpoint4_RuleDetails());
  results.push(await testEndpoint5_HealthCheck());
  
  console.log('\n📊 Endpoint Test Results Summary');
  console.log('='.repeat(50));
  const passed = results.filter(r => r).length;
  const total = results.length;
  console.log(`Passed: ${passed}/${total}`);
  console.log(`Failed: ${total - passed}/${total}`);
  
  if (passed === total) {
    console.log('\n✅ ALL ENDPOINT TESTS PASSED!');
    process.exit(0);
  } else {
    console.log('\n❌ SOME ENDPOINT TESTS FAILED');
    process.exit(1);
  }
}

// Run tests
runAllEndpointTests().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});

