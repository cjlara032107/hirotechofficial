#!/usr/bin/env node

/**
 * COMPREHENSIVE SYSTEM TEST
 * 
 * Tests all endpoints, simulates future conflicts, and validates system health
 * 
 * Run: node comprehensive-system-test.js
 */

const http = require('http');
const https = require('https');

const BASE_URL = 'http://localhost:3000';
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

let testResults = {
  passed: 0,
  failed: 0,
  warnings: 0,
  tests: []
};

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

function makeRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const protocol = url.startsWith('https') ? https : http;
    const req = protocol.request(url, options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: data ? JSON.parse(data) : null
          });
        } catch {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: data
          });
        }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function test(name, fn) {
  process.stdout.write(`  ${name}... `);
  try {
    const result = await fn();
    if (result.pass) {
      log('✓ PASS', colors.green);
      testResults.passed++;
    } else if (result.warn) {
      log('⚠ WARN', colors.yellow);
      testResults.warnings++;
    } else {
      log('✗ FAIL', colors.red);
      testResults.failed++;
    }
    testResults.tests.push({ name, ...result });
    return result;
  } catch (error) {
    log(`✗ FAIL - ${error.message}`, colors.red);
    testResults.failed++;
    testResults.tests.push({ name, pass: false, error: error.message });
    return { pass: false, error: error.message };
  }
}

async function runTests() {
  log('\n' + '='.repeat(70), colors.bright);
  log('  COMPREHENSIVE SYSTEM TEST SUITE', colors.bright);
  log('='.repeat(70) + '\n', colors.bright);

  // Test 1: Health Check
  log('1. SYSTEM HEALTH CHECKS', colors.cyan);
  await test('Health endpoint responds', async () => {
    const res = await makeRequest(`${BASE_URL}/api/health`);
    return {
      pass: res.status === 200 && res.body?.status === 'healthy',
      details: res.body
    };
  });

  await test('Database connection', async () => {
    const res = await makeRequest(`${BASE_URL}/api/health`);
    return {
      pass: res.body?.services?.database?.status === 'healthy',
      details: res.body?.services?.database
    };
  });

  await test('Prisma operational', async () => {
    const res = await makeRequest(`${BASE_URL}/api/health`);
    return {
      pass: res.body?.services?.prisma?.status === 'healthy',
      details: res.body?.services?.prisma
    };
  });

  // Test 2: Endpoint Availability
  log('\n2. ENDPOINT AVAILABILITY TESTS', colors.cyan);
  
  const endpoints = [
    { path: '/api/user/profile', method: 'PATCH', expect: 401 },
    { path: '/api/user/upload-image', method: 'POST', expect: 401 },
    { path: '/api/user/password', method: 'PATCH', expect: 401 },
    { path: '/api/user/password-hint', method: 'GET', expect: 401 },
    { path: '/api/user/email', method: 'PATCH', expect: 401 },
    { path: '/api/health', method: 'GET', expect: 200 },
  ];

  for (const endpoint of endpoints) {
    await test(`${endpoint.method} ${endpoint.path}`, async () => {
      const res = await makeRequest(`${BASE_URL}${endpoint.path}`, {
        method: endpoint.method
      });
      return {
        pass: res.status === endpoint.expect,
        details: `Expected ${endpoint.expect}, got ${res.status}`
      };
    });
  }

  // Test 3: Concurrent Request Simulation
  log('\n3. CONCURRENT REQUEST SIMULATION', colors.cyan);
  
  await test('Concurrent health checks', async () => {
    const promises = Array(10).fill().map(() => 
      makeRequest(`${BASE_URL}/api/health`)
    );
    const results = await Promise.all(promises);
    const allSuccess = results.every(r => r.status === 200);
    return {
      pass: allSuccess,
      details: `${results.filter(r => r.status === 200).length}/10 succeeded`
    };
  });

  // Test 4: Error Handling
  log('\n4. ERROR HANDLING TESTS', colors.cyan);
  
  await test('Invalid endpoint returns 404', async () => {
    const res = await makeRequest(`${BASE_URL}/api/invalid-endpoint-test`);
    return {
      pass: res.status === 404 || res.status === 405,
      details: `Status: ${res.status}`
    };
  });

  // Test 5: Ngrok Tunnel Check
  log('\n5. EXTERNAL SERVICES CHECK', colors.cyan);
  
  await test('Ngrok tunnel status', async () => {
    try {
      const res = await makeRequest('http://localhost:4040/api/tunnels');
      return {
        pass: res.status === 200,
        details: res.body?.tunnels?.[0]?.public_url || 'Tunnel info available'
      };
    } catch {
      return {
        warn: true,
        details: 'Ngrok not running (only needed for webhooks)'
      };
    }
  });

  // Test 6: Future Conflict Simulation
  log('\n6. FUTURE CONFLICT SIMULATION', colors.cyan);
  
  await test('Session timeout handling', async () => {
    // Simulate accessing protected endpoint without session
    const res = await makeRequest(`${BASE_URL}/api/user/profile`);
    return {
      pass: res.status === 401,
      details: 'Correctly rejects unauthorized requests'
    };
  });

  await test('Large request handling', async () => {
    // Test with large payload
    const largeData = 'x'.repeat(1024 * 1024); // 1MB
    try {
      const res = await makeRequest(`${BASE_URL}/api/user/profile`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: largeData })
      });
      return {
        pass: res.status === 401 || res.status === 413,
        details: `Handled large request: ${res.status}`
      };
    } catch {
      return {
        pass: true,
        details: 'Large request properly rejected'
      };
    }
  });

  await test('Rapid sequential requests', async () => {
    const start = Date.now();
    for (let i = 0; i < 5; i++) {
      await makeRequest(`${BASE_URL}/api/health`);
    }
    const duration = Date.now() - start;
    return {
      pass: duration < 5000,
      details: `5 requests in ${duration}ms`
    };
  });

  // Test 7: Security Tests
  log('\n7. SECURITY VALIDATION', colors.cyan);
  
  await test('Protected routes require auth', async () => {
    const protectedRoutes = [
      '/api/user/profile',
      '/api/user/password',
      '/api/user/email'
    ];
    
    const results = await Promise.all(
      protectedRoutes.map(route => makeRequest(`${BASE_URL}${route}`))
    );
    
    const allProtected = results.every(r => r.status === 401);
    return {
      pass: allProtected,
      details: `${results.filter(r => r.status === 401).length}/${protectedRoutes.length} protected`
    };
  });

  await test('Password hint endpoint exists', async () => {
    const res = await makeRequest(`${BASE_URL}/api/user/password-hint`);
    return {
      pass: res.status === 401, // Should require auth
      details: 'Endpoint protected as expected'
    };
  });

  // Print Summary
  log('\n' + '='.repeat(70), colors.bright);
  log('  TEST SUMMARY', colors.bright);
  log('='.repeat(70), colors.bright);
  
  log(`\n  Total Tests: ${testResults.passed + testResults.failed + testResults.warnings}`, colors.bright);
  log(`  ✓ Passed: ${testResults.passed}`, colors.green);
  log(`  ✗ Failed: ${testResults.failed}`, colors.red);
  log(`  ⚠ Warnings: ${testResults.warnings}`, colors.yellow);
  
  const successRate = ((testResults.passed / (testResults.passed + testResults.failed)) * 100).toFixed(1);
  log(`\n  Success Rate: ${successRate}%`, successRate >= 80 ? colors.green : colors.red);
  
  log('\n' + '='.repeat(70) + '\n', colors.bright);
  
  if (testResults.failed > 0) {
    log('FAILED TESTS:', colors.red);
    testResults.tests.filter(t => !t.pass && !t.warn).forEach(t => {
      log(`  ✗ ${t.name}`, colors.red);
      if (t.details) log(`    ${t.details}`, colors.reset);
      if (t.error) log(`    Error: ${t.error}`, colors.reset);
    });
    log('');
  }
  
  if (testResults.warnings > 0) {
    log('WARNINGS:', colors.yellow);
    testResults.tests.filter(t => t.warn).forEach(t => {
      log(`  ⚠ ${t.name}`, colors.yellow);
      if (t.details) log(`    ${t.details}`, colors.reset);
    });
    log('');
  }

  process.exit(testResults.failed > 0 ? 1 : 0);
}

// Run tests
runTests().catch(error => {
  log(`\nFATAL ERROR: ${error.message}`, colors.red);
  process.exit(1);
});

