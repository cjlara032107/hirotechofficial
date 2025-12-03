/**
 * Simple test runner for TASK-008: Response Length Validation Utility
 * Run with: npx tsx scripts/test-length-validator.ts
 */

import {
  validateResponseLength_v1,
  validateResponseLength_v2,
  validateResponseLength_v3,
  validateResponseLength,
} from '../src/lib/ai/validation/length-validator';

// Test cases
const testCases = [
  {
    name: 'Response meets minimum length',
    response: 'A'.repeat(500),
    minLength: 500,
    maxLength: undefined,
    expected: { valid: true, length: 500, meetsMinimum: true, exceedsMaximum: false },
  },
  {
    name: 'Response too short',
    response: 'A'.repeat(499),
    minLength: 500,
    maxLength: undefined,
    expected: { valid: false, length: 499, meetsMinimum: false, exceedsMaximum: false },
  },
  {
    name: 'Response exceeds maximum',
    response: 'A'.repeat(100001),
    minLength: 500,
    maxLength: 100000,
    expected: { valid: false, length: 100001, meetsMinimum: true, exceedsMaximum: true },
  },
  {
    name: 'Empty response',
    response: '',
    minLength: 500,
    maxLength: undefined,
    expected: { valid: false, length: 0, meetsMinimum: false, exceedsMaximum: false },
  },
  {
    name: 'Response exactly at minimum',
    response: 'A'.repeat(500),
    minLength: 500,
    maxLength: undefined,
    expected: { valid: true, length: 500, meetsMinimum: true, exceedsMaximum: false },
  },
  {
    name: 'Response with only whitespace',
    response: ' '.repeat(500),
    minLength: 500,
    maxLength: undefined,
    expected: { valid: true, length: 500, meetsMinimum: true, exceedsMaximum: false },
  },
];

// Test all implementations
const implementations = [
  { name: 'v1', fn: validateResponseLength_v1 },
  { name: 'v2', fn: validateResponseLength_v2 },
  { name: 'v3', fn: validateResponseLength_v3 },
];

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

console.log('🧪 Testing TASK-008: Response Length Validation Utility\n');

implementations.forEach(({ name, fn }) => {
  console.log(`\n📦 Testing ${name}:`);
  testCases.forEach(({ name: testName, response, minLength, maxLength, expected }) => {
    totalTests++;
    const result = fn(response, minLength, maxLength);
    const passed = JSON.stringify(result) === JSON.stringify(expected);
    
    if (passed) {
      passedTests++;
      console.log(`  ✅ ${testName}`);
    } else {
      failedTests++;
      console.log(`  ❌ ${testName}`);
      console.log(`     Expected:`, expected);
      console.log(`     Got:`, result);
    }
  });
});

// Test default export
console.log(`\n📦 Testing default export:`);
totalTests++;
const defaultResult = validateResponseLength('A'.repeat(500), 500);
if (defaultResult.valid === true) {
  passedTests++;
  console.log(`  ✅ Default export works`);
} else {
  failedTests++;
  console.log(`  ❌ Default export failed`);
}

// Performance test
console.log(`\n⚡ Performance Test:`);
const longResponse = 'A'.repeat(10000);
const iterations = 10000;

implementations.forEach(({ name, fn }) => {
  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    fn(longResponse, 500);
  }
  const duration = performance.now() - start;
  console.log(`  ${name}: ${duration.toFixed(2)}ms for ${iterations} iterations`);
});

// Summary
console.log(`\n📊 Test Summary:`);
console.log(`  Total Tests: ${totalTests}`);
console.log(`  Passed: ${passedTests} ✅`);
console.log(`  Failed: ${failedTests} ${failedTests > 0 ? '❌' : ''}`);
console.log(`  Success Rate: ${((passedTests / totalTests) * 100).toFixed(1)}%`);

if (failedTests === 0) {
  console.log(`\n✅ All tests passed! TASK-008 is working correctly.`);
  process.exit(0);
} else {
  console.log(`\n❌ Some tests failed. Please review the implementation.`);
  process.exit(1);
}









