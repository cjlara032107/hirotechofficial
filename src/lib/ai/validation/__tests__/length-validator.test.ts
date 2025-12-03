/**
 * Test cases for Response Length Validation Utility
 * TASK-008: Test all three implementations
 */

import {
  validateResponseLength_v1,
  validateResponseLength_v2,
  validateResponseLength_v3,
  validateResponseLength,
} from '../length-validator';

// Test cases for comparing implementations
const testCases = [
  {
    name: 'Response meets minimum length',
    response: 'A'.repeat(500),
    minLength: 500,
    maxLength: undefined,
    expected: {
      valid: true,
      length: 500,
      meetsMinimum: true,
      exceedsMaximum: false,
    },
  },
  {
    name: 'Response too short',
    response: 'A'.repeat(499),
    minLength: 500,
    maxLength: undefined,
    expected: {
      valid: false,
      length: 499,
      meetsMinimum: false,
      exceedsMaximum: false,
    },
  },
  {
    name: 'Response exceeds maximum',
    response: 'A'.repeat(100001),
    minLength: 500,
    maxLength: 100000,
    expected: {
      valid: false,
      length: 100001,
      meetsMinimum: true,
      exceedsMaximum: true,
    },
  },
  {
    name: 'Response exactly at minimum',
    response: 'A'.repeat(500),
    minLength: 500,
    maxLength: undefined,
    expected: {
      valid: true,
      length: 500,
      meetsMinimum: true,
      exceedsMaximum: false,
    },
  },
  {
    name: 'Empty response',
    response: '',
    minLength: 500,
    maxLength: undefined,
    expected: {
      valid: false,
      length: 0,
      meetsMinimum: false,
      exceedsMaximum: false,
    },
  },
  {
    name: 'Response within range',
    response: 'A'.repeat(1000),
    minLength: 500,
    maxLength: 5000,
    expected: {
      valid: true,
      length: 1000,
      meetsMinimum: true,
      exceedsMaximum: false,
    },
  },
  {
    name: 'Response with custom max length',
    response: 'A'.repeat(100),
    minLength: 50,
    maxLength: 200,
    expected: {
      valid: true,
      length: 100,
      meetsMinimum: true,
      exceedsMaximum: false,
    },
  },
  {
    name: 'Response with only whitespace',
    response: ' '.repeat(500),
    minLength: 500,
    maxLength: undefined,
    expected: {
      valid: true, // Technically meets length requirement (whitespace has length)
      length: 500,
      meetsMinimum: true,
      exceedsMaximum: false,
    },
  },
];

// Test all three implementations
describe('validateResponseLength', () => {
  const implementations = [
    { name: 'v1', fn: validateResponseLength_v1 },
    { name: 'v2', fn: validateResponseLength_v2 },
    { name: 'v3', fn: validateResponseLength_v3 },
  ];

  implementations.forEach(({ name, fn }) => {
    describe(name, () => {
      testCases.forEach(({ name: testName, response, minLength, maxLength, expected }) => {
        test(testName, () => {
          const result = fn(response, minLength, maxLength);
          expect(result).toEqual(expected);
        });
      });
    });
  });

  // Test default export
  test('default export works', () => {
    const result = validateResponseLength('A'.repeat(500), 500);
    expect(result.valid).toBe(true);
  });
});

// Performance comparison test (optional)
describe('Performance comparison', () => {
  const longResponse = 'A'.repeat(10000);
  const iterations = 10000;

  test('v1 performance', () => {
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      validateResponseLength_v1(longResponse, 500);
    }
    const duration = performance.now() - start;
    console.log(`v1: ${duration.toFixed(2)}ms for ${iterations} iterations`);
  });

  test('v2 performance', () => {
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      validateResponseLength_v2(longResponse, 500);
    }
    const duration = performance.now() - start;
    console.log(`v2: ${duration.toFixed(2)}ms for ${iterations} iterations`);
  });

  test('v3 performance', () => {
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      validateResponseLength_v3(longResponse, 500);
    }
    const duration = performance.now() - start;
    console.log(`v3: ${duration.toFixed(2)}ms for ${iterations} iterations`);
  });
});

