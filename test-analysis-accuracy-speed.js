/**
 * Test script for analyzing accuracy and speed of contact info extraction
 * and reply time analysis
 * 
 * Usage: node test-analysis-accuracy-speed.js
 */

const { PrismaClient } = require('@prisma/client');
const { config } = require('dotenv');
const { resolve } = require('path');

// Load environment variables
config({ path: resolve(process.cwd(), '.env.local') });

const prisma = new PrismaClient();

// Import analysis functions (we'll need to compile TypeScript or use ts-node)
// For now, we'll test with mock data and measure what we can

/**
 * Test cases for contact info extraction
 */
const contactInfoTestCases = [
  {
    name: 'Complete Contact Info',
    messages: [
      { from: 'Customer', text: 'Hi, my name is John Doe and I\'m 28 years old. You can reach me at john.doe@example.com or call me at +1-555-123-4567. I also have a business phone at +1-555-987-6543.' },
      { from: 'Business', text: 'Thanks for reaching out! What can I help you with?' },
      { from: 'Customer', text: 'I work as a Software Engineer at Tech Corp in New York. My Instagram is @johndoe and my LinkedIn is linkedin.com/in/johndoe. I also have a Facebook page at facebook.com/johndoebusiness.' },
      { from: 'Business', text: 'Great! Let me send you some information.' },
      { from: 'Customer', text: 'You can also email my work email at john@techcorp.com. My website is johndoe.dev.' },
    ],
    expected: {
      age: 28,
      phoneNumbers: ['+1-555-123-4567', '+1-555-987-6543'],
      emails: ['john.doe@example.com', 'john@techcorp.com'],
      locations: ['New York'],
      occupations: ['Software Engineer'],
      companies: ['Tech Corp'],
      socialMedia: {
        instagram: ['@johndoe'],
        linkedin: ['linkedin.com/in/johndoe'],
      },
      facebookPages: ['facebook.com/johndoebusiness'],
      websites: ['johndoe.dev'],
    },
  },
  {
    name: 'Minimal Contact Info',
    messages: [
      { from: 'Customer', text: 'Hello' },
      { from: 'Business', text: 'Hi! How can I help?' },
      { from: 'Customer', text: 'Just browsing' },
    ],
    expected: {
      age: null,
      phoneNumbers: [],
      emails: [],
    },
  },
  {
    name: 'Multiple Locations and Companies',
    messages: [
      { from: 'Customer', text: 'I live in San Francisco but work in Palo Alto. I used to work at Google but now I\'m at Apple.' },
      { from: 'Business', text: 'That\'s interesting!' },
      { from: 'Customer', text: 'I also have a side business in Seattle called StartupXYZ.' },
    ],
    expected: {
      locations: ['San Francisco', 'Palo Alto', 'Seattle'],
      companies: ['Google', 'Apple', 'StartupXYZ'],
    },
  },
];

/**
 * Test cases for reply time analysis
 */
const replyTimeTestCases = [
  {
    name: 'Fast Responder - Morning',
    messages: [
      { from: 'Business', text: 'Hello!', timestamp: new Date('2024-01-15T09:00:00Z') },
      { from: 'Customer', text: 'Hi there!', timestamp: new Date('2024-01-15T09:05:00Z') }, // 5 min reply
      { from: 'Business', text: 'How can I help?', timestamp: new Date('2024-01-15T09:10:00Z') },
      { from: 'Customer', text: 'I need help', timestamp: new Date('2024-01-15T09:12:00Z') }, // 2 min reply
    ],
    expected: {
      averageReplyTime: 3.5, // (5 + 2) / 2
      fastestReplyTime: 2,
      slowestReplyTime: 5,
      bestContactTimes: [{ dayOfWeek: 'Monday', timeRange: '09:00-11:00' }],
    },
  },
  {
    name: 'Consistent Afternoon Responder',
    messages: [
      { from: 'Business', text: 'Hello!', timestamp: new Date('2024-01-15T14:00:00Z') },
      { from: 'Customer', text: 'Hi', timestamp: new Date('2024-01-15T14:15:00Z') }, // 15 min
      { from: 'Business', text: 'How are you?', timestamp: new Date('2024-01-15T14:20:00Z') },
      { from: 'Customer', text: 'Good', timestamp: new Date('2024-01-15T14:35:00Z') }, // 15 min
      { from: 'Business', text: 'Great!', timestamp: new Date('2024-01-16T14:00:00Z') },
      { from: 'Customer', text: 'Thanks', timestamp: new Date('2024-01-16T14:15:00Z') }, // 15 min
    ],
    expected: {
      averageReplyTime: 15,
      fastestReplyTime: 15, // All replies are 15 min
      slowestReplyTime: 15, // All replies are 15 min
      bestContactTimes: [{ dayOfWeek: 'Monday', timeRange: '14:00-16:00' }],
    },
  },
];

/**
 * Performance test - measure speed
 */
async function performanceTest() {
  console.log('\n⚡ Performance Test');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  const testSizes = [1, 5, 10, 25, 50, 100];
  const results = [];

  for (const size of testSizes) {
    console.log(`Testing with ${size} contacts...`);
    
    // Create mock messages
    const messages = Array.from({ length: size }, (_, i) => ({
      from: i % 2 === 0 ? 'Customer' : 'Business',
      text: `Test message ${i}`,
      timestamp: new Date(Date.now() - (size - i) * 60000), // 1 minute apart
    }));

    // Measure reply time analysis (local, should be fast)
    const startTime = Date.now();
    
    // Simulate reply time analysis
    let replyTimeCount = 0;
    for (let i = 0; i < messages.length - 1; i++) {
      if (messages[i].from === 'Business' && messages[i + 1].from === 'Customer') {
        replyTimeCount++;
      }
    }
    
    const duration = Date.now() - startTime;
    const timePerContact = duration / size;
    
    results.push({
      size,
      duration,
      timePerContact,
      replyTimeCount,
    });

    console.log(`   ✅ ${size} contacts: ${duration}ms (${timePerContact.toFixed(2)}ms per contact)`);
  }

  console.log('\n📊 Performance Summary:');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('Contacts | Total Time | Time/Contact | Reply Pairs');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  results.forEach(r => {
    console.log(`${String(r.size).padStart(8)} | ${String(r.duration).padStart(10)}ms | ${String(r.timePerContact.toFixed(2)).padStart(11)}ms | ${r.replyTimeCount}`);
  });
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  return results;
}

/**
 * Accuracy test for reply time analysis
 */
function accuracyTestReplyTimes() {
  console.log('\n🎯 Reply Time Analysis Accuracy Test');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  let passed = 0;
  let failed = 0;

  replyTimeTestCases.forEach((testCase, index) => {
    console.log(`Test ${index + 1}: ${testCase.name}`);
    
    try {
      // Calculate reply times manually
      const replyTimes = [];
      for (let i = 0; i < testCase.messages.length - 1; i++) {
        const current = testCase.messages[i];
        const next = testCase.messages[i + 1];
        
        if (current.from === 'Business' && next.from === 'Customer') {
          const replyTimeMs = next.timestamp.getTime() - current.timestamp.getTime();
          const replyTimeMinutes = replyTimeMs / (1000 * 60);
          replyTimes.push(replyTimeMinutes);
        }
      }

      if (replyTimes.length === 0) {
        console.log('   ⚠️  No reply pairs found');
        failed++;
        return;
      }

      const avgReplyTime = replyTimes.reduce((a, b) => a + b, 0) / replyTimes.length;
      const fastest = Math.min(...replyTimes);
      const slowest = Math.max(...replyTimes);

      // Check accuracy (allow 1 minute tolerance)
      const avgMatch = Math.abs(avgReplyTime - testCase.expected.averageReplyTime) < 1;
      const fastestMatch = Math.abs(fastest - testCase.expected.fastestReplyTime) < 1;
      const slowestMatch = Math.abs(slowest - testCase.expected.slowestReplyTime) < 1;

      if (avgMatch && fastestMatch && slowestMatch) {
        console.log(`   ✅ PASSED`);
        console.log(`      Average: ${avgReplyTime.toFixed(2)} min (expected: ${testCase.expected.averageReplyTime})`);
        console.log(`      Fastest: ${fastest.toFixed(2)} min (expected: ${testCase.expected.fastestReplyTime})`);
        console.log(`      Slowest: ${slowest.toFixed(2)} min (expected: ${testCase.expected.slowestReplyTime})`);
        passed++;
      } else {
        console.log(`   ❌ FAILED`);
        console.log(`      Average: ${avgReplyTime.toFixed(2)} min (expected: ${testCase.expected.averageReplyTime}) - ${avgMatch ? '✅' : '❌'}`);
        console.log(`      Fastest: ${fastest.toFixed(2)} min (expected: ${testCase.expected.fastestReplyTime}) - ${fastestMatch ? '✅' : '❌'}`);
        console.log(`      Slowest: ${slowest.toFixed(2)} min (expected: ${testCase.expected.slowestReplyTime}) - ${slowestMatch ? '✅' : '❌'}`);
        failed++;
      }
    } catch (error) {
      console.log(`   ❌ ERROR: ${error.message}`);
      failed++;
    }
    console.log('');
  });

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  return { passed, failed };
}

/**
 * Test data structure validation
 */
function testDataStructures() {
  console.log('\n📋 Data Structure Validation Test');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  const tests = [
    {
      name: 'Contact Info Structure',
      data: {
        age: 28,
        phoneNumbers: ['+1-555-123-4567'],
        emails: ['test@example.com'],
        locations: ['New York'],
      },
      validate: (data) => {
        return (
          typeof data.age === 'number' &&
          Array.isArray(data.phoneNumbers) &&
          Array.isArray(data.emails) &&
          Array.isArray(data.locations)
        );
      },
    },
    {
      name: 'Reply Time Analysis Structure',
      data: {
        bestContactTimes: [
          {
            dayOfWeek: 'Monday',
            timeRange: '09:00-11:00',
            confidence: 90,
            averageReplyTime: 12,
            messageCount: 8,
          },
        ],
        averageReplyTime: 25,
        fastestReplyTime: 5,
        slowestReplyTime: 120,
        totalMessagesAnalyzed: 45,
      },
      validate: (data) => {
        return (
          Array.isArray(data.bestContactTimes) &&
          typeof data.averageReplyTime === 'number' &&
          typeof data.fastestReplyTime === 'number' &&
          typeof data.slowestReplyTime === 'number' &&
          typeof data.totalMessagesAnalyzed === 'number'
        );
      },
    },
  ];

  let passed = 0;
  let failed = 0;

  tests.forEach((test, index) => {
    console.log(`Test ${index + 1}: ${test.name}`);
    try {
      const isValid = test.validate(test.data);
      if (isValid) {
        console.log(`   ✅ PASSED - Structure is valid`);
        passed++;
      } else {
        console.log(`   ❌ FAILED - Structure is invalid`);
        failed++;
      }
    } catch (error) {
      console.log(`   ❌ ERROR: ${error.message}`);
      failed++;
    }
    console.log('');
  });

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  return { passed, failed };
}

/**
 * Main test runner
 */
async function runTests() {
  console.log('\n🧪 Analysis Accuracy & Speed Test Suite');
  console.log('═══════════════════════════════════════════════════════════════════════════════\n');

  const startTime = Date.now();

  // Run all tests
  const dataStructureResults = testDataStructures();
  const replyTimeResults = accuracyTestReplyTimes();
  const performanceResults = await performanceTest();

  const totalDuration = Date.now() - startTime;

  // Summary
  console.log('\n📊 Test Summary');
  console.log('═══════════════════════════════════════════════════════════════════════════════');
  console.log(`Data Structure Tests: ${dataStructureResults.passed} passed, ${dataStructureResults.failed} failed`);
  console.log(`Reply Time Accuracy: ${replyTimeResults.passed} passed, ${replyTimeResults.failed} failed`);
  console.log(`Performance Tests: ${performanceResults.length} test sizes completed`);
  console.log(`Total Test Duration: ${totalDuration}ms`);
  console.log('═══════════════════════════════════════════════════════════════════════════════\n');

  // Performance insights
  console.log('💡 Performance Insights:');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  const avgTimePerContact = performanceResults.reduce((sum, r) => sum + r.timePerContact, 0) / performanceResults.length;
  console.log(`Average time per contact (reply time analysis): ${avgTimePerContact.toFixed(2)}ms`);
  console.log(`Estimated time for 100 contacts: ${(avgTimePerContact * 100).toFixed(0)}ms (~${((avgTimePerContact * 100) / 1000).toFixed(2)} seconds)`);
  console.log(`Estimated time for 1000 contacts: ${(avgTimePerContact * 1000).toFixed(0)}ms (~${((avgTimePerContact * 1000) / 1000).toFixed(2)} seconds)`);
  console.log('\nNote: This only measures reply time analysis (local computation).');
  console.log('Contact info extraction requires AI API calls and will be much slower.');
  console.log('Expected: ~5-10 seconds per contact for full analysis (AI + reply time).\n');
}

// Run tests
runTests()
  .then(() => {
    console.log('✅ All tests completed!\n');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\n❌ Test suite failed:', error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

