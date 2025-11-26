/**
 * Test AI Analysis Functionality
 * Usage: npx tsx scripts/test-ai-analysis.ts
 */
import { config } from 'dotenv';
import { resolve } from 'path';
import { analyzeConversation } from '../src/lib/ai/google-ai-service';

// Load environment variables
config({ path: resolve(process.cwd(), '.env.local') });

async function testAiAnalysis() {
  console.log('\n🧪 AI Analysis Test');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  // Test 1: Simple conversation analysis
  console.log('1️⃣  Testing Simple Conversation Analysis:');
  const testMessages1 = [
    {
      from: 'Customer',
      text: 'Hi, I\'m interested in your product. Can you tell me more about pricing?',
      timestamp: new Date(),
    },
    {
      from: 'Agent',
      text: 'Hello! I\'d be happy to help. Our basic plan starts at $29/month. What features are you most interested in?',
      timestamp: new Date(),
    },
    {
      from: 'Customer',
      text: 'I need something for a small team of 5 people. Do you have team plans?',
      timestamp: new Date(),
    },
  ];

  try {
    console.log('   Sending conversation to AI...');
    const startTime = Date.now();
    const result1 = await analyzeConversation(testMessages1);
    const duration = Date.now() - startTime;

    if (result1) {
      console.log(`   ✅ Success! (${duration}ms)`);
      console.log(`   Summary: ${result1.substring(0, 100)}...`);
    } else {
      console.log('   ❌ Failed: No result returned');
    }
  } catch (error) {
    console.log(`   ❌ Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    if (error instanceof Error && error.stack) {
      console.log(`   Stack: ${error.stack.split('\n').slice(0, 3).join('\n')}`);
    }
  }

  // Test 2: Empty conversation
  console.log('\n2️⃣  Testing Empty Conversation:');
  try {
    const result2 = await analyzeConversation([]);
    if (result2) {
      console.log(`   ⚠️  Got result for empty conversation: ${result2}`);
    } else {
      console.log('   ✅ Correctly returned null for empty conversation');
    }
  } catch (error) {
    console.log(`   ❌ Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }

  // Test 3: Long conversation
  console.log('\n3️⃣  Testing Long Conversation:');
  const longMessages = [];
  for (let i = 0; i < 20; i++) {
    longMessages.push({
      from: i % 2 === 0 ? 'Customer' : 'Agent',
      text: `Message ${i + 1}: This is a longer conversation to test how the AI handles multiple messages.`,
      timestamp: new Date(Date.now() - (20 - i) * 60000),
    });
  }

  try {
    console.log(`   Sending ${longMessages.length} messages to AI...`);
    const startTime = Date.now();
    const result3 = await analyzeConversation(longMessages);
    const duration = Date.now() - startTime;

    if (result3) {
      console.log(`   ✅ Success! (${duration}ms)`);
      console.log(`   Summary length: ${result3.length} characters`);
      console.log(`   Summary: ${result3.substring(0, 150)}...`);
    } else {
      console.log('   ❌ Failed: No result returned');
    }
  } catch (error) {
    console.log(`   ❌ Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }

  // Test 4: Check API key availability
  console.log('\n4️⃣  Checking API Key Availability:');
  try {
    const { prisma } = await import('../src/lib/db');
    const activeKeys = await prisma.apiKey.findMany({
      where: { status: 'ACTIVE' },
      select: { id: true, name: true },
    });
    
    if (activeKeys.length > 0) {
      console.log(`   ✅ Found ${activeKeys.length} active API key(s) in database`);
      activeKeys.forEach((key, index) => {
        console.log(`      ${index + 1}. ${key.name || 'Unnamed'} (${key.id.substring(0, 8)}...)`);
      });
    } else {
      console.log('   ⚠️  No active API keys in database');
    }

    // Check environment variables
    if (process.env.NVIDIA_API_KEY) {
      console.log('   ✅ NVIDIA_API_KEY found in environment');
    } else {
      console.log('   ⚠️  NVIDIA_API_KEY not found in environment');
    }

    if (process.env.GOOGLE_AI_API_KEY) {
      console.log('   ✅ GOOGLE_AI_API_KEY found in environment');
    } else {
      console.log('   ⚠️  GOOGLE_AI_API_KEY not found in environment');
    }
  } catch (error) {
    console.log(`   ❌ Error checking API keys: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }

  // Test 5: Test with invalid/malformed data
  console.log('\n5️⃣  Testing Error Handling:');
  try {
    const invalidMessages = [
      {
        from: '',
        text: '',
        timestamp: new Date(),
      },
    ];
    const result4 = await analyzeConversation(invalidMessages);
    if (result4) {
      console.log(`   ⚠️  Got result for invalid data: ${result4}`);
    } else {
      console.log('   ✅ Correctly handled invalid data');
    }
  } catch (error) {
    console.log(`   ✅ Error caught: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }

  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('📊 Test Complete\n');
  
  await (await import('../src/lib/db')).prisma.$disconnect();
}

testAiAnalysis().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});







