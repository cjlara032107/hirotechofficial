/**
 * Test script to simulate stop-on-reply functionality
 * This simulates:
 * 1. Automation sends message to contact
 * 2. Contact replies
 * 3. System should detect reply and create stop record
 */

import { PrismaClient } from '@prisma/client';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// Load environment variables from .env.local or .env
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function loadEnv() {
  try {
    const envLocal = readFileSync(join(__dirname, '.env.local'), 'utf8');
    envLocal.split('\n').forEach(line => {
      const [key, ...valueParts] = line.split('=');
      if (key && valueParts.length > 0) {
        process.env[key.trim()] = valueParts.join('=').trim().replace(/^["']|["']$/g, '');
      }
    });
  } catch (e) {
    // .env.local not found, try .env
    try {
      const env = readFileSync(join(__dirname, '.env'), 'utf8');
      env.split('\n').forEach(line => {
        const [key, ...valueParts] = line.split('=');
        if (key && valueParts.length > 0) {
          process.env[key.trim()] = valueParts.join('=').trim().replace(/^["']|["']$/g, '');
        }
      });
    } catch (e2) {
      console.log('⚠️  No .env file found. Make sure DATABASE_URL is set in environment.');
    }
  }
}

loadEnv();

const prisma = new PrismaClient();

async function simulateStopOnReply() {
  try {
    console.log('🧪 Starting stop-on-reply simulation...\n');

    // Step 1: Find a test rule with stopOnReply enabled
    console.log('📋 Step 1: Finding automation rule with stopOnReply enabled...');
    const rule = await prisma.aIAutomationRule.findFirst({
      where: {
        enabled: true,
        stopOnReply: true,
      },
      include: {
        User: {
          select: {
            organizationId: true,
          },
        },
      },
    });

    if (!rule) {
      console.log('❌ No rule found with stopOnReply enabled. Please enable stopOnReply on a rule first.');
      return;
    }

    console.log(`✅ Found rule: "${rule.name}" (ID: ${rule.id})`);
    console.log(`   - stopOnReply: ${rule.stopOnReply}`);
    console.log(`   - removeTagOnReply: ${rule.removeTagOnReply || 'none'}\n`);

    // Step 2: Find a contact that matches the rule criteria
    console.log('👤 Step 2: Finding eligible contact...');
    const contact = await prisma.contact.findFirst({
      where: {
        organizationId: rule.User.organizationId,
        messengerPSID: { not: null },
        ...(rule.facebookPageId && { facebookPageId: rule.facebookPageId }),
        ...(rule.includeTags.length > 0 && {
          tags: { hasSome: rule.includeTags },
        }),
      },
      include: {
        conversations: {
          take: 1,
        },
      },
    });

    if (!contact) {
      console.log('❌ No eligible contact found for this rule.');
      return;
    }

    console.log(`✅ Found contact: ${contact.firstName} ${contact.lastName || ''} (ID: ${contact.id})`);
    console.log(`   - Messenger PSID: ${contact.messengerPSID}\n`);

    // Step 3: Check if contact already has a stop record
    console.log('🔍 Step 3: Checking for existing stop records...');
    const existingStop = await prisma.aIAutomationStop.findUnique({
      where: {
        ruleId_contactId: {
          ruleId: rule.id,
          contactId: contact.id,
        },
      },
    });

    if (existingStop) {
      console.log(`⚠️  Contact already has a stop record:`);
      console.log(`   - Reason: ${existingStop.stoppedReason}`);
      console.log(`   - Follow-ups sent: ${existingStop.followUpsSent}`);
      console.log(`   - Created: ${existingStop.createdAt}`);
      console.log('\n💡 To test again, delete this stop record first.');
      return;
    }

    console.log('✅ No existing stop record found.\n');

    // Step 4: Check for existing executions
    console.log('📨 Step 4: Checking for existing automation executions...');
    const executions = await prisma.aIAutomationExecution.findMany({
      where: {
        contactId: contact.id,
        ruleId: rule.id,
        status: 'sent',
      },
      orderBy: {
        executedAt: 'desc',
      },
    });

    console.log(`✅ Found ${executions.length} execution(s)`);
    if (executions.length > 0) {
      console.log(`   - Last execution: ${executions[0].executedAt.toISOString()}\n`);
    } else {
      console.log('   - No executions found yet. Creating a test execution...\n');
      
      // Create a test execution
      const testExecution = await prisma.aIAutomationExecution.create({
        data: {
          id: `exec_test_${Date.now()}`,
          ruleId: rule.id,
          userId: rule.userId,
          contactId: contact.id,
          conversationId: contact.conversations[0]?.id || null,
          recipientPSID: contact.messengerPSID || 'test',
          recipientName: `${contact.firstName} ${contact.lastName || ''}`.trim(),
          status: 'sent',
          executedAt: new Date(Date.now() - 5 * 60 * 1000), // 5 minutes ago
        },
      });
      console.log(`✅ Created test execution: ${testExecution.id}\n`);
    }

    // Step 5: Check for contact replies
    console.log('💬 Step 5: Checking for contact replies...');
    const lastExecution = executions[0] || await prisma.aIAutomationExecution.findFirst({
      where: {
        contactId: contact.id,
        ruleId: rule.id,
        status: 'sent',
      },
      orderBy: {
        executedAt: 'desc',
      },
    });

    if (!lastExecution) {
      console.log('❌ No execution found. Cannot check for replies.');
      return;
    }

    console.log(`   - Last execution time: ${lastExecution.executedAt.toISOString()}\n`);

    // Check ALL messages for this contact (both directions) for debugging
    const allMessages = await prisma.message.findMany({
      where: {
        contactId: contact.id,
      },
      orderBy: {
        createdAt: 'desc',
      },
      take: 50, // Check more messages
    });

    // Also check by messengerPSID to see if messages are under a different contact
    console.log('🔍 Checking for messages by Messenger PSID...');
    const messagesByPSID = await prisma.message.findMany({
      where: {
        contact: {
          messengerPSID: contact.messengerPSID,
        },
      },
      include: {
        contact: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
          },
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
      take: 20,
    });

    const contactMessagesByPSID = messagesByPSID.filter(m => !m.isFromBusiness);
    console.log(`   Found ${contactMessagesByPSID.length} messages from contact (by PSID) across all contacts`);
    if (contactMessagesByPSID.length > 0) {
      console.log('   Recent contact messages (by PSID):');
      contactMessagesByPSID.slice(0, 5).forEach((msg, idx) => {
        const isAfter = msg.createdAt > lastExecution.executedAt;
        const timeDiff = msg.createdAt.getTime() - lastExecution.executedAt.getTime();
        const minutesDiff = Math.floor(timeDiff / (60 * 1000));
        console.log(`   ${idx + 1}. ${msg.createdAt.toISOString()} - ${isAfter ? '✅ AFTER' : '❌ BEFORE'} execution (${minutesDiff > 0 ? '+' : ''}${minutesDiff} min)`);
        console.log(`      Contact ID: ${msg.contact.id} (${msg.contact.firstName}) - ${msg.contact.id === contact.id ? '✅ MATCH' : '❌ DIFFERENT'}`);
        console.log(`      Content: ${msg.content.substring(0, 60)}...`);
      });
    }
    console.log('');

    console.log(`📊 All messages for this contact (last 20):`);
    if (allMessages.length > 0) {
      const contactMessages = allMessages.filter(m => !m.isFromBusiness);
      const businessMessages = allMessages.filter(m => m.isFromBusiness);
      
      console.log(`   Total: ${allMessages.length} messages`);
      console.log(`   - From contact: ${contactMessages.length}`);
      console.log(`   - From business: ${businessMessages.length}\n`);
      
      console.log(`   Recent messages (showing last 10):`);
      allMessages.slice(0, 10).forEach((msg, idx) => {
        const isAfter = msg.createdAt > lastExecution.executedAt;
        const timeDiff = msg.createdAt.getTime() - lastExecution.executedAt.getTime();
        const minutesDiff = Math.floor(timeDiff / (60 * 1000));
        const direction = msg.isFromBusiness ? '📤 BUSINESS' : '📥 CONTACT';
        console.log(`   ${idx + 1}. ${msg.createdAt.toISOString()} - ${direction}`);
        console.log(`      ${isAfter ? '✅ AFTER' : '❌ BEFORE'} execution (${minutesDiff > 0 ? '+' : ''}${minutesDiff} min)`);
        console.log(`      Content: ${msg.content.substring(0, 60)}...`);
      });
    } else {
      console.log('   ⚠️  No messages found for this contact at all!');
      console.log('   This could mean:');
      console.log('   1. Contact has never sent/received messages');
      console.log('   2. Messages are stored under a different contact ID');
      console.log('   3. Webhook is not saving messages correctly\n');
    }
    console.log('');

    // Check messages after last execution
    const replies = await prisma.message.findMany({
      where: {
        contactId: contact.id,
        isFromBusiness: false,
        createdAt: {
          gt: lastExecution.executedAt,
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    console.log(`✅ Found ${replies.length} reply/replies after last automation message`);
    if (replies.length > 0) {
      console.log(`   - Last reply: ${replies[0].createdAt.toISOString()}`);
      console.log(`   - Content: ${replies[0].content.substring(0, 50)}...\n`);
    } else {
      // Check webhook events to see if replies were received
      console.log('\n🔍 Checking webhook events for incoming messages...');
      const webhookEvents = await prisma.webhookEvent.findMany({
        where: {
          platform: 'MESSENGER',
          eventType: 'page',
        },
        orderBy: {
          createdAt: 'desc',
        },
        take: 10,
      });

      console.log(`   Found ${webhookEvents.length} recent webhook events`);
      if (webhookEvents.length > 0) {
        console.log('   Recent webhook events:');
        webhookEvents.slice(0, 5).forEach((event, idx) => {
          const payload = typeof event.payload === 'string' ? JSON.parse(event.payload) : event.payload;
          const hasMessaging = payload?.entry?.[0]?.messaging?.length > 0;
          const hasMessage = payload?.entry?.[0]?.messaging?.[0]?.message;
          const isEcho = payload?.entry?.[0]?.messaging?.[0]?.message?.is_echo;
          console.log(`   ${idx + 1}. ${event.createdAt.toISOString()}`);
          console.log(`      Has messaging: ${hasMessaging}`);
          console.log(`      Has message: ${hasMessage}`);
          console.log(`      Is echo: ${isEcho}`);
          if (hasMessage && !isEcho) {
            console.log(`      Message text: ${payload.entry[0].messaging[0].message.text?.substring(0, 50)}...`);
          }
        });
      }
      console.log('');
    }

      // Step 6: Simulate the stop-on-reply check
      console.log('🛑 Step 6: Simulating stop-on-reply check...');
      
      // This is what the cron job should do
      const shouldStop = rule.stopOnReply && replies.length > 0;
      
      if (shouldStop) {
        console.log('✅ Contact replied - should create stop record!\n');
        
        // Create stop record (simulating what cron should do)
        const stopRecord = await prisma.aIAutomationStop.create({
          data: {
            id: `stop_test_${Date.now()}`,
            ruleId: rule.id,
            contactId: contact.id,
            recipientPSID: contact.messengerPSID || 'test',
            stoppedReason: 'User replied to automated message (test simulation)',
            followUpsSent: executions.length,
          },
        });

        console.log('✅ Stop record created:');
        console.log(`   - ID: ${stopRecord.id}`);
        console.log(`   - Rule: ${rule.name}`);
        console.log(`   - Contact: ${contact.firstName}`);
        console.log(`   - Follow-ups sent: ${stopRecord.followUpsSent}`);
        console.log(`   - Reason: ${stopRecord.stoppedReason}\n`);

        // Check tag removal if configured
        if (rule.removeTagOnReply) {
          const contactData = await prisma.contact.findUnique({
            where: { id: contact.id },
            select: { tags: true },
          });

          if (contactData && contactData.tags.includes(rule.removeTagOnReply)) {
            console.log(`🏷️  Tag "${rule.removeTagOnReply}" should be removed from contact.`);
            console.log(`   Current tags: ${contactData.tags.join(', ')}`);
          } else {
            console.log(`🏷️  Tag "${rule.removeTagOnReply}" not found on contact or already removed.`);
          }
        }

        console.log('\n✅ Simulation complete! Stop record created successfully.');
      } else {
        console.log('❌ Should not stop - rule.stopOnReply is false or no replies found.');
      }
    } else {
      console.log('⚠️  No replies found after last automation message.');
      console.log('   - Last execution: ' + lastExecution.executedAt.toISOString());
      console.log('\n💡 Possible issues:');
      console.log('   1. Webhook not receiving messages from contact');
      console.log('   2. Messages being saved with wrong isFromBusiness flag');
      console.log('   3. Messages being saved to different contact');
      console.log('   4. Contact replied but webhook not called\n');
    }

  } catch (error) {
    console.error('❌ Error during simulation:', error);
  } finally {
    await prisma.$disconnect();
  }
}

// Run the simulation
simulateStopOnReply();

