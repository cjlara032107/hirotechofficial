/**
 * Quick test script to simulate contact reply and test stop-on-reply
 * This creates a test message from the contact and checks if stop record is created
 */

import { PrismaClient } from '@prisma/client';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// Load environment variables
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
    try {
      const env = readFileSync(join(__dirname, '.env'), 'utf8');
      env.split('\n').forEach(line => {
        const [key, ...valueParts] = line.split('=');
        if (key && valueParts.length > 0) {
          process.env[key.trim()] = valueParts.join('=').trim().replace(/^["']|["']$/g, '');
        }
      });
    } catch (e2) {
      console.log('⚠️  No .env file found.');
    }
  }
}

loadEnv();

const prisma = new PrismaClient();

async function quickTest() {
  try {
    console.log('🚀 Quick Stop-on-Reply Test\n');

    // Step 1: Find rule with stopOnReply
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
      console.log('❌ No rule with stopOnReply enabled found.');
      return;
    }

    console.log(`✅ Found rule: "${rule.name}" (${rule.id})\n`);

    // Step 2: Find contact that has executions (has received automation messages)
    const execution = await prisma.aIAutomationExecution.findFirst({
      where: {
        ruleId: rule.id,
        status: 'sent',
      },
      orderBy: {
        executedAt: 'desc',
      },
    });

    if (!execution) {
      console.log('❌ No executions found. Please send at least one automation message first.');
      return;
    }

    const contact = await prisma.contact.findUnique({
      where: { id: execution.contactId },
      include: {
        conversations: {
          take: 1,
        },
      },
    });

    if (!contact) {
      console.log('❌ Contact not found.');
      return;
    }

    if (!contact) {
      console.log('❌ No eligible contact found.');
      return;
    }

    console.log(`✅ Found contact: ${contact.firstName} (${contact.id})\n`);

    // Step 3: Check for existing executions
    const executions = await prisma.aIAutomationExecution.findMany({
      where: {
        contactId: contact.id,
        ruleId: rule.id,
        status: 'sent',
      },
      orderBy: {
        executedAt: 'desc',
      },
      take: 1,
    });

    if (executions.length === 0) {
      console.log('❌ No executions found. Please send at least one automation message first.');
      return;
    }

    const lastExecution = executions[0];
    console.log(`✅ Found last execution: ${lastExecution.executedAt.toISOString()}\n`);

    // Step 4: Create a test reply message (simulating contact reply)
    console.log('📝 Creating test reply message from contact...');
    
    let conversation = contact.conversations[0];
    if (!conversation) {
      conversation = await prisma.conversation.create({
        data: {
          contactId: contact.id,
          facebookPageId: contact.facebookPageId || rule.facebookPageId || '',
          platform: 'MESSENGER',
          status: 'OPEN',
          lastMessageAt: new Date(),
        },
      });
      console.log(`   Created conversation: ${conversation.id}`);
    }

    const testMessage = await prisma.message.create({
      data: {
        content: 'Test reply from contact - please stop automation',
        platform: 'MESSENGER',
        status: 'DELIVERED',
        contactId: contact.id,
        conversationId: conversation.id,
        isFromBusiness: false, // ⭐ CRITICAL: This is a message FROM the contact
        deliveredAt: new Date(),
        createdAt: new Date(), // Set to now (after last execution)
      },
    });

    console.log(`✅ Created test message: ${testMessage.id}`);
    console.log(`   - isFromBusiness: ${testMessage.isFromBusiness}`);
    console.log(`   - Created at: ${testMessage.createdAt.toISOString()}\n`);

    // Step 5: Check if stop record should be created (simulate cron check)
    console.log('🔍 Checking if stop record should be created...');
    
    const replies = await prisma.message.findMany({
      where: {
        contactId: contact.id,
        isFromBusiness: false,
        createdAt: {
          gt: lastExecution.executedAt,
        },
      },
    });

    console.log(`   Found ${replies.length} reply/replies after last execution\n`);

    if (replies.length > 0 && rule.stopOnReply) {
      // Check if stop record exists
      const existingStop = await prisma.aIAutomationStop.findUnique({
        where: {
          ruleId_contactId: {
            ruleId: rule.id,
            contactId: contact.id,
          },
        },
      });

      if (existingStop) {
        console.log('⚠️  Stop record already exists:');
        console.log(`   - ID: ${existingStop.id}`);
        console.log(`   - Reason: ${existingStop.stoppedReason}`);
        console.log(`   - Created: ${existingStop.createdAt.toISOString()}\n`);
      } else {
        console.log('✅ Creating stop record...');
        const stopRecord = await prisma.aIAutomationStop.create({
          data: {
            id: `stop_test_${Date.now()}`,
            ruleId: rule.id,
            contactId: contact.id,
            recipientPSID: contact.messengerPSID || 'test',
            stoppedReason: 'User replied to automated message (quick test)',
            followUpsSent: executions.length,
          },
        });

        console.log('✅ Stop record created:');
        console.log(`   - ID: ${stopRecord.id}`);
        console.log(`   - Rule: ${rule.name}`);
        console.log(`   - Contact: ${contact.firstName}`);
        console.log(`   - Follow-ups sent: ${stopRecord.followUpsSent}\n`);

        // Remove tag if configured
        if (rule.removeTagOnReply) {
          const contactData = await prisma.contact.findUnique({
            where: { id: contact.id },
            select: { tags: true },
          });

          if (contactData && contactData.tags.includes(rule.removeTagOnReply)) {
            await prisma.contact.update({
              where: { id: contact.id },
              data: {
                tags: contactData.tags.filter(tag => tag !== rule.removeTagOnReply),
              },
            });
            console.log(`✅ Removed tag "${rule.removeTagOnReply}" from contact\n`);
          }
        }
      }
    }

    console.log('✅ Quick test complete!');
    console.log('\n💡 Next steps:');
    console.log('   1. Wait for next cron run (or trigger manually)');
    console.log('   2. Check logs to see if automation stops for this contact');
    console.log('   3. Verify no more messages are sent to this contact\n');

  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await prisma.$disconnect();
  }
}

quickTest();

