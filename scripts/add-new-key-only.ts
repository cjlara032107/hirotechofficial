/**
 * Simple script to add the new working API key
 * 
 * Run this after setting up DATABASE_URL and ENCRYPTION_KEY:
 * npx tsx scripts/add-new-key-only.ts
 */

import dotenv from 'dotenv';
import path from 'path';

// Load environment variables
dotenv.config({ path: path.join(process.cwd(), '.env.local') });
dotenv.config({ path: path.join(process.cwd(), '.env') });

if (!process.env.DATABASE_URL || !process.env.ENCRYPTION_KEY) {
  console.error('❌ Missing required environment variables!');
  console.error('   Please set DATABASE_URL and ENCRYPTION_KEY in .env.local');
  process.exit(1);
}

import { prisma } from '@/lib/db';
import { encryptKey } from '@/lib/crypto/encryption';
import { ApiKeyStatus } from '@prisma/client';

const NEW_KEY = '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';

async function main() {
  try {
    await prisma.$connect();
    console.log('✅ Connected to database\n');

    // Check if key already exists
    const encryptedNewKey = encryptKey(NEW_KEY);
    const existing = await prisma.apiKey.findFirst({
      where: { encryptedKey: encryptedNewKey },
    });

    if (existing) {
      console.log('✅ Key already exists in database!');
      console.log(`   ID: ${existing.id}`);
      console.log(`   Name: ${existing.name || 'Unnamed'}`);
    } else {
      const apiKey = await prisma.apiKey.create({
        data: {
          name: 'NVIDIA API Key (Working)',
          encryptedKey: encryptedNewKey,
          status: ApiKeyStatus.ACTIVE,
          metadata: {
            prefix: NEW_KEY.substring(0, 12),
            length: NEW_KEY.length,
            addedAt: new Date().toISOString(),
            addedBy: 'add-new-key-only-script',
          },
        },
      });

      console.log('✅ Successfully added new API key!');
      console.log(`   ID: ${apiKey.id}`);
      console.log(`   Name: ${apiKey.name}`);
    }

    await prisma.$disconnect();
  } catch (error) {
    console.error('❌ Error:', error instanceof Error ? error.message : String(error));
    await prisma.$disconnect();
    process.exit(1);
  }
}

main();




