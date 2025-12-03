/**
 * Script to add the fourth new working API key
 */

import dotenv from 'dotenv';
import path from 'path';

// Load environment variables
dotenv.config({ path: path.join(process.cwd(), '.env.local') });
dotenv.config({ path: path.join(process.cwd(), '.env') });

// Use encryption key from docs if not set
if (!process.env.ENCRYPTION_KEY) {
  process.env.ENCRYPTION_KEY = 'f902ad293f5f9af42c98b007dfdc0eede8614ac2be7a985c23347e051f3bcf81';
}

// Check DATABASE_URL
if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL is required!');
  process.exit(1);
}

import { PrismaClient } from '@prisma/client';
import { encryptKey } from '@/lib/crypto/encryption';

const NEW_KEY = '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';

// Create Prisma client with explicit DATABASE_URL
const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DATABASE_URL,
    },
  },
});

async function main() {
  try {
    console.log('='.repeat(70));
    console.log('➕ Adding Fourth New API Key');
    console.log('='.repeat(70));
    console.log('');

    await prisma.$connect();
    console.log('✅ Connected to database\n');

    // Encrypt the new key
    console.log('🔐 Encrypting API key...');
    const encryptedKey = encryptKey(NEW_KEY);
    console.log('✅ Key encrypted\n');

    // Check if key already exists
    console.log('🔍 Checking if key already exists...');
    const existing = await prisma.apiKey.findFirst({
      where: { encryptedKey },
    });

    if (existing) {
      console.log('✅ Key already exists in database!');
      console.log(`   ID: ${existing.id}`);
      console.log(`   Name: ${existing.name || 'Unnamed'}`);
      console.log(`   Status: ${existing.status}`);
    } else {
      console.log('📝 Creating new API key record...');
      
      const apiKey = await prisma.apiKey.create({
        data: {
          name: 'NVIDIA API Key 4 (Working)',
          encryptedKey: encryptedKey,
          status: 'ACTIVE',
          metadata: {
            prefix: NEW_KEY.substring(0, 12),
            length: NEW_KEY.length,
            addedAt: new Date().toISOString(),
            addedBy: 'add-fourth-key-script',
          },
        },
      });

      console.log('✅ Successfully added new API key!');
      console.log(`   ID: ${apiKey.id}`);
      console.log(`   Name: ${apiKey.name}`);
      console.log(`   Status: ${apiKey.status}`);
    }

    // Show final count
    const totalActive = await prisma.apiKey.count({
      where: { status: 'ACTIVE' },
    });

    console.log('');
    console.log('='.repeat(70));
    console.log('📊 Summary');
    console.log('='.repeat(70));
    console.log(`Total active keys: ${totalActive}`);
    console.log('='.repeat(70));

    await prisma.$disconnect();
    console.log('\n✅ Done!');
  } catch (error) {
    console.error('\n❌ Error:', error instanceof Error ? error.message : String(error));
    if (error instanceof Error && error.stack) {
      console.error('\nStack trace:');
      console.error(error.stack);
    }
    await prisma.$disconnect();
    process.exit(1);
  }
}

main();




