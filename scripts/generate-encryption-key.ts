/**
 * Generate Encryption Key Script
 * 
 * Generates a secure encryption key for ENCRYPTION_KEY environment variable
 */

import { generateEncryptionKey } from '../src/lib/crypto/encryption';

const key = generateEncryptionKey();

console.log('\n🔐 Generated Encryption Key:\n');
console.log(key);
console.log('\n📝 Add this to your .env.local file:');
console.log(`ENCRYPTION_KEY=${key}\n`);
console.log('⚠️  IMPORTANT: Keep this key secure and never commit it to version control!\n');
