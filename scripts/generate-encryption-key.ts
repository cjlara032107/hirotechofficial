/**
 * Generate a secure encryption key for ENCRYPTION_KEY environment variable
 * Usage: npx tsx scripts/generate-encryption-key.ts
 */
import { generateEncryptionKey } from '../src/lib/crypto/encryption';

function main() {
  console.log('\n🔐 Generating Secure Encryption Key\n');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  
  const key = generateEncryptionKey();
  
  console.log('✅ Encryption Key Generated!\n');
  console.log('📋 Add this to your Vercel environment variables:');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`ENCRYPTION_KEY=${key}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  console.log('⚠️  IMPORTANT:');
  console.log('1. Copy the key above');
  console.log('2. Go to Vercel Dashboard → Your Project → Settings → Environment Variables');
  console.log('3. Add ENCRYPTION_KEY with the value above');
  console.log('4. Enable for: Production, Preview, and Development');
  console.log('5. Redeploy your application\n');
  console.log('🔒 Keep this key secure! Do not share it publicly.\n');
}

main();









