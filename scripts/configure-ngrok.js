#!/usr/bin/env node

/**
 * Ngrok Authtoken Configuration Script
 * Configures ngrok with your authtoken
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const NGROK_EXE = path.join(__dirname, '..', 'ngrok.exe');
const AUTHTOKEN = process.argv[2] || process.env.NGROK_AUTHTOKEN;

if (!AUTHTOKEN) {
  console.error('❌ Error: No authtoken provided!');
  console.error('\nUsage:');
  console.error('  node scripts/configure-ngrok.js YOUR_AUTHTOKEN');
  console.error('  or');
  console.error('  NGROK_AUTHTOKEN=your-token node scripts/configure-ngrok.js');
  process.exit(1);
}

console.log('🔧 Configuring ngrok authtoken...\n');

// Check if ngrok.exe exists
if (!fs.existsSync(NGROK_EXE)) {
  console.error('❌ Error: ngrok.exe not found!');
  console.error(`   Expected location: ${NGROK_EXE}`);
  console.error('\n   Please download ngrok from: https://ngrok.com/download');
  process.exit(1);
}

try {
  // Configure ngrok authtoken
  console.log('📡 Setting ngrok authtoken...');
  execSync(`"${NGROK_EXE}" config add-authtoken ${AUTHTOKEN}`, {
    stdio: 'inherit',
    shell: true
  });
  
  console.log('\n✅ Ngrok authtoken configured successfully!');
  console.log('\n📋 Next steps:');
  console.log('   1. Start ngrok: npm run ngrok:start');
  console.log('   2. Copy your public URL');
  console.log('   3. Update .env.local with the ngrok URL');
  console.log('   4. Update Facebook App settings');
  
} catch (error) {
  console.error('\n❌ Error configuring ngrok:', error.message);
  console.error('\n💡 Try running manually:');
  console.error(`   "${NGROK_EXE}" config add-authtoken ${AUTHTOKEN}`);
  process.exit(1);
}









