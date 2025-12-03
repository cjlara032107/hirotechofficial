#!/usr/bin/env node

/**
 * Verify Ngrok Setup Script
 * Checks if ngrok is running and configured correctly
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🔍 Verifying Ngrok Setup...\n');

let allGood = true;

// Check 1: Is ngrok running?
console.log('1️⃣  Checking if ngrok is running...');
try {
  const response = execSync('curl -s http://localhost:4040/api/tunnels', { encoding: 'utf-8' });
  const data = JSON.parse(response);
  const tunnel = data.tunnels?.find(t => t.proto === 'https');
  
  if (tunnel) {
    console.log('   ✅ Ngrok is running');
    console.log(`   🌐 Public URL: ${tunnel.public_url}`);
    console.log(`   🔗 Local: ${tunnel.config.addr}`);
  } else {
    console.log('   ❌ No HTTPS tunnel found');
    allGood = false;
  }
} catch (error) {
  console.log('   ❌ Ngrok is not running or not accessible');
  console.log('   💡 Start it with: npm run ngrok:start');
  allGood = false;
}

// Check 2: Is .env.local configured?
console.log('\n2️⃣  Checking .env.local configuration...');
const envPath = path.join(__dirname, '..', '.env.local');
if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, 'utf-8');
  const hasAppUrl = envContent.includes('NEXT_PUBLIC_APP_URL');
  const hasAuthUrl = envContent.includes('NEXTAUTH_URL');
  const hasNgrokToken = envContent.includes('NGROK_AUTHTOKEN');
  
  if (hasAppUrl && hasAuthUrl) {
    const appUrlMatch = envContent.match(/NEXT_PUBLIC_APP_URL=(.+)/);
    const authUrlMatch = envContent.match(/NEXTAUTH_URL=(.+)/);
    
    if (appUrlMatch && authUrlMatch) {
      const appUrl = appUrlMatch[1].trim();
      const authUrl = authUrlMatch[1].trim();
      
      console.log('   ✅ NEXT_PUBLIC_APP_URL is set');
      console.log(`      Value: ${appUrl}`);
      console.log('   ✅ NEXTAUTH_URL is set');
      console.log(`      Value: ${authUrl}`);
      
      if (appUrl.includes('ngrok') && authUrl.includes('ngrok')) {
        console.log('   ✅ Both URLs point to ngrok');
      } else if (appUrl.includes('localhost') && authUrl.includes('localhost')) {
        console.log('   ⚠️  URLs point to localhost (not ngrok)');
        console.log('   💡 Update them to your ngrok URL');
      }
    }
  } else {
    console.log('   ❌ Missing NEXT_PUBLIC_APP_URL or NEXTAUTH_URL');
    allGood = false;
  }
  
  if (hasNgrokToken) {
    console.log('   ✅ NGROK_AUTHTOKEN is set');
  } else {
    console.log('   ⚠️  NGROK_AUTHTOKEN not found (optional)');
  }
} else {
  console.log('   ❌ .env.local file not found');
  allGood = false;
}

// Check 3: Is dev server running?
console.log('\n3️⃣  Checking if dev server is running...');
try {
  // Use a cross-platform approach
  const platform = process.platform;
  let checkCommand;
  
  if (platform === 'win32') {
    // Windows: use curl with proper redirect
    checkCommand = 'curl -s http://localhost:3000 >nul 2>&1';
  } else {
    // Unix-like: use /dev/null
    checkCommand = 'curl -s http://localhost:3000 > /dev/null 2>&1';
  }
  
  execSync(checkCommand, { encoding: 'utf-8', stdio: 'ignore' });
  console.log('   ✅ Dev server is running on port 3000');
} catch (error) {
  console.log('   ⚠️  Dev server is not running on port 3000');
  console.log('   💡 Start it with: npm run dev');
}

// Summary
console.log('\n' + '='.repeat(50));
if (allGood) {
  console.log('✅ Setup looks good!');
  console.log('\n📋 Next Steps:');
  console.log('   1. Update Facebook App settings with your ngrok URL');
  console.log('   2. Restart dev server if you just updated .env.local');
  console.log('   3. Test your app at the ngrok URL');
} else {
  console.log('⚠️  Some issues found. See above for details.');
}
console.log('='.repeat(50));

