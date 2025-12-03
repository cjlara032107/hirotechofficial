#!/usr/bin/env node

/**
 * Complete Setup Script
 * Waits for dev server, starts ngrok, updates env, and verifies everything
 */

const http = require('http');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('\n' + '='.repeat(60));
console.log('🚀 COMPLETE PROJECT SETUP WITH NGROK');
console.log('='.repeat(60));

// Step 1: Wait for dev server
async function waitForServer() {
  console.log('\n1️⃣  Waiting for dev server to be ready...');
  let attempts = 0;
  const maxAttempts = 30;
  
  while (attempts < maxAttempts) {
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    const ready = await new Promise((resolve) => {
      const req = http.get('http://localhost:3000', { timeout: 3000 }, (res) => {
        resolve(true);
      });
      req.on('error', () => resolve(false));
      req.on('timeout', () => {
        req.destroy();
        resolve(false);
      });
    });
    
    if (ready) {
      console.log('   ✅ Dev server is ready!');
      return true;
    }
    
    attempts++;
    process.stdout.write('.');
  }
  
  console.log('\n   ❌ Dev server did not become ready');
  return false;
}

// Step 2: Get ngrok URL
async function getNgrokUrl() {
  console.log('\n2️⃣  Getting ngrok URL...');
  
  return new Promise((resolve) => {
    const req = http.get('http://localhost:4040/api/tunnels', { timeout: 5000 }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const tunnels = JSON.parse(data);
          const httpsUrl = tunnels.tunnels?.find(t => t.proto === 'https')?.public_url;
          if (httpsUrl) {
            console.log(`   ✅ Ngrok URL: ${httpsUrl}`);
            resolve(httpsUrl);
          } else {
            console.log('   ⚠️  No HTTPS tunnel found, starting ngrok...');
            resolve(null);
          }
        } catch (e) {
          console.log('   ⚠️  Could not parse ngrok response');
          resolve(null);
        }
      });
    });
    
    req.on('error', () => {
      console.log('   ⚠️  Ngrok not running, will start it...');
      resolve(null);
    });
    
    req.setTimeout(5000, () => {
      req.destroy();
      resolve(null);
    });
  });
}

// Step 3: Start ngrok
function startNgrok() {
  return new Promise((resolve) => {
    console.log('\n3️⃣  Starting ngrok...');
    const child = exec('node scripts/start-ngrok.js', (error, stdout, stderr) => {
      // This will run after ngrok starts
    });
    
    // Wait a bit for ngrok to start
    setTimeout(async () => {
      const url = await getNgrokUrl();
      resolve(url);
    }, 5000);
  });
}

// Step 4: Update .env.local
function updateEnvFile(ngrokUrl) {
  console.log('\n4️⃣  Updating .env.local...');
  
  const envPath = path.join(process.cwd(), '.env.local');
  let envContent = '';
  
  if (fs.existsSync(envPath)) {
    envContent = fs.readFileSync(envPath, 'utf8');
  }
  
  // Remove old values
  envContent = envContent.replace(/NEXT_PUBLIC_APP_URL=.*/g, '');
  envContent = envContent.replace(/NEXTAUTH_URL=.*/g, '');
  
  // Add new values
  envContent = envContent.trim();
  if (envContent && !envContent.endsWith('\n')) {
    envContent += '\n';
  }
  envContent += `NEXT_PUBLIC_APP_URL=${ngrokUrl}\n`;
  envContent += `NEXTAUTH_URL=${ngrokUrl}\n`;
  
  fs.writeFileSync(envPath, envContent);
  console.log(`   ✅ Updated .env.local with: ${ngrokUrl}`);
}

// Step 5: Final verification
async function verifySetup(ngrokUrl) {
  console.log('\n5️⃣  Verifying setup...');
  
  // Test dev server
  const serverOk = await new Promise((resolve) => {
    const req = http.get('http://localhost:3000', { timeout: 3000 }, (res) => {
      resolve(true);
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
  
  // Test ngrok
  const ngrokOk = await getNgrokUrl();
  
  console.log('\n' + '='.repeat(60));
  console.log('📊 SETUP COMPLETE - STATUS');
  console.log('='.repeat(60));
  console.log(`\n✅ Dev Server: ${serverOk ? 'Running' : 'Not responding'}`);
  console.log(`✅ Ngrok Tunnel: ${ngrokOk ? 'Active' : 'Not active'}`);
  console.log(`\n🌐 Public URL: ${ngrokUrl}`);
  console.log(`📋 Local URL: http://localhost:3000`);
  console.log(`📊 Ngrok Dashboard: http://localhost:4040`);
  
  console.log('\n📋 OAuth Callback URLs (for Facebook App):');
  console.log(`   1. ${ngrokUrl}/api/facebook/callback`);
  console.log(`   2. ${ngrokUrl}/api/facebook/callback-popup`);
  
  console.log('\n💡 Next Steps:');
  console.log('   1. Restart dev server to load new env vars (if needed)');
  console.log('   2. Update Facebook App settings with OAuth URLs above');
  console.log('   3. Test your app at the public URL');
  
  console.log('\n' + '='.repeat(60) + '\n');
}

// Main execution
(async () => {
  // Wait for dev server
  const serverReady = await waitForServer();
  if (!serverReady) {
    console.log('\n❌ Dev server is not ready. Please check for errors.');
    process.exit(1);
  }
  
  // Check if ngrok is already running
  let ngrokUrl = await getNgrokUrl();
  
  // Start ngrok if not running
  if (!ngrokUrl) {
    ngrokUrl = await startNgrok();
    // Wait a bit more and try again
    await new Promise(resolve => setTimeout(resolve, 5000));
    ngrokUrl = await getNgrokUrl();
  }
  
  if (!ngrokUrl) {
    console.log('\n❌ Could not get ngrok URL. Please start ngrok manually:');
    console.log('   npm run ngrok:start');
    process.exit(1);
  }
  
  // Update environment file
  updateEnvFile(ngrokUrl);
  
  // Verify everything
  await verifySetup(ngrokUrl);
})();




