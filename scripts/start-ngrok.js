#!/usr/bin/env node

/**
 * Ngrok Tunnel Starter Script
 * 
 * This script:
 * 1. Checks if ngrok is already running
 * 2. Starts ngrok tunnel on port 3000
 * 3. Extracts the public URL
 * 4. Displays instructions for updating .env.local
 */

const ngrok = require('ngrok');
const http = require('http');

const PORT = process.env.PORT || 3000;

console.log('🚀 Starting Ngrok Tunnel...\n');

// Check if ngrok is already running
function checkExistingTunnel() {
  return new Promise((resolve) => {
    const req = http.get('http://localhost:4040/api/tunnels', (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const tunnels = JSON.parse(data);
          if (tunnels.tunnels && tunnels.tunnels.length > 0) {
            const httpsUrl = tunnels.tunnels.find(t => t.proto === 'https')?.public_url;
            if (httpsUrl) {
              console.log('⚠️  Ngrok is already running!');
              console.log(`✅ Current ngrok URL: ${httpsUrl}\n`);
              console.log('   To stop it, run: npm run ngrok:stop\n');
              resolve(true);
              return;
            }
          }
        } catch (e) {
          // Invalid JSON, continue
        }
        resolve(false);
      });
    });
    
    req.on('error', () => {
      // Ngrok not running, continue
      resolve(false);
    });
    
    req.setTimeout(2000, () => {
      req.destroy();
      resolve(false);
    });
  });
}

// Start ngrok tunnel
async function startTunnel() {
  try {
    console.log(`📡 Starting ngrok tunnel on port ${PORT}...\n`);
    
    const url = await ngrok.connect({
      addr: PORT,
      authtoken: process.env.NGROK_AUTH_TOKEN, // Optional: set in .env.local
    });
    
    console.log('\n' + '='.repeat(60));
    console.log('✅ NGROK TUNNEL STARTED SUCCESSFULLY!');
    console.log('='.repeat(60));
    console.log(`\n🌐 Your Public URL: ${url}`);
    console.log(`\n📋 Next Steps:\n`);
    console.log('1. Update your .env.local file:');
    console.log(`   NEXT_PUBLIC_APP_URL=${url}`);
    console.log(`   NEXTAUTH_URL=${url}`);
    console.log('\n2. Update Facebook App Settings:');
    console.log(`   OAuth Redirect URI: ${url}/api/facebook/callback`);
    console.log(`   Webhook URL: ${url}/api/webhooks/facebook`);
    console.log('\n3. Restart your dev server (npm run dev)');
    console.log('\n4. Clear browser cookies');
    console.log('\n' + '='.repeat(60));
    console.log(`\n📊 Ngrok Dashboard: http://localhost:4040`);
    console.log(`\n⚠️  Keep this terminal open to keep the tunnel active!`);
    console.log(`   Press Ctrl+C to stop ngrok\n`);
    
    // Handle process termination
    process.on('SIGINT', async () => {
      console.log('\n\n🛑 Stopping ngrok...');
      await ngrok.disconnect();
      await ngrok.kill();
      process.exit(0);
    });
    
    process.on('SIGTERM', async () => {
      await ngrok.disconnect();
      await ngrok.kill();
      process.exit(0);
    });
    
  } catch (error) {
    console.error('❌ Error starting ngrok:', error.message);
    console.error('\n💡 Tips:');
    console.error('   - Make sure port 3000 is not already in use');
    console.error('   - If you have an ngrok account, set NGROK_AUTH_TOKEN in .env.local');
    console.error('   - Check ngrok documentation: https://ngrok.com/docs');
    process.exit(1);
  }
}

// Main execution
(async () => {
  const isRunning = await checkExistingTunnel();
  if (!isRunning) {
    await startTunnel();
  } else {
    process.exit(0);
  }
})();
