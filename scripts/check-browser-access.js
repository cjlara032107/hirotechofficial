#!/usr/bin/env node

/**
 * Browser Access Check Script
 * Checks if the app is accessible via browser (localhost and ngrok)
 */

const { execSync } = require('child_process');
const http = require('http');
const https = require('https');

console.log('🌐 Checking Browser Access...\n');

// Get ngrok URL from .env.local or API
let ngrokUrl = null;
try {
  const fs = require('fs');
  const path = require('path');
  const envPath = path.join(__dirname, '..', '.env.local');
  
  if (fs.existsSync(envPath)) {
    const envContent = fs.readFileSync(envPath, 'utf-8');
    const match = envContent.match(/NEXT_PUBLIC_APP_URL=(.+)/);
    if (match && match[1].includes('ngrok')) {
      ngrokUrl = match[1].trim();
    }
  }
  
  // Try to get from ngrok API
  if (!ngrokUrl) {
    try {
      const apiResponse = execSync('curl -s http://localhost:4040/api/tunnels', { encoding: 'utf-8' });
      const data = JSON.parse(apiResponse);
      const tunnel = data.tunnels?.find(t => t.proto === 'https');
      if (tunnel) {
        ngrokUrl = tunnel.public_url;
      }
    } catch (e) {
      // Ignore
    }
  }
} catch (e) {
  // Ignore
}

// Check localhost
console.log('1️⃣  Checking Localhost (http://localhost:3000)...');
try {
  const response = http.get('http://localhost:3000', { timeout: 5000 }, (res) => {
    console.log(`   ✅ Status: ${res.statusCode}`);
    console.log(`   ✅ Accessible via browser`);
    console.log(`   🔗 URL: http://localhost:3000`);
  });
  
  response.on('error', (err) => {
    console.log(`   ❌ Not accessible: ${err.message}`);
    console.log(`   💡 Start dev server: npm run dev`);
  });
  
  response.on('timeout', () => {
    console.log(`   ⚠️  Timeout - server may be slow or not responding`);
    response.destroy();
  });
  
  setTimeout(() => {
    if (!response.destroyed) {
      response.destroy();
    }
  }, 5000);
} catch (error) {
  console.log(`   ❌ Error: ${error.message}`);
}

// Check ngrok URL
if (ngrokUrl) {
  console.log(`\n2️⃣  Checking Ngrok URL (${ngrokUrl})...`);
  
  setTimeout(() => {
    try {
      const url = new URL(ngrokUrl);
      const options = {
        hostname: url.hostname,
        path: url.pathname || '/',
        method: 'GET',
        timeout: 10000,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      };
      
      const req = https.request(options, (res) => {
        console.log(`   ✅ Status: ${res.statusCode}`);
        console.log(`   ✅ Accessible via browser`);
        console.log(`   🔗 URL: ${ngrokUrl}`);
        
        if (res.statusCode === 200) {
          console.log(`   ✅ App is working!`);
        } else if (res.statusCode === 307 || res.statusCode === 308) {
          console.log(`   ⚠️  Redirect detected (may be ngrok warning page)`);
        }
      });
      
      req.on('error', (err) => {
        console.log(`   ❌ Not accessible: ${err.message}`);
        console.log(`   💡 Check if ngrok is running: npm run ngrok:start`);
      });
      
      req.on('timeout', () => {
        console.log(`   ⚠️  Timeout - ngrok may be slow`);
        req.destroy();
      });
      
      req.setTimeout(10000);
      req.end();
    } catch (error) {
      console.log(`   ❌ Error: ${error.message}`);
    }
  }, 1000);
} else {
  console.log(`\n2️⃣  Checking Ngrok URL...`);
  console.log(`   ⚠️  Ngrok URL not found`);
  console.log(`   💡 Start ngrok: npm run ngrok:start`);
}

// Summary
setTimeout(() => {
  console.log('\n' + '='.repeat(50));
  console.log('📋 Browser Access Summary:');
  console.log('='.repeat(50));
  console.log('\n✅ To access your app:');
  if (ngrokUrl) {
    console.log(`   Public: ${ngrokUrl}`);
  }
  console.log(`   Local:  http://localhost:3000`);
  console.log('\n💡 Tips:');
  console.log('   - Clear browser cache if you see old content');
  console.log('   - Use Incognito/Private window for testing');
  console.log('   - Check browser console (F12) for errors');
  console.log('   - Ngrok dashboard: http://localhost:4040');
  console.log('='.repeat(50));
}, 6000);









