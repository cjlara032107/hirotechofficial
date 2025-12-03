#!/usr/bin/env node

/**
 * Fix ngrok ERR_NGROK_3004 Error
 * This error means ngrok is receiving invalid HTTP responses from the local server
 */

const http = require('http');
const { exec } = require('child_process');

console.log('\n' + '='.repeat(60));
console.log('🔧 FIXING NGROK ERR_NGROK_3004 ERROR');
console.log('='.repeat(60));

// Step 1: Check if dev server is responding
console.log('\n1️⃣  Testing local server...');
const testServer = () => {
  return new Promise((resolve) => {
    const req = http.get('http://localhost:3000', { timeout: 5000 }, (res) => {
      let data = '';
      res.on('data', () => {});
      res.on('end', () => {
        console.log(`   ✅ Server responding (Status: ${res.statusCode})`);
        resolve(true);
      });
    });
    
    req.on('error', (err) => {
      console.log(`   ❌ Server not responding: ${err.message}`);
      resolve(false);
    });
    
    req.on('timeout', () => {
      req.destroy();
      console.log('   ❌ Server timeout - not responding');
      resolve(false);
    });
  });
};

// Step 2: Check ngrok status
const checkNgrok = () => {
  return new Promise((resolve) => {
    const req = http.get('http://localhost:4040/api/tunnels', { timeout: 3000 }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const tunnels = JSON.parse(data);
          const tunnel = tunnels.tunnels?.find(t => t.proto === 'https');
          if (tunnel) {
            console.log(`   ✅ Ngrok active: ${tunnel.public_url}`);
            resolve(true);
          } else {
            console.log('   ⚠️  Ngrok running but no tunnel found');
            resolve(false);
          }
        } catch (e) {
          console.log('   ⚠️  Could not parse ngrok status');
          resolve(false);
        }
      });
    });
    
    req.on('error', () => {
      console.log('   ❌ Ngrok API not accessible');
      resolve(false);
    });
    
    req.setTimeout(3000, () => {
      req.destroy();
      console.log('   ❌ Ngrok API timeout');
      resolve(false);
    });
  });
};

(async () => {
  const serverOk = await testServer();
  const ngrokOk = await checkNgrok();
  
  console.log('\n2️⃣  Diagnosis:');
  
  if (!serverOk) {
    console.log('\n❌ PROBLEM: Dev server is not responding properly');
    console.log('\n📋 Solution:');
    console.log('   1. Stop the current dev server (Ctrl+C)');
    console.log('   2. Check for build errors:');
    console.log('      npm run build');
    console.log('   3. Restart dev server:');
    console.log('      npm run dev');
    console.log('   4. Wait for "Ready" message');
    console.log('   5. Test: curl http://localhost:3000');
    console.log('   6. Then restart ngrok');
  } else if (!ngrokOk) {
    console.log('\n❌ PROBLEM: Ngrok tunnel not active');
    console.log('\n📋 Solution:');
    console.log('   1. Stop ngrok: npm run ngrok:stop');
    console.log('   2. Restart ngrok: npm run ngrok:start');
    console.log('   3. Wait for tunnel to establish');
  } else {
    console.log('\n✅ Both services appear to be running');
    console.log('\n⚠️  If you still see ERR_NGROK_3004:');
    console.log('   1. Clear browser cache and cookies');
    console.log('   2. Try incognito/private window');
    console.log('   3. Wait 30 seconds and refresh');
    console.log('   4. Check server logs for errors');
    console.log('   5. Restart both services:');
    console.log('      - Stop dev server (Ctrl+C)');
    console.log('      - npm run ngrok:stop');
    console.log('      - npm run dev');
    console.log('      - npm run ngrok:start');
  }
  
  console.log('\n3️⃣  Common Causes of ERR_NGROK_3004:');
  console.log('   • Dev server crashed or not fully started');
  console.log('   • Build errors preventing server from starting');
  console.log('   • Port 3000 blocked or in use by another process');
  console.log('   • Server returning malformed HTTP responses');
  console.log('   • Network/firewall blocking localhost connections');
  console.log('   • Server timeout or hanging requests');
  
  console.log('\n' + '='.repeat(60) + '\n');
})();





