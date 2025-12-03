#!/usr/bin/env node

/**
 * Check Ngrok URL Script
 * Retrieves and displays the current ngrok public URL
 */

const http = require('http');

function getNgrokUrl() {
  return new Promise((resolve, reject) => {
    const req = http.get('http://localhost:4040/api/tunnels', (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          const tunnel = json.tunnels?.find(t => t.proto === 'https');
          if (tunnel) {
            resolve(tunnel.public_url);
          } else {
            resolve(null);
          }
        } catch (e) {
          reject(new Error('Failed to parse ngrok response'));
        }
      });
    });
    
    req.on('error', () => {
      reject(new Error('Ngrok API not accessible. Is ngrok running?'));
    });
    
    req.setTimeout(5000, () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
  });
}

(async () => {
  try {
    const url = await getNgrokUrl();
    if (url) {
      console.log('\n' + '='.repeat(60));
      console.log('✅ NGROK TUNNEL IS ACTIVE');
      console.log('='.repeat(60));
      console.log(`\n🌐 Public URL: ${url}`);
      console.log(`\n📋 Update your .env.local with:`);
      console.log(`   NEXT_PUBLIC_APP_URL=${url}`);
      console.log(`   NEXTAUTH_URL=${url}`);
      console.log(`\n📊 Ngrok Dashboard: http://localhost:4040`);
      console.log('='.repeat(60) + '\n');
    } else {
      console.log('⚠️  Ngrok is running but no HTTPS tunnel found');
    }
  } catch (error) {
    console.log(`\n❌ ${error.message}`);
    console.log('\n💡 Make sure ngrok is running: npm run ngrok:start\n');
    process.exit(1);
  }
})();

