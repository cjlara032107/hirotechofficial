#!/usr/bin/env node

/**
 * Update .env.local with the current ngrok URL
 */

const fs = require('fs');
const http = require('http');
const path = require('path');

function getNgrokUrl() {
  return new Promise((resolve, reject) => {
    const req = http.get('http://localhost:4040/api/tunnels', (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const tunnels = JSON.parse(data);
          const httpsUrl = tunnels.tunnels?.find(t => t.proto === 'https')?.public_url;
          if (httpsUrl) {
            resolve(httpsUrl);
          } else {
            reject(new Error('No HTTPS tunnel found'));
          }
        } catch (e) {
          reject(e);
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

async function updateEnvFile() {
  try {
    const ngrokUrl = await getNgrokUrl();
    const envPath = path.join(process.cwd(), '.env.local');
    
    let envContent = '';
    if (fs.existsSync(envPath)) {
      envContent = fs.readFileSync(envPath, 'utf8');
    }
    
    // Remove existing NEXT_PUBLIC_APP_URL and NEXTAUTH_URL
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
    
    console.log('\n' + '='.repeat(60));
    console.log('✅ UPDATED .env.local WITH NGROK URL');
    console.log('='.repeat(60));
    console.log(`\n🌐 Public URL: ${ngrokUrl}`);
    console.log(`\n📋 Updated variables:`);
    console.log(`   NEXT_PUBLIC_APP_URL=${ngrokUrl}`);
    console.log(`   NEXTAUTH_URL=${ngrokUrl}`);
    console.log('\n💡 Restart your dev server to apply changes');
    console.log('='.repeat(60) + '\n');
    
  } catch (error) {
    console.error('\n❌ Error:', error.message);
    console.error('\n💡 Make sure ngrok is running: npm run ngrok:start\n');
    process.exit(1);
  }
}

updateEnvFile();





