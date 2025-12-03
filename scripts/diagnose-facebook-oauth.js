#!/usr/bin/env node

/**
 * Diagnose Facebook OAuth Issues
 * Checks all common problems with Facebook OAuth setup
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const NGROK_URL = 'https://unglamourous-unaccustomedly-audra.ngrok-free.dev';

console.log('\n' + '='.repeat(60));
console.log('🔍 FACEBOOK OAUTH DIAGNOSTIC TOOL');
console.log('='.repeat(60) + '\n');

// 1. Check environment variables
console.log('1️⃣  Checking Environment Variables...');
const envPath = path.join(process.cwd(), '.env.local');
let envContent = '';
if (fs.existsSync(envPath)) {
  envContent = fs.readFileSync(envPath, 'utf8');
}

const envVars = {
  NEXT_PUBLIC_APP_URL: envContent.match(/NEXT_PUBLIC_APP_URL=(.+)/)?.[1]?.trim(),
  NEXTAUTH_URL: envContent.match(/NEXTAUTH_URL=(.+)/)?.[1]?.trim(),
  FACEBOOK_APP_ID: envContent.match(/FACEBOOK_APP_ID=(.+)/)?.[1]?.trim(),
  FACEBOOK_APP_SECRET: envContent.match(/FACEBOOK_APP_SECRET=(.+)/)?.[1]?.trim(),
};

console.log('   NEXT_PUBLIC_APP_URL:', envVars.NEXT_PUBLIC_APP_URL || '❌ NOT SET');
console.log('   NEXTAUTH_URL:', envVars.NEXTAUTH_URL || '❌ NOT SET');
console.log('   FACEBOOK_APP_ID:', envVars.FACEBOOK_APP_ID || '❌ NOT SET');
console.log('   FACEBOOK_APP_SECRET:', envVars.FACEBOOK_APP_SECRET ? '✅ Set' : '❌ NOT SET');

// 2. Check if URLs match
console.log('\n2️⃣  Checking URL Consistency...');
if (envVars.NEXT_PUBLIC_APP_URL && envVars.NEXT_PUBLIC_APP_URL !== NGROK_URL) {
  console.log('   ⚠️  WARNING: NEXT_PUBLIC_APP_URL does not match current ngrok URL!');
  console.log('      Current ngrok URL:', NGROK_URL);
  console.log('      .env.local URL:', envVars.NEXT_PUBLIC_APP_URL);
  console.log('   💡 Run: npm run ngrok:update-env');
} else {
  console.log('   ✅ URLs match');
}

// 3. Check OAuth callback URLs
console.log('\n3️⃣  OAuth Callback URLs (must be added to Facebook):');
const callbackUrls = [
  `${NGROK_URL}/api/facebook/callback`,
  `${NGROK_URL}/api/facebook/callback-popup`,
];
callbackUrls.forEach(url => {
  console.log('   -', url);
});

// 4. Test if endpoints are accessible
console.log('\n4️⃣  Testing Endpoint Accessibility...');

function testEndpoint(url, name) {
  return new Promise((resolve) => {
    const client = url.startsWith('https') ? https : http;
    const req = client.get(url, { timeout: 5000 }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          accessible: res.statusCode < 500,
        });
      });
    });
    
    req.on('error', () => {
      resolve({ status: 'ERROR', accessible: false });
    });
    
    req.on('timeout', () => {
      req.destroy();
      resolve({ status: 'TIMEOUT', accessible: false });
    });
  });
}

(async () => {
  const endpoints = [
    { url: `${NGROK_URL}`, name: 'Homepage' },
    { url: `${NGROK_URL}/api/debug/oauth-urls`, name: 'OAuth Debug Endpoint' },
    { url: `${NGROK_URL}/api/facebook/callback`, name: 'OAuth Callback' },
    { url: `${NGROK_URL}/api/facebook/callback-popup`, name: 'OAuth Callback (Popup)' },
  ];

  for (const endpoint of endpoints) {
    const result = await testEndpoint(endpoint.url, endpoint.name);
    if (result.accessible) {
      console.log(`   ✅ ${endpoint.name}: Accessible (${result.status})`);
    } else {
      console.log(`   ❌ ${endpoint.name}: Not accessible (${result.status})`);
    }
  }

  // 5. Check ngrok status
  console.log('\n5️⃣  Checking Ngrok Status...');
  const ngrokStatus = await new Promise((resolve) => {
    http.get('http://localhost:4040/api/tunnels', (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const tunnels = JSON.parse(data);
          const httpsUrl = tunnels.tunnels?.find(t => t.proto === 'https')?.public_url;
          resolve(httpsUrl || null);
        } catch {
          resolve(null);
        }
      });
    }).on('error', () => resolve(null));
  });

  if (ngrokStatus) {
    console.log('   ✅ Ngrok is running');
    console.log('   URL:', ngrokStatus);
    if (ngrokStatus !== NGROK_URL) {
      console.log('   ⚠️  URL has changed! Update .env.local');
    }
  } else {
    console.log('   ❌ Ngrok API not accessible');
  }

  // 6. Common issues checklist
  console.log('\n6️⃣  Common Issues Checklist:');
  console.log('   □ Facebook App Settings → Facebook Login → Settings');
  console.log('      - "Client OAuth Login" is ON');
  console.log('      - "Web OAuth Login" is ON');
  console.log('      - Both callback URLs are added (see above)');
  console.log('   □ Dev server restarted after .env.local changes');
  console.log('   □ No trailing slashes in Facebook redirect URIs');
  console.log('   □ URLs use https:// (not http://)');
  console.log('   □ Ngrok free tier warning page clicked through');

  console.log('\n' + '='.repeat(60));
  console.log('📋 NEXT STEPS:');
  console.log('='.repeat(60));
  console.log('\n1. Verify Facebook App Settings match the URLs above');
  console.log('2. Make sure dev server was restarted after env changes');
  console.log('3. Try accessing:', NGROK_URL);
  console.log('4. Check browser console for errors');
  console.log('5. Check server logs for OAuth errors');
  console.log('\n' + '='.repeat(60) + '\n');
})();

