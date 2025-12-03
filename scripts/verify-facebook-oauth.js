#!/usr/bin/env node

/**
 * Verify Facebook OAuth Configuration
 * Tests the actual endpoints to see what's happening
 */

const http = require('http');
require('dotenv').config({ path: '.env.local' });

const appUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';
const ngrokUrl = 'https://unglamourous-unaccustomedly-audra.ngrok-free.dev';

console.log('\n' + '='.repeat(60));
console.log('🔍 FACEBOOK OAUTH VERIFICATION');
console.log('='.repeat(60));

// Test 1: Check if ngrok URL matches
console.log('\n1️⃣  Checking ngrok URL...');
http.get('http://localhost:4040/api/tunnels', (res) => {
  let data = '';
  res.on('data', (chunk) => { data += chunk; });
  res.on('end', () => {
    try {
      const tunnels = JSON.parse(data);
      const currentNgrokUrl = tunnels.tunnels?.find(t => t.proto === 'https')?.public_url;
      if (currentNgrokUrl) {
        console.log(`   Current ngrok URL: ${currentNgrokUrl}`);
        console.log(`   Expected URL: ${ngrokUrl}`);
        if (currentNgrokUrl !== ngrokUrl) {
          console.log('   ⚠️  WARNING: Ngrok URL has changed!');
          console.log(`   Run: npm run ngrok:update-env`);
        } else {
          console.log('   ✅ Ngrok URL matches');
        }
      }
    } catch (e) {
      console.log('   ⚠️  Could not check ngrok status');
    }
    
    // Test 2: Check environment variables
    console.log('\n2️⃣  Checking environment variables...');
    console.log(`   NEXT_PUBLIC_APP_URL: ${process.env.NEXT_PUBLIC_APP_URL || '❌ NOT SET'}`);
    console.log(`   FACEBOOK_APP_ID: ${process.env.FACEBOOK_APP_ID ? '✅ Set' : '❌ NOT SET'}`);
    console.log(`   FACEBOOK_APP_SECRET: ${process.env.FACEBOOK_APP_SECRET ? '✅ Set' : '❌ NOT SET'}`);
    
    // Test 3: Expected OAuth URLs
    console.log('\n3️⃣  Expected OAuth Callback URLs:');
    const callbackUrl = `${process.env.NEXT_PUBLIC_APP_URL}/api/facebook/callback`;
    const callbackPopupUrl = `${process.env.NEXT_PUBLIC_APP_URL}/api/facebook/callback-popup`;
    console.log(`   Regular: ${callbackUrl}`);
    console.log(`   Popup: ${callbackPopupUrl}`);
    
    console.log('\n4️⃣  Facebook App Settings Checklist:');
    console.log('   Go to: https://developers.facebook.com/apps/');
    console.log('   → Select your app');
    console.log('   → Facebook Login → Settings');
    console.log('   → Valid OAuth Redirect URIs should include:');
    console.log(`      • ${callbackUrl}`);
    console.log(`      • ${callbackPopupUrl}`);
    console.log('\n   ⚠️  Make sure:');
    console.log('      - URLs match EXACTLY (copy-paste, no typos)');
    console.log('      - No trailing slashes');
    console.log('      - Both URLs are added');
    console.log('      - Clicked "Save Changes"');
    console.log('      - Waited 10-30 seconds after saving');
    
    console.log('\n5️⃣  Common Issues:');
    console.log('   ❌ Redirect URI mismatch - URLs must be EXACTLY the same');
    console.log('   ❌ Dev server not restarted - env vars not loaded');
    console.log('   ❌ Facebook settings not saved or not propagated');
    console.log('   ❌ Using wrong callback URL (regular vs popup)');
    console.log('   ❌ Ngrok URL changed but .env.local not updated');
    
    console.log('\n6️⃣  Next Steps:');
    console.log('   1. Verify Facebook app settings match URLs above');
    console.log('   2. Restart dev server: npm run dev');
    console.log('   3. Clear browser cookies/cache');
    console.log('   4. Try OAuth flow again');
    console.log('   5. Check browser console for errors');
    console.log('   6. Check server logs for detailed error messages');
    
    console.log('\n' + '='.repeat(60) + '\n');
  });
}).on('error', () => {
  console.log('   ⚠️  Ngrok API not accessible');
});





