#!/usr/bin/env node

/**
 * Test OAuth Configuration
 * Checks if the OAuth URLs match what's configured
 */

require('dotenv').config({ path: '.env.local' });

const appUrl = process.env.NEXT_PUBLIC_APP_URL;
const appId = process.env.FACEBOOK_APP_ID;
const appSecret = process.env.FACEBOOK_APP_SECRET;

console.log('\n' + '='.repeat(60));
console.log('🔍 OAUTH CONFIGURATION CHECK');
console.log('='.repeat(60));

console.log('\n📋 Environment Variables:');
console.log(`   NEXT_PUBLIC_APP_URL: ${appUrl || '❌ NOT SET'}`);
console.log(`   FACEBOOK_APP_ID: ${appId ? '✅ Set' : '❌ NOT SET'}`);
console.log(`   FACEBOOK_APP_SECRET: ${appSecret ? '✅ Set' : '❌ NOT SET'}`);

if (!appUrl) {
  console.log('\n❌ ERROR: NEXT_PUBLIC_APP_URL is not set!');
  console.log('   Run: npm run ngrok:update-env');
  process.exit(1);
}

console.log('\n🔗 OAuth URLs:');
const callbackUrl = `${appUrl}/api/facebook/callback`;
const callbackPopupUrl = `${appUrl}/api/facebook/callback-popup`;
console.log(`   Regular Callback: ${callbackUrl}`);
console.log(`   Popup Callback: ${callbackPopupUrl}`);

console.log('\n📋 Facebook App Settings Required:');
console.log('   Add these to Facebook App → Facebook Login → Settings:');
console.log(`   1. ${callbackUrl}`);
console.log(`   2. ${callbackPopupUrl}`);

console.log('\n⚠️  Common Issues:');
console.log('   1. URLs must match EXACTLY (case-sensitive, no trailing slashes)');
console.log('   2. Must use https:// (not http://)');
console.log('   3. Dev server must be restarted after changing .env.local');
console.log('   4. Wait 10-30 seconds after updating Facebook settings');

console.log('\n🧪 Test Commands:');
console.log(`   curl ${appUrl}/api/debug/oauth-urls`);
console.log(`   curl ${appUrl}/api/debug/facebook-config`);

console.log('\n' + '='.repeat(60) + '\n');





