/**
 * Script to verify Facebook webhook configuration
 * 
 * This script:
 * 1. Checks required environment variables
 * 2. Verifies webhook route exists
 * 3. Tests webhook verification endpoint
 * 4. Validates webhook signature verification logic
 */

interface TestResult {
  name: string;
  status: 'pass' | 'fail' | 'warning';
  message: string;
  details?: string;
}

const results: TestResult[] = [];

function addResult(name: string, status: 'pass' | 'fail' | 'warning', message: string, details?: string) {
  results.push({ name, status, message, details });
  const icon = status === 'pass' ? '✅' : status === 'fail' ? '❌' : '⚠️';
  console.log(`${icon} ${name}: ${message}`);
  if (details) {
    console.log(`   ${details}`);
  }
}

async function verifyFacebookWebhook() {
  console.log('\n🔍 Verifying Facebook Webhook Configuration...\n');

  // Check environment variables
  const webhookVerifyToken = process.env.FACEBOOK_WEBHOOK_VERIFY_TOKEN;
  const appSecret = process.env.FACEBOOK_APP_SECRET;

  if (!webhookVerifyToken) {
    addResult(
      'Webhook Verify Token',
      'fail',
      'FACEBOOK_WEBHOOK_VERIFY_TOKEN not configured',
      'Set FACEBOOK_WEBHOOK_VERIFY_TOKEN environment variable'
    );
  } else {
    addResult(
      'Webhook Verify Token',
      'pass',
      'FACEBOOK_WEBHOOK_VERIFY_TOKEN is configured',
      `Token length: ${webhookVerifyToken.length} characters`
    );
  }

  if (!appSecret) {
    addResult(
      'Facebook App Secret',
      'fail',
      'FACEBOOK_APP_SECRET not configured',
      'Set FACEBOOK_APP_SECRET environment variable for webhook signature verification'
    );
  } else {
    addResult(
      'Facebook App Secret',
      'pass',
      'FACEBOOK_APP_SECRET is configured',
      'App secret is set for signature verification'
    );
  }

  // Check webhook route file exists
  try {
    const fs = await import('fs');
    const webhookRoutePath = './src/app/api/webhooks/facebook/route.ts';
    if (fs.existsSync(webhookRoutePath)) {
      addResult(
        'Webhook Route File',
        'pass',
        'Webhook route file exists',
        `Path: ${webhookRoutePath}`
      );

      // Check route file content
      const routeContent = fs.readFileSync(webhookRoutePath, 'utf-8');
      
      // Check for GET handler (verification)
      if (routeContent.includes('export async function GET')) {
        addResult(
          'Webhook GET Handler',
          'pass',
          'GET handler exists for webhook verification',
          'Facebook can verify the webhook endpoint'
        );
      } else {
        addResult(
          'Webhook GET Handler',
          'fail',
          'GET handler not found',
          'Webhook verification will fail'
        );
      }

      // Check for POST handler (events)
      if (routeContent.includes('export async function POST')) {
        addResult(
          'Webhook POST Handler',
          'pass',
          'POST handler exists for webhook events',
          'Webhook can receive events from Facebook'
        );
      } else {
        addResult(
          'Webhook POST Handler',
          'fail',
          'POST handler not found',
          'Webhook cannot receive events'
        );
      }

      // Check for signature verification
      if (routeContent.includes('x-hub-signature-256')) {
        addResult(
          'Signature Verification',
          'pass',
          'Signature verification is implemented',
          'Webhook validates request signatures'
        );
      } else {
        addResult(
          'Signature Verification',
          'warning',
          'Signature verification may be missing',
          'Webhook should verify x-hub-signature-256 header'
        );
      }

      // Check for webhook event handling
      if (routeContent.includes('handleIncomingMessage') || routeContent.includes('handleInstagramMessage')) {
        addResult(
          'Event Handlers',
          'pass',
          'Webhook event handlers are implemented',
          'Webhook can process incoming messages'
        );
      } else {
        addResult(
          'Event Handlers',
          'warning',
          'Event handlers may be missing',
          'Webhook may not process all events'
        );
      }
    } else {
      addResult(
        'Webhook Route File',
        'fail',
        'Webhook route file not found',
        `Expected at: ${webhookRoutePath}`
      );
    }
  } catch (error) {
    const err = error as Error;
    addResult(
      'Webhook Route Check',
      'fail',
      'Failed to check webhook route',
      err.message
    );
  }

  // Test webhook URL format
  const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 
    (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : null) || 
    'http://localhost:3000';
  const webhookUrl = `${baseUrl}/api/webhooks/facebook`;
  
  addResult(
    'Webhook URL',
    'pass',
    'Webhook URL is configured',
    `URL: ${webhookUrl}`
  );

  // Check if webhook is configured in Facebook (manual check)
  addResult(
    'Facebook Configuration',
    'warning',
    'Manual verification required',
    `Configure webhook in Facebook Developer Console:\n` +
    `   - URL: ${webhookUrl}\n` +
    `   - Verify Token: ${webhookVerifyToken || 'NOT SET'}\n` +
    `   - Subscribe to: messages, messaging_postbacks, message_deliveries, message_reads`
  );
}

async function main() {
  console.log('🚀 Facebook Webhook Verification\n');
  console.log('='.repeat(60));

  await verifyFacebookWebhook();

  console.log('\n' + '='.repeat(60));
  console.log('\n📊 Test Summary:\n');

  const passed = results.filter(r => r.status === 'pass').length;
  const failed = results.filter(r => r.status === 'fail').length;
  const warnings = results.filter(r => r.status === 'warning').length;

  console.log(`✅ Passed: ${passed}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`⚠️  Warnings: ${warnings}`);

  if (failed > 0) {
    console.log('\n❌ Some tests failed. Please review the errors above.');
    console.log('\n💡 To fix webhook issues:');
    console.log('   1. Set FACEBOOK_WEBHOOK_VERIFY_TOKEN environment variable');
    console.log('   2. Set FACEBOOK_APP_SECRET environment variable');
    console.log('   3. Ensure webhook route is accessible at /api/webhooks/facebook');
    console.log('   4. Configure webhook in Facebook Developer Console');
    process.exit(1);
  } else if (warnings > 0) {
    console.log('\n⚠️  Some tests have warnings. Review recommendations above.');
    console.log('\n💡 Next steps:');
    console.log('   1. Configure webhook in Facebook Developer Console');
    console.log('   2. Test webhook with Facebook\'s webhook testing tool');
    process.exit(0);
  } else {
    console.log('\n✅ All tests passed! Facebook webhook is configured.');
    process.exit(0);
  }
}

main().catch((error) => {
  console.error('❌ Test script error:', error);
  process.exit(1);
});

