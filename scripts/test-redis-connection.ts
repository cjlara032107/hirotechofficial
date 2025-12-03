/**
 * Test Redis Connection for Concurrency Limits
 * 
 * This script tests:
 * 1. Redis connection availability
 * 2. Redis concurrency handling
 * 3. BullMQ queue creation (if BullMQ is used)
 * 4. Connection pool limits
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

async function testRedisConnection() {
  console.log('\n🔍 Testing Redis Connection...\n');

  // Check if REDIS_URL is configured
  const redisUrl = process.env.REDIS_URL;
  if (!redisUrl) {
    addResult(
      'Redis Configuration',
      'warning',
      'REDIS_URL not configured',
      'Redis is optional for campaigns. Set REDIS_URL if using BullMQ queues.'
    );
    return;
  }

  addResult(
    'Redis Configuration',
    'pass',
    'REDIS_URL is configured',
    `URL: ${redisUrl.replace(/:[^:@]+@/, ':****@')}` // Hide password
  );

  // Test basic connection
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const Redis = require('ioredis');
    const redis = new Redis(redisUrl);

    // Test ping
    const pingResult = await redis.ping();
    if (pingResult === 'PONG') {
      addResult(
        'Redis Connection',
        'pass',
        'Successfully connected to Redis',
        'PING/PONG test passed'
      );
    } else {
      addResult(
        'Redis Connection',
        'fail',
        'Redis did not respond with PONG',
        `Received: ${pingResult}`
      );
      await redis.disconnect();
      return;
    }

    // Test concurrency with multiple commands
    console.log('\n📊 Testing Redis Concurrency...\n');
    const concurrencyTests = [1, 5, 10, 20, 50];
    let maxConcurrency = 0;

    for (const concurrency of concurrencyTests) {
      try {
        const startTime = Date.now();
        const promises = Array.from({ length: concurrency }, (_, i) =>
          redis.set(`test:concurrency:${i}`, `value-${i}`, 'EX', 10)
        );
        await Promise.all(promises);
        const duration = Date.now() - startTime;

        // Clean up
        await Promise.all(
          Array.from({ length: concurrency }, (_, i) =>
            redis.del(`test:concurrency:${i}`)
          )
        );

        if (duration < 5000) {
          // If it completes in under 5 seconds, consider it successful
          maxConcurrency = concurrency;
          addResult(
            `Concurrency Test (${concurrency} commands)`,
            'pass',
            `Completed in ${duration}ms`,
            `All ${concurrency} commands executed successfully`
          );
        } else {
          addResult(
            `Concurrency Test (${concurrency} commands)`,
            'warning',
            `Took ${duration}ms (may be slow)`,
            'Consider checking Redis server performance'
          );
          break;
        }
      } catch (error) {
        const err = error as Error;
        addResult(
          `Concurrency Test (${concurrency} commands)`,
          'fail',
          'Failed to execute concurrent commands',
          err.message
        );
        break;
      }
    }

    addResult(
      'Redis Concurrency Limit',
      maxConcurrency >= 20 ? 'pass' : 'warning',
      `Successfully handled ${maxConcurrency} concurrent commands`,
      maxConcurrency >= 20
        ? 'Redis can handle high concurrency'
        : 'Consider optimizing Redis configuration for higher concurrency'
    );

    // Test BullMQ if available
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { Queue } = require('bullmq');
      const testQueue = new Queue('test-queue', {
        connection: redisUrl as any,
      });

      // Test queue creation
      await testQueue.add('test-job', { test: true });
      addResult(
        'BullMQ Queue Creation',
        'pass',
        'Successfully created BullMQ queue',
        'Queue can be used for campaign message processing'
      );

      // Clean up
      await testQueue.close();
    } catch (error) {
      const err = error as Error;
      if (err.message.includes('bullmq')) {
        addResult(
          'BullMQ Queue Creation',
          'warning',
          'BullMQ not installed or not used',
          'BullMQ is optional. Install with: npm install bullmq'
        );
      } else {
        addResult(
          'BullMQ Queue Creation',
          'fail',
          'Failed to create BullMQ queue',
          err.message
        );
      }
    }

    // Test connection pool limits
    console.log('\n📊 Testing Connection Pool Limits...\n');
    const poolTests = [1, 5, 10];
    let maxPoolSize = 0;

    for (const poolSize of poolTests) {
      try {
        const connections = Array.from({ length: poolSize }, () => new Redis(redisUrl));
        const startTime = Date.now();
        await Promise.all(connections.map(conn => conn.ping()));
        const duration = Date.now() - startTime;

        await Promise.all(connections.map(conn => conn.disconnect()));

        if (duration < 2000) {
          maxPoolSize = poolSize;
          addResult(
            `Connection Pool Test (${poolSize} connections)`,
            'pass',
            `All ${poolSize} connections established in ${duration}ms`,
            'Connection pool working correctly'
          );
        } else {
          addResult(
            `Connection Pool Test (${poolSize} connections)`,
            'warning',
            `Took ${duration}ms to establish connections`,
            'Consider connection pool limits'
          );
          break;
        }
      } catch (error) {
        const err = error as Error;
        addResult(
          `Connection Pool Test (${poolSize} connections)`,
          'fail',
          'Failed to establish connection pool',
          err.message
        );
        break;
      }
    }

    addResult(
      'Redis Connection Pool',
      maxPoolSize >= 5 ? 'pass' : 'warning',
      `Successfully tested ${maxPoolSize} concurrent connections`,
      maxPoolSize >= 5
        ? 'Connection pool can handle multiple concurrent connections'
        : 'Consider checking Redis maxclients setting'
    );

    await redis.disconnect();
  } catch (error) {
    const err = error as Error;
    addResult(
      'Redis Connection',
      'fail',
      'Failed to connect to Redis',
      err.message
    );
  }
}

async function main() {
  console.log('🚀 Redis Connection & Concurrency Test\n');
  console.log('=' .repeat(60));

  await testRedisConnection();

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
    process.exit(1);
  } else if (warnings > 0) {
    console.log('\n⚠️  Some tests have warnings. Review recommendations above.');
    process.exit(0);
  } else {
    console.log('\n✅ All tests passed!');
    process.exit(0);
  }
}

main().catch((error) => {
  console.error('❌ Test script error:', error);
  process.exit(1);
});

