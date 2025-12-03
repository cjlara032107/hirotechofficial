/**
 * Script to verify error monitoring setup
 * 
 * This script:
 * 1. Checks error monitoring modules exist
 * 2. Verifies error tracking is initialized
 * 3. Tests error logging functionality
 * 4. Validates monitoring endpoints
 */

// System monitor will be imported dynamically
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let systemMonitor: any;

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

async function verifyErrorMonitoring() {
  console.log('\n🔍 Verifying Error Monitoring Setup...\n');

  // Import system monitor dynamically
  try {
    const monitorModule = await import('../src/lib/monitoring/system-monitor');
    systemMonitor = monitorModule.systemMonitor;
  } catch (error) {
    const err = error as Error;
    addResult(
      'System Monitor Import',
      'fail',
      'Failed to import system monitor',
      err.message
    );
    return;
  }

  // Check system monitor exists
  try {
    if (systemMonitor) {
      addResult(
        'System Monitor',
        'pass',
        'System monitor is initialized',
        'Error monitoring system is available'
      );
    } else {
      addResult(
        'System Monitor',
        'fail',
        'System monitor not initialized',
        'Error monitoring is not available'
      );
      return;
    }
  } catch (error) {
    const err = error as Error;
    addResult(
      'System Monitor',
      'fail',
      'Failed to initialize system monitor',
      err.message
    );
    return;
  }

  // Test error tracking
  try {
    const testError = new Error('Test error for monitoring verification');
    systemMonitor.recordError({
      errorType: 'TestError',
      errorCode: 'TEST_001',
      errorMessage: testError.message,
      stack: testError.stack,
      timestamp: Date.now(),
    });

    const errorStats = systemMonitor.getErrorStats();
    if (errorStats.totalErrors > 0) {
      addResult(
        'Error Tracking',
        'pass',
        'Error tracking is working',
        `Recorded ${errorStats.totalErrors} error(s)`
      );
    } else {
      addResult(
        'Error Tracking',
        'warning',
        'Error tracking may not be working',
        'No errors recorded in system monitor'
      );
    }
  } catch (error) {
    const err = error as Error;
    addResult(
      'Error Tracking',
      'fail',
      'Failed to track error',
      err.message
    );
  }

  // Check error tracking module
  try {
    const fs = await import('fs');
    const trackErrorPath = './src/lib/monitoring/track-error.ts';
    if (fs.existsSync(trackErrorPath)) {
      addResult(
        'Error Tracking Module',
        'pass',
        'Error tracking module exists',
        `Path: ${trackErrorPath}`
      );

      const moduleContent = fs.readFileSync(trackErrorPath, 'utf-8');
      
      if (moduleContent.includes('trackError')) {
        addResult(
          'trackError Function',
          'pass',
          'trackError function is exported',
          'Can be used to track errors in API routes'
        );
      }

      if (moduleContent.includes('trackDatabaseError')) {
        addResult(
          'trackDatabaseError Function',
          'pass',
          'trackDatabaseError function is exported',
          'Can be used to track database errors'
        );
      }
    } else {
      addResult(
        'Error Tracking Module',
        'fail',
        'Error tracking module not found',
        `Expected at: ${trackErrorPath}`
      );
    }
  } catch (error) {
    const err = error as Error;
    addResult(
      'Error Tracking Module Check',
      'fail',
      'Failed to check error tracking module',
      err.message
    );
  }

  // Check alert monitor
  try {
    const fs = await import('fs');
    const alertMonitorPath = './src/lib/monitoring/alert-monitor.ts';
    if (fs.existsSync(alertMonitorPath)) {
      addResult(
        'Alert Monitor Module',
        'pass',
        'Alert monitor module exists',
        `Path: ${alertMonitorPath}`
      );

      const moduleContent = fs.readFileSync(alertMonitorPath, 'utf-8');
      
      if (moduleContent.includes('checkJobFailures')) {
        addResult(
          'Job Failure Monitoring',
          'pass',
          'Job failure monitoring is implemented',
          'Can detect and alert on job failures'
        );
      }

      if (moduleContent.includes('checkErrorRates')) {
        addResult(
          'Error Rate Monitoring',
          'pass',
          'Error rate monitoring is implemented',
          'Can detect high error rates'
        );
      }

      if (moduleContent.includes('checkPerformanceDegradation')) {
        addResult(
          'Performance Monitoring',
          'pass',
          'Performance monitoring is implemented',
          'Can detect performance degradation'
        );
      }
    } else {
      addResult(
        'Alert Monitor Module',
        'warning',
        'Alert monitor module not found',
        'Alert monitoring may not be available'
      );
    }
  } catch (error) {
    const err = error as Error;
    addResult(
      'Alert Monitor Check',
      'warning',
      'Failed to check alert monitor',
      err.message
    );
  }

  // Check monitoring API endpoint
  try {
    const fs = await import('fs');
    const monitoringRoutePath = './src/app/api/monitoring/metrics/route.ts';
    if (fs.existsSync(monitoringRoutePath)) {
      addResult(
        'Monitoring API Endpoint',
        'pass',
        'Monitoring API endpoint exists',
        'Can query monitoring metrics via API'
      );
    } else {
      addResult(
        'Monitoring API Endpoint',
        'warning',
        'Monitoring API endpoint not found',
        'Metrics may not be accessible via API'
      );
    }
  } catch (error) {
    const err = error as Error;
    addResult(
      'Monitoring API Check',
      'warning',
      'Failed to check monitoring API',
      err.message
    );
  }

  // Check database error logging
  try {
    const { PrismaClient } = await import('@prisma/client');
    const prisma = new PrismaClient();
    
    // Check if ErrorLog table exists
    try {
      await prisma.$queryRaw`SELECT 1 FROM "ErrorLog" LIMIT 1`;
      addResult(
        'Error Log Table',
        'pass',
        'ErrorLog table exists in database',
        'Errors can be persisted to database'
      );
      await prisma.$disconnect();
    } catch (error) {
      addResult(
        'Error Log Table',
        'warning',
        'ErrorLog table may not exist',
        'Run migrations to create error logging tables'
      );
      await prisma.$disconnect();
    }
  } catch (error) {
    const err = error as Error;
    addResult(
      'Database Error Log Check',
      'warning',
      'Could not verify database error logging',
      err.message
    );
  }

  // Test system metrics
  try {
    const metrics = systemMonitor.getSystemMetrics();
    if (metrics) {
      addResult(
        'System Metrics',
        'pass',
        'System metrics are available',
        `Database queries: ${metrics.database.totalQueries}, Errors: ${metrics.errors.totalErrors}`
      );
    } else {
      addResult(
        'System Metrics',
        'warning',
        'System metrics may not be available',
        'Check system monitor initialization'
      );
    }
  } catch (error) {
    const err = error as Error;
    addResult(
      'System Metrics',
      'fail',
      'Failed to get system metrics',
      err.message
    );
  }
}

async function main() {
  console.log('🚀 Error Monitoring Verification\n');
  console.log('='.repeat(60));

  await verifyErrorMonitoring();

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
    console.log('\n💡 To fix error monitoring issues:');
    console.log('   1. Ensure error monitoring modules are imported');
    console.log('   2. Check that system monitor is initialized');
    console.log('   3. Run database migrations to create error logging tables');
    process.exit(1);
  } else if (warnings > 0) {
    console.log('\n⚠️  Some tests have warnings. Review recommendations above.');
    console.log('\n💡 Next steps:');
    console.log('   1. Ensure all monitoring modules are properly imported');
    console.log('   2. Test error tracking in a real API route');
    console.log('   3. Verify monitoring endpoints are accessible');
    process.exit(0);
  } else {
    console.log('\n✅ All tests passed! Error monitoring is properly set up.');
    process.exit(0);
  }
}

main().catch((error) => {
  console.error('❌ Test script error:', error);
  process.exit(1);
});

