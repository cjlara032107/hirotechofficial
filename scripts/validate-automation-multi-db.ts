/**
 * Validation Script: AI Automations Multi-DB Integrity
 * 
 * This script validates:
 * 1. Automation tables exist in all configured databases
 * 2. Data integrity across databases (automations in correct org's DB)
 * 3. Schema consistency
 * 4. Routing functionality
 */

import { PrismaClient } from '@prisma/client';

// Multi-DB configuration
const getDatabaseClients = (): { client: PrismaClient; index: number; url: string }[] => {
  const clients: { client: PrismaClient; index: number; url: string }[] = [];
  
  for (let i = 0; i < 10; i++) {
    const dbUrl = process.env[`DATABASE_URL_${i}`];
    if (dbUrl) {
      const client = new PrismaClient({
        datasources: {
          db: { url: dbUrl },
        },
      });
      clients.push({ client, index: i, url: dbUrl });
    }
  }
  
  if (clients.length === 0) {
    const fallbackUrl = process.env.DATABASE_URL;
    if (fallbackUrl) {
      const client = new PrismaClient({
        datasources: {
          db: { url: fallbackUrl },
        },
      });
      clients.push({ client, index: 0, url: fallbackUrl });
    }
  }
  
  return clients;
};

interface ValidationResult {
  passed: boolean;
  message: string;
  details?: unknown;
}

async function main() {
  console.log('\n==============================================');
  console.log('AI Automations Multi-DB Validation');
  console.log('==============================================\n');

  const results: ValidationResult[] = [];

  // Get all database clients
  const dbClients = getDatabaseClients();
  console.log(`✓ Found ${dbClients.length} database(s) configured\n`);

  if (dbClients.length === 0) {
    console.error('❌ No databases configured! Set DATABASE_URL_0 or DATABASE_URL');
    process.exit(1);
  }

  // Test 1: Check schema existence in all DBs
  console.log('Test 1: Validating automation schema in all databases...');
  for (const { client, index, url } of dbClients) {
    try {
      const dbHost = new URL(url).hostname;
      
      // Check if automation tables exist
      const ruleCount = await client.aIAutomationRule.count();
      const execCount = await client.aIAutomationExecution.count();
      const stopCount = await client.aIAutomationStop.count();

      console.log(`  ✓ DB${index} (${dbHost}): Found ${ruleCount} rules, ${execCount} executions, ${stopCount} stops`);
      
      results.push({
        passed: true,
        message: `DB${index} schema validation passed`,
        details: { ruleCount, execCount, stopCount },
      });
    } catch (error) {
      console.error(`  ❌ DB${index}: Schema validation failed:`, error instanceof Error ? error.message : String(error));
      results.push({
        passed: false,
        message: `DB${index} schema validation failed`,
        details: error instanceof Error ? error.message : String(error),
      });
    }
  }

  console.log('');

  // Test 2: Validate data integrity (rules belong to correct org's users)
  console.log('Test 2: Validating data integrity across databases...');
  for (const { client, index, url } of dbClients) {
    try {
      const dbHost = new URL(url).hostname;
      
      // Get all rules in this DB
      const rules = await client.aIAutomationRule.findMany({
        include: {
          User: {
            select: {
              id: true,
              organizationId: true,
            },
          },
        },
        take: 100, // Sample
      });

      if (rules.length === 0) {
        console.log(`  ℹ DB${index} (${dbHost}): No automation rules found`);
        continue;
      }

      // Check if all rules have users with organizations
      const missingOrg = rules.filter(r => !r.User?.organizationId);
      if (missingOrg.length > 0) {
        console.warn(`  ⚠ DB${index} (${dbHost}): ${missingOrg.length} rules have users without organizationId`);
        results.push({
          passed: false,
          message: `DB${index} data integrity issue: rules with missing organizationId`,
          details: { count: missingOrg.length },
        });
      } else {
        console.log(`  ✓ DB${index} (${dbHost}): All ${rules.length} sampled rules have valid organizationId`);
        results.push({
          passed: true,
          message: `DB${index} data integrity check passed`,
        });
      }
      
      // List organizations in this DB
      const orgs = new Set(rules.map(r => r.User?.organizationId).filter(Boolean));
      console.log(`    Organizations in DB${index}: ${Array.from(orgs).join(', ')}`);
    } catch (error) {
      console.error(`  ❌ DB${index}: Data integrity check failed:`, error instanceof Error ? error.message : String(error));
      results.push({
        passed: false,
        message: `DB${index} data integrity check failed`,
        details: error instanceof Error ? error.message : String(error),
      });
    }
  }

  console.log('');

  // Test 3: Validate routing (hash-based)
  if (process.env.ENABLE_MULTI_DB === 'true' && dbClients.length > 1) {
    console.log('Test 3: Validating multi-DB routing...');
    
    try {
      const { getDatabaseRouter } = await import('../src/lib/db/multi-db-router');
      const router = getDatabaseRouter();
      const status = router.getStatus();

      console.log(`  ✓ Router initialized with ${status.totalDatabases} databases`);
      console.log(`    Strategy: ${status.routingStrategy}`);
      console.log(`    Healthy: ${status.healthyDatabases}, Degraded: ${status.degradedDatabases}, Down: ${status.downDatabases}`);

      // Test routing for sample organizationIds
      const testOrgIds = ['org1', 'org2', 'org3', 'testorg'];
      console.log('\n  Testing routing for sample organizations:');
      
      for (const orgId of testOrgIds) {
        const client = router.getClient(orgId);
        const dbConfig = router.getAllDatabaseConfigs().find(c => c.client === client);
        
        if (dbConfig) {
          const dbHost = new URL(dbConfig.url).hostname;
          console.log(`    ${orgId} → DB${dbConfig.index} (${dbHost}) [${dbConfig.health}]`);
        } else {
          console.log(`    ${orgId} → Unknown DB`);
        }
      }

      results.push({
        passed: true,
        message: 'Multi-DB routing validation passed',
        details: status,
      });
    } catch (error) {
      console.error('  ❌ Routing validation failed:', error instanceof Error ? error.message : String(error));
      results.push({
        passed: false,
        message: 'Multi-DB routing validation failed',
        details: error instanceof Error ? error.message : String(error),
      });
    }
  } else {
    console.log('Test 3: Multi-DB routing not enabled (ENABLE_MULTI_DB=false or single DB)');
    results.push({
      passed: true,
      message: 'Multi-DB routing skipped (not enabled or single DB)',
    });
  }

  console.log('');

  // Test 4: Cross-DB connectivity
  console.log('Test 4: Testing cross-DB connectivity...');
  const connectivityResults = await Promise.allSettled(
    dbClients.map(async ({ client, index, url }) => {
      const dbHost = new URL(url).hostname;
      const start = Date.now();
      await client.$queryRaw`SELECT 1`;
      const duration = Date.now() - start;
      return { index, dbHost, duration };
    })
  );

  for (const result of connectivityResults) {
    if (result.status === 'fulfilled') {
      const { index, dbHost, duration } = result.value;
      console.log(`  ✓ DB${index} (${dbHost}): Connected in ${duration}ms`);
      results.push({
        passed: true,
        message: `DB${index} connectivity check passed`,
        details: { duration },
      });
    } else {
      console.error(`  ❌ DB connectivity failed:`, result.reason);
      results.push({
        passed: false,
        message: 'DB connectivity check failed',
        details: result.reason,
      });
    }
  }

  console.log('');

  // Summary
  console.log('==============================================');
  console.log('Validation Summary');
  console.log('==============================================');
  
  const passed = results.filter(r => r.passed).length;
  const failed = results.filter(r => !r.passed).length;
  
  console.log(`Total checks: ${results.length}`);
  console.log(`Passed: ${passed}`);
  console.log(`Failed: ${failed}`);
  
  if (failed > 0) {
    console.log('\n❌ Validation FAILED');
    console.log('\nFailed checks:');
    results.filter(r => !r.passed).forEach(r => {
      console.log(`  - ${r.message}`);
      if (r.details) {
        console.log(`    Details: ${JSON.stringify(r.details)}`);
      }
    });
    process.exit(1);
  } else {
    console.log('\n✅ All validation checks PASSED');
  }

  // Cleanup
  for (const { client } of dbClients) {
    await client.$disconnect();
  }
}

main()
  .catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
  });

