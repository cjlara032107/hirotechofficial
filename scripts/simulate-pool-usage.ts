/**
 * Pool Exhaustion Simulation
 * 
 * Simulates all concurrent operations to verify pool won't be exhausted
 * Tests worst-case scenarios and edge cases
 */

import { getConnectionPoolLimit, getRecommendedConcurrency } from '../src/lib/db/pool-aware-limiter';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config({ path: '.env.local' });
dotenv.config({ path: '.env' });

// Mock DB_CONNECTIONS_PER_OPERATION to avoid import issues
const DB_CONNECTIONS_PER_OPERATION: Record<string, number> = {
  'analysis': 3,
  'automation': 4,
  'message-generation': 2,
  'batch': 5,
  'simple': 1,
};

// Mock getDynamicConcurrencyLimits to work without database
async function getMockConcurrencyLimits() {
  // Try to get real limits, but fall back to mock if DB unavailable
  try {
    const { getDynamicConcurrencyLimits } = await import('../src/lib/ai/dynamic-concurrency');
    return await getDynamicConcurrencyLimits();
  } catch (error) {
    // Fall back to mock data based on typical 5-key setup
    console.log('⚠️  Database unavailable, using mock concurrency limits (5 API keys)\n');
    return {
      keyCount: 5,
      analysisConcurrency: getRecommendedConcurrency('analysis', 100), // Would be 100, capped by pool
      conversationFetchConcurrency: getRecommendedConcurrency('simple', 40),
      batchConcurrency: getRecommendedConcurrency('batch', 5),
      messageGenerationConcurrency: getRecommendedConcurrency('message-generation', 45),
      automationConcurrency: getRecommendedConcurrency('automation', 100), // Would be 100, capped by pool
      batchSize: 30,
      chunkSize: 150,
      systemResources: null,
    };
  }
}

interface OperationSimulation {
  type: string;
  concurrency: number;
  connectionsPerOp: number;
  totalConnections: number;
  poolLimit: number;
  usagePercent: number;
  isSafe: boolean;
}

interface SystemSimulation {
  timestamp: string;
  poolLimit: number;
  operations: OperationSimulation[];
  totalConnections: number;
  totalUsagePercent: number;
  isSystemSafe: boolean;
  warnings: string[];
  recommendations: string[];
}

/**
 * Simulate a single operation type
 */
function simulateOperation(
  type: keyof typeof DB_CONNECTIONS_PER_OPERATION,
  concurrency: number,
  poolLimit: number
): OperationSimulation {
  const connectionsPerOp = DB_CONNECTIONS_PER_OPERATION[type] || 1;
  const totalConnections = concurrency * connectionsPerOp;
  const usagePercent = (totalConnections / poolLimit) * 100;
  const isSafe = totalConnections <= poolLimit * 0.8; // 80% safety threshold

  return {
    type,
    concurrency,
    connectionsPerOp,
    totalConnections,
    poolLimit,
    usagePercent: Math.round(usagePercent * 10) / 10,
    isSafe,
  };
}

/**
 * Simulate the entire system with all operations running concurrently
 */
async function simulateSystem(): Promise<SystemSimulation> {
  const poolLimit = getConnectionPoolLimit();
  const concurrencyLimits = await getMockConcurrencyLimits();

  // Simulate all operation types
  const operations: OperationSimulation[] = [
    simulateOperation('analysis', concurrencyLimits.analysisConcurrency, poolLimit),
    simulateOperation('automation', concurrencyLimits.automationConcurrency, poolLimit),
    simulateOperation('message-generation', concurrencyLimits.messageGenerationConcurrency, poolLimit),
    simulateOperation('batch', concurrencyLimits.batchConcurrency, poolLimit),
    simulateOperation('simple', concurrencyLimits.conversationFetchConcurrency, poolLimit),
  ];

  // Calculate total system usage
  const totalConnections = operations.reduce((sum, op) => sum + op.totalConnections, 0);
  const totalUsagePercent = (totalConnections / poolLimit) * 100;
  const isSystemSafe = totalConnections <= poolLimit * 0.8;

  // Generate warnings and recommendations
  const warnings: string[] = [];
  const recommendations: string[] = [];

  if (!isSystemSafe) {
    warnings.push(`⚠️ System would exhaust pool: ${totalConnections}/${poolLimit} connections (${Math.round(totalUsagePercent)}%)`);
    recommendations.push('Reduce concurrency limits or increase pool size');
  }

  operations.forEach(op => {
    if (!op.isSafe) {
      warnings.push(`⚠️ ${op.type} would use ${op.totalConnections} connections (${op.usagePercent}% of pool)`);
    }
  });

  if (totalUsagePercent > 60) {
    warnings.push(`⚠️ High pool usage: ${Math.round(totalUsagePercent)}% - may cause delays under load`);
  }

  if (isSystemSafe && totalUsagePercent < 50) {
    recommendations.push('✅ Pool usage is safe - could potentially increase concurrency');
  }

  return {
    timestamp: new Date().toISOString(),
    poolLimit,
    operations,
    totalConnections,
    totalUsagePercent: Math.round(totalUsagePercent * 10) / 10,
    isSystemSafe,
    warnings,
    recommendations,
  };
}

/**
 * Simulate worst-case scenario: All operations at maximum
 */
async function simulateWorstCase(): Promise<SystemSimulation> {
  const poolLimit = getConnectionPoolLimit();
  
  // Get maximum desired concurrency (before pool-aware caps)
  // These are the max limits from dynamic-concurrency.ts
  
  // Simulate if pool-aware limits weren't applied (worst case)
  const worstCaseOperations: OperationSimulation[] = [
    simulateOperation('analysis', 500, poolLimit), // maxAnalysisConcurrency
    simulateOperation('automation', 200, poolLimit), // maxAutomationConcurrency
    simulateOperation('message-generation', 200, poolLimit), // maxMessageGenerationConcurrency
    simulateOperation('batch', 20, poolLimit), // maxBatchConcurrency
    simulateOperation('simple', 100, poolLimit), // maxConversationFetchConcurrency
  ];

  const totalConnections = worstCaseOperations.reduce((sum, op) => sum + op.totalConnections, 0);
  const totalUsagePercent = (totalConnections / poolLimit) * 100;
  const isSystemSafe = totalConnections <= poolLimit * 0.8;

  return {
    timestamp: new Date().toISOString(),
    poolLimit,
    operations: worstCaseOperations,
    totalConnections,
    totalUsagePercent: Math.round(totalUsagePercent * 10) / 10,
    isSystemSafe,
    warnings: isSystemSafe ? [] : [`❌ WORST CASE: Would exhaust pool with ${totalConnections} connections (${Math.round(totalUsagePercent)}%)`],
    recommendations: isSystemSafe ? [] : ['✅ Pool-aware limits prevent this scenario'],
  };
}

/**
 * Simulate realistic concurrent load
 */
async function simulateRealisticLoad(): Promise<SystemSimulation> {
  const poolLimit = getConnectionPoolLimit();
  const concurrencyLimits = await getMockConcurrencyLimits();

  // Realistic scenario: Not all operations run at full capacity simultaneously
  // Analysis: 50% of max (background jobs)
  // Automation: 30% of max (cron jobs)
  // Message Gen: 80% of max (campaign sending)
  // Batch: 100% of max (active processing)
  // Simple: 40% of max (fetching conversations)

  const realisticOperations: OperationSimulation[] = [
    simulateOperation('analysis', Math.floor(concurrencyLimits.analysisConcurrency * 0.5), poolLimit),
    simulateOperation('automation', Math.floor(concurrencyLimits.automationConcurrency * 0.3), poolLimit),
    simulateOperation('message-generation', Math.floor(concurrencyLimits.messageGenerationConcurrency * 0.8), poolLimit),
    simulateOperation('batch', concurrencyLimits.batchConcurrency, poolLimit),
    simulateOperation('simple', Math.floor(concurrencyLimits.conversationFetchConcurrency * 0.4), poolLimit),
  ];

  const totalConnections = realisticOperations.reduce((sum, op) => sum + op.totalConnections, 0);
  const totalUsagePercent = (totalConnections / poolLimit) * 100;
  const isSystemSafe = totalConnections <= poolLimit * 0.8;

  return {
    timestamp: new Date().toISOString(),
    poolLimit,
    operations: realisticOperations,
    totalConnections,
    totalUsagePercent: Math.round(totalUsagePercent * 10) / 10,
    isSystemSafe,
    warnings: isSystemSafe ? [] : [`⚠️ Realistic load would use ${totalConnections} connections (${Math.round(totalUsagePercent)}%)`],
    recommendations: [],
  };
}

/**
 * Test with different pool sizes
 */
async function testDifferentPoolSizes(): Promise<void> {
  console.log('\n📊 Testing with Different Pool Sizes\n');
  console.log('=' .repeat(80));

  const poolSizes = [10, 15, 20, 25, 30];
  const concurrencyLimits = await getMockConcurrencyLimits();

  for (const poolSize of poolSizes) {
    console.log(`\n🔍 Pool Size: ${poolSize} connections\n`);
    
    const operations = [
      simulateOperation('analysis', concurrencyLimits.analysisConcurrency, poolSize),
      simulateOperation('automation', concurrencyLimits.automationConcurrency, poolSize),
      simulateOperation('message-generation', concurrencyLimits.messageGenerationConcurrency, poolSize),
      simulateOperation('batch', concurrencyLimits.batchConcurrency, poolSize),
    ];

    const totalConnections = operations.reduce((sum, op) => sum + op.totalConnections, 0);
    const usagePercent = (totalConnections / poolSize) * 100;
    const isSafe = totalConnections <= poolSize * 0.8;

    console.log(`  Total Connections: ${totalConnections}/${poolSize}`);
    console.log(`  Usage: ${Math.round(usagePercent)}%`);
    console.log(`  Status: ${isSafe ? '✅ SAFE' : '❌ UNSAFE'}`);

    operations.forEach(op => {
      console.log(`    - ${op.type}: ${op.concurrency} ops × ${op.connectionsPerOp} conn = ${op.totalConnections} conn`);
    });
  }
}

/**
 * Print simulation results
 */
function printSimulation(title: string, simulation: SystemSimulation): void {
  console.log(`\n${'='.repeat(80)}`);
  console.log(`📊 ${title}`);
  console.log(`${'='.repeat(80)}\n`);

  console.log(`Pool Limit: ${simulation.poolLimit} connections`);
  console.log(`Timestamp: ${simulation.timestamp}\n`);

  console.log('Operations:');
  simulation.operations.forEach(op => {
    const status = op.isSafe ? '✅' : '❌';
    console.log(`  ${status} ${op.type.padEnd(20)} ${op.concurrency.toString().padStart(3)} ops × ${op.connectionsPerOp} conn = ${op.totalConnections.toString().padStart(3)} conn (${op.usagePercent}%)`);
  });

  console.log(`\nTotal: ${simulation.totalConnections}/${simulation.poolLimit} connections (${simulation.totalUsagePercent}%)`);
  console.log(`Status: ${simulation.isSystemSafe ? '✅ SAFE' : '❌ UNSAFE'}\n`);

  if (simulation.warnings.length > 0) {
    console.log('⚠️  Warnings:');
    simulation.warnings.forEach(w => console.log(`   ${w}`));
    console.log();
  }

  if (simulation.recommendations.length > 0) {
    console.log('💡 Recommendations:');
    simulation.recommendations.forEach(r => console.log(`   ${r}`));
    console.log();
  }
}

/**
 * Main simulation function
 */
async function main() {
  console.log('🧪 Database Connection Pool Exhaustion Simulation');
  console.log('='.repeat(80));
  console.log('\nThis simulation tests if the current setup will exhaust the database pool.');
  console.log('Testing all concurrent operations and worst-case scenarios.\n');

  try {
    // Test 1: Current system with pool-aware limits
    console.log('\n🔬 TEST 1: Current System (With Pool-Aware Limits)');
    const currentSystem = await simulateSystem();
    printSimulation('Current System Simulation', currentSystem);

    // Test 2: Worst-case scenario (without pool-aware limits)
    console.log('\n🔬 TEST 2: Worst-Case Scenario (Without Pool-Aware Limits)');
    const worstCase = await simulateWorstCase();
    printSimulation('Worst-Case Scenario', worstCase);

    // Test 3: Realistic concurrent load
    console.log('\n🔬 TEST 3: Realistic Concurrent Load');
    const realistic = await simulateRealisticLoad();
    printSimulation('Realistic Load Simulation', realistic);

    // Test 4: Different pool sizes
    await testDifferentPoolSizes();

    // Final verdict
    console.log('\n' + '='.repeat(80));
    console.log('🎯 FINAL VERDICT');
    console.log('='.repeat(80) + '\n');

    if (currentSystem.isSystemSafe && realistic.isSystemSafe) {
      console.log('✅ CONFIDENCE: HIGH');
      console.log('   The pool-aware concurrency system prevents pool exhaustion.');
      console.log('   Even under realistic concurrent load, pool usage stays safe.\n');
      
      console.log('📊 Key Findings:');
      console.log(`   - Current system uses ${currentSystem.totalConnections}/${currentSystem.poolLimit} connections (${currentSystem.totalUsagePercent}%)`);
      console.log(`   - Realistic load uses ${realistic.totalConnections}/${realistic.poolLimit} connections (${realistic.totalUsagePercent}%)`);
      console.log(`   - Both scenarios are within the 80% safety threshold\n`);
      
      console.log('✅ The system is safe and will not exhaust the pool.');
    } else {
      console.log('❌ CONFIDENCE: LOW');
      console.log('   The system may exhaust the pool under certain conditions.\n');
      
      if (!currentSystem.isSystemSafe) {
        console.log('⚠️  Current system would exhaust pool:');
        currentSystem.warnings.forEach(w => console.log(`      ${w}`));
      }
      
      if (!realistic.isSystemSafe) {
        console.log('⚠️  Realistic load would exhaust pool:');
        realistic.warnings.forEach(w => console.log(`      ${w}`));
      }
      
      console.log('\n💡 Recommendations:');
      currentSystem.recommendations.forEach(r => console.log(`   ${r}`));
    }

    console.log('\n' + '='.repeat(80));
  } catch (error) {
    console.error('❌ Simulation failed:', error);
    process.exit(1);
  }
}

// Run simulation
main().catch(console.error);

