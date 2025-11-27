/**
 * Script to verify risk scoring migration
 */

import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function verifyMigration() {
  try {
    console.log('Verifying risk scoring migration...\n');

    // Check enum
    const enumExists = await prisma.$queryRaw<Array<{ exists: boolean }>>`
      SELECT EXISTS (
        SELECT 1 FROM pg_type WHERE typname = 'ApprovalStatus'
      ) as exists;
    `;
    console.log(`✅ ApprovalStatus enum: ${enumExists[0]?.exists ? 'EXISTS' : 'MISSING'}`);

    // Check columns
    const columns = await prisma.$queryRaw<Array<{ column_name: string; data_type: string }>>`
      SELECT column_name, data_type 
      FROM information_schema.columns 
      WHERE table_name = 'Contact' 
      AND column_name IN ('riskScore', 'riskLevel', 'approvalStatus', 'riskReasons', 'approvedAt', 'approvedBy', 'rejectedAt', 'rejectedBy', 'feedback', 'feedbackAt')
      ORDER BY column_name;
    `;

    const expectedColumns = [
      'riskScore',
      'riskLevel',
      'approvalStatus',
      'riskReasons',
      'approvedAt',
      'approvedBy',
      'rejectedAt',
      'rejectedBy',
      'feedback',
      'feedbackAt',
    ];

    console.log('\n📋 Columns Status:');
    for (const col of expectedColumns) {
      const exists = columns.find(c => c.column_name === col);
      console.log(`  ${exists ? '✅' : '❌'} ${col}${exists ? ` (${exists.data_type})` : ' - MISSING'}`);
    }

    // Check indexes
    const indexes = await prisma.$queryRaw<Array<{ indexname: string }>>`
      SELECT indexname 
      FROM pg_indexes 
      WHERE tablename = 'Contact' 
      AND indexname IN (
        'Contact_approvalStatus_idx',
        'Contact_riskScore_idx',
        'Contact_organizationId_approvalStatus_idx',
        'Contact_organizationId_riskScore_idx'
      )
      ORDER BY indexname;
    `;

    const expectedIndexes = [
      'Contact_approvalStatus_idx',
      'Contact_riskScore_idx',
      'Contact_organizationId_approvalStatus_idx',
      'Contact_organizationId_riskScore_idx',
    ];

    console.log('\n📊 Indexes Status:');
    for (const idx of expectedIndexes) {
      const exists = indexes.find(i => i.indexname === idx);
      console.log(`  ${exists ? '✅' : '❌'} ${idx}${exists ? '' : ' - MISSING'}`);
    }

    // Summary
    const allColumnsExist = expectedColumns.every(col => columns.find(c => c.column_name === col));
    const allIndexesExist = expectedIndexes.every(idx => indexes.find(i => i.indexname === idx));

    console.log('\n📊 Summary:');
    console.log(`  Enum: ${enumExists[0]?.exists ? '✅' : '❌'}`);
    console.log(`  Columns: ${allColumnsExist ? '✅ All exist' : '❌ Some missing'}`);
    console.log(`  Indexes: ${allIndexesExist ? '✅ All exist' : '❌ Some missing'}`);

    if (enumExists[0]?.exists && allColumnsExist && allIndexesExist) {
      console.log('\n✅ Migration verification: SUCCESS - All components are in place!');
    } else {
      console.log('\n⚠️ Migration verification: INCOMPLETE - Some components are missing');
    }
  } catch (error) {
    console.error('❌ Verification failed:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

verifyMigration()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error('❌ Error:', error);
    process.exit(1);
  });

