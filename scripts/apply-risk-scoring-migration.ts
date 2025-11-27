/**
 * Script to apply risk scoring migration
 * Run this if DIRECT_URL is not set in environment
 */

import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function applyMigration() {
  try {
    console.log('Applying risk scoring migration...');

    // Check if enum already exists
    const enumExists = await prisma.$queryRaw<Array<{ exists: boolean }>>`
      SELECT EXISTS (
        SELECT 1 FROM pg_type WHERE typname = 'ApprovalStatus'
      ) as exists;
    `;

    if (!enumExists[0]?.exists) {
      // Create enum
      await prisma.$executeRawUnsafe(`
        CREATE TYPE "ApprovalStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'AUTO_APPROVED');
      `);
      console.log('✅ Created ApprovalStatus enum');
    } else {
      console.log('✅ ApprovalStatus enum already exists');
    }

    // Check if columns already exist
    const columnsExist = await prisma.$queryRaw<Array<{ column_name: string }>>`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'Contact' 
      AND column_name IN ('riskScore', 'riskLevel', 'approvalStatus');
    `;

    const existingColumns = columnsExist.map(c => c.column_name);

    // Add columns if they don't exist
    if (!existingColumns.includes('riskScore')) {
      await prisma.$executeRawUnsafe(`ALTER TABLE "Contact" ADD COLUMN "riskScore" INTEGER;`);
      console.log('✅ Added riskScore column');
    }

    if (!existingColumns.includes('riskLevel')) {
      await prisma.$executeRawUnsafe(`ALTER TABLE "Contact" ADD COLUMN "riskLevel" TEXT;`);
      console.log('✅ Added riskLevel column');
    }

    if (!existingColumns.includes('approvalStatus')) {
      await prisma.$executeRawUnsafe(`ALTER TABLE "Contact" ADD COLUMN "approvalStatus" "ApprovalStatus";`);
      console.log('✅ Added approvalStatus column');
    }

    // Check if riskReasons exists separately (it's an array type)
    const riskReasonsExists = await prisma.$queryRaw<Array<{ exists: boolean }>>`
      SELECT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'Contact' AND column_name = 'riskReasons'
      ) as exists;
    `;

    if (!riskReasonsExists[0]?.exists) {
      await prisma.$executeRawUnsafe(`ALTER TABLE "Contact" ADD COLUMN "riskReasons" TEXT[] DEFAULT ARRAY[]::TEXT[];`);
      console.log('✅ Added riskReasons column');
    } else {
      console.log('✅ riskReasons column already exists');
    }

    // Add other columns
    const otherColumns = [
      { name: 'approvedAt', type: 'TIMESTAMP(3)' },
      { name: 'approvedBy', type: 'TEXT' },
      { name: 'rejectedAt', type: 'TIMESTAMP(3)' },
      { name: 'rejectedBy', type: 'TEXT' },
      { name: 'feedback', type: 'TEXT' },
      { name: 'feedbackAt', type: 'TIMESTAMP(3)' },
    ];

    for (const col of otherColumns) {
      const exists = await prisma.$queryRaw<Array<{ exists: boolean }>>`
        SELECT EXISTS (
          SELECT 1 FROM information_schema.columns 
          WHERE table_name = 'Contact' AND column_name = ${col.name}
        ) as exists;
      `;

      if (!exists[0]?.exists) {
        await prisma.$executeRawUnsafe(`ALTER TABLE "Contact" ADD COLUMN "${col.name}" ${col.type};`);
        console.log(`✅ Added ${col.name} column`);
      }
    }

    // Create indexes
    const indexes = [
      'Contact_approvalStatus_idx',
      'Contact_riskScore_idx',
      'Contact_organizationId_approvalStatus_idx',
      'Contact_organizationId_riskScore_idx',
    ];

    for (const indexName of indexes) {
      const exists = await prisma.$queryRaw<Array<{ exists: boolean }>>`
        SELECT EXISTS (
          SELECT 1 FROM pg_indexes WHERE indexname = ${indexName}
        ) as exists;
      `;

      if (!exists[0]?.exists) {
        const indexSQL = indexName.includes('organizationId')
          ? `CREATE INDEX "${indexName}" ON "Contact"("organizationId", "${indexName.includes('approvalStatus') ? 'approvalStatus' : 'riskScore'}");`
          : `CREATE INDEX "${indexName}" ON "Contact"("${indexName.replace('Contact_', '').replace('_idx', '')}");`;
        
        await prisma.$executeRawUnsafe(indexSQL);
        console.log(`✅ Created index ${indexName}`);
      } else {
        console.log(`✅ Index ${indexName} already exists`);
      }
    }

    console.log('✅ Migration completed successfully!');
  } catch (error) {
    console.error('❌ Migration failed:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

applyMigration()
  .then(() => {
    console.log('✅ All done!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('❌ Error:', error);
    process.exit(1);
  });

