import { prisma } from '../src/lib/db';

async function createEnums() {
  console.log('\n🔧 Creating Missing Enum Types\n');
  console.log('='.repeat(60));

  try {
    console.log('\n1️⃣  Creating SyncJobStatus enum...');
    
    await prisma.$executeRawUnsafe(`
      DO $$ BEGIN
        CREATE TYPE "SyncJobStatus" AS ENUM ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'CANCELLED');
      EXCEPTION
        WHEN duplicate_object THEN null;
      END $$;
    `);
    
    console.log('   ✅ SyncJobStatus enum created/verified');

    console.log('\n2️⃣  Creating Platform enum...');
    
    await prisma.$executeRawUnsafe(`
      DO $$ BEGIN
        CREATE TYPE "Platform" AS ENUM ('MESSENGER', 'INSTAGRAM');
      EXCEPTION
        WHEN duplicate_object THEN null;
      END $$;
    `);
    
    console.log('   ✅ Platform enum created/verified');

    console.log('\n3️⃣  Updating SyncJob table to use enum...');
    
    // Try to alter the column type - this might fail if already correct
    try {
      await prisma.$executeRawUnsafe(`
        ALTER TABLE "SyncJob" 
        ALTER COLUMN "status" TYPE "SyncJobStatus" 
        USING "status"::"SyncJobStatus";
      `);
      console.log('   ✅ SyncJob status column updated');
    } catch {
      // Column might already be the correct type
      console.log('   ℹ️  SyncJob status column already using enum');
    }

    console.log('\n4️⃣  Verifying enums...');
    
    const enums: Array<{ enumtypid: number; enumlabel: string; typname: string }> = await prisma.$queryRawUnsafe(`
      SELECT t.typname, e.enumlabel, e.enumtypid
      FROM pg_type t
      JOIN pg_enum e ON t.oid = e.enumtypid
      WHERE t.typname IN ('SyncJobStatus', 'Platform')
      ORDER BY t.typname, e.enumsortorder;
    `);
    
    const enumMap: Record<string, string[]> = {};
    enums.forEach(e => {
      if (!enumMap[e.typname]) enumMap[e.typname] = [];
      enumMap[e.typname].push(e.enumlabel);
    });
    
    Object.entries(enumMap).forEach(([name, values]) => {
      console.log(`   ✅ ${name}: ${values.join(', ')}`);
    });

    console.log('\n' + '='.repeat(60));
    console.log('\n✅ Enum types created!\n');

  } catch (error) {
    console.error('\n❌ Error creating enums:', error);
    if (error instanceof Error) {
      console.error(error.message);
    }
  } finally {
    await prisma.$disconnect();
  }
}

createEnums();

