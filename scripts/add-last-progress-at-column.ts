import { prisma, connectPrisma } from '../src/lib/db';

async function addLastProgressAtColumn() {
  console.log('\n🔧 Adding lastProgressAt column to SyncJob table\n');
  console.log('='.repeat(60));

  try {
    // Ensure database connection
    await connectPrisma();
    console.log('✅ Database connected\n');

    // Check if column already exists
    console.log('1️⃣  Checking if column exists...');
    const columnExists = await prisma.$queryRaw<Array<{ exists: boolean }>>`
      SELECT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name = 'SyncJob' 
        AND column_name = 'lastProgressAt'
      ) as exists;
    `;

    if (columnExists[0]?.exists) {
      console.log('   ✅ Column "lastProgressAt" already exists');
      console.log('\n✅ No changes needed. Database is up to date.\n');
      return;
    }

    console.log('   ⚠️  Column does not exist, adding it...\n');

    // Add the column
    console.log('2️⃣  Adding lastProgressAt column...');
    await prisma.$executeRawUnsafe(`
      ALTER TABLE "SyncJob" 
      ADD COLUMN IF NOT EXISTS "lastProgressAt" TIMESTAMP(3);
    `);
    console.log('   ✅ Column added\n');

    // Add indexes
    console.log('3️⃣  Creating indexes...');
    
    // Index on lastProgressAt
    await prisma.$executeRawUnsafe(`
      CREATE INDEX IF NOT EXISTS "SyncJob_lastProgressAt_idx" 
      ON "SyncJob"("lastProgressAt");
    `);
    console.log('   ✅ Index on lastProgressAt created');

    // Composite index on status and lastProgressAt
    await prisma.$executeRawUnsafe(`
      CREATE INDEX IF NOT EXISTS "SyncJob_status_lastProgressAt_idx" 
      ON "SyncJob"("status", "lastProgressAt");
    `);
    console.log('   ✅ Composite index on (status, lastProgressAt) created\n');

    console.log('✅ Successfully added lastProgressAt column and indexes!\n');
    console.log('📝 Regenerating Prisma client...');
    
    // Note: User will need to run `npx prisma generate` separately
    console.log('⚠️  Please run: npx prisma generate\n');
    
  } catch (error) {
    console.error('\n❌ Error:', error);
    if (error instanceof Error) {
      console.error('Error message:', error.message);
      console.error('Error stack:', error.stack);
    }
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

addLastProgressAtColumn();









