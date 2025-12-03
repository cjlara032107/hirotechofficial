/**
 * Script to create a test user for login testing
 * Run with: npx tsx create-test-user.ts
 */

import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  console.log('🚀 Creating test user for login...\n');

  const email = 'admin@hiro.com';
  const password = 'admin123'; // Change this!
  const name = 'Admin User';

  try {
    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      console.log('ℹ️  User already exists:', email);
      console.log('   Use these credentials to login:\n');
      console.log('   Email:', email);
      console.log('   Password:', password);
      console.log('\n✅ Ready to test login!\n');
      return;
    }

    // Check if any organization exists
    let organization = await prisma.organization.findFirst();

    // Create organization if none exists
    if (!organization) {
      console.log('📦 Creating test organization...');
      organization = await prisma.organization.create({
        data: {
          name: 'Hiro Tech',
          slug: 'hiro-tech',
        },
      });
      console.log('✅ Organization created:', organization.name);
    } else {
      console.log('✅ Using existing organization:', organization.name);
    }

    // Hash password
    console.log('🔐 Hashing password...');
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    console.log('👤 Creating user...');
    await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name,
        role: 'ADMIN',
        organizationId: organization.id,
      },
    });

    console.log('\n✅ Test user created successfully!\n');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('📧 Email:   ', email);
    console.log('🔑 Password:', password);
    console.log('👤 Name:    ', name);
    console.log('🏢 Org:     ', organization.name);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    console.log('🎯 Next Steps:');
    console.log('   1. Start dev server: npm run dev');
    console.log('   2. Go to: http://localhost:3000/login');
    console.log('   3. Login with above credentials');
    console.log('\n✅ Ready to test!\n');
  } catch (error) {
    console.error('\n❌ Error creating test user:');
    console.error(error);
    console.log('\nPossible issues:');
    console.log('- Database not running');
    console.log('- DATABASE_URL incorrect in .env.local');
    console.log('- Schema not pushed (run: npx prisma db push)');
    process.exit(1);
  }
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });

