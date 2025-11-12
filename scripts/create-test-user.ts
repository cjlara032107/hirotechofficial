/**
 * Create a test user for development and testing
 * Usage: DATABASE_URL="your-db-url" npx tsx scripts/create-test-user.ts
 */
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function createTestUser() {
  try {
    console.log('Creating test user...');

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: 'admin@test.com' },
    });

    if (existingUser) {
      console.log('✅ Test user already exists!');
      console.log('Email: admin@test.com');
      console.log('Password: password123');
      return;
    }

    // Hash password
    const hashedPassword = await bcrypt.hash('password123', 10);

    // Create organization and user
    const user = await prisma.$transaction(async (tx) => {
      const organization = await tx.organization.create({
        data: {
          name: 'Test Organization',
          slug: 'test-org',
        },
      });

      return await tx.user.create({
        data: {
          name: 'Test Admin',
          email: 'admin@test.com',
          password: hashedPassword,
          role: 'ADMIN',
          organizationId: organization.id,
        },
      });
    });

    console.log('✅ Test user created successfully!');
    console.log('\nLogin credentials:');
    console.log('Email: admin@test.com');
    console.log('Password: password123');
    console.log('\nOrganization:', user.organizationId);
  } catch (error) {
    console.error('❌ Error creating test user:', error);
  } finally {
    await prisma.$disconnect();
  }
}

createTestUser();
