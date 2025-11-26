/**
 * Setup developer account - creates profile after user registers
 * Usage: npx tsx scripts/setup-developer-account.ts
 * 
 * Option 1: If user already registered, this will convert them to DEVELOPER
 * Option 2: Register first at /register, then run this script
 */
import { PrismaClient } from '@prisma/client';
import { createClient } from '@supabase/supabase-js';
import { config } from 'dotenv';
import { resolve } from 'path';

// Load environment variables
config({ path: resolve(process.cwd(), '.env.local') });

const prisma = new PrismaClient();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseAnonKey) {
  console.error('❌ Missing Supabase credentials!');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseAnonKey);

async function setupDeveloperAccount() {
  try {
    const email = 'hirotech.developer@gmail.com';
    const password = 'demet5732595';
    const name = 'Hiro Tech Developer';

    console.log('🚀 Setting up developer account...\n');
    console.log(`📧 Email: ${email}`);
    console.log(`👤 Name: ${name}\n`);

    // Try to sign in to check if user exists
    console.log('🔍 Checking if user exists in Supabase Auth...');
    const { data: signInData, error: signInError } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    let userId: string;

    if (signInError || !signInData.user) {
      // User doesn't exist or wrong password - try to sign up
      console.log('📝 User not found, attempting to create account...');
      
      const { data: signUpData, error: signUpError } = await supabase.auth.signUp({
        email,
        password,
        options: {
          data: {
            name,
          },
        },
      });

      if (signUpError || !signUpData.user) {
        console.error('❌ Could not create user in Supabase Auth');
        console.error('Error:', signUpError?.message || 'Unknown error');
        console.log('\n💡 Alternative:');
        console.log('1. Register manually at: http://localhost:3000/register');
        console.log(`   Email: ${email}`);
        console.log(`   Password: ${password}`);
        console.log('2. Then run this script again to convert to DEVELOPER\n');
        return;
      }

      userId = signUpData.user.id;
      console.log('✅ User created in Supabase Auth');
    } else {
      userId = signInData.user.id;
      console.log('✅ User exists in Supabase Auth');
    }

    // Check if profile exists in database
    const existingProfile = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (existingProfile) {
      console.log('✅ Profile already exists in database');
      
      if (existingProfile.role !== 'DEVELOPER') {
        await prisma.user.update({
          where: { id: userId },
          data: { role: 'DEVELOPER' },
        });
        console.log('✅ Updated role to DEVELOPER');
      } else {
        console.log('✅ User is already a DEVELOPER');
      }
    } else {
      // Create profile
      console.log('📝 Creating user profile in database...');
      
      // Get or create organization
      let organization = await prisma.organization.findFirst();
      
      if (!organization) {
        organization = await prisma.organization.create({
          data: {
            name: 'Hiro Tech',
            slug: 'hiro-tech',
          },
        });
        console.log('✅ Organization created');
      }

      await prisma.user.create({
        data: {
          id: userId,
          email,
          name,
          password: null, // Managed by Supabase
          role: 'DEVELOPER',
          organizationId: organization.id,
        },
      });
      console.log('✅ Profile created with DEVELOPER role');
    }

    // Get final user info
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { organization: true },
    });

    console.log('\n✅ Developer account setup complete!\n');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('📧 DEVELOPER ACCOUNT CREDENTIALS');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`Email:          ${email}`);
    console.log(`Password:       ${password}`);
    console.log(`Name:           ${user!.name || name}`);
    console.log(`Role:           ${user!.role}`);
    console.log(`User ID:        ${userId}`);
    console.log(`Organization:   ${user!.organization.name}`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    console.log('🎯 Next Steps:');
    console.log('1. Login at: http://localhost:3000/login');
    console.log('2. Go to: /settings/developer (to manage page access)');
    console.log('3. Go to: /settings/api-keys (to manage API keys)\n');
  } catch (error) {
    console.error('❌ Error setting up developer account:', error);
    if (error instanceof Error) {
      console.error('Details:', error.message);
    }
  } finally {
    await prisma.$disconnect();
  }
}

setupDeveloperAccount();





