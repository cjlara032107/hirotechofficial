/**
 * Guide to get Supabase URLs and Anon Keys for all databases
 */

import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });
dotenv.config({ path: '.env' });

console.log('🔑 Supabase Configuration Guide\n');
console.log('='.repeat(80));

const projects = [
  { index: 0, ref: 'qudsmrrfbatasnyvuxch', name: 'Database 0' },
  { index: 1, ref: 'vivelzjlltbytnhybdcm', name: 'Database 1' },
  { index: 2, ref: 'kzvhbgqpxykganquikmv', name: 'Database 2' },
];

console.log('\n📋 Current Configuration:\n');

projects.forEach(project => {
  const urlKey = project.index === 0 ? 'NEXT_PUBLIC_SUPABASE_URL' : `NEXT_PUBLIC_SUPABASE_URL_${project.index}`;
  const anonKey = project.index === 0 ? 'NEXT_PUBLIC_SUPABASE_ANON_KEY' : `NEXT_PUBLIC_SUPABASE_ANON_KEY_${project.index}`;
  
  const url = process.env[urlKey] || '❌ Not set';
  const anon = process.env[anonKey] || '❌ Not set';
  
  console.log(`${project.name} (${project.ref}):`);
  console.log(`  ${urlKey}: ${url}`);
  console.log(`  ${anonKey}: ${anon.substring(0, 50)}${anon.length > 50 ? '...' : ''}`);
  console.log('');
});

console.log('='.repeat(80));
console.log('\n🔧 HOW TO GET SUPABASE KEYS:\n');

projects.forEach(project => {
  if (project.index > 0) {
    console.log(`\n📊 For ${project.name} (${project.ref}):`);
    console.log(`   1. Go to: https://${project.ref}.supabase.co`);
    console.log(`   2. Navigate to: Settings → API`);
    console.log(`   3. Copy "Project URL" → Use for NEXT_PUBLIC_SUPABASE_URL_${project.index}`);
    console.log(`   4. Copy "anon public" key → Use for NEXT_PUBLIC_SUPABASE_ANON_KEY_${project.index}`);
    console.log(`   5. Add to .env.local:`);
    console.log(`      NEXT_PUBLIC_SUPABASE_URL_${project.index}=https://${project.ref}.supabase.co`);
    console.log(`      NEXT_PUBLIC_SUPABASE_ANON_KEY_${project.index}=[paste anon key here]`);
  }
});

console.log('\n' + '='.repeat(80));
console.log('\n💡 NOTE:\n');
console.log('Currently, the app uses a single Supabase project for authentication.');
console.log('If you want to use separate Supabase projects for each database,');
console.log('you may need to update the Supabase client code to support multiple projects.');
console.log('\nFor now, you can use Database 0\'s Supabase URL and key for all databases.');
console.log('='.repeat(80));


 * Guide to get Supabase URLs and Anon Keys for all databases
 */

import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });
dotenv.config({ path: '.env' });

console.log('🔑 Supabase Configuration Guide\n');
console.log('='.repeat(80));

const projects = [
  { index: 0, ref: 'qudsmrrfbatasnyvuxch', name: 'Database 0' },
  { index: 1, ref: 'vivelzjlltbytnhybdcm', name: 'Database 1' },
  { index: 2, ref: 'kzvhbgqpxykganquikmv', name: 'Database 2' },
];

console.log('\n📋 Current Configuration:\n');

projects.forEach(project => {
  const urlKey = project.index === 0 ? 'NEXT_PUBLIC_SUPABASE_URL' : `NEXT_PUBLIC_SUPABASE_URL_${project.index}`;
  const anonKey = project.index === 0 ? 'NEXT_PUBLIC_SUPABASE_ANON_KEY' : `NEXT_PUBLIC_SUPABASE_ANON_KEY_${project.index}`;
  
  const url = process.env[urlKey] || '❌ Not set';
  const anon = process.env[anonKey] || '❌ Not set';
  
  console.log(`${project.name} (${project.ref}):`);
  console.log(`  ${urlKey}: ${url}`);
  console.log(`  ${anonKey}: ${anon.substring(0, 50)}${anon.length > 50 ? '...' : ''}`);
  console.log('');
});

console.log('='.repeat(80));
console.log('\n🔧 HOW TO GET SUPABASE KEYS:\n');

projects.forEach(project => {
  if (project.index > 0) {
    console.log(`\n📊 For ${project.name} (${project.ref}):`);
    console.log(`   1. Go to: https://${project.ref}.supabase.co`);
    console.log(`   2. Navigate to: Settings → API`);
    console.log(`   3. Copy "Project URL" → Use for NEXT_PUBLIC_SUPABASE_URL_${project.index}`);
    console.log(`   4. Copy "anon public" key → Use for NEXT_PUBLIC_SUPABASE_ANON_KEY_${project.index}`);
    console.log(`   5. Add to .env.local:`);
    console.log(`      NEXT_PUBLIC_SUPABASE_URL_${project.index}=https://${project.ref}.supabase.co`);
    console.log(`      NEXT_PUBLIC_SUPABASE_ANON_KEY_${project.index}=[paste anon key here]`);
  }
});

console.log('\n' + '='.repeat(80));
console.log('\n💡 NOTE:\n');
console.log('Currently, the app uses a single Supabase project for authentication.');
console.log('If you want to use separate Supabase projects for each database,');
console.log('you may need to update the Supabase client code to support multiple projects.');
console.log('\nFor now, you can use Database 0\'s Supabase URL and key for all databases.');
console.log('='.repeat(80));




