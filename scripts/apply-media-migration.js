#!/usr/bin/env node
/**
 * Script to apply the campaign media migration
 * Sets DIRECT_URL from DATABASE_URL if not already set
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Try to load .env file
const envPath = path.join(process.cwd(), '.env');
const envLocalPath = path.join(process.cwd(), '.env.local');

let envVars = {};

// Load .env.local first (takes precedence)
if (fs.existsSync(envLocalPath)) {
  const envLocal = fs.readFileSync(envLocalPath, 'utf8');
  envLocal.split('\n').forEach(line => {
    const match = line.match(/^([^=]+)=(.*)$/);
    if (match) {
      envVars[match[1].trim()] = match[2].trim();
    }
  });
}

// Load .env
if (fs.existsSync(envPath)) {
  const env = fs.readFileSync(envPath, 'utf8');
  env.split('\n').forEach(line => {
    const match = line.match(/^([^=]+)=(.*)$/);
    if (match) {
      const key = match[1].trim();
      if (!envVars[key]) { // Don't override .env.local values
        envVars[key] = match[2].trim();
      }
    }
  });
}

// Set DIRECT_URL from DATABASE_URL if not set
if (!envVars.DIRECT_URL && envVars.DATABASE_URL) {
  envVars.DIRECT_URL = envVars.DATABASE_URL;
  process.env.DIRECT_URL = envVars.DATABASE_URL;
  console.log('✅ Set DIRECT_URL from DATABASE_URL');
}

// Set environment variables
Object.keys(envVars).forEach(key => {
  if (!process.env[key]) {
    process.env[key] = envVars[key];
  }
});

if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL not found in .env or .env.local');
  console.error('Please set DATABASE_URL in your .env file');
  process.exit(1);
}

if (!process.env.DIRECT_URL) {
  process.env.DIRECT_URL = process.env.DATABASE_URL;
  console.log('✅ Using DATABASE_URL as DIRECT_URL');
}

console.log('🚀 Applying migration...');
try {
  execSync('npx prisma migrate deploy', { 
    stdio: 'inherit',
    env: { ...process.env }
  });
  console.log('✅ Migration applied successfully!');
} catch (error) {
  console.error('❌ Migration failed:', error.message);
  process.exit(1);
}









