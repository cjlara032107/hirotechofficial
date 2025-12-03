/**
 * Database Backup Script
 * 
 * Creates a backup of the PostgreSQL database using pg_dump.
 * Supports both Supabase and standard PostgreSQL databases.
 * 
 * Usage:
 *   npx tsx scripts/backup-database.ts [--output=backup.sql] [--format=sql|custom]
 */

import { execSync } from 'child_process';
import { writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import * as dotenv from 'dotenv';

dotenv.config();

interface BackupOptions {
  output?: string;
  format?: 'sql' | 'custom';
  compress?: boolean;
}

function parseDatabaseUrl(url: string): {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
} {
  try {
    // Parse DATABASE_URL format: postgresql://user:password@host:port/database
    const urlObj = new URL(url);
    return {
      host: urlObj.hostname,
      port: parseInt(urlObj.port || '5432', 10),
      database: urlObj.pathname.slice(1), // Remove leading /
      user: urlObj.username,
      password: urlObj.password,
    };
  } catch (error) {
    throw new Error(`Invalid DATABASE_URL format: ${error}`);
  }
}

function createBackup(options: BackupOptions = {}): void {
  const databaseUrl = process.env.DATABASE_URL || process.env.DIRECT_URL;
  
  if (!databaseUrl) {
    throw new Error('DATABASE_URL or DIRECT_URL environment variable is required');
  }

  const dbConfig = parseDatabaseUrl(databaseUrl);
  const format = options.format || 'sql';
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const defaultOutput = `backup-${timestamp}.${format === 'custom' ? 'dump' : 'sql'}`;
  const outputPath = options.output || defaultOutput;

  // Create backups directory if it doesn't exist
  const backupsDir = join(process.cwd(), 'backups');
  mkdirSync(backupsDir, { recursive: true });
  const fullOutputPath = join(backupsDir, outputPath);

  console.log(`[Backup] Starting database backup...`);
  console.log(`[Backup] Database: ${dbConfig.database}`);
  console.log(`[Backup] Host: ${dbConfig.host}:${dbConfig.port}`);
  console.log(`[Backup] Format: ${format}`);
  console.log(`[Backup] Output: ${fullOutputPath}`);

  try {
    // Build pg_dump command
    const pgDumpArgs = [
      `--host=${dbConfig.host}`,
      `--port=${dbConfig.port}`,
      `--username=${dbConfig.user}`,
      `--dbname=${dbConfig.database}`,
      '--no-password', // Use PGPASSWORD env var instead
      '--verbose',
      '--no-owner', // Don't include ownership commands
      '--no-acl', // Don't include ACL commands
    ];

    if (format === 'custom') {
      pgDumpArgs.push('--format=custom');
      pgDumpArgs.push('--compress=9');
    } else {
      pgDumpArgs.push('--format=plain');
    }

    // Add schema and data options
    pgDumpArgs.push('--schema=public');
    pgDumpArgs.push('--data-only=false'); // Include both schema and data

    const command = `PGPASSWORD="${dbConfig.password}" pg_dump ${pgDumpArgs.join(' ')} > "${fullOutputPath}"`;

    console.log(`[Backup] Executing backup...`);
    execSync(command, {
      stdio: 'inherit',
      env: {
        ...process.env,
        PGPASSWORD: dbConfig.password,
      },
    });

    // Create backup metadata
    const metadata = {
      timestamp: new Date().toISOString(),
      database: dbConfig.database,
      host: dbConfig.host,
      format,
      outputPath: fullOutputPath,
      version: '1.0.0',
    };

    const metadataPath = fullOutputPath.replace(/\.(sql|dump)$/, '.metadata.json');
    writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));

    console.log(`[Backup] ✅ Backup completed successfully!`);
    console.log(`[Backup] Backup file: ${fullOutputPath}`);
    console.log(`[Backup] Metadata: ${metadataPath}`);

    // Get file size
    const fs = require('fs');
    const stats = fs.statSync(fullOutputPath);
    const fileSizeMB = (stats.size / (1024 * 1024)).toFixed(2);
    console.log(`[Backup] Backup size: ${fileSizeMB} MB`);
  } catch (error) {
    console.error('[Backup] ❌ Backup failed:', error);
    throw error;
  }
}

// Parse command line arguments
const args = process.argv.slice(2);
const options: BackupOptions = {};

for (const arg of args) {
  if (arg.startsWith('--output=')) {
    options.output = arg.split('=')[1];
  } else if (arg.startsWith('--format=')) {
    const format = arg.split('=')[1];
    if (format === 'sql' || format === 'custom') {
      options.format = format;
    } else {
      throw new Error(`Invalid format: ${format}. Must be 'sql' or 'custom'`);
    }
  } else if (arg === '--compress') {
    options.compress = true;
  }
}

// Run backup
try {
  createBackup(options);
  process.exit(0);
} catch (error) {
  console.error('Backup script failed:', error);
  process.exit(1);
}









