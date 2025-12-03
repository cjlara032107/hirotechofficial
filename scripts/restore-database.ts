/**
 * Database Restore Script
 * 
 * Restores a PostgreSQL database from a backup file.
 * Supports both SQL and custom format backups.
 * 
 * Usage:
 *   npx tsx scripts/restore-database.ts <backup-file> [--dry-run] [--confirm]
 * 
 * WARNING: This will overwrite existing data in the database!
 */

import { execSync } from 'child_process';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import * as dotenv from 'dotenv';

dotenv.config();

interface RestoreOptions {
  backupFile: string;
  dryRun?: boolean;
  confirm?: boolean;
}

function parseDatabaseUrl(url: string): {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
} {
  try {
    const urlObj = new URL(url);
    return {
      host: urlObj.hostname,
      port: parseInt(urlObj.port || '5432', 10),
      database: urlObj.pathname.slice(1),
      user: urlObj.username,
      password: urlObj.password,
    };
  } catch (error) {
    throw new Error(`Invalid DATABASE_URL format: ${error}`);
  }
}

function loadBackupMetadata(backupFile: string): any {
  const metadataPath = backupFile.replace(/\.(sql|dump)$/, '.metadata.json');
  if (existsSync(metadataPath)) {
    return JSON.parse(readFileSync(metadataPath, 'utf-8'));
  }
  return null;
}

function restoreDatabase(options: RestoreOptions): void {
  const databaseUrl = process.env.DATABASE_URL || process.env.DIRECT_URL;
  
  if (!databaseUrl) {
    throw new Error('DATABASE_URL or DIRECT_URL environment variable is required');
  }

  const dbConfig = parseDatabaseUrl(databaseUrl);
  const backupPath = options.backupFile.startsWith('/') 
    ? options.backupFile 
    : join(process.cwd(), 'backups', options.backupFile);

  if (!existsSync(backupPath)) {
    throw new Error(`Backup file not found: ${backupPath}`);
  }

  const metadata = loadBackupMetadata(backupPath);
  const isCustomFormat = backupPath.endsWith('.dump');

  console.log(`[Restore] Preparing to restore database...`);
  console.log(`[Restore] Database: ${dbConfig.database}`);
  console.log(`[Restore] Host: ${dbConfig.host}:${dbConfig.port}`);
  console.log(`[Restore] Backup file: ${backupPath}`);
  if (metadata) {
    console.log(`[Restore] Backup created: ${metadata.timestamp}`);
  }

  if (options.dryRun) {
    console.log(`[Restore] 🔍 DRY RUN MODE - No changes will be made`);
    console.log(`[Restore] Would execute: ${isCustomFormat ? 'pg_restore' : 'psql'} command`);
    return;
  }

  if (!options.confirm) {
    console.error(`[Restore] ⚠️  WARNING: This will overwrite all data in the database!`);
    console.error(`[Restore] To proceed, run with --confirm flag`);
    throw new Error('Restore requires --confirm flag');
  }

  console.log(`[Restore] ⚠️  WARNING: This will overwrite existing data!`);
  console.log(`[Restore] Starting restore in 3 seconds... (Ctrl+C to cancel)`);
  
  // Give user a moment to cancel
  const startTime = Date.now();
  while (Date.now() - startTime < 3000) {
    // Wait 3 seconds
  }

  try {
    if (isCustomFormat) {
      // Use pg_restore for custom format
      const pgRestoreArgs = [
        `--host=${dbConfig.host}`,
        `--port=${dbConfig.port}`,
        `--username=${dbConfig.user}`,
        `--dbname=${dbConfig.database}`,
        '--no-password',
        '--verbose',
        '--clean', // Clean (drop) database objects before recreating
        '--if-exists', // Use IF EXISTS when dropping objects
        '--no-owner', // Don't restore ownership
        '--no-acl', // Don't restore ACLs
        backupPath,
      ];

      const command = `PGPASSWORD="${dbConfig.password}" pg_restore ${pgRestoreArgs.join(' ')}`;
      
      console.log(`[Restore] Executing pg_restore...`);
      execSync(command, {
        stdio: 'inherit',
        env: {
          ...process.env,
          PGPASSWORD: dbConfig.password,
        },
      });
    } else {
      // Use psql for SQL format
      const psqlArgs = [
        `--host=${dbConfig.host}`,
        `--port=${dbConfig.port}`,
        `--username=${dbConfig.user}`,
        `--dbname=${dbConfig.database}`,
        '--no-password',
        '--file=' + backupPath,
      ];

      const command = `PGPASSWORD="${dbConfig.password}" psql ${psqlArgs.join(' ')}`;
      
      console.log(`[Restore] Executing psql...`);
      execSync(command, {
        stdio: 'inherit',
        env: {
          ...process.env,
          PGPASSWORD: dbConfig.password,
        },
      });
    }

    console.log(`[Restore] ✅ Restore completed successfully!`);
  } catch (error) {
    console.error('[Restore] ❌ Restore failed:', error);
    throw error;
  }
}

// Parse command line arguments
const args = process.argv.slice(2);
const options: RestoreOptions = {
  backupFile: '',
};

for (const arg of args) {
  if (arg === '--dry-run') {
    options.dryRun = true;
  } else if (arg === '--confirm') {
    options.confirm = true;
  } else if (!arg.startsWith('--')) {
    options.backupFile = arg;
  }
}

if (!options.backupFile) {
  console.error('Usage: npx tsx scripts/restore-database.ts <backup-file> [--dry-run] [--confirm]');
  process.exit(1);
}

// Run restore
try {
  restoreDatabase(options);
  process.exit(0);
} catch (error) {
  console.error('Restore script failed:', error);
  process.exit(1);
}









