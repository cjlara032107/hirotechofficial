# Backup and Recovery Procedures

This document describes the backup and recovery procedures for the HIRO application database.

## Overview

The backup and recovery system provides:
- Automated database backups
- Point-in-time recovery
- Backup verification
- Metadata tracking

## Backup Procedures

### Creating a Backup

#### Using npm script:
```bash
npm run backup:db
```

#### Using direct script:
```bash
npx tsx scripts/backup-database.ts
```

#### Custom options:
```bash
# Specify output filename
npx tsx scripts/backup-database.ts --output=my-backup.sql

# Use custom format (compressed)
npx tsx scripts/backup-database.ts --format=custom --output=my-backup.dump
```

### Backup Formats

1. **SQL Format** (default)
   - Human-readable SQL dump
   - Can be edited manually
   - Larger file size
   - Extension: `.sql`

2. **Custom Format** (compressed)
   - Binary format
   - Smaller file size
   - Faster restore
   - Extension: `.dump`

### Backup Location

Backups are stored in the `backups/` directory in the project root.

### Backup Metadata

Each backup includes a metadata file (`.metadata.json`) containing:
- Timestamp
- Database name
- Host information
- Format type
- Version information

## Recovery Procedures

### Restoring from Backup

⚠️ **WARNING**: Restoring will overwrite all existing data in the database!

#### Dry Run (Preview):
```bash
npx tsx scripts/restore-database.ts backup-2024-01-01.sql --dry-run
```

#### Full Restore:
```bash
npx tsx scripts/restore-database.ts backup-2024-01-01.sql --confirm
```

#### Using npm script:
```bash
npm run restore:db backup-2024-01-01.sql --confirm
```

### Recovery Steps

1. **Verify Backup File**
   ```bash
   ls -lh backups/backup-2024-01-01.sql
   ```

2. **Check Metadata**
   ```bash
   cat backups/backup-2024-01-01.metadata.json
   ```

3. **Dry Run** (recommended first)
   ```bash
   npx tsx scripts/restore-database.ts backup-2024-01-01.sql --dry-run
   ```

4. **Perform Restore**
   ```bash
   npx tsx scripts/restore-database.ts backup-2024-01-01.sql --confirm
   ```

5. **Verify Restore**
   - Check database connectivity
   - Verify critical data
   - Test application functionality

## Automated Backups

### Setting Up Automated Backups

#### Using cron (Linux/Mac):
```bash
# Add to crontab (runs daily at 2 AM)
0 2 * * * cd /path/to/project && npm run backup:db
```

#### Using Windows Task Scheduler:
1. Open Task Scheduler
2. Create Basic Task
3. Set trigger (daily at 2 AM)
4. Action: Start a program
5. Program: `npm`
6. Arguments: `run backup:db`
7. Start in: Project directory

### Backup Retention

Recommended retention policy:
- Daily backups: Keep for 7 days
- Weekly backups: Keep for 4 weeks
- Monthly backups: Keep for 12 months

## Testing Backup and Recovery

### Run Tests

```bash
npm test -- scripts/__tests__/backup-restore.test.ts
```

### Manual Testing

1. **Create Test Backup**
   ```bash
   npm run backup:db -- --output=test-backup.sql
   ```

2. **Verify Backup Created**
   ```bash
   ls -lh backups/test-backup.sql
   ```

3. **Test Restore (Dry Run)**
   ```bash
   npx tsx scripts/restore-database.ts test-backup.sql --dry-run
   ```

## Environment Variables

Required environment variables:
- `DATABASE_URL` - Primary database connection string
- `DIRECT_URL` - Direct database connection (optional, uses DATABASE_URL if not set)

## Troubleshooting

### Backup Fails

**Error**: `DATABASE_URL or DIRECT_URL environment variable is required`
- **Solution**: Ensure `.env` file contains `DATABASE_URL`

**Error**: `pg_dump: command not found`
- **Solution**: Install PostgreSQL client tools
  - macOS: `brew install postgresql`
  - Ubuntu: `sudo apt-get install postgresql-client`
  - Windows: Install PostgreSQL from postgresql.org

**Error**: `Connection refused`
- **Solution**: Verify database is accessible and credentials are correct

### Restore Fails

**Error**: `Backup file not found`
- **Solution**: Check file path and ensure backup exists in `backups/` directory

**Error**: `Restore requires --confirm flag`
- **Solution**: Add `--confirm` flag to proceed with restore

**Error**: `Permission denied`
- **Solution**: Ensure database user has necessary permissions

## Best Practices

1. **Regular Backups**
   - Schedule automated daily backups
   - Test restore procedures monthly
   - Keep backups in multiple locations

2. **Before Major Changes**
   - Always create a backup before:
     - Running migrations
     - Major data updates
     - System updates

3. **Backup Verification**
   - Regularly verify backup files are not corrupted
   - Test restore procedures in staging environment
   - Document restore procedures

4. **Security**
   - Encrypt backups containing sensitive data
   - Store backups securely
   - Limit access to backup files
   - Don't commit backups to version control

5. **Monitoring**
   - Monitor backup script execution
   - Alert on backup failures
   - Track backup sizes and storage usage

## Integration with Monitoring

Backup and restore operations are tracked by the monitoring system:
- Backup failures trigger alerts
- Restore operations are logged
- Backup metadata is stored for audit

## Support

For issues or questions:
1. Check logs in `backups/` directory
2. Review metadata files for backup information
3. Test with `--dry-run` flag first
4. Contact system administrator for assistance









