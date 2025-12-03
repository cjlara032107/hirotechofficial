#!/bin/bash
# Migration Application Script
# This script applies the database migration for enhanced AI fields

echo "Applying database migration..."

# Check if DATABASE_URL is set
if [ -z "$DATABASE_URL" ]; then
    echo "ERROR: DATABASE_URL environment variable is not set."
    echo "Please set DATABASE_URL in your environment or .env file."
    exit 1
fi

# Set DIRECT_URL to DATABASE_URL if not already set (for non-pooled connections)
if [ -z "$DIRECT_URL" ]; then
    echo "DIRECT_URL not set. Using DATABASE_URL as DIRECT_URL..."
    export DIRECT_URL="$DATABASE_URL"
fi

# Apply migration
echo "Running: npx prisma migrate deploy"
npx prisma migrate deploy

if [ $? -eq 0 ]; then
    echo ""
    echo "Migration applied successfully!"
    echo "Regenerating Prisma client..."
    npx prisma generate
    echo ""
    echo "Done! All enhanced AI fields have been added to the database."
else
    echo ""
    echo "Migration failed. Please check the error messages above."
    exit 1
fi













