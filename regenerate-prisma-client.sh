#!/bin/bash
# Regenerate Prisma Client Script

echo "Regenerating Prisma Client..."

# Load environment variables
if [ -f .env.local ]; then
    export $(cat .env.local | grep -E '^(DATABASE_URL|DIRECT_URL)=' | xargs)
fi

# Set DIRECT_URL if not set
if [ -z "$DIRECT_URL" ] && [ -n "$DATABASE_URL" ]; then
    export DIRECT_URL="$DATABASE_URL"
fi

# Regenerate Prisma client
echo "Running: npx prisma generate"
npx prisma generate

if [ $? -eq 0 ]; then
    echo ""
    echo "Prisma client regenerated successfully!"
    echo "You can now use the new enhanced AI fields in your application."
else
    echo ""
    echo "Error regenerating Prisma client."
    echo "If you see a file lock error (EPERM), please:"
    echo "1. Stop your dev server (Ctrl+C)"
    echo "2. Run this script again"
    echo "3. Restart your dev server"
    exit 1
fi
