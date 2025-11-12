#!/bin/bash

echo "===================================="
echo "Database Connection Pool Fix"
echo "===================================="
echo

echo "[1/5] Checking environment variables..."
if [ -z "$DATABASE_URL" ]; then
    echo "ERROR: DATABASE_URL not set!"
    echo "Please add DATABASE_URL to your .env.local file"
    echo "Format: postgresql://...@host:6543/postgres?pgbouncer=true"
    exit 1
fi

if [ -z "$DIRECT_URL" ]; then
    echo "ERROR: DIRECT_URL not set!"
    echo "Please add DIRECT_URL to your .env.local file"
    echo "Format: postgresql://...@host:5432/postgres"
    exit 1
fi

echo "✓ Environment variables found"
echo

echo "[2/5] Clearing Next.js cache..."
if [ -d ".next" ]; then
    rm -rf .next
    echo "✓ Cache cleared"
else
    echo "✓ No cache to clear"
fi
echo

echo "[3/5] Clearing Prisma client cache..."
if [ -d "node_modules/.prisma" ]; then
    rm -rf node_modules/.prisma
    echo "✓ Prisma cache cleared"
else
    echo "✓ No Prisma cache to clear"
fi
echo

echo "[4/5] Regenerating Prisma Client..."
npx prisma generate
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to generate Prisma Client"
    exit 1
fi
echo "✓ Prisma Client regenerated"
echo

echo "[5/5] Starting development server..."
echo
echo "===================================="
echo "Fix Applied Successfully!"
echo "===================================="
echo
echo "Next steps:"
echo "1. Verify your .env.local has correct URLs"
echo "2. DATABASE_URL should use port 6543 (pooled)"
echo "3. DIRECT_URL should use port 5432 (direct)"
echo
echo "Starting server now..."
echo

npm run dev

