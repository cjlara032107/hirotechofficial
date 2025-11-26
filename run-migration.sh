#!/bin/bash

echo "========================================"
echo "Production Database Migration"
echo "========================================"
echo ""
echo "This script will add the contactInfo and bestContactTimes"
echo "columns to your Contact table in the production database."
echo ""
echo "Make sure your DATABASE_URL is set in .env.local"
echo ""
read -p "Press Enter to continue..."

echo ""
echo "Running migration..."
echo ""

node apply-production-migration.js

if [ $? -eq 0 ]; then
    echo ""
    echo "========================================"
    echo "Migration completed successfully!"
    echo "========================================"
else
    echo ""
    echo "========================================"
    echo "Migration failed! Check the error above."
    echo "========================================"
    exit 1
fi


