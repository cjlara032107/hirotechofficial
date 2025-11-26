#!/bin/bash

echo "Running database migration for AnalysisJob model..."
echo ""

# Check if .env file exists
if [ ! -f .env ]; then
    echo "ERROR: .env file not found!"
    echo ""
    echo "Please create a .env file with the following variables:"
    echo "  DATABASE_URL=your_database_connection_string"
    echo "  DIRECT_URL=your_direct_database_connection_string"
    echo ""
    exit 1
fi

echo "Applying migration..."
npx prisma migrate deploy

if [ $? -eq 0 ]; then
    echo ""
    echo "Migration completed successfully!"
    echo ""
else
    echo ""
    echo "Migration failed. Please check the error messages above."
    echo ""
    exit 1
fi


