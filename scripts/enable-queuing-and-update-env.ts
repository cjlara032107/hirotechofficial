import fs from 'fs';
import path from 'path';

/**
 * Script to enable request queuing and update environment variables
 */

const ENV_FILE = path.join(process.cwd(), '.env.local');

async function updateEnvFile() {
  console.log('\n🔧 Updating .env.local to enable request queuing...\n');
  
  let envContent = '';
  
  // Read existing .env.local if it exists
  if (fs.existsSync(ENV_FILE)) {
    envContent = fs.readFileSync(ENV_FILE, 'utf-8');
    console.log('✅ Found existing .env.local\n');
  } else {
    console.log('⚠️  .env.local not found, will create new file\n');
  }
  
  // Define the new/updated variables
  const updates: Record<string, string> = {
    // Enable analysis queue
    'USE_ANALYSIS_QUEUE': 'true',
    
    // Analysis queue configuration
    'AI_ANALYSIS_QUEUE_CONCURRENCY': '50',  // Adjust based on number of keys (5-10 per key)
    'AI_ANALYSIS_QUEUE_INTERVAL': '100',     // Check queue every 100ms
    'AI_ANALYSIS_QUEUE_MAX_SIZE': '1000',   // Max queue size
    
    // Request queue configuration (for general AI requests)
    'AI_REQUEST_QUEUE_MAX_CONCURRENT': '50', // Scale with keys (5-10 per key)
    'AI_USE_DYNAMIC_CONCURRENCY': 'true',    // Enable dynamic scaling based on API keys
  };
  
  // Parse existing env file
  const lines = envContent.split('\n');
  const existingKeys = new Set<string>();
  const newLines: string[] = [];
  
  // Process existing lines
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      newLines.push(line);
      continue;
    }
    
    const match = trimmed.match(/^([^=]+)=(.*)$/);
    if (match) {
      const key = match[1].trim();
      existingKeys.add(key);
      
      // Update if key exists in updates
      if (updates[key]) {
        newLines.push(`${key}=${updates[key]}`);
        console.log(`  ✅ Updated: ${key}=${updates[key]}`);
        delete updates[key]; // Remove from updates so we don't add it again
      } else {
        newLines.push(line); // Keep original line
      }
    } else {
      newLines.push(line);
    }
  }
  
  // Add new variables
  for (const [key, value] of Object.entries(updates)) {
    newLines.push(`${key}=${value}`);
    console.log(`  ➕ Added: ${key}=${value}`);
  }
  
  // Write back to file
  fs.writeFileSync(ENV_FILE, newLines.join('\n'), 'utf-8');
  
  console.log('\n✅ .env.local updated successfully!');
  console.log('\n📋 Summary of changes:');
  console.log('  - Enabled analysis queue (USE_ANALYSIS_QUEUE=true)');
  console.log('  - Set analysis queue concurrency to 50');
  console.log('  - Set request queue concurrency to 50');
  console.log('  - Enabled dynamic concurrency scaling');
  console.log('\n💡 Note: Restart your dev server for changes to take effect.\n');
}

updateEnvFile().catch((error) => {
  console.error('❌ Error updating .env.local:', error);
  process.exit(1);
});




