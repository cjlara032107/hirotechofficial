#!/usr/bin/env node

/**
 * Wait for dev server to be ready
 */

const http = require('http');

console.log('⏳ Waiting for dev server to be ready...');

function checkServer() {
  return new Promise((resolve) => {
    const req = http.get('http://localhost:3000', { timeout: 2000 }, (res) => {
      console.log(`✅ Server is ready! (Status: ${res.statusCode})`);
      resolve(true);
    });
    
    req.on('error', () => {
      process.stdout.write('.');
      setTimeout(() => resolve(false), 2000);
    });
    
    req.on('timeout', () => {
      req.destroy();
      process.stdout.write('.');
      setTimeout(() => resolve(false), 2000);
    });
  });
}

(async () => {
  let attempts = 0;
  const maxAttempts = 30; // 60 seconds max
  
  while (attempts < maxAttempts) {
    const ready = await checkServer();
    if (ready) {
      console.log('\n✅ Dev server is ready and responding!');
      process.exit(0);
    }
    attempts++;
  }
  
  console.log('\n❌ Server did not become ready after 60 seconds');
  console.log('   Check the dev server terminal for errors');
  process.exit(1);
})();





