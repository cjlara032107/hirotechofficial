#!/usr/bin/env node

/**
 * Ngrok Tunnel Stopper Script
 * Stops all running ngrok tunnels
 */

const ngrok = require('ngrok');
const http = require('http');

console.log('🛑 Stopping ngrok...\n');

function checkTunnels() {
  return new Promise((resolve) => {
    const req = http.get('http://localhost:4040/api/tunnels', (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const tunnels = JSON.parse(data);
          resolve(tunnels.tunnels && tunnels.tunnels.length > 0);
        } catch (e) {
          resolve(false);
        }
      });
    });
    
    req.on('error', () => {
      resolve(false);
    });
    
    req.setTimeout(2000, () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function stopTunnel() {
  try {
    // Check if ngrok is running
    const hasTunnels = await checkTunnels();
    
    if (hasTunnels) {
      // Disconnect all tunnels
      await ngrok.disconnect();
      await ngrok.kill();
      console.log('✅ Ngrok stopped successfully');
    } else {
      console.log('ℹ️  No active ngrok tunnels found');
    }
  } catch (error) {
    // If we can't connect to ngrok API, it's likely not running
    console.log('ℹ️  Ngrok is not running');
  }
}

stopTunnel();
