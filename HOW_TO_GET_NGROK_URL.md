# 🌐 How to Get Your Ngrok URL

## 🚀 Method 1: Start Ngrok (Easiest)

### Step 1: Start Ngrok

**Option A: Using NPM Script**
```bash
npm run ngrok:start
```

**Option B: Using Batch File (Windows)**
Double-click: `start-ngrok.bat`

**Option C: Direct Command**
```bash
./ngrok.exe http 3000
```

### Step 2: Look for the URL in Terminal

After starting, you'll see output like:

```
ngrok                                                                        

Session Status                online
Account                       Your Name (Plan: Free)
Version                       3.x.x
Region                        United States (us)
Latency                       45ms
Web Interface                 http://127.0.0.1:4040
Forwarding                    https://abc123.ngrok-free.dev -> http://localhost:3000

Connections                   ttl     opn     rt1     rt5     p50     p90
                              0       0       0.00    0.00    0.00    0.00
```

**Your URL is here:** `https://abc123.ngrok-free.dev`

---

## 📊 Method 2: Ngrok Dashboard (Web Interface)

### Access the Dashboard

1. **Start ngrok** (using any method above)
2. **Open in browser:**
   ```
   http://localhost:4040
   ```
3. **You'll see:**
   - Your public URL at the top
   - Request/response logs
   - Tunnel statistics

**Screenshot of what you'll see:**
```
┌─────────────────────────────────────────┐
│  ngrok                                   │
├─────────────────────────────────────────┤
│  Forwarding                              │
│  https://abc123.ngrok-free.dev          │
│  -> http://localhost:3000              │
│                                          │
│  [Request Logs Below]                    │
└─────────────────────────────────────────┘
```

---

## 🔧 Method 3: API Endpoint (Programmatic)

### Get URL via API

While ngrok is running, you can get the URL programmatically:

**Using curl:**
```bash
curl http://localhost:4040/api/tunnels
```

**Response:**
```json
{
  "tunnels": [
    {
      "name": "command_line",
      "uri": "/api/tunnels/command_line",
      "public_url": "https://abc123.ngrok-free.dev",
      "proto": "https",
      "config": {
        "addr": "http://localhost:3000",
        "inspect": true
      },
      "metrics": { ... }
    }
  ]
}
```

**Extract just the URL:**
```bash
curl -s http://localhost:4040/api/tunnels | grep -o '"public_url":"[^"]*"' | head -1
```

---

## 🎯 Quick Reference

### Where to Find It:

1. **Terminal Output** - Right after starting ngrok
   ```
   Forwarding  https://abc123.ngrok-free.dev -> http://localhost:3000
   ```

2. **Web Dashboard** - `http://localhost:4040`
   - Shows at the top of the page
   - Click "Open in Browser" button

3. **API** - `http://localhost:4040/api/tunnels`
   - JSON response with all tunnel info

---

## ⚠️ Important Notes

### URL Changes Every Time

**Free ngrok accounts** get a **new URL** each time you restart ngrok.

**Example:**
- First start: `https://abc123.ngrok-free.dev`
- Restart: `https://xyz789.ngrok-free.dev` (different!)

**Solution:**
- ✅ Update `.env.local` each time URL changes
- ✅ Update Facebook App settings each time
- ✅ Or get a paid ngrok account for static domain

### Keep Ngrok Running

- ✅ **Don't close** the ngrok terminal/process
- ✅ URL stays active as long as ngrok is running
- ✅ If ngrok stops, you'll get a new URL when restarting

---

## 📋 Step-by-Step: Get Your URL Now

### 1. Start Ngrok

```bash
npm run ngrok:start
```

### 2. Wait 2-3 seconds

Ngrok needs a moment to establish the tunnel.

### 3. Check Terminal Output

Look for a line like:
```
Forwarding  https://abc123.ngrok-free.dev -> http://localhost:3000
```

**That's your URL!** Copy the `https://` part.

### 4. Or Open Dashboard

Open: `http://localhost:4040`

You'll see your URL at the top of the page.

---

## 🔍 Troubleshooting

### Problem: "No URL shown"

**Check:**
1. ✅ Is ngrok actually running? (check task manager)
2. ✅ Did you wait a few seconds for it to start?
3. ✅ Check `http://localhost:4040` - is it accessible?

### Problem: "Can't access dashboard"

**Check:**
1. ✅ Is ngrok running? (`tasklist | findstr ngrok` on Windows)
2. ✅ Try: `http://127.0.0.1:4040` instead
3. ✅ Check firewall isn't blocking port 4040

### Problem: "URL keeps changing"

**This is normal for free accounts!**
- Each restart = new URL
- Update your `.env.local` and Facebook settings each time
- Or upgrade to paid ngrok for static domain

---

## 🎯 Quick Commands

```bash
# Start ngrok and see URL
npm run ngrok:start

# Get URL via API (while ngrok is running)
curl http://localhost:4040/api/tunnels

# Open dashboard in browser
# Windows: start http://localhost:4040
# Mac/Linux: open http://localhost:4040
```

---

## ✅ Summary

**Easiest Way:**
1. Run `npm run ngrok:start`
2. Look at terminal output
3. Copy the `https://` URL shown

**Alternative:**
1. Start ngrok
2. Open `http://localhost:4040`
3. Copy URL from dashboard

**That's it!** 🎉









