# 🚀 Ngrok Quick Start

## ⚡ Fastest Way to Start

### Windows (Easiest)

**Double-click:** `start-ngrok.bat`

Or in terminal:
```bash
start-ngrok.bat
```

### All Platforms

```bash
npm run ngrok:start
```

---

## 📋 What Happens Next

1. **Ngrok starts** and creates a public URL
2. **Copy the HTTPS URL** (shown in terminal or at `http://localhost:4040`)
3. **Update `.env.local`**:
   ```env
   NEXT_PUBLIC_APP_URL=https://your-url.ngrok-free.dev
   NEXTAUTH_URL=https://your-url.ngrok-free.dev
   ```
4. **Update Facebook App** with the new URLs
5. **Restart dev server**: `npm run dev`
6. **Clear browser cookies**

---

## 🛑 Stop Ngrok

**Windows:**
```bash
stop-ngrok.bat
```

**All Platforms:**
```bash
npm run ngrok:stop
```

---

## 📊 View Tunnel Status

Open in browser:
```
http://localhost:4040
```

Shows:
- ✅ Your public URL
- ✅ Request/response logs
- ✅ Tunnel statistics

---

## ⚠️ Important

- **Keep ngrok running** while testing
- **URL changes** each time you restart (free accounts)
- **Update `.env.local`** and Facebook settings when URL changes

---

## 🆘 Need Help?

See full guide: `NGROK_SETUP_GUIDE.md`

---

**That's it!** 🎉









