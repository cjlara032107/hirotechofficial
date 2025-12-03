# Add 4 Working API Keys

## Option 1: Via UI (Recommended)

1. **Start your dev server:**
   ```bash
   npm run dev
   ```

2. **Login as Developer** at `http://localhost:3000`

3. **Navigate to Settings → API Keys**

4. **Click "Add API Key"**

5. **Paste all 4 keys** (one per line):
   ```
   nvapi-key1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   nvapi-key2-yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
   nvapi-key3-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
   nvapi-key4-wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww
   ```

6. **Click "Add"** - The system will automatically detect and add all 4 keys

## Option 2: Via Script

1. **Update the script** with your 4 keys:
   - Open `scripts/add-4-working-api-keys.ts`
   - Replace the `WORKING_KEYS` array with your actual keys

2. **Run the script:**
   ```bash
   npx tsx scripts/add-4-working-api-keys.ts
   ```

## Option 3: Via API (cURL)

If you have your session cookie, you can add keys via API:

```bash
curl -X POST http://localhost:3000/api/api-keys \
  -H "Content-Type: application/json" \
  -H "Cookie: your-session-cookie" \
  -d '{
    "keys": [
      {"key": "nvapi-key1-...", "name": "Key 1"},
      {"key": "nvapi-key2-...", "name": "Key 2"},
      {"key": "nvapi-key3-...", "name": "Key 3"},
      {"key": "nvapi-key4-...", "name": "Key 4"}
    ]
  }'
```

## ✅ Verification

After adding keys:

1. **Check the UI** - Go to Settings → API Keys and verify all 4 keys are listed
2. **Check count** - You should see the total count increase by 4
3. **Test AI features** - Sync a contact and verify AI analysis works with the new keys

---

**Note**: Please provide your 4 working API keys so I can update the script for you!




