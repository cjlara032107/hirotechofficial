# Philippine Time (PHT) Migration Guide

## Overview

All time-related features in the application now use **Philippine Time (PHT, UTC+8)** instead of UTC or server local time. This ensures consistent timezone handling across all features including:

- Best contact times calculation and display
- Time-based automation checks
- Date/time displays in the UI
- Cron job scheduling

## Changes Made

### 1. Timezone Utility (`src/lib/utils/timezone.ts`)

Created a comprehensive timezone utility module with functions for:
- Getting current time in PHT: `nowPHT()`
- Formatting times in PHT: `formatTimePHT()`, `formatDatePHT()`, `formatDateTimePHT()`
- Time window checks: `isTimeInWindowPHT()`
- Day of week operations: `getDayOfWeekPHT()`, `getDayNamePHT()`
- Creating dates in PHT: `createDatePHT()`

### 2. Best Contact Times

**Files Updated:**
- `src/lib/contacts/best-contact-times.ts` - Formatting now uses PHT
- `src/lib/ai/best-contact-time-checker.ts` - All time checks use PHT
- `src/lib/contacts/default-contact-times.ts` - Times are interpreted in PHT

**Changes:**
- Best contact times are now calculated and displayed in Philippine Time
- Time windows are checked against PHT current time
- All time ranges are formatted in PHT

### 3. Conflict Prevention

**File Updated:** `src/lib/ai/conflict-prevention.ts`

**Changes:**
- `getSafeSendTimeWindow()` now uses PHT for all time calculations
- Active hours are interpreted in Philippine Time

### 4. Cron Jobs

**File Updated:** `vercel.json`

**Changes:**
- Auto-sync cron job adjusted from `0 0 * * *` (midnight UTC) to `0 16 * * *` (4 PM UTC = midnight PHT)
- Other cron jobs remain on their current schedules (they run frequently enough that timezone doesn't matter)

**Note:** Vercel cron jobs run in UTC. To run at a specific PHT time:
- PHT midnight (00:00) = UTC 16:00 (previous day) = `0 16 * * *`
- PHT 9 AM (09:00) = UTC 1:00 AM = `0 1 * * *`
- PHT 5 PM (17:00) = UTC 9:00 AM = `0 9 * * *`

## Usage Examples

### Getting Current Time in PHT

```typescript
import { nowPHT } from '@/lib/utils/timezone';

const currentTime = nowPHT(); // Returns Date object representing current PHT time
```

### Formatting Times

```typescript
import { formatTimePHT, formatDatePHT, formatDateTimePHT } from '@/lib/utils/timezone';

const time = formatTimePHT(new Date()); // "9:00 AM"
const date = formatDatePHT(new Date()); // "January 15, 2025"
const dateTime = formatDateTimePHT(new Date()); // "January 15, 2025, 9:00 AM"
```

### Checking Time Windows

```typescript
import { isTimeInWindowPHT } from '@/lib/utils/timezone';

// Check if current PHT time is between 9 AM and 5 PM
const isWithinWindow = isTimeInWindowPHT(9, 0, 17, 0);
```

### Creating Dates in PHT

```typescript
import { createDatePHT } from '@/lib/utils/timezone';

// Create a date for 9:00 AM PHT today
const date = createDatePHT(9, 0);
```

## Migration Notes

### For Developers

1. **Replace `new Date()`** with `nowPHT()` when you need current time in PHT
2. **Use timezone utilities** instead of native Date methods for formatting
3. **All time comparisons** should use PHT-aware functions
4. **Best contact times** stored in database are already in PHT format

### For Existing Data

- Existing best contact times in the database will continue to work
- Times are stored as strings (e.g., "9:00 AM - 11:00 AM") and are interpreted in PHT
- No database migration needed

### Testing

When testing time-based features:
1. Ensure your system clock or test environment accounts for PHT
2. Use the timezone utilities for all time operations
3. Verify that times display correctly in the UI

## Benefits

1. **Consistency**: All times are in the same timezone (PHT)
2. **User Experience**: Users see times in their local timezone (Philippines)
3. **Accuracy**: Best contact times are calculated and checked in the correct timezone
4. **Maintainability**: Centralized timezone handling makes future changes easier

## Future Considerations

- If expanding to other regions, consider making timezone configurable per user/organization
- For now, PHT is hardcoded as the application timezone
- All cron jobs should be adjusted if they need to run at specific PHT times




