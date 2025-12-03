# Campaign UI Components - Implementation Notes

## Overview

The backend campaign system is fully implemented with multi-DB routing, comprehensive logging, and all features working. The UI components already exist in the codebase at:

- `src/app/(dashboard)/campaigns/page.tsx` - Campaign list page
- `src/app/(dashboard)/campaigns/[id]/page.tsx` - Campaign details page  
- `src/app/(dashboard)/campaigns/new/page.tsx` - Create new campaign page
- `src/app/(dashboard)/campaigns/scheduled/page.tsx` - Scheduled campaigns page

## Recommended UI Enhancements

### 1. Real-Time Status Updates

**Component:** Campaign Details Page (`src/app/(dashboard)/campaigns/[id]/page.tsx`)

**Enhancement:**
```typescript
// Add polling hook
function useCampaignStatus(campaignId: string) {
  const [status, setStatus] = useState(null);
  const [isPolling, setIsPolling] = useState(false);

  useEffect(() => {
    if (!isPolling) return;

    const poll = async () => {
      const res = await fetch(`/api/campaigns/${campaignId}/status`);
      const data = await res.json();
      setStatus(data);

      // Continue polling if campaign is active
      if (data.progress.isActive) {
        setTimeout(poll, 2000);
      } else {
        setIsPolling(false);
      }
    };

    poll();
  }, [campaignId, isPolling]);

  return { status, startPolling: () => setIsPolling(true) };
}

// Usage in component
function CampaignDetailsPage({ params }: { params: { id: string } }) {
  const { status, startPolling } = useCampaignStatus(params.id);

  // Start polling when campaign is sent
  const handleSendCampaign = async () => {
    await fetch(`/api/campaigns/${params.id}/send`, { method: 'POST' });
    startPolling();
  };

  return (
    <div>
      {status && (
        <div>
          <ProgressBar value={status.progress.percentage} />
          <p>Sent: {status.metrics.sent} / {status.metrics.totalRecipients}</p>
          <p>Failed: {status.metrics.failed}</p>
          {status.progress.estimatedTimeRemaining && (
            <p>Est. time remaining: {status.progress.estimatedTimeRemaining}s</p>
          )}
        </div>
      )}
    </div>
  );
}
```

### 2. Campaign Creation Wizard

**Component:** New Campaign Page (`src/app/(dashboard)/campaigns/new/page.tsx`)

**Enhancement Steps:**
1. **Target Selection Step:**
   - Radio buttons for: "Selected Contacts", "All Contacts", "By Tags", "By Pipeline Stage"
   - Contact picker (multi-select) for selected contacts
   - Tag selector for tag-based targeting

2. **Message Configuration Step:**
   - Template selector
   - AI personalization toggle
   - Custom instructions textarea (if AI enabled)
   - Media upload/URL input

3. **Schedule & Send Step:**
   - "Send Now" vs "Schedule" toggle
   - Date/time picker for scheduled sends
   - Auto-fetch toggle (for scheduled campaigns)
   - Review summary

**Example Structure:**
```typescript
function NewCampaignWizard() {
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState({
    targeting: 'selected',
    contactIds: [],
    useAi: false,
    aiInstructions: '',
    template: null,
    media: null,
    schedule: 'now',
    scheduledAt: null,
  });

  return (
    <div>
      {step === 1 && <TargetSelectionStep data={formData} onChange={setFormData} />}
      {step === 2 && <MessageConfigStep data={formData} onChange={setFormData} />}
      {step === 3 && <ScheduleStep data={formData} onChange={setFormData} />}
      
      <div>
        {step > 1 && <Button onClick={() => setStep(step - 1)}>Back</Button>}
        {step < 3 && <Button onClick={() => setStep(step + 1)}>Next</Button>}
        {step === 3 && <Button onClick={handleCreateCampaign}>Create Campaign</Button>}
      </div>
    </div>
  );
}
```

### 3. Campaign List with Filters

**Component:** Campaign List Page (`src/app/(dashboard)/campaigns/page.tsx`)

**Enhancement:**
```typescript
function CampaignListPage() {
  const [filters, setFilters] = useState({
    status: 'all',
    platform: 'all',
    dateRange: 'all',
  });

  return (
    <div>
      <div className="filters">
        <Select value={filters.status} onChange={(v) => setFilters({...filters, status: v})}>
          <option value="all">All Statuses</option>
          <option value="DRAFT">Draft</option>
          <option value="SCHEDULED">Scheduled</option>
          <option value="SENDING">Sending</option>
          <option value="COMPLETED">Completed</option>
        </Select>
        
        <Select value={filters.platform} onChange={(v) => setFilters({...filters, platform: v})}>
          <option value="all">All Platforms</option>
          <option value="MESSENGER">Messenger</option>
          <option value="INSTAGRAM">Instagram</option>
        </Select>
      </div>

      <CampaignList filters={filters} />
    </div>
  );
}
```

### 4. Campaign Analytics Dashboard

**New Component:** `src/app/(dashboard)/campaigns/[id]/analytics/page.tsx`

**Features:**
- Delivery rate chart over time
- Read rate by contact
- Response rate tracking
- Geographic distribution (if available)
- Best performing messages (if A/B testing)
- Engagement heatmap (best send times)

**Data Source:**
- Use `/api/campaigns/[id]/status` for metrics
- Fetch message-level data from `/api/campaigns/[id]/messages` (create this endpoint)

### 5. Error Handling UI

**Component:** Throughout campaign pages

**Enhancement:**
```typescript
function ErrorDisplay({ error }: { error: CampaignError }) {
  const getErrorHelp = (error: string) => {
    if (error.includes('routed database')) {
      return {
        title: 'Database Connectivity Issue',
        description: 'The campaign data may exist in a different database. Check your multi-DB configuration.',
        action: 'Contact Support',
      };
    }
    
    if (error.includes('access denied')) {
      return {
        title: 'Permission Denied',
        description: 'You do not have permission to access this campaign.',
        action: 'Request Access',
      };
    }
    
    return {
      title: 'Error',
      description: error,
      action: 'Retry',
    };
  };

  const help = getErrorHelp(error.message);

  return (
    <Alert variant="destructive">
      <AlertTitle>{help.title}</AlertTitle>
      <AlertDescription>{help.description}</AlertDescription>
      <Button onClick={error.retry}>{help.action}</Button>
    </Alert>
  );
}
```

### 6. Scheduled Campaign Calendar View

**New Component:** `src/app/(dashboard)/campaigns/calendar/page.tsx`

**Features:**
- Calendar view of scheduled campaigns
- Click on date to see campaigns scheduled for that day
- Drag-and-drop to reschedule
- Color-coded by status/platform

### 7. Campaign Templates Library

**Enhancement to:** Create Campaign Page

**Features:**
- Pre-built template categories (promotion, announcement, follow-up, etc.)
- Template preview
- Variable placeholders highlighted
- Save custom templates

## State Management Recommendations

### Option 1: React Query (Recommended)
```typescript
// hooks/useCampaign.ts
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';

export function useCampaign(id: string) {
  return useQuery({
    queryKey: ['campaign', id],
    queryFn: () => fetch(`/api/campaigns/${id}`).then(r => r.json()),
  });
}

export function useCampaignStatus(id: string, shouldPoll = false) {
  return useQuery({
    queryKey: ['campaign-status', id],
    queryFn: () => fetch(`/api/campaigns/${id}/status`).then(r => r.json()),
    refetchInterval: shouldPoll ? 2000 : false,
  });
}

export function useSendCampaign() {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (id: string) => 
      fetch(`/api/campaigns/${id}/send`, { method: 'POST' }).then(r => r.json()),
    onSuccess: (data, id) => {
      queryClient.invalidateQueries({ queryKey: ['campaign', id] });
      queryClient.invalidateQueries({ queryKey: ['campaign-status', id] });
    },
  });
}
```

### Option 2: Zustand
```typescript
// store/campaignStore.ts
import { create } from 'zustand';

interface CampaignStore {
  campaigns: Campaign[];
  selectedCampaign: Campaign | null;
  isLoading: boolean;
  fetchCampaigns: () => Promise<void>;
  sendCampaign: (id: string) => Promise<void>;
}

export const useCampaignStore = create<CampaignStore>((set) => ({
  campaigns: [],
  selectedCampaign: null,
  isLoading: false,
  
  fetchCampaigns: async () => {
    set({ isLoading: true });
    const res = await fetch('/api/campaigns');
    const campaigns = await res.json();
    set({ campaigns, isLoading: false });
  },
  
  sendCampaign: async (id) => {
    await fetch(`/api/campaigns/${id}/send`, { method: 'POST' });
    // Refresh campaigns list
    const res = await fetch('/api/campaigns');
    const campaigns = await res.json();
    set({ campaigns });
  },
}));
```

## UI Component Library

The project uses:
- **Shadcn UI** for components
- **Tailwind CSS** for styling
- **Radix UI** for primitives

### Key Components to Use:

1. **Progress Bar:**
   ```tsx
   import { Progress } from '@/components/ui/progress';
   <Progress value={campaign.progress} />
   ```

2. **Status Badge:**
   ```tsx
   import { Badge } from '@/components/ui/badge';
   <Badge variant={getStatusVariant(campaign.status)}>
     {campaign.status}
   </Badge>
   ```

3. **Data Table:**
   ```tsx
   import { DataTable } from '@/components/ui/data-table';
   <DataTable 
     columns={campaignColumns} 
     data={campaigns}
     onRowClick={(row) => router.push(`/campaigns/${row.id}`)}
   />
   ```

4. **Form:**
   ```tsx
   import { Form, FormField, FormItem, FormLabel } from '@/components/ui/form';
   <Form {...form}>
     <FormField
       control={form.control}
       name="name"
       render={({ field }) => (
         <FormItem>
           <FormLabel>Campaign Name</FormLabel>
           <Input {...field} />
         </FormItem>
       )}
     />
   </Form>
   ```

## Testing UI Components

### Unit Tests (Jest + React Testing Library)
```typescript
// __tests__/components/CampaignStatus.test.tsx
import { render, screen } from '@testing-library/react';
import { CampaignStatus } from '@/components/campaigns/CampaignStatus';

describe('CampaignStatus', () => {
  it('displays progress correctly', () => {
    const status = {
      progress: { percentage: 75 },
      metrics: { sent: 75, totalRecipients: 100 },
    };
    
    render(<CampaignStatus status={status} />);
    
    expect(screen.getByText('75%')).toBeInTheDocument();
    expect(screen.getByText('75 / 100')).toBeInTheDocument();
  });
});
```

### E2E Tests (Playwright)
```typescript
// e2e/campaigns.spec.ts
import { test, expect } from '@playwright/test';

test('create and send campaign', async ({ page }) => {
  await page.goto('/campaigns/new');
  
  // Fill in campaign details
  await page.fill('[name="name"]', 'Test Campaign');
  await page.selectOption('[name="platform"]', 'MESSENGER');
  
  // Select contacts
  await page.click('[data-testid="contact-selector"]');
  await page.click('[data-testid="contact-1"]');
  await page.click('[data-testid="contact-2"]');
  
  // Create campaign
  await page.click('button:has-text("Create Campaign")');
  
  // Wait for redirect to campaign details
  await expect(page).toHaveURL(/\/campaigns\/.+/);
  
  // Send campaign
  await page.click('button:has-text("Send Now")');
  
  // Verify status updates
  await expect(page.locator('[data-testid="campaign-status"]')).toHaveText('SENDING');
});
```

## Accessibility (A11y) Checklist

- [ ] All interactive elements have keyboard navigation
- [ ] Focus indicators are visible
- [ ] ARIA labels for screen readers
- [ ] Color contrast meets WCAG AA standards
- [ ] Error messages are announced to screen readers
- [ ] Loading states have proper announcements
- [ ] Forms have proper label associations

## Performance Optimization

1. **Code Splitting:**
   ```typescript
   const CampaignAnalytics = dynamic(() => import('@/components/campaigns/Analytics'), {
     loading: () => <Skeleton />,
   });
   ```

2. **Memoization:**
   ```typescript
   const campaignList = useMemo(() => {
     return campaigns.filter(c => c.status === selectedStatus);
   }, [campaigns, selectedStatus]);
   ```

3. **Virtualization (for large lists):**
   ```typescript
   import { useVirtualizer } from '@tanstack/react-virtual';
   
   const virtualizer = useVirtualizer({
     count: campaigns.length,
     getScrollElement: () => parentRef.current,
     estimateSize: () => 100,
   });
   ```

## Next Steps for UI Implementation

1. **Priority 1 (Critical):**
   - [ ] Add real-time status polling to campaign details page
   - [ ] Improve error messages and handling
   - [ ] Add loading states throughout

2. **Priority 2 (Important):**
   - [ ] Create campaign wizard with better UX
   - [ ] Add campaign list filters
   - [ ] Implement campaign analytics dashboard

3. **Priority 3 (Nice-to-have):**
   - [ ] Calendar view for scheduled campaigns
   - [ ] Template library
   - [ ] A/B testing UI
   - [ ] Bulk operations (pause/cancel multiple campaigns)

## Resources

- [Shadcn UI Documentation](https://ui.shadcn.com/)
- [React Query Documentation](https://tanstack.com/query/latest)
- [Next.js App Router Documentation](https://nextjs.org/docs/app)
- [Accessibility Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)

