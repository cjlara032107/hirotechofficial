'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import { Switch } from '@/components/ui/switch';
import { toast } from 'sonner';
import { MESSAGE_TAGS } from '@/lib/facebook/message-tags';
import { CalendarIcon, Clock, Search, X, Users, Loader2, RefreshCw, Sparkles, Eye } from 'lucide-react';

export default function NewCampaignPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [name, setName] = useState('');
  const [platform, setPlatform] = useState('MESSENGER');
  const [messageTag, setMessageTag] = useState('');
  const [messageContent, setMessageContent] = useState('');
  const [tags, setTags] = useState<Array<{ id: string; name: string; color: string; contactCount: number }>>([]);
  const [selectedTags, setSelectedTags] = useState<string[]>([]);
  const [facebookPages, setFacebookPages] = useState<Array<{ id: string; pageName: string; platform: string }>>([]);
  const [selectedPageId, setSelectedPageId] = useState('');
  const [creating, setCreating] = useState(false);
  const [loadingPages, setLoadingPages] = useState(true);
  const [isScheduled, setIsScheduled] = useState(false);
  const [scheduledDate, setScheduledDate] = useState('');
  const [scheduledTime, setScheduledTime] = useState('');
  const [autoFetchEnabled, setAutoFetchEnabled] = useState(false);
  const [targetContacts, setTargetContacts] = useState<Array<{
    id: string;
    firstName: string;
    lastName: string;
    email: string | null;
    phone: string | null;
    tags: string[];
  }>>([]);
  const [excludedContactIds, setExcludedContactIds] = useState<Set<string>>(new Set());
  const [searchQuery, setSearchQuery] = useState('');
  const [loadingContacts, setLoadingContacts] = useState(false);
  const [useAiPersonalization, setUseAiPersonalization] = useState(false);
  const [aiCustomInstructions, setAiCustomInstructions] = useState('');
  const [previewingContactId, setPreviewingContactId] = useState<string | null>(null);
  const [previewMessage, setPreviewMessage] = useState<string | null>(null);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [hasPreselectedContacts, setHasPreselectedContacts] = useState(false);
  const fetchingContactsRef = useRef(false);
  const preselectedContactsLoadedRef = useRef(false);
  const isSettingPreselectedRef = useRef(false);

  // Fetch tags and pages on mount
  useEffect(() => {
    fetchTags();
    fetchFacebookPages();
    const preselectedTags = searchParams.get('tags');
    if (preselectedTags) {
      setSelectedTags([preselectedTags]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Handle preselected contacts from URL (only once, after pages load)
  useEffect(() => {
    if (preselectedContactsLoadedRef.current || facebookPages.length === 0) {
      return;
    }
    
    const preselectedContacts = searchParams.get('contacts');
    if (preselectedContacts) {
      const contactIds = preselectedContacts.split(',').filter(Boolean);
      if (contactIds.length > 0 && !hasPreselectedContacts && !fetchingContactsRef.current) {
        preselectedContactsLoadedRef.current = true;
        fetchPreselectedContacts(contactIds);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [facebookPages.length]); // Only when pages are loaded

  // Fetch target contacts when settings change (only if not using preselected contacts)
  useEffect(() => {
    // Don't fetch if we're currently setting preselected contacts
    if (isSettingPreselectedRef.current) {
      return;
    }
    
    // Don't fetch if we have preselected contacts already loaded
    if (hasPreselectedContacts && targetContacts.length > 0) {
      return;
    }
    
    // Don't fetch if already loading
    if (loadingContacts || fetchingContactsRef.current) {
      return;
    }
    
    if (selectedPageId && platform) {
      // Small delay to ensure state is updated
      const timer = setTimeout(() => {
        // Double-check we're not setting preselected contacts
        if (!isSettingPreselectedRef.current && !hasPreselectedContacts) {
          fetchTargetContacts();
        }
      }, 100);
      return () => clearTimeout(timer);
    } else {
      // Only clear if we don't have preselected contacts
      if (!hasPreselectedContacts && !isSettingPreselectedRef.current) {
        setTargetContacts([]);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedPageId, platform, selectedTags]);

  const fetchTags = async () => {
    try {
      const response = await fetch('/api/tags');
      
      // Check if response is JSON
      const contentType = response.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        throw new Error('Server returned non-JSON response');
      }
      
      const data = await response.json();
      if (response.ok) {
        setTags(data);
      } else {
        toast.error(data.error || 'Failed to fetch tags');
      }
    } catch (error) {
      console.error('Error fetching tags:', error);
      const err = error as Error;
      toast.error(err.message || 'An error occurred while fetching tags');
    }
  };

  const fetchFacebookPages = async () => {
    setLoadingPages(true);
    try {
      const response = await fetch('/api/facebook/pages/connected');
      
      // Check if response is JSON
      const contentType = response.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        throw new Error('Server returned non-JSON response');
      }
      
      const data = await response.json();
      if (response.ok && data.pages) {
        setFacebookPages(data.pages);
        // Auto-select first page if only one exists
        if (data.pages.length === 1) {
          setSelectedPageId(data.pages[0].id);
        }
      } else {
        console.error('Failed to fetch pages:', data.error);
        toast.error(data.error || 'Failed to load Facebook pages');
      }
    } catch (error) {
      console.error('Error fetching Facebook pages:', error);
      const err = error as Error;
      toast.error(err.message || 'An error occurred while loading Facebook pages');
    } finally {
      setLoadingPages(false);
    }
  };

  const fetchPreselectedContacts = async (contactIds: string[]) => {
    // Prevent multiple calls
    if (hasPreselectedContacts || fetchingContactsRef.current || isSettingPreselectedRef.current) {
      return;
    }
    
    isSettingPreselectedRef.current = true;
    fetchingContactsRef.current = true;
    setLoadingContacts(true);
    try {
      // Fetch contact details for preselected contacts
      const response = await fetch('/api/campaigns/preview-contacts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetingType: 'SPECIFIC_CONTACTS',
          targetContactIds: contactIds,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to fetch contacts');
      }

      const data = await response.json();
      if (data.contacts && data.contacts.length > 0) {
        // Only update if we don't already have these contacts loaded
        if (!hasPreselectedContacts) {
          // Set contacts first
          setTargetContacts(data.contacts);
          setHasPreselectedContacts(true);
          
          // Auto-select the first page if contacts have the same page
          const firstContact = data.contacts[0];
          if (firstContact.facebookPageId && facebookPages.length > 0) {
            const matchingPage = facebookPages.find(p => p.id === firstContact.facebookPageId);
            if (matchingPage) {
              // Use a small delay to batch state updates and prevent triggering other useEffects
              setTimeout(() => {
                setSelectedPageId(matchingPage.id);
              }, 50);
            }
          }
          
          // Determine platform from contacts
          const hasMessenger = data.contacts.some((c: any) => c.hasMessenger);
          const hasInstagram = data.contacts.some((c: any) => c.hasInstagram);
          if (hasMessenger && !hasInstagram) {
            setTimeout(() => {
              setPlatform('MESSENGER');
            }, 50);
          } else if (hasInstagram && !hasMessenger) {
            setTimeout(() => {
              setPlatform('INSTAGRAM');
            }, 50);
          }
          
          // Mark that we're done setting preselected contacts after a delay
          setTimeout(() => {
            isSettingPreselectedRef.current = false;
          }, 200);
          
          // Only show toast once - use a unique ID to prevent duplicates
          toast.success(`Loaded ${data.contacts.length} selected contact(s)`, {
            id: 'preselected-contacts-loaded', // Unique ID prevents duplicate toasts
          });
        } else {
          isSettingPreselectedRef.current = false;
        }
      } else {
        isSettingPreselectedRef.current = false;
      }
    } catch (error) {
      console.error('Error fetching preselected contacts:', error);
      const err = error as Error;
      toast.error(err.message || 'Failed to load preselected contacts');
      isSettingPreselectedRef.current = false;
    } finally {
      setLoadingContacts(false);
      fetchingContactsRef.current = false;
    }
  };

  const fetchTargetContacts = async () => {
    if (!selectedPageId || !platform) return;
    
    // Prevent multiple simultaneous calls
    if (loadingContacts || fetchingContactsRef.current || isSettingPreselectedRef.current) {
      return;
    }
    
    // Don't fetch if we have preselected contacts
    if (hasPreselectedContacts && targetContacts.length > 0) {
      return;
    }

    fetchingContactsRef.current = true;
    setLoadingContacts(true);
    try {
      const response = await fetch('/api/campaigns/preview-contacts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          facebookPageId: selectedPageId,
          platform,
          targetingType: selectedTags.length === 0 ? 'ALL_CONTACTS' : 'TAGS',
          targetTags: selectedTags,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to fetch contacts');
      }

      const data = await response.json();
      setTargetContacts(data.contacts || []);
      // Reset excluded contacts when contacts list changes
      setExcludedContactIds(new Set());
    } catch (error) {
      console.error('Error fetching target contacts:', error);
      const err = error as Error;
      toast.error(err.message || 'Failed to load target contacts');
    } finally {
      setLoadingContacts(false);
      fetchingContactsRef.current = false;
    }
  };

  const handleRemoveContact = (contactId: string) => {
    setExcludedContactIds((prev) => {
      const newSet = new Set(prev);
      newSet.add(contactId);
      return newSet;
    });
  };

  const handleRestoreContact = (contactId: string) => {
    setExcludedContactIds((prev) => {
      const newSet = new Set(prev);
      newSet.delete(contactId);
      return newSet;
    });
  };

  // Filter contacts based on search and exclusions
  const filteredContacts = targetContacts.filter((contact) => {
    // Filter by search query
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      const fullName = `${contact.firstName} ${contact.lastName}`.toLowerCase();
      const email = (contact.email || '').toLowerCase();
      const phone = (contact.phone || '').toLowerCase();
      
      if (!fullName.includes(query) && !email.includes(query) && !phone.includes(query)) {
        return false;
      }
    }
    
    // Filter out excluded contacts
    return !excludedContactIds.has(contact.id);
  });

  const displayedContacts = filteredContacts;
  const excludedCount = excludedContactIds.size;

  const handlePreviewPersonalizedMessage = async (contactId: string) => {
    // Use message content or default template when AI personalization is enabled
    const templateMessage = messageContent || (useAiPersonalization 
      ? 'Hello {firstName}! I wanted to reach out to you.' 
      : '');
    
    if (!templateMessage) {
      toast.error('Please enter a message template first');
      return;
    }

    setPreviewingContactId(contactId);
    setLoadingPreview(true);
    setPreviewMessage(null);

    try {
      const response = await fetch('/api/campaigns/preview-personalized-message', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contactId,
          templateMessage: templateMessage,
          customInstructions: aiCustomInstructions || undefined,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to generate preview');
      }

      const data = await response.json();
      setPreviewMessage(data.personalizedMessage);
    } catch (error) {
      console.error('Error generating preview:', error);
      const err = error as Error;
      toast.error(err.message || 'Failed to generate personalized message preview');
    } finally {
      setLoadingPreview(false);
    }
  };

  const handleCreate = async () => {
    if (!name) {
      toast.error('Please enter a campaign name');
      return;
    }

    // Message content is only required if AI personalization is disabled
    if (!useAiPersonalization && !messageContent) {
      toast.error('Please enter a message or enable AI personalization');
      return;
    }

    if (!selectedPageId) {
      toast.error('Please select a Facebook page');
      return;
    }

    if (platform === 'MESSENGER' && !messageTag) {
      toast.error('Please select a message tag for Messenger campaigns');
      return;
    }

    // Validate scheduling if enabled
    if (isScheduled) {
      if (!scheduledDate || !scheduledTime) {
        toast.error('Please select both date and time for scheduled campaign');
        return;
      }

      // Combine date and time and validate it's in the future
      const scheduledDateTime = new Date(`${scheduledDate}T${scheduledTime}`);
      if (scheduledDateTime <= new Date()) {
        toast.error('Scheduled time must be in the future');
        return;
      }
    }

    setCreating(true);

    try {
      // Use message content or default template when AI personalization is enabled
      const templateContent = messageContent || (useAiPersonalization 
        ? 'Hello {firstName}! I wanted to reach out to you.' 
        : '');
      
      // First create template
      const templateRes = await fetch('/api/templates', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: `${name} Template`,
          content: templateContent,
          platform,
        }),
      });

      // Check if response is JSON
      const templateContentType = templateRes.headers.get('content-type');
      if (!templateContentType?.includes('application/json')) {
        throw new Error('Server returned non-JSON response for template');
      }

      if (!templateRes.ok) {
        const errorData = await templateRes.json();
        toast.error(errorData.error || 'Failed to create template');
        setCreating(false);
        return;
      }

      const template = await templateRes.json();

      // Prepare scheduledAt if scheduling is enabled
      let scheduledAt: string | null = null;
      if (isScheduled && scheduledDate && scheduledTime) {
        // Create date in local timezone, then convert to ISO (UTC)
        // The date and time inputs are in user's local timezone
        const localDateTime = new Date(`${scheduledDate}T${scheduledTime}`);
        
        // Validate it's in the future
        if (localDateTime <= new Date()) {
          toast.error('Scheduled time must be in the future');
          setCreating(false);
          return;
        }
        
        scheduledAt = localDateTime.toISOString();
      }

      // Prepare target contact IDs (exclude removed contacts)
      const finalTargetContactIds = targetContacts
        .filter((contact) => !excludedContactIds.has(contact.id))
        .map((contact) => contact.id);

      // Check if contacts were preselected from URL
      const preselectedContacts = searchParams.get('contacts');
      const hasPreselectedContacts = preselectedContacts && preselectedContacts.split(',').length > 0;

      // If contacts were preselected or excluded, use SPECIFIC_CONTACTS targeting
      const finalTargetingType = (hasPreselectedContacts || excludedContactIds.size > 0)
        ? 'SPECIFIC_CONTACTS' 
        : (selectedTags.length === 0 ? 'ALL_CONTACTS' : 'TAGS');

      // Use background job API for campaign creation with AI messages
      // This allows generation to continue even if user navigates away
      const campaignRes = await fetch('/api/campaigns/create-with-messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name,
          platform,
          messageTag: messageTag && messageTag !== 'NONE' ? messageTag : null,
          facebookPageId: selectedPageId,
          templateId: template.id,
          targetingType: finalTargetingType,
          targetTags: selectedTags,
          targetContactIds: finalTargetingType === 'SPECIFIC_CONTACTS' ? finalTargetContactIds : undefined,
          scheduledAt,
          autoFetchEnabled: isScheduled ? autoFetchEnabled : false,
          useAiPersonalization: useAiPersonalization || undefined,
          aiCustomInstructions: useAiPersonalization && aiCustomInstructions ? aiCustomInstructions : undefined,
          templateContent: templateContent, // Pass template for background generation
        }),
      });

      // Check if response is JSON
      const campaignContentType = campaignRes.headers.get('content-type');
      if (!campaignContentType?.includes('application/json')) {
        throw new Error('Server returned non-JSON response for campaign');
      }

      if (campaignRes.ok) {
        const campaign = await campaignRes.json();
        const recipientCount = targetContacts.length - excludedContactIds.size;
        
        // Show success message immediately and allow navigation
        if (campaign.messageGenerationInProgress) {
          toast.success('Campaign created! AI messages are being generated in the background. You can navigate away safely.', {
            duration: 8000,
          });
        } else if (isScheduled && scheduledAt) {
          if (recipientCount > 0) {
            toast.success(`Campaign scheduled successfully! It will be sent to ${recipientCount} contact${recipientCount !== 1 ? 's' : ''} at the scheduled time.`);
          } else {
            toast.success('Campaign scheduled successfully! Recipients will be determined when the campaign is sent at the scheduled time.');
          }
        } else {
          if (recipientCount > 0) {
            toast.success(`Campaign created successfully! ${recipientCount} contact${recipientCount !== 1 ? 's' : ''} will receive the message.`);
          } else {
            toast.success('Campaign created successfully!');
          }
        }
        
        // Reset creating state immediately to allow navigation
        setCreating(false);
        
        // Navigate immediately - background jobs will continue
        router.push(`/campaigns/${campaign.id}`);
        
        // Don't wait for anything else - return immediately
        return;
      } else {
        const data = await campaignRes.json();
        toast.error(data.error || 'Failed to create campaign');
      }
    } catch (error) {
      console.error('Error creating campaign:', error);
      const err = error as Error;
      toast.error(err.message || 'An error occurred while creating campaign');
      setCreating(false);
    }
    // Note: setCreating(false) is called before navigation in success case
    // to allow immediate navigation without waiting
  };

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      <div className="space-y-2">
        <h1 className="text-4xl font-bold tracking-tight">Create Campaign</h1>
        <p className="text-muted-foreground text-lg">Set up a new bulk messaging campaign</p>
      </div>

      <Card className="border-border/50 shadow-sm">
        <CardHeader className="space-y-1.5 pb-6">
          <CardTitle className="text-2xl">Campaign Details</CardTitle>
          <p className="text-sm text-muted-foreground">Configure your campaign settings and target audience</p>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-2.5">
            <Label className="text-sm font-semibold">Campaign Name *</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., Summer Promotion"
              className="h-11 rounded-xl border-border/50 focus-visible:ring-primary/30"
            />
          </div>

          <div className="space-y-2.5">
            <Label className="text-sm font-semibold">Facebook Page *</Label>
            <Select 
              value={selectedPageId} 
              onValueChange={setSelectedPageId}
              disabled={loadingPages || facebookPages.length === 0}
            >
              <SelectTrigger className="h-11 rounded-xl border-border/50">
                <SelectValue placeholder={
                  loadingPages 
                    ? "Loading pages..." 
                    : facebookPages.length === 0 
                      ? "No pages connected"
                      : "Select a Facebook page..."
                } />
              </SelectTrigger>
              <SelectContent className="rounded-xl">
                {facebookPages.length === 0 ? (
                  <div className="p-2 text-sm text-muted-foreground text-center">
                    No Facebook pages connected
                  </div>
                ) : (
                  facebookPages.map((page) => (
                    <SelectItem key={page.id} value={page.id} className="rounded-lg">
                      {page.pageName}
                    </SelectItem>
                  ))
                )}
              </SelectContent>
            </Select>
            {!loadingPages && facebookPages.length === 0 && (
              <div className="mt-3 p-4 bg-amber-50/50 border border-amber-200/50 rounded-xl">
                <p className="text-sm text-amber-900">
                  ⚠️ No Facebook pages connected. Please connect a Facebook page in{' '}
                  <Link href="/settings/integrations" className="underline font-semibold hover:text-amber-950">
                    Settings → Integrations
                  </Link>{' '}
                  before creating a campaign.
                </p>
              </div>
            )}
          </div>

          <div className="space-y-2.5">
            <Label className="text-sm font-semibold">Platform *</Label>
            <Select value={platform} onValueChange={setPlatform}>
              <SelectTrigger className="h-11 rounded-xl border-border/50">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="rounded-xl">
                <SelectItem value="MESSENGER" className="rounded-lg">Facebook Messenger</SelectItem>
                <SelectItem value="INSTAGRAM" className="rounded-lg">Instagram DM</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {platform === 'MESSENGER' && (
            <div className="space-y-2.5">
              <Label className="text-sm font-semibold">Message Tag *</Label>
              <p className="text-xs text-muted-foreground">
                Required by Facebook to send messages outside 24-hour window
              </p>
              <Select value={messageTag} onValueChange={setMessageTag}>
                <SelectTrigger className="h-11 rounded-xl border-border/50">
                  <SelectValue placeholder="Select a message tag..." />
                </SelectTrigger>
                <SelectContent className="rounded-xl">
                  {Object.values(MESSAGE_TAGS).map((tag) => (
                    <SelectItem key={tag.value} value={tag.value} className="rounded-lg">
                      {tag.icon} {tag.label}
                    </SelectItem>
                  ))}
                  <SelectItem value="NONE" className="rounded-lg text-muted-foreground">
                    ⚠️ None (Only for contacts who messaged within 24hrs)
                  </SelectItem>
                </SelectContent>
              </Select>
              {messageTag === 'NONE' && (
                <div className="mt-2 p-3 bg-amber-50/50 border border-amber-200/50 rounded-xl">
                  <p className="text-xs text-amber-900">
                    ⚠️ <strong>Warning:</strong> Messages will only be sent to contacts who messaged your page within the last 24 hours. Use a message tag to send to all contacts.
                  </p>
                </div>
              )}
              {!messageTag && (
                <div className="mt-2 p-3 bg-blue-50/50 border border-blue-200/50 rounded-xl">
                  <p className="text-xs text-blue-900">
                    ℹ️ Facebook requires message tags to send messages outside the 24-hour window. Select a tag that matches your message purpose.
                  </p>
                </div>
              )}
            </div>
          )}

          <div className="space-y-2.5">
            <Label className="text-sm font-semibold">Target Audience (Optional)</Label>
            <p className="text-xs text-muted-foreground">
              Select tags to target specific contacts, or leave empty to target all contacts
            </p>
            {selectedTags.length === 0 && tags.length > 0 && (
              <div className="mt-2 p-3 bg-blue-50/50 border border-blue-200/50 rounded-xl">
                <p className="text-xs text-blue-900">
                  ℹ️ No tags selected - campaign will be sent to <strong>all contacts</strong> on the selected page
                </p>
              </div>
            )}
            <div className="mt-3 space-y-2.5">
              {tags.length === 0 ? (
                <div className="p-6 border border-dashed border-border/50 rounded-xl text-center bg-muted/20">
                  <p className="text-sm text-muted-foreground mb-2 font-medium">No tags available</p>
                  <p className="text-xs text-muted-foreground">
                    Create tags in{' '}
                    <Link href="/tags" className="underline font-semibold hover:text-foreground transition-colors">
                      Tags page
                    </Link>{' '}
                    to organize your contacts
                  </p>
                </div>
              ) : (
                tags.map((tag) => (
                  <div
                    key={tag.id}
                    className={`p-4 border rounded-xl cursor-pointer transition-all duration-200 ${
                      selectedTags.includes(tag.name) 
                        ? 'border-primary bg-primary/5 shadow-sm ring-1 ring-primary/20' 
                        : 'border-border/50 hover:border-primary/50 hover:bg-accent/50'
                    }`}
                    onClick={() => {
                      if (selectedTags.includes(tag.name)) {
                        setSelectedTags(selectedTags.filter((t) => t !== tag.name));
                      } else {
                        setSelectedTags([...selectedTags, tag.name]);
                      }
                    }}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div
                          className="w-3.5 h-3.5 rounded-full ring-2 ring-background shadow-sm"
                          style={{ backgroundColor: tag.color }}
                        />
                        <span className="font-semibold text-sm">{tag.name}</span>
                      </div>
                      <Badge variant="secondary" className="rounded-lg">{tag.contactCount} contacts</Badge>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="space-y-2.5">
            <Label className="text-sm font-semibold">
              Message Content {useAiPersonalization ? '(Optional)' : '*'}
            </Label>
            {useAiPersonalization && (
              <div className="p-3 bg-blue-50/50 border border-blue-200/50 rounded-lg mb-2">
                <p className="text-xs text-blue-900">
                  💡 <strong>AI Personalization Enabled:</strong> You can leave this empty and AI will generate unique messages for each contact based on their conversation history and context. 
                  Or provide a template message that AI will personalize for each contact.
                </p>
              </div>
            )}
            <Textarea
              value={messageContent}
              onChange={(e) => setMessageContent(e.target.value)}
              placeholder={
                useAiPersonalization 
                  ? "Optional: Enter a template message for AI to personalize, or leave empty for AI to generate from scratch..."
                  : "Enter your message... Use {firstName}, {lastName} for personalization"
              }
              rows={6}
              className="rounded-xl border-border/50 resize-none focus-visible:ring-primary/30"
            />
            {!useAiPersonalization && (
              <p className="text-xs text-muted-foreground mt-2 flex items-center gap-1.5">
                <span className="font-medium">Available variables:</span>
                <code className="px-1.5 py-0.5 rounded bg-muted text-foreground">{'{firstName}'}</code>
                <code className="px-1.5 py-0.5 rounded bg-muted text-foreground">{'{lastName}'}</code>
                <code className="px-1.5 py-0.5 rounded bg-muted text-foreground">{'{name}'}</code>
              </p>
            )}
          </div>

          {/* AI Personalization Section */}
          <div className="space-y-4 pt-2 border-t border-border/50">
            <div className="flex items-center space-x-3">
              <Switch
                id="ai-personalization"
                checked={useAiPersonalization}
                onCheckedChange={setUseAiPersonalization}
              />
              <div className="flex-1">
                <Label 
                  htmlFor="ai-personalization" 
                  className="text-sm font-semibold cursor-pointer flex items-center gap-2"
                >
                  <Sparkles className="h-4 w-4 text-primary" />
                  AI Personalization
                </Label>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Generate personalized messages for each contact based on their conversation history and context
                </p>
              </div>
            </div>

            {useAiPersonalization && (
              <div className="ml-8 space-y-4 p-4 bg-muted/30 rounded-xl border border-border/50">
                <div className="space-y-2.5">
                  <Label className="text-sm font-semibold">Custom Prompt Instructions (Optional)</Label>
                  <Textarea
                    value={aiCustomInstructions}
                    onChange={(e) => setAiCustomInstructions(e.target.value)}
                    placeholder="e.g., Keep the tone professional, mention their last purchase, or focus on their specific interests..."
                    rows={4}
                    className="rounded-xl border-border/50 resize-none focus-visible:ring-primary/30"
                  />
                  <p className="text-xs text-muted-foreground">
                    Provide additional instructions to customize how AI generates personalized messages. 
                    The AI will use the contact's conversation history and context to create unique messages for each recipient.
                  </p>
                </div>

                <div className="p-3 bg-blue-50/50 border border-blue-200/50 rounded-lg space-y-2">
                  <p className="text-xs text-blue-900">
                    ✨ <strong>How it works:</strong> The AI will analyze each contact's conversation history, 
                    AI context, and your template message to create a personalized version that feels natural and relevant.
                  </p>
                  {aiCustomInstructions && (
                    <p className="text-xs text-blue-900">
                      📝 <strong>Custom instructions:</strong> Your prompt will guide the AI to follow specific 
                      tone, style, or content requirements when generating messages.
                    </p>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Target Contacts Preview */}
          {selectedPageId ? (
            <div className="space-y-4 pt-2 border-t border-border/50">
              <div className="flex items-center justify-between">
                <div>
                  <Label className="text-sm font-semibold flex items-center gap-2">
                    <Users className="h-4 w-4" />
                    Recipients Preview
                  </Label>
                  <p className="text-xs text-muted-foreground mt-1">
                    {loadingContacts ? (
                      'Loading contacts...'
                    ) : (
                      <>
                        {targetContacts.length > 0 ? (
                          <>
                            <span className="font-medium text-foreground">
                              {displayedContacts.length} of {targetContacts.length} contact{targetContacts.length !== 1 ? 's' : ''}
                            </span>
                            {' will receive this message'}
                            {excludedCount > 0 && (
                              <span className="text-amber-600 ml-2 font-medium">
                                ({excludedCount} excluded)
                              </span>
                            )}
                          </>
                        ) : (
                          <span className="text-amber-600">
                            ⚠️ No contacts found matching your criteria. Please check your page selection, platform, and tags.
                          </span>
                        )}
                      </>
                    )}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  {targetContacts.length > 0 && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={fetchTargetContacts}
                      disabled={loadingContacts}
                      className="h-8"
                    >
                      {loadingContacts ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        'Refresh'
                      )}
                    </Button>
                  )}
                </div>
              </div>

              {loadingContacts ? (
                <div className="p-8 border border-dashed border-border/50 rounded-xl text-center bg-muted/20">
                  <Loader2 className="h-6 w-6 animate-spin mx-auto mb-2 text-muted-foreground" />
                  <p className="text-sm text-muted-foreground">Loading contacts...</p>
                </div>
              ) : targetContacts.length > 0 ? (
                <div className="space-y-3">
                  {/* Search Box */}
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                      type="text"
                      placeholder="Search contacts by name, email, or phone..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="pl-10 h-11 rounded-xl border-border/50 focus-visible:ring-primary/30"
                    />
                  </div>

                  {/* Contacts List */}
                  <div className="max-h-96 overflow-y-auto border border-border/50 rounded-xl divide-y divide-border/50">
                    {displayedContacts.length === 0 ? (
                      <div className="p-6 text-center">
                        <p className="text-sm text-muted-foreground">
                          {searchQuery ? 'No contacts match your search' : 'All contacts have been excluded'}
                        </p>
                        {excludedCount > 0 && (
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            onClick={() => setExcludedContactIds(new Set())}
                            className="mt-2"
                          >
                            Restore all excluded contacts
                          </Button>
                        )}
                      </div>
                    ) : (
                      displayedContacts.map((contact) => (
                        <div
                          key={contact.id}
                          className="p-4 hover:bg-accent/50 transition-colors"
                        >
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-1">
                                <p className="font-semibold text-sm truncate">
                                  {contact.firstName} {contact.lastName}
                                </p>
                                {contact.tags && contact.tags.length > 0 && (
                                  <div className="flex gap-1 flex-wrap">
                                    {contact.tags.slice(0, 2).map((tag) => (
                                      <Badge key={tag} variant="secondary" className="text-xs">
                                        {tag}
                                      </Badge>
                                    ))}
                                    {contact.tags.length > 2 && (
                                      <Badge variant="secondary" className="text-xs">
                                        +{contact.tags.length - 2}
                                      </Badge>
                                    )}
                                  </div>
                                )}
                              </div>
                              <div className="flex gap-4 text-xs text-muted-foreground">
                                {contact.email && (
                                  <span className="truncate">{contact.email}</span>
                                )}
                                {contact.phone && (
                                  <span className="truncate">{contact.phone}</span>
                                )}
                              </div>
                            </div>
                            <div className="flex items-center gap-2 ml-4">
                              {useAiPersonalization && (
                                <Button
                                  type="button"
                                  variant="outline"
                                  size="sm"
                                  onClick={() => handlePreviewPersonalizedMessage(contact.id)}
                                  disabled={loadingPreview && previewingContactId === contact.id}
                                  className="h-8 text-xs"
                                >
                                  {loadingPreview && previewingContactId === contact.id ? (
                                    <>
                                      <Loader2 className="h-3 w-3 animate-spin mr-1" />
                                      Generating...
                                    </>
                                  ) : (
                                    <>
                                      <Eye className="h-3 w-3 mr-1" />
                                      Preview
                                    </>
                                  )}
                                </Button>
                              )}
                              <Button
                                type="button"
                                variant="ghost"
                                size="sm"
                                onClick={() => handleRemoveContact(contact.id)}
                                className="h-8 w-8 p-0 text-destructive hover:text-destructive hover:bg-destructive/10"
                              >
                                <X className="h-4 w-4" />
                              </Button>
                            </div>
                          </div>
                          {previewingContactId === contact.id && previewMessage && (
                            <div className="mt-3 p-3 bg-primary/5 border border-primary/20 rounded-lg">
                              <p className="text-xs font-semibold text-primary mb-2">AI Personalized Preview:</p>
                              <p className="text-sm text-foreground whitespace-pre-wrap">{previewMessage}</p>
                            </div>
                          )}
                        </div>
                      ))
                    )}
                  </div>

                  {/* Excluded Contacts Section */}
                  {excludedCount > 0 && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <Label className="text-sm font-semibold text-muted-foreground">
                          Excluded Contacts ({excludedCount})
                        </Label>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          onClick={() => setExcludedContactIds(new Set())}
                          className="h-7 text-xs"
                        >
                          Restore All
                        </Button>
                      </div>
                      <div className="max-h-32 overflow-y-auto border border-border/50 rounded-xl divide-y divide-border/50 bg-muted/20">
                        {targetContacts
                          .filter((contact) => excludedContactIds.has(contact.id))
                          .map((contact) => (
                            <div
                              key={contact.id}
                              className="p-3 flex items-center justify-between text-sm"
                            >
                              <span className="text-muted-foreground truncate">
                                {contact.firstName} {contact.lastName}
                              </span>
                              <Button
                                type="button"
                                variant="ghost"
                                size="sm"
                                onClick={() => handleRestoreContact(contact.id)}
                                className="ml-4 h-6 w-6 p-0 text-primary hover:text-primary hover:bg-primary/10"
                              >
                                <X className="h-3 w-3 rotate-45" />
                              </Button>
                            </div>
                          ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="p-6 border border-dashed border-amber-200/50 rounded-xl text-center bg-amber-50/30">
                  <Users className="h-8 w-8 mx-auto mb-2 text-amber-600" />
                  <p className="text-sm font-semibold text-amber-900 mb-2">No contacts found</p>
                  <p className="text-xs text-amber-800 mb-3">
                    No contacts match your selected criteria. This could be because:
                  </p>
                  <ul className="text-xs text-amber-800 text-left space-y-1 max-w-md mx-auto mb-3">
                    <li>• No contacts have {platform === 'MESSENGER' ? 'Messenger' : 'Instagram'} enabled</li>
                    <li>• Selected tags don't match any contacts</li>
                    <li>• Contacts haven't been synced from Facebook yet</li>
                  </ul>
                  <div className="flex gap-2 justify-center">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={fetchTargetContacts}
                      disabled={loadingContacts}
                      className="h-8 text-xs"
                    >
                      {loadingContacts ? (
                        <Loader2 className="h-3 w-3 animate-spin mr-1" />
                      ) : (
                        'Try Again'
                      )}
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => router.push('/contacts')}
                      className="h-8 text-xs"
                    >
                      View Contacts
                    </Button>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="space-y-4 pt-2 border-t border-border/50">
              <div className="p-4 border border-dashed border-border/50 rounded-xl bg-muted/20">
                <p className="text-sm text-muted-foreground flex items-center gap-2">
                  <Users className="h-4 w-4" />
                  <span>
                    <strong>Recipients Preview</strong> will appear after you select a Facebook page
                  </span>
                </p>
              </div>
            </div>
          )}

          <div className="space-y-4 pt-2 border-t border-border/50">
            <div className="flex items-center space-x-3">
              <Checkbox
                id="schedule-campaign"
                checked={isScheduled}
                onCheckedChange={(checked) => setIsScheduled(checked === true)}
                className="rounded-md"
              />
              <div className="flex-1">
                <Label 
                  htmlFor="schedule-campaign" 
                  className="text-sm font-semibold cursor-pointer"
                >
                  Schedule this campaign
                </Label>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Send this campaign automatically at a specific date and time
                </p>
              </div>
            </div>

            {isScheduled && (
              <div className="ml-8 space-y-4 p-4 bg-muted/30 rounded-xl border border-border/50">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2.5">
                    <Label className="text-sm font-semibold flex items-center gap-2">
                      <CalendarIcon className="h-4 w-4" />
                      Schedule Date *
                    </Label>
                    <Input
                      type="date"
                      value={scheduledDate}
                      onChange={(e) => setScheduledDate(e.target.value)}
                      min={new Date().toISOString().split('T')[0]}
                      className="h-11 rounded-xl border-border/50 focus-visible:ring-primary/30"
                    />
                    {scheduledDate && (
                      <p className="text-xs text-muted-foreground">
                        Selected: {new Date(scheduledDate).toLocaleDateString('en-US', { 
                          weekday: 'long', 
                          year: 'numeric', 
                          month: 'long', 
                          day: 'numeric' 
                        })}
                      </p>
                    )}
                  </div>

                  <div className="space-y-2.5">
                    <Label className="text-sm font-semibold flex items-center gap-2">
                      <Clock className="h-4 w-4" />
                      Schedule Time *
                    </Label>
                    <Input
                      type="time"
                      value={scheduledTime}
                      onChange={(e) => setScheduledTime(e.target.value)}
                      className="h-11 rounded-xl border-border/50 focus-visible:ring-primary/30"
                    />
                    {scheduledDate && scheduledTime && (
                      <p className="text-xs text-muted-foreground">
                        {(() => {
                          const scheduledDateTime = new Date(`${scheduledDate}T${scheduledTime}`);
                          const now = new Date();
                          const diff = scheduledDateTime.getTime() - now.getTime();
                          const hours = Math.floor(diff / (1000 * 60 * 60));
                          const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
                          
                          if (diff < 0) {
                            return '⚠️ This time is in the past';
                          } else if (hours < 1) {
                            return `⏰ Sending in ${minutes} minute${minutes !== 1 ? 's' : ''}`;
                          } else {
                            return `⏰ Sending in ${hours} hour${hours !== 1 ? 's' : ''} and ${minutes} minute${minutes !== 1 ? 's' : ''}`;
                          }
                        })()}
                      </p>
                    )}
                  </div>
                </div>

                {/* Auto-Fetch Toggle */}
                <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg border border-border/50">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <RefreshCw className="h-4 w-4 text-muted-foreground" />
                      <Label htmlFor="auto-fetch" className="text-sm font-semibold cursor-pointer">
                        Auto-fetch new conversations
                      </Label>
                    </div>
                    <p className="text-xs text-muted-foreground ml-6">
                      Automatically fetch newly added conversations from Facebook and include them in this campaign when it sends
                    </p>
                  </div>
                  <Switch
                    id="auto-fetch"
                    checked={autoFetchEnabled}
                    onCheckedChange={setAutoFetchEnabled}
                  />
                </div>

                <div className="p-3 bg-blue-50/50 border border-blue-200/50 rounded-lg space-y-2">
                  <p className="text-xs text-blue-900">
                    ℹ️ <strong>Scheduled campaigns</strong> will be automatically sent by the system at the specified time. 
                    You can view and manage scheduled campaigns from the campaigns page.
                  </p>
                  {autoFetchEnabled && (
                    <p className="text-xs text-blue-900">
                      🔄 <strong>Auto-fetch enabled:</strong> The system will fetch fresh conversations from Facebook right before sending, 
                      ensuring new contacts are included in this campaign.
                    </p>
                  )}
                  {targetContacts.length === 0 && !autoFetchEnabled && (
                    <p className="text-xs text-blue-900">
                      📋 <strong>Note:</strong> Recipients will be fetched automatically when the campaign is sent. 
                      If you want to preview recipients now, make sure you've selected a Facebook page and the contacts are synced.
                    </p>
                  )}
                </div>
              </div>
            )}
          </div>

          <div className="flex gap-3 pt-4">
            <Button 
              variant="outline" 
              onClick={() => router.push('/campaigns')}
              className="rounded-xl h-11 px-6"
            >
              Cancel
            </Button>
            <Button 
              onClick={handleCreate} 
              disabled={creating || facebookPages.length === 0} 
              className="flex-1 rounded-xl h-11 shadow-sm hover:shadow-md transition-all"
            >
              {creating ? 'Creating...' : 'Create Campaign'}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

