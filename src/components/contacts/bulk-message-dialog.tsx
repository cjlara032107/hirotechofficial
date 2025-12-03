'use client';

import { useState, useRef } from 'react';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { toast } from 'sonner';
import { Upload, X, Image, Video, Loader2 } from 'lucide-react';
import { MESSAGE_TAGS } from '@/lib/facebook/message-tags';

interface BulkMessageDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  contactIds: string[];
  onSuccess: () => void;
}

export function BulkMessageDialog({
  open,
  onOpenChange,
  contactIds,
  onSuccess,
}: BulkMessageDialogProps) {
  const [message, setMessage] = useState('');
  const [platform, setPlatform] = useState<'MESSENGER' | 'INSTAGRAM'>('MESSENGER');
  const [messageTag, setMessageTag] = useState<string>('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [mediaUrl, setMediaUrl] = useState<string | null>(null);
  const [mediaType, setMediaType] = useState<'image' | 'video' | null>(null);
  const [uploading, setUploading] = useState(false);
  const [sending, setSending] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB (reduced for Vercel)

  async function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;

    // Validate file size
    if (file.size > MAX_FILE_SIZE) {
      toast.error(`File size must be less than 10MB. Current size: ${(file.size / 1024 / 1024).toFixed(2)}MB`);
      return;
    }

    // Validate file type
    const isImage = file.type.startsWith('image/');
    const isVideo = file.type.startsWith('video/');

    if (!isImage && !isVideo) {
      toast.error('File must be an image or video');
      return;
    }

    setSelectedFile(file);
    setMediaType(isImage ? 'image' : 'video');

    // Upload file
    setUploading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch('/api/messages/upload-media', {
        method: 'POST',
        body: formData,
      });

      // Check if response is JSON
      const contentType = response.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        const text = await response.text();
        throw new Error(text || 'Server returned non-JSON response');
      }

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to upload file');
      }

      setMediaUrl(data.mediaUrl);
      toast.success('File uploaded successfully');
    } catch (error: unknown) {
      let errorMessage = 'Failed to upload file';
      if (error instanceof Error) {
        errorMessage = error.message;
      } else if (typeof error === 'string') {
        errorMessage = error;
      }
      toast.error(errorMessage);
      setSelectedFile(null);
      setMediaType(null);
      setMediaUrl(null);
    } finally {
      setUploading(false);
    }
  }

  function handleRemoveFile() {
    setSelectedFile(null);
    setMediaUrl(null);
    setMediaType(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  }

  async function handleSend() {
    if (!message.trim() && !mediaUrl) {
      toast.error('Please enter a message or upload a file');
      return;
    }

    setSending(true);
    try {
      const response = await fetch('/api/contacts/bulk-message', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contactIds,
          message: message.trim() || undefined,
          mediaUrl: mediaUrl || undefined,
          mediaType: mediaType || undefined,
          platform,
          messageTag: messageTag && messageTag !== 'NONE' ? messageTag : undefined,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to send messages');
      }

      toast.success(
        `Successfully sent ${data.sent} message(s)${data.failed > 0 ? `, ${data.failed} failed` : ''}`
      );

      // Reset form
      setMessage('');
      setSelectedFile(null);
      setMediaUrl(null);
      setMediaType(null);
      setMessageTag('');
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }

      onSuccess();
      onOpenChange(false);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to send messages';
      toast.error(errorMessage);
    } finally {
      setSending(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[600px]">
        <DialogHeader>
          <DialogTitle>Send Bulk Message</DialogTitle>
          <DialogDescription>
            Send a message to {contactIds.length} selected contact(s)
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          <div className="space-y-2">
            <Label htmlFor="platform">Platform *</Label>
            <Select value={platform} onValueChange={(value) => setPlatform(value as 'MESSENGER' | 'INSTAGRAM')}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="MESSENGER">Messenger</SelectItem>
                <SelectItem value="INSTAGRAM">Instagram</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="message">Message</Label>
            <Textarea
              id="message"
              placeholder="Enter your message (optional if sending media)"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              rows={4}
            />
          </div>

          <div className="space-y-2">
            <Label>Media (Photo or Video)</Label>
            <div className="flex items-center gap-2">
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*,video/*"
                onChange={handleFileSelect}
                className="hidden"
                id="media-upload"
              />
              <Button
                type="button"
                variant="outline"
                onClick={() => fileInputRef.current?.click()}
                disabled={uploading || sending}
              >
                <Upload className="h-4 w-4 mr-2" />
                {uploading ? 'Uploading...' : 'Upload Media'}
              </Button>
              <span className="text-sm text-muted-foreground">Max 25MB</span>
            </div>

            {selectedFile && (
              <div className="flex items-center gap-2 p-3 border rounded-md">
                {mediaType === 'image' ? (
                  <Image className="h-5 w-5 text-blue-500" aria-label="Image file" />
                ) : (
                  <Video className="h-5 w-5 text-purple-500" aria-label="Video file" />
                )}
                <span className="flex-1 text-sm truncate">{selectedFile.name}</span>
                <span className="text-xs text-muted-foreground">
                  {(selectedFile.size / 1024 / 1024).toFixed(2)}MB
                </span>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={handleRemoveFile}
                  disabled={uploading || sending}
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="messageTag">Message Tag (Optional)</Label>
            <Select value={messageTag || undefined} onValueChange={(value) => setMessageTag(value === 'NONE' ? '' : value)}>
              <SelectTrigger>
                <SelectValue placeholder="Select message tag" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="NONE">None</SelectItem>
                {Object.values(MESSAGE_TAGS).map((tag) => (
                  <SelectItem key={tag.value} value={tag.value}>
                    {tag.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              Required for sending messages outside the 24-hour window
            </p>
          </div>
        </div>

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={sending || uploading}
          >
            Cancel
          </Button>
          <Button
            type="button"
            onClick={handleSend}
            disabled={sending || uploading || (!message.trim() && !mediaUrl)}
          >
            {sending ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Sending...
              </>
            ) : (
              `Send to ${contactIds.length} contact(s)`
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

