import { unlink } from 'fs/promises';
import { join } from 'path';
import { existsSync } from 'fs';

/**
 * Delete media file associated with a campaign
 * @param mediaUrl - Full URL or relative path to the media file
 * @param mediaType - Type of media ('image' or 'video')
 */
export async function deleteCampaignMedia(
  mediaUrl: string | null | undefined,
  mediaType: string | null | undefined
): Promise<void> {
  if (!mediaUrl || !mediaType) {
    return; // No media to delete
  }

  try {
    // Extract the relative path from the URL
    // mediaUrl could be:
    // - Full URL: https://example.com/uploads/messages/images/file.jpg
    // - Relative path: /uploads/messages/images/file.jpg
    // - Local path: uploads/messages/images/file.jpg
    
    let relativePath = mediaUrl;
    
    // Remove protocol and domain if present
    if (mediaUrl.startsWith('http://') || mediaUrl.startsWith('https://')) {
      const url = new URL(mediaUrl);
      relativePath = url.pathname;
    }
    
    // Remove leading slash if present
    if (relativePath.startsWith('/')) {
      relativePath = relativePath.substring(1);
    }
    
    // Build the full file path
    const filePath = join(process.cwd(), 'public', relativePath);
    
    // Verify the file exists before attempting to delete
    if (existsSync(filePath)) {
      await unlink(filePath);
      console.log(`✅ Deleted campaign media file: ${filePath}`);
    } else {
      console.warn(`⚠️ Campaign media file not found (may have been already deleted): ${filePath}`);
    }
  } catch (error) {
    // Log error but don't throw - we don't want media deletion failures to break campaign completion
    console.error(`❌ Failed to delete campaign media file (${mediaUrl}):`, error);
  }
}









