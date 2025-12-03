import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { writeFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { existsSync } from 'fs';

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB (reduced for Vercel)
const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
const ALLOWED_VIDEO_TYPES = ['video/mp4', 'video/mpeg', 'video/quicktime', 'video/x-msvideo'];
const UPLOAD_TIMEOUT = 10000; // 10 seconds (much shorter to prevent 504)

export async function POST(request: NextRequest) {
  const uploadStartTime = Date.now();
  
  try {
    const session = await auth();
    
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Set timeout for the entire operation
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(new Error('Upload timeout - request took too long'));
      }, UPLOAD_TIMEOUT);
    });

    const uploadPromise = (async () => {
      const formData = await request.formData();
      const file = formData.get('file') as File;

      if (!file) {
        return NextResponse.json(
          { error: 'No file provided' },
          { status: 400 }
        );
      }

      // Validate file size (25MB max)
      if (file.size > MAX_FILE_SIZE) {
        return NextResponse.json(
          { error: `File size must be less than 25MB. Current size: ${(file.size / 1024 / 1024).toFixed(2)}MB` },
          { status: 400 }
        );
      }

      // Validate file type
      const isImage = ALLOWED_IMAGE_TYPES.includes(file.type);
      const isVideo = ALLOWED_VIDEO_TYPES.includes(file.type);

      if (!isImage && !isVideo) {
        return NextResponse.json(
          { error: 'File must be an image (JPEG, PNG, GIF, WebP) or video (MP4, MPEG, MOV, AVI)' },
          { status: 400 }
        );
      }

      // For Vercel/serverless, always use base64 data URL (no filesystem writes)
      // This is faster and works in serverless environments
      const isVercel = process.env.VERCEL === '1' || process.env.NODE_ENV === 'production';
      
      if (isVercel) {
        // Convert to base64 data URL (works in serverless)
        const bytes = await file.arrayBuffer();
        const buffer = Buffer.from(bytes);
        const base64 = buffer.toString('base64');
        const dataUrl = `data:${file.type};base64,${base64}`;
        
        return NextResponse.json({
          mediaUrl: dataUrl,
          localUrl: dataUrl,
          mediaType: isImage ? 'image' : 'video',
          fileName: file.name,
          size: file.size,
          message: 'File uploaded successfully',
        });
      } else {
        // Local development - use filesystem
        const bytes = await file.arrayBuffer();
        const buffer = Buffer.from(bytes);

        // Create unique filename
        const timestamp = Date.now();
        const fileExtension = file.name.split('.').pop() || (isImage ? 'jpg' : 'mp4');
        const fileName = `${session.user.id}-${timestamp}.${fileExtension}`;
        const mediaType = isImage ? 'images' : 'videos';

        // Create uploads directory if it doesn't exist
        const uploadsDir = join(process.cwd(), 'public', 'uploads', 'messages', mediaType);
        if (!existsSync(uploadsDir)) {
          await mkdir(uploadsDir, { recursive: true });
        }

        // Save file
        const filePath = join(uploadsDir, fileName);
        await writeFile(filePath, buffer);

        // Return public URL and metadata
        const mediaUrl = `/uploads/messages/${mediaType}/${fileName}`;
        const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';
        const fullUrl = `${baseUrl}${mediaUrl}`;

        return NextResponse.json({
          mediaUrl: fullUrl,
          localUrl: mediaUrl,
          mediaType: isImage ? 'image' : 'video',
          fileName: file.name,
          size: file.size,
          message: 'File uploaded successfully',
        });
      }
    })();

    // Race between upload and timeout
    return await Promise.race([uploadPromise, timeoutPromise]);
  } catch (error) {
    const elapsed = Date.now() - uploadStartTime;
    const errorMessage = error instanceof Error ? error.message : 'Failed to upload file';
    
    console.error('Media upload error:', errorMessage, { elapsed });
    
    // Always return JSON, even on timeout
    try {
      // Check if it's a timeout
      if (errorMessage.includes('timeout') || elapsed >= UPLOAD_TIMEOUT) {
        return NextResponse.json(
          { error: 'Upload timed out. Please try a smaller file (max 10MB) or check your connection.' },
          { status: 408 }
        );
      }
      
      // Check if it's a filesystem error (likely Vercel)
      if (errorMessage.includes('EACCES') || errorMessage.includes('EROFS') || errorMessage.includes('read-only')) {
        return NextResponse.json(
          { error: 'File upload error. Please try a smaller file or contact support.' },
          { status: 503 }
        );
      }
      
      return NextResponse.json(
        { error: errorMessage },
        { status: 500 }
      );
    } catch (jsonError) {
      // Fallback if JSON creation fails
      console.error('Failed to create error response:', jsonError);
      return new NextResponse(
        JSON.stringify({ error: 'An unexpected error occurred' }),
        { 
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
  }
}









