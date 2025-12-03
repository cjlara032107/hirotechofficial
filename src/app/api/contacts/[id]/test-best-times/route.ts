import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { computeAndStoreBestContactTimes } from '@/lib/contacts/compute-contact-times';

interface RouteParams {
  params: Promise<{ id: string }>;
}

/**
 * GET /api/contacts/[id]/test-best-times
 * Diagnostic endpoint to test best contact times computation
 */
export async function GET(
  request: NextRequest,
  { params }: RouteParams
) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { id } = await params;

    // Get contact info
    const contact = await prisma.contact.findFirst({
      where: {
        id,
        organizationId: session.user.organizationId,
      },
      select: {
        id: true,
        firstName: true,
        lastName: true,
      },
    });

    if (!contact) {
      return NextResponse.json({ error: 'Contact not found' }, { status: 404 });
    }

    // Get messages
    const messages = await prisma.message.findMany({
      where: {
        contactId: id,
      },
      orderBy: {
        createdAt: 'asc',
      },
      select: {
        id: true,
        isFromBusiness: true,
        createdAt: true,
        sentAt: true,
      },
    });

    const businessMessages = messages.filter(m => m.isFromBusiness);
    const contactMessages = messages.filter(m => !m.isFromBusiness);

    // Try to compute
    let computationResult = null;
    let computationError = null;
    try {
      computationResult = await computeAndStoreBestContactTimes(id);
    } catch (error) {
      // SECURITY: Sanitize error messages to prevent sensitive data exposure
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      const sanitizedMessage = errorMessage
        .replace(/[a-zA-Z0-9]{20,}/g, '[REDACTED]') // Remove long tokens/IDs
        .replace(/at\s+.*/g, '') // Remove stack trace lines
        .replace(/\(.*?\)/g, '') // Remove file paths
        .substring(0, 200); // Limit length
      
      computationError = {
        message: sanitizedMessage,
        // Only expose sanitized stack in development
        stack: process.env.NODE_ENV === 'development' && error instanceof Error
          ? error.stack?.replace(/[a-zA-Z0-9]{20,}/g, '[REDACTED]')
          : undefined,
      };
    }

    return NextResponse.json({
      contact: {
        id: contact.id,
        name: `${contact.firstName} ${contact.lastName}`,
      },
      messages: {
        total: messages.length,
        fromBusiness: businessMessages.length,
        fromContact: contactMessages.length,
      },
      sampleMessages: messages.slice(0, 10).map(m => ({
        id: m.id,
        isFromBusiness: m.isFromBusiness,
        createdAt: m.createdAt instanceof Date ? m.createdAt.toISOString() : m.createdAt,
        sentAt: m.sentAt instanceof Date ? m.sentAt.toISOString() : m.sentAt,
      })),
      computation: {
        success: computationResult !== null,
        error: computationError,
        result: computationResult ? {
          bestContactTimes: (computationResult as Record<string, unknown>).bestContactTimes,
          totalMessagesAnalyzed: (computationResult as Record<string, unknown>).totalMessagesAnalyzed,
        } : null,
      },
    });
  } catch (error) {
    console.error('[TestBestTimes] Error:', error);
    // SECURITY: Sanitize error messages to prevent sensitive data exposure
    // Never expose stack traces or raw error messages to clients
    const sanitizedError = error instanceof Error 
      ? error.message.replace(/[a-zA-Z0-9]{20,}/g, '[REDACTED]') // Remove long tokens/IDs
        .replace(/at\s+.*/g, '') // Remove stack trace lines
        .replace(/\(.*?\)/g, '') // Remove file paths
        .substring(0, 200) // Limit length
      : 'An error occurred while processing your request';
    
    return NextResponse.json(
      {
        error: sanitizedError,
        // Only expose sanitized stack in development
        stack: process.env.NODE_ENV === 'development' && error instanceof Error
          ? error.stack?.replace(/[a-zA-Z0-9]{20,}/g, '[REDACTED]')
          : undefined,
      },
      { status: 500 }
    );
  }
}

