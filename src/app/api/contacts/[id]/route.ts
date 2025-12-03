import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { validateUUID } from '@/lib/api/validate-uuid';

export async function GET(
  request: NextRequest,
  props: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await props.params;
    
    // Validate UUID format
    const uuidValidation = validateUUID(id);
    if (uuidValidation?.error) {
      return NextResponse.json({ error: uuidValidation.error.message }, { status: uuidValidation.error.status });
    }
    
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Use getPrismaForOrg for multi-DB routing support
    const prisma = getPrismaForOrg(session.user.organizationId);

    const { searchParams } = new URL(request.url);
    const includeMessages = searchParams.get('includeMessages') === 'true';
    const messagesLimit = parseInt(searchParams.get('messagesLimit') || '20');

    const contact = await prisma.contact.findFirst({
      where: {
        id: id,
        organizationId: session.user.organizationId,
      },
      include: {
        stage: true,
        pipeline: true,
        facebookPage: true,
        activities: {
          take: 50,
          orderBy: { createdAt: 'desc' },
          include: {
            user: {
              select: { name: true, email: true },
            },
          },
        },
        ...(includeMessages && {
          conversations: {
            include: {
              messages: {
                take: messagesLimit,
                orderBy: { createdAt: 'desc' }
              }
            }
          }
        })
      },
    });

    if (!contact) {
      return NextResponse.json({ error: 'Contact not found' }, { status: 404 });
    }

    return NextResponse.json(contact);
  } catch (error) {
    const err = error as Error;
    console.error('Get contact error:', err);
    return NextResponse.json(
      { error: 'Failed to fetch contact' },
      { status: 500 }
    );
  }
}

export async function PATCH(
  request: NextRequest,
  props: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await props.params;
    
    // Validate UUID format
    const uuidValidation = validateUUID(id);
    if (uuidValidation?.error) {
      return NextResponse.json({ error: uuidValidation.error.message }, { status: uuidValidation.error.status });
    }
    
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Use getPrismaForOrg for multi-DB routing support
    const prisma = getPrismaForOrg(session.user.organizationId);

    const body = await request.json();
    const { firstName, lastName, notes, leadScore, leadStatus, expectedUpdatedAt } = body;

    // Handle concurrent updates with optimistic locking
    // If expectedUpdatedAt is provided, verify the contact hasn't been modified
    const maxRetries = 3;
    let lastError: Error | null = null;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        // First, verify the contact exists and belongs to the user's organization
        const existingContact = await prisma.contact.findFirst({
          where: {
            id: id,
            organizationId: session.user.organizationId,
          },
          select: { updatedAt: true },
        });

        if (!existingContact) {
          return NextResponse.json({ error: 'Contact not found' }, { status: 404 });
        }

        // If expectedUpdatedAt is provided, check for concurrent modification
        if (expectedUpdatedAt) {
          const expectedDate = new Date(expectedUpdatedAt);
          if (existingContact.updatedAt.getTime() !== expectedDate.getTime()) {
            // Contact was modified by another request
            if (attempt < maxRetries - 1) {
              // Wait a bit before retrying (exponential backoff)
              await new Promise(resolve => setTimeout(resolve, 100 * Math.pow(2, attempt)));
              continue;
            } else {
              return NextResponse.json(
                { 
                  error: 'Contact was modified by another request. Please refresh and try again.',
                  code: 'CONCURRENT_MODIFICATION'
                },
                { status: 409 }
              );
            }
          }
        }

        // Perform the update within a transaction to prevent race conditions
        const contact = await prisma.$transaction(async (tx) => {
          // Re-check updatedAt within transaction to ensure consistency
          const currentContact = await tx.contact.findFirst({
            where: {
              id: id,
              organizationId: session.user.organizationId,
            },
            select: { updatedAt: true },
          });

          if (!currentContact) {
            throw new Error('Contact not found');
          }

          if (expectedUpdatedAt) {
            const expectedDate = new Date(expectedUpdatedAt);
            if (currentContact.updatedAt.getTime() !== expectedDate.getTime()) {
              throw new Error('CONCURRENT_MODIFICATION');
            }
          }

          // Update the contact
          return await tx.contact.update({
            where: {
              id: id,
            },
            data: {
              ...(firstName && { firstName }),
              ...(lastName && { lastName }),
              ...(notes !== undefined && { notes }),
              ...(leadScore !== undefined && { leadScore }),
              ...(leadStatus && { leadStatus }),
            },
          });
        });

        return NextResponse.json(contact);
      } catch (error) {
        lastError = error as Error;
        
        // Check if it's a concurrent modification error
        if (lastError.message === 'CONCURRENT_MODIFICATION') {
          if (attempt < maxRetries - 1) {
            // Wait before retrying
            await new Promise(resolve => setTimeout(resolve, 100 * Math.pow(2, attempt)));
            continue;
          } else {
            return NextResponse.json(
              { 
                error: 'Contact was modified by another request. Please refresh and try again.',
                code: 'CONCURRENT_MODIFICATION'
              },
              { status: 409 }
            );
          }
        }

        // Check if it's a deadlock (P2034) or other retryable error
        const prismaError = error as any;
        const isDeadlock = prismaError?.code === 'P2034' || 
                          prismaError?.message?.includes('deadlock') ||
                          prismaError?.message?.includes('Deadlock');
        
        if (isDeadlock && attempt < maxRetries - 1) {
          // Wait with exponential backoff before retrying deadlock
          const backoffDelay = 50 * Math.pow(2, attempt) + Math.random() * 50; // 50-200ms with jitter
          await new Promise(resolve => setTimeout(resolve, backoffDelay));
          continue;
        }

        // For other errors or final attempt, throw
        throw error;
      }
    }

    // Should not reach here, but handle it
    throw lastError || new Error('Failed to update contact after retries');
  } catch (error) {
    const err = error as Error;
    console.error('Update contact error:', err);
    
    // Handle Prisma known errors
    const prismaError = error as any;
    if (prismaError?.code === 'P2025') {
      return NextResponse.json({ error: 'Contact not found' }, { status: 404 });
    }
    
    if (prismaError?.code === 'P2034' || err.message?.includes('deadlock')) {
      return NextResponse.json(
        { error: 'Database conflict occurred. Please try again.', code: 'DEADLOCK' },
        { status: 503 }
      );
    }

    return NextResponse.json(
      { error: 'Failed to update contact' },
      { status: 500 }
    );
  }
}

export async function DELETE(
  request: NextRequest,
  props: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await props.params;
    
    // Validate UUID format
    const uuidValidation = validateUUID(id);
    if (uuidValidation?.error) {
      return NextResponse.json({ error: uuidValidation.error.message }, { status: uuidValidation.error.status });
    }
    
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Use getPrismaForOrg for multi-DB routing support
    const prisma = getPrismaForOrg(session.user.organizationId);

    console.log('[Delete Contact API] Looking for contact:', {
      contactId: id,
      organizationId: session.user.organizationId,
    });

    // Verify contact belongs to user's organization before deleting
    let contact = await prisma.contact.findFirst({
      where: {
        id: id,
        organizationId: session.user.organizationId,
      },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        organizationId: true,
      },
    });

    // If not found and multi-DB is enabled, try checking the default database as fallback
    if (!contact && process.env.ENABLE_MULTI_DB === 'true') {
      try {
        const { prisma: defaultPrisma } = await import('@/lib/db');
        const contactInDefault = await defaultPrisma.contact.findFirst({
          where: { id },
          select: {
            id: true,
            firstName: true,
            lastName: true,
            organizationId: true,
          },
        });
        
        if (contactInDefault) {
          if (contactInDefault.organizationId !== session.user.organizationId) {
            console.error('[Delete Contact API] Contact belongs to different organization:', {
              contactId: id,
              contactOrganizationId: contactInDefault.organizationId,
              userOrganizationId: session.user.organizationId,
            });
            return NextResponse.json(
              { error: 'Contact not found or access denied. This contact belongs to a different organization.' },
              { status: 403 }
            );
          }
          console.warn('[Delete Contact API] Contact found in default database but not in routed database. Using contact from default database.');
          contact = contactInDefault;
        }
      } catch (fallbackError) {
        console.error('[Delete Contact API] Error checking default database:', fallbackError);
      }
    }

    if (!contact) {
      console.warn('[Delete Contact API] Contact not found:', {
        contactId: id,
        organizationId: session.user.organizationId,
        multiDbEnabled: process.env.ENABLE_MULTI_DB === 'true',
      });
      return NextResponse.json({ error: 'Contact not found' }, { status: 404 });
    }

    console.log('[Delete Contact API] Found contact, deleting:', {
      contactId: contact.id,
      firstName: contact.firstName,
      lastName: contact.lastName,
    });

    await prisma.contact.delete({
      where: { id: id },
    });

    console.log('[Delete Contact API] Successfully deleted contact:', id);

    return NextResponse.json({ success: true });
  } catch (error) {
    const err = error as Error;
    console.error('Delete contact error:', err);
    return NextResponse.json(
      { error: 'Failed to delete contact' },
      { status: 500 }
    );
  }
}

