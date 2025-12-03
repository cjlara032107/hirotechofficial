'use server';

import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { ActivityType } from '@prisma/client';
import { revalidatePath } from 'next/cache';
import { logger } from '@/lib/utils/logger';

export async function addTagToContact(contactId: string, tag: string) {
  try {
    const session = await auth();
    
    if (!session?.user) {
      return { success: false, error: 'Unauthorized' };
    }

    // Verify contact belongs to user's organization
    const contact = await prisma.contact.findFirst({
      where: {
        id: contactId,
        organizationId: session.user.organizationId,
      },
      select: {
        id: true,
        tags: true,
      },
    });

    if (!contact) {
      return { success: false, error: 'Contact not found' };
    }

    // Check if tag already exists
    if (contact.tags.includes(tag)) {
      return { success: false, error: 'Tag already added' };
    }

    // Add tag to contact
    await prisma.contact.update({
      where: { id: contactId },
      data: {
        tags: {
          push: tag,
        },
      },
    });

    // ⭐ AI AUTOMATION: Remove stop records when user manually adds a tag
    // This allows the contact to be re-automated if they have the automation tag
    const rulesWithThisTag = await prisma.aIAutomationRule.findMany({
      where: {
        enabled: true,
        includeTags: { has: tag },
      },
      select: { id: true },
    });

    if (rulesWithThisTag.length > 0) {
      await prisma.aIAutomationStop.deleteMany({
        where: {
          contactId,
          ruleId: { in: rulesWithThisTag.map((r: { id: string }) => r.id) },
        },
      });
      logger.debug('Removed stop records after adding tag', { 
        contactId, 
        tag, 
        stopRecordsRemoved: rulesWithThisTag.length 
      });
    }

    // Create activity log
    await prisma.contactActivity.create({
      data: {
        contactId,
        userId: session.user.id,
        type: 'TAG_ADDED',
        title: 'Tag Added',
        description: `Added tag: ${tag}`,
      },
    });

    // Revalidate the contact page to show updated data
    revalidatePath(`/contacts/${contactId}`);
    
    return { success: true };
  } catch (error) {
    logger.error('Error adding tag', error instanceof Error ? error : new Error(String(error)), { contactId, tag });
    return { success: false, error: 'Failed to add tag' };
  }
}

export async function removeTagFromContact(contactId: string, tag: string) {
  try {
    const session = await auth();
    
    if (!session?.user) {
      return { success: false, error: 'Unauthorized' };
    }

    // Verify contact belongs to user's organization
    const contact = await prisma.contact.findFirst({
      where: {
        id: contactId,
        organizationId: session.user.organizationId,
      },
      select: {
        id: true,
        tags: true,
      },
    });

    if (!contact) {
      return { success: false, error: 'Contact not found' };
    }

    // Remove tag from contact
    const updatedTags = contact.tags.filter((t: string) => t !== tag);
    
    await prisma.contact.update({
      where: { id: contactId },
      data: {
        tags: updatedTags,
      },
    });

    // Create activity log
    await prisma.contactActivity.create({
      data: {
        contactId,
        userId: session.user.id,
        type: 'TAG_ADDED',
        title: 'Tag Removed',
        description: `Removed tag: ${tag}`,
      },
    });

    // Revalidate the contact page to show updated data
    revalidatePath(`/contacts/${contactId}`);
    
    return { success: true };
  } catch (error) {
    logger.error('Error removing tag', error instanceof Error ? error : new Error(String(error)), { contactId, tag });
    return { success: false, error: 'Failed to remove tag' };
  }
}
