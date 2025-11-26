'use server';

import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { ActivityType } from '@prisma/client';
import { revalidatePath } from 'next/cache';

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
          ruleId: { in: rulesWithThisTag.map(r => r.id) },
        },
      });
      console.log(`[Tag Action] Removed ${rulesWithThisTag.length} stop records for contact ${contactId} after adding tag "${tag}"`);
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
    console.error('Error adding tag:', error);
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
    const updatedTags = contact.tags.filter((t) => t !== tag);
    
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
    console.error('Error removing tag:', error);
    return { success: false, error: 'Failed to remove tag' };
  }
}
