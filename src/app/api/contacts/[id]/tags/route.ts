import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';

export async function POST(
  request: NextRequest,
  props: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await props.params;
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { tag } = await request.json();
    const contactId = id;

    const contact = await prisma.contact.findUnique({
      where: { id: contactId },
    });

    if (!contact) {
      return NextResponse.json({ error: 'Contact not found' }, { status: 404 });
    }

    if (contact.tags.includes(tag)) {
      return NextResponse.json(
        { error: 'Tag already exists' },
        { status: 400 }
      );
    }

    const updated = await prisma.contact.update({
      where: { id: contactId },
      data: {
        tags: {
          push: tag,
        },
      },
    });

    // Update tag contact count
    await prisma.tag.updateMany({
      where: {
        name: tag,
        organizationId: session.user.organizationId,
      },
      data: {
        contactCount: { increment: 1 },
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
      console.log(`[Tag API] Removed ${rulesWithThisTag.length} stop records for contact ${contactId} after adding tag "${tag}"`);
    }

    // Log activity
    await prisma.contactActivity.create({
      data: {
        contactId,
        type: 'TAG_ADDED',
        title: `Tag "${tag}" added`,
        metadata: { tag },
        userId: session.user.id,
      },
    });

    return NextResponse.json(updated);
  } catch (error) {
    const err = error as Error;
    console.error('Add tag error:', err);
    return NextResponse.json({ error: 'Failed to add tag' }, { status: 500 });
  }
}

export async function DELETE(
  request: NextRequest,
  props: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await props.params;
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { tag } = await request.json();
    const contactId = id;

    const contact = await prisma.contact.findUnique({
      where: { id: contactId },
    });

    if (!contact) {
      return NextResponse.json({ error: 'Contact not found' }, { status: 404 });
    }

    const updated = await prisma.contact.update({
      where: { id: contactId },
      data: {
        tags: contact.tags.filter((t) => t !== tag),
      },
    });

    // Update tag contact count
    await prisma.tag.updateMany({
      where: {
        name: tag,
        organizationId: session.user.organizationId,
      },
      data: {
        contactCount: { decrement: 1 },
      },
    });

    return NextResponse.json(updated);
  } catch (error) {
    const err = error as Error;
    console.error('Remove tag error:', err);
    return NextResponse.json(
      { error: 'Failed to remove tag' },
      { status: 500 }
    );
  }
}

