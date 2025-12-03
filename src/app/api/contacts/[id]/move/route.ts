import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { recordStageChangeFeedback } from '@/lib/ai/feedback-tracker';

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

    const { toStageId } = await request.json();
    const contactId = id;

    // Verify contact exists and belongs to user's organization
    const contact = await prisma.contact.findFirst({
      where: {
        id: contactId,
        organizationId: session.user.organizationId,
      },
      select: { stageId: true },
    });

    if (!contact) {
      return NextResponse.json({ error: 'Contact not found' }, { status: 404 });
    }

    // Use transaction to ensure atomicity: contact update and activity log must both succeed or both fail
    const updated = await prisma.$transaction(async (tx) => {
      const updatedContact = await tx.contact.update({
        where: { id: contactId },
        data: {
          stageId: toStageId,
          stageEnteredAt: new Date(),
        },
      });

      // Log activity within the same transaction
      await tx.contactActivity.create({
        data: {
          contactId,
          type: 'STAGE_CHANGED',
          title: 'Contact moved to new stage',
          fromStageId: contact.stageId || undefined,
          toStageId,
          userId: session.user.id,
        },
      });

      return updatedContact;
    });

    // Record feedback for learning (fire-and-forget)
    recordStageChangeFeedback(
      contactId,
      contact.stageId,
      toStageId,
      session.user.id
    ).catch(error => {
      console.error('[Move Contact] Error recording feedback:', error);
      // Don't fail the request if feedback tracking fails
    });

    return NextResponse.json(updated);
  } catch (error) {
    const err = error as Error;
    console.error('Move contact error:', err);
    return NextResponse.json(
      { error: 'Failed to move contact' },
      { status: 500 }
    );
  }
}

