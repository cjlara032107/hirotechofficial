import { NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma, connectPrisma } from '@/lib/db';

export async function GET() {
  try {
    // Ensure Prisma is connected before queries
    await connectPrisma();
    
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Get total contact count for the user's organization
    const count = await prisma.contact.count({
      where: {
        organizationId: session.user.organizationId,
      },
    });

    return NextResponse.json({ count });
  } catch (error) {
    console.error('Error fetching total contact count:', error);
    return NextResponse.json(
      { error: 'Failed to fetch total contact count' },
      { status: 500 }
    );
  }
}

