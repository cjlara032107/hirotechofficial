import { NextResponse } from 'next/server';
import { getAuthUser } from '@/lib/supabase/auth-helpers';
import { prisma, connectPrisma } from '@/lib/db';

/**
 * Get current user session with full profile data
 * Used by client-side useSession hook
 */
export async function GET() {
  try {
    const user = await getAuthUser();
    
    if (!user) {
      return NextResponse.json({ user: null }, { status: 401 });
    }

    // Fetch additional team context if user has an active team
    let teamContext = null;
    if (user.organizationId) {
      // Ensure connection before query
      await connectPrisma();
      const dbUser = await prisma.user.findUnique({
        where: { id: user.id },
        select: { activeTeamId: true },
      });

      if (dbUser?.activeTeamId) {
        const teamMember = await prisma.teamMember.findFirst({
          where: {
            userId: user.id,
            teamId: dbUser.activeTeamId,
            status: 'ACTIVE',
          },
          include: {
            team: {
              select: {
                id: true,
                name: true,
              },
            },
          },
        });

        if (teamMember) {
          teamContext = {
            teamId: teamMember.teamId,
            teamName: teamMember.team.name,
            memberId: teamMember.id,
            memberRole: teamMember.role,
            memberStatus: teamMember.status,
          };
        }
      }
    }

    return NextResponse.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        image: user.image,
        role: user.role,
        organizationId: user.organizationId,
        teamContext,
      },
    });
  } catch (error) {
    console.error('Check session error:', error);
    return NextResponse.json({ user: null }, { status: 500 });
  }
}

