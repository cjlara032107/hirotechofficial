import { NextResponse } from 'next/server';
import { getAuthUser } from '@/lib/supabase/auth-helpers';
import { prisma } from '@/lib/db';
import { safePrismaOperation, handlePrismaError } from '@/lib/prisma-error-handler';

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
      const dbUser = await safePrismaOperation(
        () => prisma.user.findUnique({
          where: { id: user.id },
          select: { activeTeamId: true },
        }),
        { operationName: 'find user for team context' }
      );

      if (dbUser?.activeTeamId) {
        const teamMember = await safePrismaOperation(
          () => prisma.teamMember.findFirst({
            where: {
              userId: user.id,
              teamId: dbUser.activeTeamId!, // Non-null assertion since we checked above
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
          }),
          { operationName: 'find team member' }
        );

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
    const { message, status } = handlePrismaError(error, 'Failed to check session');
    return NextResponse.json({ 
      user: null,
      error: message 
    }, { status });
  }
}

