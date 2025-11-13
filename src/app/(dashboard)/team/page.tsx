import { auth } from '@/auth'
import { redirect } from 'next/navigation'
import { prisma } from '@/lib/db'
import { ComprehensiveTeamDashboard } from '@/components/teams/comprehensive-team-dashboard'

async function getTeamData(userId: string) {
  // Get user's team membership
  const member = await prisma.teamMember.findFirst({
    where: {
      userId,
      status: 'ACTIVE'
    },
    include: {
      team: true,
      user: {
        select: {
          id: true,
          name: true,
          email: true,
          image: true
        }
      }
    },
    orderBy: {
      joinedAt: 'desc'
    }
  })

  if (!member) {
    return null
  }

  // Check if user is admin
  const isAdmin = member.role === 'OWNER' || member.role === 'ADMIN'

  return {
    member,
    team: member.team,
    isAdmin
  }
}

export default async function TeamPage() {
  const session = await auth()
  
  if (!session?.user?.id) {
    redirect('/login')
  }

  const teamData = await getTeamData(session.user.id)

  if (!teamData) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold">Teams</h1>
          <p className="text-muted-foreground mt-2">
            You are not a member of any team yet.
          </p>
        </div>
      </div>
    )
  }

  return (
    <ComprehensiveTeamDashboard
      team={teamData.team}
      currentMember={teamData.member}
      currentUserId={session.user.id}
      isAdmin={teamData.isAdmin}
    />
  )
}
