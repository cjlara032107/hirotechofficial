'use client'

import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { 
  MessageSquare, 
  Users, 
  CheckSquare, 
  Activity,
  Settings,
  Crown,
  Shield
} from 'lucide-react'
import { EnhancedTeamInboxWithPagination } from './enhanced-team-inbox-with-pagination'
import { TeamMembers } from './team-members'
import { TeamTasks } from './team-tasks'
import { TeamActivity } from './team-activity'
import { PendingTasksWidget } from './pending-tasks-widget'
import { TeamSettings } from './team-settings'

interface Team {
  id: string
  name: string
  description?: string | null
  avatar?: string | null
  status: string
  ownerId: string
}

interface TeamMember {
  id: string
  displayName?: string | null
  role: string
  user: {
    id: string
    name: string | null
    email: string
    image?: string | null
  }
}

interface ComprehensiveTeamDashboardProps {
  team: Team
  currentMember: TeamMember
  currentUserId: string
  isAdmin: boolean
}

export function ComprehensiveTeamDashboard({
  team,
  currentMember,
  currentUserId,
  isAdmin
}: ComprehensiveTeamDashboardProps) {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-3xl font-bold">{team.name}</h1>
            {isAdmin && (
              <Badge variant="secondary" className="gap-1">
                {currentMember.role === 'OWNER' ? (
                  <>
                    <Crown className="w-3 h-3" />
                    Owner
                  </>
                ) : (
                  <>
                    <Shield className="w-3 h-3" />
                    Admin
                  </>
                )}
              </Badge>
            )}
          </div>
          {team.description && (
            <p className="text-muted-foreground mt-2">{team.description}</p>
          )}
          <p className="text-sm text-muted-foreground mt-1">
            Signed in as{' '}
            <span className="font-medium">
              {currentMember.displayName || currentMember.user.name || currentMember.user.email}
            </span>
          </p>
        </div>
      </div>

      {/* Main Content */}
      <Tabs defaultValue="messages" className="space-y-4">
        <TabsList>
          <TabsTrigger value="messages" className="gap-2">
            <MessageSquare className="w-4 h-4" />
            Messages
          </TabsTrigger>
          <TabsTrigger value="tasks" className="gap-2">
            <CheckSquare className="w-4 h-4" />
            Tasks
          </TabsTrigger>
          <TabsTrigger value="members" className="gap-2">
            <Users className="w-4 h-4" />
            Members
          </TabsTrigger>
          <TabsTrigger value="activity" className="gap-2">
            <Activity className="w-4 h-4" />
            Activity
          </TabsTrigger>
          {isAdmin && (
            <TabsTrigger value="settings" className="gap-2">
              <Settings className="w-4 h-4" />
              Settings
            </TabsTrigger>
          )}
        </TabsList>

        {/* Messages Tab */}
        <TabsContent value="messages" className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-3">
            <div className="lg:col-span-3">
              <EnhancedTeamInboxWithPagination
                teamId={team.id}
                currentMemberId={currentMember.id}
                currentUserId={currentUserId}
                isAdmin={isAdmin}
              />
            </div>
          </div>
        </TabsContent>

        {/* Tasks Tab */}
        <TabsContent value="tasks" className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <TeamTasks teamId={team.id} currentMemberId={currentMember.id} isAdmin={isAdmin} />
            </div>
            <div>
              <PendingTasksWidget
                teamId={team.id}
                memberId={currentMember.id}
                limit={10}
              />
            </div>
          </div>
        </TabsContent>

        {/* Members Tab */}
        <TabsContent value="members">
          <TeamMembers
            teamId={team.id}
            currentUserId={currentUserId}
            isAdmin={isAdmin}
          />
        </TabsContent>

        {/* Activity Tab */}
        <TabsContent value="activity">
          <TeamActivity teamId={team.id} memberId={currentMember.id} />
        </TabsContent>

        {/* Settings Tab (Admin Only) */}
        {isAdmin && (
          <TabsContent value="settings">
            <TeamSettings
              team={{ ...team, description: team.description ?? null }}
              currentUserId={currentUserId}
              onUpdate={() => {
                // Refresh team data
              }}
            />
          </TabsContent>
        )}
      </Tabs>
    </div>
  )
}

