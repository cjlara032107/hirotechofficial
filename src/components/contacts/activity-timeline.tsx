import { formatDistanceToNow } from 'date-fns';
import {
  MessageSquare,
  Tag,
  GitBranch,
  User,
  FileText,
  type LucideIcon,
} from 'lucide-react';

interface Activity {
  id: string;
  type: string;
  title: string;
  description: string | null;
  createdAt: string | Date;
  user?: {
    name: string | null;
  } | null;
}

const activityIcons: Record<string, LucideIcon> = {
  MESSAGE_SENT: MessageSquare,
  MESSAGE_RECEIVED: MessageSquare,
  TAG_ADDED: Tag,
  STAGE_CHANGED: GitBranch,
  NOTE_ADDED: FileText,
  STATUS_CHANGED: User,
};

export function ActivityTimeline({ activities }: { activities: Activity[] }) {
  if (!activities || activities.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">No activity yet</p>
    );
  }

  return (
    <div className="space-y-4">
      {activities.map((activity, index) => {
        const Icon = activityIcons[activity.type] || FileText;
        return (
          <div key={activity.id} className="flex gap-4">
            <div className="relative">
              <div className="flex h-10 w-10 items-center justify-center rounded-full border bg-background">
                <Icon className="h-4 w-4 text-muted-foreground" />
              </div>
              {index < activities.length - 1 && (
                <div className="absolute left-5 top-10 h-full w-px bg-border" />
              )}
            </div>

            <div className="flex-1 space-y-1 pb-8">
              <div className="flex items-center justify-between">
                <p className="text-sm font-medium">{activity.title}</p>
                <p className="text-xs text-muted-foreground">
                  {formatDistanceToNow(new Date(activity.createdAt), {
                    addSuffix: true,
                  })}
                </p>
              </div>
              {activity.description && (
                <p className="text-sm text-muted-foreground">
                  {activity.description}
                </p>
              )}
              {activity.user?.name && (
                <p className="text-xs text-muted-foreground">
                  by {activity.user.name}
                </p>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

