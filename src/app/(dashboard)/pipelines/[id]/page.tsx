'use client';

import { useEffect, useCallback, useReducer, Suspense, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';
import {
  ArrowLeft,
  Plus,
  Trash2,
  Edit2,
  Users,
  RefreshCw,
  Target,
} from 'lucide-react';
import { LoadingSpinner } from '@/components/ui/loading-spinner';
import { toast } from 'sonner';
import {
  DndContext,
  DragEndEvent,
  DragOverlay,
  DragStartEvent,
  PointerSensor,
  useSensor,
  useSensors,
} from '@dnd-kit/core';
import dynamic from 'next/dynamic';
import { PipelineStageCardVirtualized } from '@/components/pipelines/pipeline-stage-card-virtualized';
import { ContactCard } from '@/components/pipelines/contact-card';
import { useDebounce } from '@/hooks/use-debounce';
import { useSupabasePipelineRealtime } from '@/hooks/use-supabase-pipeline-realtime';

// Lazy load dialog components
const AddStageDialog = dynamic(() => import('@/components/pipelines/add-stage-dialog').then(mod => ({ default: mod.AddStageDialog })));
const EditPipelineDialog = dynamic(() => import('@/components/pipelines/edit-pipeline-dialog').then(mod => ({ default: mod.EditPipelineDialog })));
const AddContactsDialog = dynamic(() => import('@/components/pipelines/add-contacts-dialog').then(mod => ({ default: mod.AddContactsDialog })));
const BulkTagDialog = dynamic(() => import('@/components/pipelines/bulk-tag-dialog').then(mod => ({ default: mod.BulkTagDialog })));
const ScoreRangeDialog = dynamic(() => import('@/components/pipelines/score-range-dialog').then(mod => ({ default: mod.ScoreRangeDialog })));
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';

interface Contact {
  id: string;
  firstName: string;
  lastName?: string;
  profilePicUrl?: string;
  leadScore: number;
  tags: string[];
}

interface Stage {
  id: string;
  name: string;
  color: string;
  type: string;
  leadScoreMin?: number;
  leadScoreMax?: number;
  contacts: Contact[];
  _count: {
    contacts: number;
  };
}

interface Pipeline {
  id: string;
  name: string;
  description?: string;
  color: string;
  stages: Stage[];
}

interface PipelineState {
  pipeline: Pipeline | null;
  loading: boolean;
  activeContact: Contact | null;
  stageSearchQueries: Record<string, string>;
  stagePagination: Record<string, number>;
  selectedStageContacts: Record<string, Set<string>>;
  selectedStages: Set<string>;
  dialogs: {
    showAddStage: boolean;
    showEditPipeline: boolean;
    showDeleteStages: boolean;
    showAddContacts: boolean;
    showBulkTag: boolean;
    showRemoveContacts: boolean;
    showRemoveAllContacts: boolean;
  };
  selectedStageForTag: string | null;
  selectedStageForRemove: string | null;
  isDeleting: boolean;
  isRemovingAllContacts: boolean;
}

type PipelineAction =
  | { type: 'SET_PIPELINE'; payload: Pipeline | null }
  | { type: 'SET_LOADING'; payload: boolean }
  | { type: 'SET_ACTIVE_CONTACT'; payload: Contact | null }
  | { type: 'SET_STAGE_SEARCH_QUERY'; payload: { stageId: string; query: string } }
  | { type: 'SET_STAGE_PAGINATION'; payload: { stageId: string; page: number } }
  | { type: 'TOGGLE_CONTACT_SELECTION'; payload: { stageId: string; contactId: string } }
  | { type: 'CLEAR_STAGE_SELECTIONS'; payload: string }
  | { type: 'TOGGLE_STAGE_SELECTION'; payload: string }
  | { type: 'CLEAR_ALL_STAGE_SELECTIONS' }
  | { type: 'TOGGLE_DIALOG'; payload: { dialog: keyof PipelineState['dialogs']; value: boolean } }
  | { type: 'SET_SELECTED_STAGE_FOR_TAG'; payload: string | null }
  | { type: 'SET_SELECTED_STAGE_FOR_REMOVE'; payload: string | null }
  | { type: 'SET_IS_DELETING'; payload: boolean }
  | { type: 'SET_IS_REMOVING_ALL_CONTACTS'; payload: boolean }
  | { type: 'UPDATE_REALTIME_COUNTS'; payload: Array<{ id: string; _count: { contacts: number } }> };

function pipelineReducer(state: PipelineState, action: PipelineAction): PipelineState {
  switch (action.type) {
    case 'SET_PIPELINE':
      return { ...state, pipeline: action.payload };
    case 'SET_LOADING':
      return { ...state, loading: action.payload };
    case 'SET_ACTIVE_CONTACT':
      return { ...state, activeContact: action.payload };
    case 'SET_STAGE_SEARCH_QUERY':
      return {
        ...state,
        stageSearchQueries: {
          ...state.stageSearchQueries,
          [action.payload.stageId]: action.payload.query,
        },
      };
    case 'SET_STAGE_PAGINATION':
      return {
        ...state,
        stagePagination: {
          ...state.stagePagination,
          [action.payload.stageId]: action.payload.page,
        },
      };
    case 'TOGGLE_CONTACT_SELECTION': {
      const stageContacts = new Set(state.selectedStageContacts[action.payload.stageId] || []);
      if (stageContacts.has(action.payload.contactId)) {
        stageContacts.delete(action.payload.contactId);
      } else {
        stageContacts.add(action.payload.contactId);
      }
      return {
        ...state,
        selectedStageContacts: {
          ...state.selectedStageContacts,
          [action.payload.stageId]: stageContacts,
        },
      };
    }
    case 'CLEAR_STAGE_SELECTIONS':
      return {
        ...state,
        selectedStageContacts: {
          ...state.selectedStageContacts,
          [action.payload]: new Set(),
        },
      };
    case 'TOGGLE_STAGE_SELECTION': {
      const newSelection = new Set(state.selectedStages);
      if (newSelection.has(action.payload)) {
        newSelection.delete(action.payload);
      } else {
        newSelection.add(action.payload);
      }
      return { ...state, selectedStages: newSelection };
    }
    case 'CLEAR_ALL_STAGE_SELECTIONS':
      return { ...state, selectedStages: new Set() };
    case 'TOGGLE_DIALOG':
      return {
        ...state,
        dialogs: {
          ...state.dialogs,
          [action.payload.dialog]: action.payload.value,
        },
      };
    case 'SET_SELECTED_STAGE_FOR_TAG':
      return { ...state, selectedStageForTag: action.payload };
    case 'SET_SELECTED_STAGE_FOR_REMOVE':
      return { ...state, selectedStageForRemove: action.payload };
    case 'SET_IS_DELETING':
      return { ...state, isDeleting: action.payload };
    case 'SET_IS_REMOVING_ALL_CONTACTS':
      return { ...state, isRemovingAllContacts: action.payload };
    case 'UPDATE_REALTIME_COUNTS':
      if (!state.pipeline) return state;
      return {
        ...state,
        pipeline: {
          ...state.pipeline,
          stages: state.pipeline.stages.map(stage => {
            const updated = action.payload.find(s => s.id === stage.id);
            return updated ? {
              ...stage,
              _count: { contacts: updated._count.contacts }
            } : stage;
          })
        }
      };
    default:
      return state;
  }
}

const initialState: PipelineState = {
  pipeline: null,
  loading: true,
  activeContact: null,
  stageSearchQueries: {},
  stagePagination: {},
  selectedStageContacts: {},
  selectedStages: new Set(),
  dialogs: {
    showAddStage: false,
    showEditPipeline: false,
    showDeleteStages: false,
    showAddContacts: false,
    showBulkTag: false,
    showRemoveContacts: false,
    showRemoveAllContacts: false,
  },
  selectedStageForTag: null,
  selectedStageForRemove: null,
  isDeleting: false,
  isRemovingAllContacts: false,
};

export default function PipelinePage() {
  const params = useParams();
  const router = useRouter();
  const [state, dispatch] = useReducer(pipelineReducer, initialState);
  const debouncedSearchQueries = useDebounce(state.stageSearchQueries, 300);
  const [lastUpdate, setLastUpdate] = useState<number>(Date.now());
  const [showScoreRangeDialog, setShowScoreRangeDialog] = useState(false);
  const [isReassigning, setIsReassigning] = useState(false);

  // Supabase Realtime - instant updates when contacts change
  const { updateSignal, isSubscribed } = useSupabasePipelineRealtime(params.id as string);

  const sensors = useSensors(
    useSensor(PointerSensor, {
      activationConstraint: {
        distance: 8,
      },
    })
  );

  const fetchPipeline = useCallback(async () => {
    try {
      const response = await fetch(`/api/pipelines/${params.id}`);
      const data = await response.json();
      if (response.ok) {
        dispatch({ type: 'SET_PIPELINE', payload: data });
      }
    } catch (error) {
      console.error('Error fetching pipeline:', error);
      toast.error('Failed to fetch pipeline');
    } finally {
      dispatch({ type: 'SET_LOADING', payload: false });
    }
  }, [params.id]);

  useEffect(() => {
    fetchPipeline();
  }, [fetchPipeline]);

  // Refetch pipeline when Supabase broadcasts a change
  useEffect(() => {
    if (updateSignal && state.pipeline) {
      console.log('[Pipeline] Realtime update detected, refetching pipeline data...');
      fetchPipeline(); // Refetch to get fresh counts
      setLastUpdate(updateSignal.timestamp);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [updateSignal?.timestamp]); // Only watch timestamp to prevent infinite loops

  const handleDragStart = (event: DragStartEvent) => {
    const contact = event.active.data.current as Contact;
    dispatch({ type: 'SET_ACTIVE_CONTACT', payload: contact });
  };

  const handleDragEnd = async (event: DragEndEvent) => {
    const { active, over } = event;
    dispatch({ type: 'SET_ACTIVE_CONTACT', payload: null });

    if (!over || !state.pipeline) return;

    const contactId = active.id as string;
    const targetStageId = over.id as string;

    // Find source stage
    const sourceStage = state.pipeline.stages.find((stage) =>
      stage.contacts.some((c) => c.id === contactId)
    );

    if (!sourceStage || sourceStage.id === targetStageId) return;

    // Optimistically update UI
    const updatedPipeline = {
      ...state.pipeline,
      stages: state.pipeline.stages.map((stage) => {
        if (stage.id === sourceStage.id) {
          return {
            ...stage,
            contacts: stage.contacts.filter((c) => c.id !== contactId),
            _count: { contacts: stage._count.contacts - 1 },
          };
        }
        if (stage.id === targetStageId) {
          const contact = sourceStage.contacts.find((c) => c.id === contactId)!;
          return {
            ...stage,
            contacts: [contact, ...stage.contacts],
            _count: { contacts: stage._count.contacts + 1 },
          };
        }
        return stage;
      }),
    };
    dispatch({ type: 'SET_PIPELINE', payload: updatedPipeline });

    // Make API call
    try {
      const response = await fetch(`/api/contacts/${contactId}/move`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ stageId: targetStageId }),
      });

      if (!response.ok) {
        // Revert on error
        dispatch({ type: 'SET_PIPELINE', payload: state.pipeline });
        toast.error('Failed to move contact');
      } else {
        toast.success('Contact moved successfully');
      }
    } catch (error) {
      console.error('Error moving contact:', error);
      dispatch({ type: 'SET_PIPELINE', payload: state.pipeline });
      toast.error('An error occurred');
    }
  };

  const handleStageSearch = (stageId: string, query: string) => {
    dispatch({ type: 'SET_STAGE_SEARCH_QUERY', payload: { stageId, query } });
  };

  useEffect(() => {
    const performSearch = async () => {
      for (const [stageId, query] of Object.entries(debouncedSearchQueries)) {
        if (!query.trim()) {
          continue;
        }

        try {
          const response = await fetch(
            `/api/pipelines/stages/${stageId}/contacts?search=${encodeURIComponent(query)}&page=1&limit=20`
          );
          const data = await response.json();

          if (response.ok && state.pipeline) {
            dispatch({
              type: 'SET_PIPELINE',
              payload: {
                ...state.pipeline,
                stages: state.pipeline.stages.map((stage) =>
                  stage.id === stageId
                    ? { ...stage, contacts: data.contacts }
                    : stage
                ),
              },
            });
          }
        } catch (error) {
          console.error('Error searching stage contacts:', error);
        }
      }
    };

    performSearch();
  }, [debouncedSearchQueries, state.pipeline]);

  const handleStagePagination = async (stageId: string, page: number) => {
    dispatch({ type: 'SET_STAGE_PAGINATION', payload: { stageId, page } });

    try {
      const searchQuery = state.stageSearchQueries[stageId] || '';
      const response = await fetch(
        `/api/pipelines/stages/${stageId}/contacts?search=${encodeURIComponent(searchQuery)}&page=${page}&limit=20`
      );
      const data = await response.json();

      if (response.ok && state.pipeline) {
        const updatedPipeline = {
          ...state.pipeline,
          stages: state.pipeline.stages.map((stage) =>
            stage.id === stageId
              ? { ...stage, contacts: data.contacts }
              : stage
          ),
        };
        dispatch({ type: 'SET_PIPELINE', payload: updatedPipeline });
      }
    } catch (error) {
      console.error('Error loading page:', error);
      toast.error('Failed to load contacts');
    }
  };

  const toggleContactSelection = (stageId: string, contactId: string) => {
    dispatch({ type: 'TOGGLE_CONTACT_SELECTION', payload: { stageId, contactId } });
  };

  const toggleStageSelection = (stageId: string) => {
    dispatch({ type: 'TOGGLE_STAGE_SELECTION', payload: stageId });
  };

  const handleBulkRemoveContacts = async (stageId: string) => {
    const contactIds = Array.from(state.selectedStageContacts[stageId] || []);
    if (contactIds.length === 0) return;

    // Show confirmation dialog instead of immediately removing
    dispatch({ type: 'SET_SELECTED_STAGE_FOR_REMOVE', payload: stageId });
    dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showRemoveContacts', value: true } });
  };

  const confirmRemoveContacts = async () => {
    if (!state.selectedStageForRemove) return;

    const stageId = state.selectedStageForRemove;
    const contactIds = Array.from(state.selectedStageContacts[stageId] || []);
    
    dispatch({ type: 'SET_IS_DELETING', payload: true });
    
    try {
      const response = await fetch(
        `/api/pipelines/stages/${stageId}/contacts/bulk-remove`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ contactIds }),
        }
      );

      if (response.ok) {
        toast.success(`Removed ${contactIds.length} contact(s) from pipeline`);
        dispatch({ type: 'CLEAR_STAGE_SELECTIONS', payload: stageId });
        await fetchPipeline();
      } else {
        toast.error('Failed to remove contacts');
      }
    } catch (error) {
      console.error('Error removing contacts:', error);
      toast.error('An error occurred');
    } finally {
      dispatch({ type: 'SET_IS_DELETING', payload: false });
      dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showRemoveContacts', value: false } });
      dispatch({ type: 'SET_SELECTED_STAGE_FOR_REMOVE', payload: null });
    }
  };

  const handleBulkDeleteStages = async () => {
    if (state.selectedStages.size === 0) return;

    dispatch({ type: 'SET_IS_DELETING', payload: true });
    try {
      const response = await fetch(
        `/api/pipelines/${params.id}/stages/bulk-delete`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ stageIds: Array.from(state.selectedStages) }),
        }
      );

      if (response.ok) {
        toast.success(`Deleted ${state.selectedStages.size} stage(s)`);
        dispatch({ type: 'CLEAR_ALL_STAGE_SELECTIONS' });
        await fetchPipeline();
      } else {
        toast.error('Failed to delete stages');
      }
    } catch (error) {
      console.error('Error deleting stages:', error);
      toast.error('An error occurred');
    } finally {
      dispatch({ type: 'SET_IS_DELETING', payload: false });
      dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showDeleteStages', value: false } });
    }
  };

  const handleAddStage = async (stageData: {
    name: string;
    description?: string;
    color: string;
    type: string;
  }) => {
    try {
      const response = await fetch(`/api/pipelines/${params.id}/stages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(stageData),
      });

      if (response.ok) {
        toast.success('Stage added successfully');
        dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showAddStage', value: false } });
        await fetchPipeline();
      } else {
        toast.error('Failed to add stage');
      }
    } catch (error) {
      console.error('Error adding stage:', error);
      toast.error('An error occurred');
    }
  };

  const handleUpdatePipeline = async (pipelineData: {
    name: string;
    description?: string;
    color: string;
  }) => {
    try {
      const response = await fetch(`/api/pipelines/${params.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(pipelineData),
      });

      if (response.ok) {
        toast.success('Pipeline updated successfully');
        dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showEditPipeline', value: false } });
        await fetchPipeline();
      } else {
        toast.error('Failed to update pipeline');
      }
    } catch (error) {
      console.error('Error updating pipeline:', error);
      toast.error('An error occurred');
    }
  };

  const handleReassignAll = async () => {
    if (!confirm('Re-assign all contacts based on their lead scores? This will move contacts to stages matching their scores.')) {
      return;
    }

    setIsReassigning(true);
    try {
      const response = await fetch(`/api/pipelines/${params.id}/reassign-all`, {
        method: 'POST',
      });

      if (!response.ok) throw new Error('Failed to re-assign');

      const data = await response.json();

      toast.success(
        `Successfully re-assigned ${data.reassigned} contacts! ${data.skipped} contacts were already in correct stages.`
      );

      // Refresh pipeline view
      fetchPipeline();
    } catch (error) {
      console.error('Re-assignment error:', error);
      toast.error('Failed to re-assign contacts');
    } finally {
      setIsReassigning(false);
    }
  };

  const handleRemoveAllContacts = () => {
    // Calculate total contacts in pipeline
    const totalContacts = state.pipeline?.stages.reduce(
      (sum, stage) => sum + stage._count.contacts,
      0
    ) || 0;

    if (totalContacts === 0) {
      toast.info('No contacts to remove');
      return;
    }

    // Show confirmation dialog
    dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showRemoveAllContacts', value: true } });
  };

  const confirmRemoveAllContacts = async () => {
    dispatch({ type: 'SET_IS_REMOVING_ALL_CONTACTS', payload: true });
    
    try {
      const response = await fetch(
        `/api/pipelines/${params.id}/remove-all-contacts`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        }
      );

      const data = await response.json();

      if (response.ok) {
        toast.success(data.message || `Successfully removed ${data.removedCount} contact(s) from pipeline`);
        await fetchPipeline();
      } else {
        toast.error(data.error || 'Failed to remove contacts');
      }
    } catch (error) {
      console.error('Error removing all contacts:', error);
      toast.error('An error occurred');
    } finally {
      dispatch({ type: 'SET_IS_REMOVING_ALL_CONTACTS', payload: false });
      dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showRemoveAllContacts', value: false } });
    }
  };

  if (state.loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  if (!state.pipeline) {
    return <div>Pipeline not found</div>;
  }

  return (
    <DndContext
      sensors={sensors}
      onDragStart={handleDragStart}
      onDragEnd={handleDragEnd}
    >
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Button variant="ghost" onClick={() => router.push('/pipelines')}>
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back
            </Button>
          </div>

          <div className="flex items-center gap-2">
            {state.selectedStages.size > 0 && (
              <Button
                variant="destructive"
                size="sm"
                onClick={() => dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showDeleteStages', value: true } })}
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Delete Stages ({state.selectedStages.size})
              </Button>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowScoreRangeDialog(true)}
            >
              <Target className="h-4 w-4 mr-2" />
              Score Ranges
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleReassignAll}
              disabled={isReassigning}
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              {isReassigning ? 'Re-assigning...' : 'Re-assign All'}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showAddContacts', value: true } })}
            >
              <Users className="h-4 w-4 mr-2" />
              Add Contacts
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showAddStage', value: true } })}
            >
              <Plus className="h-4 w-4 mr-2" />
              Add Stage
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showEditPipeline', value: true } })}
            >
              <Edit2 className="h-4 w-4 mr-2" />
              Edit
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={handleRemoveAllContacts}
              disabled={state.isRemovingAllContacts || !state.pipeline || state.pipeline.stages.reduce((sum, stage) => sum + stage._count.contacts, 0) === 0}
            >
              <Trash2 className="h-4 w-4 mr-2" />
              {state.isRemovingAllContacts ? 'Removing...' : 'Remove All Contacts'}
            </Button>
          </div>
        </div>

        <div>
          <div className="flex items-center gap-3">
            <div
              className="w-4 h-4 rounded-full"
              style={{ backgroundColor: state.pipeline.color }}
            />
            <h1 className="text-3xl font-bold">{state.pipeline.name}</h1>
          </div>
          {state.pipeline.description && (
            <p className="text-muted-foreground mt-2">{state.pipeline.description}</p>
          )}
          <div className="flex items-center gap-2 mt-2 text-xs text-muted-foreground">
            <RefreshCw className={`h-3 w-3 ${isSubscribed ? 'text-green-600' : ''}`} />
            <span>Last updated: {new Date(lastUpdate).toLocaleTimeString()}</span>
            {isSubscribed && <span className="text-green-600">● Live</span>}
            {!isSubscribed && <span className="text-yellow-600">○ Connecting...</span>}
          </div>
        </div>

        <div className="flex gap-4 overflow-x-auto pb-4">
          {state.pipeline.stages.map((stage) => {
            const currentPage = state.stagePagination[stage.id] || 1;
            const totalPages = Math.ceil(stage._count.contacts / 20);
            const selectedContacts = state.selectedStageContacts[stage.id] || new Set();

            return (
              <Suspense
                key={stage.id}
                fallback={
                  <div className="shrink-0 w-80">
                    <div className="h-[600px] bg-muted animate-pulse rounded-lg" />
                  </div>
                }
              >
                <PipelineStageCardVirtualized
                  stage={stage}
                  isSelected={state.selectedStages.has(stage.id)}
                  selectedContacts={selectedContacts}
                  searchQuery={state.stageSearchQueries[stage.id] || ''}
                  currentPage={currentPage}
                  totalPages={totalPages}
                  pipelineId={params.id as string}
                  onToggleSelection={() => toggleStageSelection(stage.id)}
                  onSearchChange={(query) => handleStageSearch(stage.id, query)}
                  onToggleContactSelection={toggleContactSelection}
                  onRemoveSelected={() => handleBulkRemoveContacts(stage.id)}
                  onAddTag={() => {
                    dispatch({ type: 'SET_SELECTED_STAGE_FOR_TAG', payload: stage.id });
                    dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showBulkTag', value: true } });
                  }}
                  onPageChange={(page) => handleStagePagination(stage.id, page)}
                />
              </Suspense>
            );
          })}
        </div>

        <DragOverlay>
          {state.activeContact && <ContactCard contact={state.activeContact} isDragging />}
        </DragOverlay>
      </div>

      {state.dialogs.showAddStage && (
        <AddStageDialog
          open={state.dialogs.showAddStage}
          onOpenChange={(value) => dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showAddStage', value } })}
          onSubmit={handleAddStage}
        />
      )}

      {state.dialogs.showEditPipeline && state.pipeline && (
        <EditPipelineDialog
          open={state.dialogs.showEditPipeline}
          onOpenChange={(value) => dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showEditPipeline', value } })}
          pipeline={state.pipeline}
          onSubmit={handleUpdatePipeline}
        />
      )}

      {state.dialogs.showAddContacts && (
        <AddContactsDialog
          open={state.dialogs.showAddContacts}
          onOpenChange={(value) => dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showAddContacts', value } })}
          stages={state.pipeline.stages}
          onSuccess={fetchPipeline}
        />
      )}

      {state.dialogs.showBulkTag && state.selectedStageForTag && (
        <BulkTagDialog
          open={state.dialogs.showBulkTag}
          onOpenChange={(value) => dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showBulkTag', value } })}
          stageId={state.selectedStageForTag}
          contactIds={Array.from(state.selectedStageContacts[state.selectedStageForTag] || [])}
          onSuccess={async () => {
            dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showBulkTag', value: false } });
            dispatch({ type: 'SET_SELECTED_STAGE_FOR_TAG', payload: null });
            await fetchPipeline();
          }}
        />
      )}

      <AlertDialog open={state.dialogs.showDeleteStages} onOpenChange={(value) => dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showDeleteStages', value } })}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Stages?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete {state.selectedStages.size} stage(s). Contacts in these
              stages will be removed from the pipeline. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={state.isDeleting}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleBulkDeleteStages}
              disabled={state.isDeleting}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {state.isDeleting ? 'Deleting...' : 'Delete'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={state.dialogs.showRemoveAllContacts} onOpenChange={(value) => dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showRemoveAllContacts', value } })}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove All Contacts from Pipeline?</AlertDialogTitle>
            <AlertDialogDescription>
              This will remove all contacts from the pipeline &quot;{state.pipeline?.name}&quot;. 
              Contacts will be unassigned from this pipeline and all its stages, but they will not be deleted. 
              This action cannot be undone.
              <br /><br />
              <strong>Total contacts to remove: {state.pipeline?.stages.reduce((sum, stage) => sum + stage._count.contacts, 0) || 0}</strong>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={state.isRemovingAllContacts}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmRemoveAllContacts}
              disabled={state.isRemovingAllContacts}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {state.isRemovingAllContacts ? 'Removing...' : 'Remove All Contacts'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={state.dialogs.showRemoveContacts} onOpenChange={(value) => dispatch({ type: 'TOGGLE_DIALOG', payload: { dialog: 'showRemoveContacts', value } })}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove Contacts from Pipeline?</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to remove {state.selectedStageForRemove ? (state.selectedStageContacts[state.selectedStageForRemove]?.size || 0) : 0} contact(s) from this pipeline stage?
              {' '}This will remove them from the pipeline but will not delete the contacts themselves.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={state.isDeleting}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmRemoveContacts}
              disabled={state.isDeleting}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {state.isDeleting ? 'Removing...' : 'Remove Contacts'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {showScoreRangeDialog && state.pipeline && (
        <ScoreRangeDialog
          stages={state.pipeline.stages.map(s => ({
            id: s.id,
            name: s.name,
            leadScoreMin: s.leadScoreMin || 0,
            leadScoreMax: s.leadScoreMax || 100,
            type: s.type,
            order: 0
          }))}
          pipelineId={state.pipeline.id}
          open={showScoreRangeDialog}
          onOpenChange={setShowScoreRangeDialog}
          onSaved={fetchPipeline}
        />
      )}
    </DndContext>
  );
}
