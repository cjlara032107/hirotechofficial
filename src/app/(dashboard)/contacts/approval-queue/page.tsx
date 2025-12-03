'use client';

import { useState, useEffect } from 'react';
import Image from 'next/image';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import { Textarea } from '@/components/ui/textarea';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Loader2, CheckCircle2, XCircle, AlertTriangle, Shield, User } from 'lucide-react';
import { toast } from 'sonner';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';

interface Contact {
  id: string;
  firstName: string;
  lastName: string | null;
  messengerPSID: string | null;
  instagramSID: string | null;
  profilePicUrl: string | null;
  riskScore: number | null;
  riskLevel: string | null;
  riskReasons: string[];
  leadScore: number;
  leadStatus: string;
  aiContext: string | null;
  lastInteraction: string | null;
  createdAt: string;
  facebookPage: {
    pageName: string;
  };
}

interface ApprovalQueueResponse {
  contacts: Contact[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

export default function ApprovalQueuePage() {
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [selectedContacts, setSelectedContacts] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [processing, setProcessing] = useState(false);
  const [pagination, setPagination] = useState({ page: 1, limit: 50, total: 0, totalPages: 0 });
  const [showFeedbackDialog, setShowFeedbackDialog] = useState(false);
  const [feedback, setFeedback] = useState('');
  const [pendingAction, setPendingAction] = useState<'approve' | 'reject' | null>(null);

  const loadContacts = async () => {
    try {
      setLoading(true);
      const response = await fetch(`/api/contacts/approval-queue?page=${pagination.page}&limit=${pagination.limit}`);
      if (response.ok) {
        const data: ApprovalQueueResponse = await response.json();
        setContacts(data.contacts);
        setPagination(data.pagination);
      } else {
        toast.error('Failed to load approval queue');
      }
    } catch (error) {
      console.error('Error loading contacts:', error);
      toast.error('Failed to load approval queue');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadContacts();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pagination.page]);

  const handleSelectAll = () => {
    if (selectedContacts.size === contacts.length) {
      setSelectedContacts(new Set());
    } else {
      setSelectedContacts(new Set(contacts.map(c => c.id)));
    }
  };

  const handleSelectContact = (contactId: string) => {
    const newSelected = new Set(selectedContacts);
    if (newSelected.has(contactId)) {
      newSelected.delete(contactId);
    } else {
      newSelected.add(contactId);
    }
    setSelectedContacts(newSelected);
  };

  const handleApprove = () => {
    if (selectedContacts.size === 0) {
      toast.error('Please select at least one contact');
      return;
    }
    setPendingAction('approve');
    setShowFeedbackDialog(true);
  };

  const handleReject = () => {
    if (selectedContacts.size === 0) {
      toast.error('Please select at least one contact');
      return;
    }
    setPendingAction('reject');
    setShowFeedbackDialog(true);
  };

  const handleSubmitAction = async () => {
    if (selectedContacts.size === 0 || !pendingAction) return;

    try {
      setProcessing(true);
      const response = await fetch('/api/contacts/approval-queue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contactIds: Array.from(selectedContacts),
          action: pendingAction,
          feedback: feedback.trim() || undefined,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        toast.success(
          `${pendingAction === 'approve' ? 'Approved' : 'Rejected'} ${data.updated} contact(s) successfully`
        );
        setSelectedContacts(new Set());
        setFeedback('');
        setShowFeedbackDialog(false);
        setPendingAction(null);
        loadContacts();
      } else {
        const error = await response.json();
        toast.error(error.error || 'Failed to process action');
      }
    } catch (error) {
      console.error('Error processing action:', error);
      toast.error('Failed to process action');
    } finally {
      setProcessing(false);
    }
  };

  const getRiskBadge = (level: string | null, score: number | null) => {
    if (!level) return null;
    
    const variants: Record<string, { variant: 'default' | 'secondary' | 'destructive' | 'outline'; icon: typeof AlertTriangle }> = {
      LOW: { variant: 'default', icon: CheckCircle2 },
      MEDIUM: { variant: 'secondary', icon: AlertTriangle },
      HIGH: { variant: 'destructive', icon: Shield },
      CRITICAL: { variant: 'destructive', icon: Shield },
    };

    const config = variants[level] || variants.MEDIUM;
    const Icon = config.icon;

    return (
      <Badge variant={config.variant} className="flex items-center gap-1">
        <Icon className="h-3 w-3" />
        {level} ({score || 'N/A'})
      </Badge>
    );
  };

  if (loading && contacts.length === 0) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="container mx-auto py-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Approval Queue</h1>
          <p className="text-muted-foreground mt-1">
            Review and approve high-risk contacts that require manual verification
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={handleReject}
            disabled={selectedContacts.size === 0 || processing}
          >
            <XCircle className="h-4 w-4 mr-2" />
            Reject ({selectedContacts.size})
          </Button>
          <Button
            onClick={handleApprove}
            disabled={selectedContacts.size === 0 || processing}
          >
            <CheckCircle2 className="h-4 w-4 mr-2" />
            Approve ({selectedContacts.size})
          </Button>
        </div>
      </div>

      {contacts.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <CheckCircle2 className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-lg font-medium">No contacts pending approval</p>
            <p className="text-muted-foreground mt-2">
              All contacts have been reviewed or there are no high-risk contacts.
            </p>
          </CardContent>
        </Card>
      ) : (
        <>
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Pending Approval ({pagination.total})</CardTitle>
                  <CardDescription>
                    Contacts with risk score ≥ 40 or HIGH/CRITICAL risk level
                  </CardDescription>
                </div>
                <div className="flex items-center gap-2">
                  <Checkbox
                    checked={selectedContacts.size === contacts.length && contacts.length > 0}
                    onCheckedChange={handleSelectAll}
                  />
                  <span className="text-sm text-muted-foreground">Select All</span>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {contacts.map((contact) => (
                  <div
                    key={contact.id}
                    className="border rounded-lg p-4 hover:bg-muted/50 transition-colors"
                  >
                    <div className="flex items-start gap-4">
                      <Checkbox
                        checked={selectedContacts.has(contact.id)}
                        onCheckedChange={() => handleSelectContact(contact.id)}
                      />
                      <div className="flex-1 space-y-3">
                        <div className="flex items-start justify-between">
                          <div className="flex items-center gap-3">
                            {contact.profilePicUrl ? (
                              <Image
                                src={contact.profilePicUrl}
                                alt={`${contact.firstName} ${contact.lastName || ''}`}
                                width={40}
                                height={40}
                                className="w-10 h-10 rounded-full"
                              />
                            ) : (
                              <div className="w-10 h-10 rounded-full bg-muted flex items-center justify-center">
                                <User className="h-5 w-5 text-muted-foreground" />
                              </div>
                            )}
                            <div>
                              <h3 className="font-semibold">
                                {contact.firstName} {contact.lastName || ''}
                              </h3>
                              <p className="text-sm text-muted-foreground">
                                {contact.facebookPage.pageName}
                              </p>
                            </div>
                          </div>
                          {getRiskBadge(contact.riskLevel, contact.riskScore)}
                        </div>

                        {contact.riskReasons.length > 0 && (
                          <Alert>
                            <AlertTriangle className="h-4 w-4" />
                            <AlertDescription>
                              <div className="space-y-1">
                                <p className="font-medium">Risk Reasons:</p>
                                <ul className="list-disc list-inside text-sm space-y-0.5">
                                  {contact.riskReasons.map((reason, idx) => (
                                    <li key={idx}>{reason}</li>
                                  ))}
                                </ul>
                              </div>
                            </AlertDescription>
                          </Alert>
                        )}

                        {contact.aiContext && (
                          <div className="text-sm">
                            <p className="font-medium mb-1">AI Context:</p>
                            <p className="text-muted-foreground line-clamp-2">{contact.aiContext}</p>
                          </div>
                        )}

                        <div className="flex items-center gap-4 text-sm text-muted-foreground">
                          <span>Lead Score: {contact.leadScore}</span>
                          <span>Status: {contact.leadStatus}</span>
                          {contact.lastInteraction && (
                            <span>
                              Last Interaction: {new Date(contact.lastInteraction).toLocaleDateString()}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {pagination.totalPages > 1 && (
            <div className="flex items-center justify-center gap-2">
              <Button
                variant="outline"
                onClick={() => setPagination(prev => ({ ...prev, page: prev.page - 1 }))}
                disabled={pagination.page === 1}
              >
                Previous
              </Button>
              <span className="text-sm text-muted-foreground">
                Page {pagination.page} of {pagination.totalPages}
              </span>
              <Button
                variant="outline"
                onClick={() => setPagination(prev => ({ ...prev, page: prev.page + 1 }))}
                disabled={pagination.page >= pagination.totalPages}
              >
                Next
              </Button>
            </div>
          )}
        </>
      )}

      <Dialog open={showFeedbackDialog} onOpenChange={setShowFeedbackDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {pendingAction === 'approve' ? 'Approve' : 'Reject'} {selectedContacts.size} Contact(s)
            </DialogTitle>
            <DialogDescription>
              {pendingAction === 'approve'
                ? 'Approve these contacts and optionally provide feedback.'
                : 'Reject these contacts and optionally provide feedback for improvement.'}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium mb-2 block">
                Feedback (Optional)
              </label>
              <Textarea
                placeholder="Add feedback about these contacts..."
                value={feedback}
                onChange={(e) => setFeedback(e.target.value)}
                rows={4}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowFeedbackDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleSubmitAction} disabled={processing}>
              {processing ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Processing...
                </>
              ) : (
                <>
                  {pendingAction === 'approve' ? (
                    <>
                      <CheckCircle2 className="h-4 w-4 mr-2" />
                      Approve
                    </>
                  ) : (
                    <>
                      <XCircle className="h-4 w-4 mr-2" />
                      Reject
                    </>
                  )}
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
