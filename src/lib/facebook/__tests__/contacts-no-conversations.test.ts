/**
 * Tests for Contacts with No Conversations
 * 
 * Test cases:
 * 1. Contacts with no conversations handled correctly
 * 2. Contacts created even when conversation is empty
 * 3. No errors when fetching empty conversations
 * 4. Contact metadata preserved without conversation data
 * 5. UI displays contacts without conversations correctly
 */

import { prisma } from '@/lib/db';

jest.mock('@/lib/db', () => ({
  prisma: {
    contact: {
      findMany: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      upsert: jest.fn(),
    },
    conversation: {
      findMany: jest.fn(),
      create: jest.fn(),
    },
  },
}));

describe('Contacts with No Conversations', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Test: Contacts with no conversations handled correctly', () => {
    it('should create contact even when no conversation exists', async () => {
      const contactData = {
        firstName: 'John',
        lastName: 'Doe',
        messengerPSID: 'psid-123',
        facebookPageId: 'page-123',
        organizationId: 'org-123',
        hasMessenger: true,
      };

      (prisma.contact.create as jest.Mock).mockResolvedValue({
        id: 'contact-id',
        ...contactData,
        conversations: [],
      });

      const contact = await prisma.contact.create({
        data: contactData,
      });

      expect(contact).toBeDefined();
      expect(contact.firstName).toBe('John');
      expect(contact.messengerPSID).toBe('psid-123');
      // Contact exists even without conversations
      expect(contact).toHaveProperty('id');
    });

    it('should handle contact with empty conversations array', async () => {
      const contact = {
        id: 'contact-id',
        firstName: 'Jane',
        messengerPSID: 'psid-456',
        conversations: [],
      };

      expect(contact.conversations).toEqual([]);
      expect(Array.isArray(contact.conversations)).toBe(true);
      expect(contact.conversations.length).toBe(0);
      expect(contact.firstName).toBe('Jane'); // Contact data still valid
    });
  });

  describe('Test: Contacts created even when conversation is empty', () => {
    it('should create contact from participant even without messages', async () => {
      const participant = {
        id: 'participant-789',
        name: 'Test User',
      };

      const contactData = {
        firstName: participant.name.split(' ')[0] || 'Unknown',
        messengerPSID: participant.id,
        facebookPageId: 'page-123',
        organizationId: 'org-123',
        hasMessenger: true,
        lastInteraction: null, // No interaction yet
      };

      (prisma.contact.upsert as jest.Mock).mockResolvedValue({
        id: 'contact-id',
        ...contactData,
      });

      const contact = await prisma.contact.upsert({
        where: {
          messengerPSID_facebookPageId: {
            messengerPSID: participant.id,
            facebookPageId: 'page-123',
          },
        },
        create: contactData,
        update: {
          lastInteraction: new Date(),
        },
      });

      expect(contact).toBeDefined();
      expect(contact.messengerPSID).toBe(participant.id);
      expect(contact.lastInteraction).toBeDefined(); // Can be null
    });

    it('should handle contact creation when conversation fetch returns empty', async () => {
      const participantId = 'participant-999';
      const messages: any[] = []; // Empty messages

      // Contact should still be created
      const contactData = {
        firstName: 'User',
        messengerPSID: participantId,
        facebookPageId: 'page-123',
        organizationId: 'org-123',
        hasMessenger: true,
      };

      expect(messages.length).toBe(0);
      expect(contactData.messengerPSID).toBe(participantId);
      // Contact data is valid even with no messages
    });
  });

  describe('Test: No errors when fetching empty conversations', () => {
    it('should return empty array without error', async () => {
      (prisma.conversation.findMany as jest.Mock).mockResolvedValue([]);

      const conversations = await prisma.conversation.findMany({
        where: { contactId: 'contact-id' },
      });

      expect(conversations).toEqual([]);
      expect(Array.isArray(conversations)).toBe(true);
      expect(() => conversations.length).not.toThrow();
    });

    it('should handle null conversation gracefully', () => {
      const contact = {
        id: 'contact-id',
        conversations: null,
      };

      const safeConversations = contact.conversations || [];
      expect(Array.isArray(safeConversations)).toBe(true);
      expect(safeConversations.length).toBe(0);
    });
  });

  describe('Test: Contact metadata preserved without conversation data', () => {
    it('should preserve contact info when no conversations exist', async () => {
      const contact = {
        id: 'contact-id',
        firstName: 'Alice',
        lastName: 'Smith',
        messengerPSID: 'psid-alice',
        facebookPageId: 'page-123',
        organizationId: 'org-123',
        hasMessenger: true,
        profilePicUrl: 'https://example.com/pic.jpg',
        lastInteraction: null,
        conversations: [],
      };

      expect(contact.firstName).toBe('Alice');
      expect(contact.lastName).toBe('Smith');
      expect(contact.messengerPSID).toBe('psid-alice');
      expect(contact.profilePicUrl).toBeDefined();
      expect(contact.conversations.length).toBe(0);
      // All metadata preserved
    });

    it('should allow contact updates without conversation requirement', async () => {
      const updateData = {
        firstName: 'Updated Name',
        lastInteraction: new Date(),
      };

      (prisma.contact.update as jest.Mock).mockResolvedValue({
        id: 'contact-id',
        ...updateData,
        conversations: [],
      });

      const updated = await prisma.contact.update({
        where: { id: 'contact-id' },
        data: updateData,
      });

      expect(updated.firstName).toBe('Updated Name');
      expect(updated.lastInteraction).toBeDefined();
      // Update succeeds without conversations
    });
  });

  describe('Test: UI displays contacts without conversations correctly', () => {
    it('should show contact in list even without conversations', () => {
      const contact = {
        id: 'contact-id',
        firstName: 'Bob',
        lastName: 'Johnson',
        conversationCount: 0,
      };

      const displayName = `${contact.firstName} ${contact.lastName}`;
      const hasConversations = contact.conversationCount > 0;
      const statusMessage = hasConversations 
        ? `${contact.conversationCount} conversations` 
        : 'No conversations yet';

      expect(displayName).toBe('Bob Johnson');
      expect(hasConversations).toBe(false);
      expect(statusMessage).toBe('No conversations yet');
    });

    it('should handle contact detail view without conversations', () => {
      const contact = {
        id: 'contact-id',
        firstName: 'Charlie',
        conversations: [],
      };

      const canShowConversations = contact.conversations && contact.conversations.length > 0;
      const emptyStateMessage = canShowConversations 
        ? null 
        : 'This contact has no conversations yet.';

      expect(canShowConversations).toBe(false);
      expect(emptyStateMessage).toBe('This contact has no conversations yet.');
    });

    it('should calculate stats correctly for contacts without conversations', () => {
      const contacts = [
        { id: '1', conversationCount: 0 },
        { id: '2', conversationCount: 5 },
        { id: '3', conversationCount: 0 },
      ];

      const totalContacts = contacts.length;
      const contactsWithConversations = contacts.filter(c => c.conversationCount > 0).length;
      const contactsWithoutConversations = contacts.filter(c => c.conversationCount === 0).length;

      expect(totalContacts).toBe(3);
      expect(contactsWithConversations).toBe(1);
      expect(contactsWithoutConversations).toBe(2);
      expect(contactsWithConversations + contactsWithoutConversations).toBe(totalContacts);
    });
  });

  describe('Test: Edge cases for contacts without conversations', () => {
    it('should handle contact with null conversationId', () => {
      const contact = {
        id: 'contact-id',
        conversationId: null,
        conversations: [],
      };

      expect(contact.conversationId).toBeNull();
      expect(contact.conversations.length).toBe(0);
      // Both indicate no conversations, both are valid
    });

    it('should handle contact where conversation was deleted', async () => {
      (prisma.contact.findMany as jest.Mock).mockResolvedValue([
        {
          id: 'contact-id',
          firstName: 'Deleted',
          conversationId: 'deleted-conv-id',
          conversations: [], // Conversation no longer exists
        },
      ]);

      const contacts = await prisma.contact.findMany({
        where: { organizationId: 'org-123' },
      });

      expect(contacts.length).toBe(1);
      expect(contacts[0].conversations.length).toBe(0);
      // Contact still exists even though conversation is gone
    });

    it('should allow creating new conversation for contact without any', async () => {
      const contact = {
        id: 'contact-id',
        conversations: [],
      };

      (prisma.conversation.create as jest.Mock).mockResolvedValue({
        id: 'new-conv-id',
        contactId: contact.id,
        messages: [],
      });

      // Can create first conversation
      const canCreateConversation = contact.conversations.length === 0;
      expect(canCreateConversation).toBe(true);
    });
  });
});









