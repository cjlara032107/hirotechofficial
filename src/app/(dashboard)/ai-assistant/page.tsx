'use client';

import { useState, useEffect, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Plus, Send, Trash2, Loader2 } from 'lucide-react';

interface Message {
  id: string;
  role: 'USER' | 'ASSISTANT';
  content: string;
  createdAt: string;
}

interface Chat {
  id: string;
  title: string | null;
  updatedAt: string;
  _count: { messages: number };
}

export default function AIAssistantPage() {
  const [chats, setChats] = useState<Chat[]>([]);
  const [selectedChat, setSelectedChat] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [creatingChat, setCreatingChat] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    loadChats();
  }, []);

  useEffect(() => {
    if (selectedChat) {
      loadMessages(selectedChat);
    } else {
      setMessages([]);
    }
  }, [selectedChat]);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const loadChats = async () => {
    try {
      const res = await fetch('/api/ai-assistant/chats');
      if (res.ok) {
        const data = await res.json();
        setChats(data);
      }
    } catch (error) {
      console.error('Failed to load chats:', error);
    }
  };

  const loadMessages = async (chatId: string) => {
    try {
      const res = await fetch(`/api/ai-assistant/chats/${chatId}`);
      if (res.ok) {
        const data = await res.json();
        setMessages(data.messages || []);
      }
    } catch (error) {
      console.error('Failed to load messages:', error);
    }
  };

  const createChat = async () => {
    setCreatingChat(true);
    try {
      const res = await fetch('/api/ai-assistant/chats', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: 'New Chat' }),
      });

      if (res.ok) {
        const newChat = await res.json();
        await loadChats();
        setSelectedChat(newChat.id);
      }
    } catch (error) {
      console.error('Failed to create chat:', error);
    } finally {
      setCreatingChat(false);
    }
  };

  const sendMessage = async () => {
    if (!input.trim() || !selectedChat || loading) return;

    const userMessage = input;
    setInput('');
    setLoading(true);

    // Add user message optimistically
    const tempUserMessage: Message = {
      id: `temp-${Date.now()}`,
      role: 'USER',
      content: userMessage,
      createdAt: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, tempUserMessage]);

    try {
      const res = await fetch(`/api/ai-assistant/chats/${selectedChat}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: userMessage }),
      });

      if (res.ok) {
        const data = await res.json();
        // Replace temp message and add assistant response
        setMessages((prev) => [
          ...prev.filter((m) => m.id !== tempUserMessage.id),
          data.userMessage,
          data.assistantMessage,
        ]);
        // Reload chats to update counts
        await loadChats();
      } else {
        const error = await res.json();
        alert(error.error || 'Failed to send message');
        // Remove temp message on error
        setMessages((prev) => prev.filter((m) => m.id !== tempUserMessage.id));
      }
    } catch (error) {
      console.error('Failed to send message:', error);
      alert('Failed to send message');
      setMessages((prev) => prev.filter((m) => m.id !== tempUserMessage.id));
    } finally {
      setLoading(false);
    }
  };

  const deleteChat = async (chatId: string) => {
    if (!confirm('Are you sure you want to delete this chat?')) return;

    try {
      const res = await fetch(`/api/ai-assistant/chats/${chatId}`, {
        method: 'DELETE',
      });

      if (res.ok) {
        await loadChats();
        if (selectedChat === chatId) {
          setSelectedChat(null);
          setMessages([]);
        }
      }
    } catch (error) {
      console.error('Failed to delete chat:', error);
    }
  };

  return (
    <div className="flex h-[calc(100vh-4rem)]">
      {/* Sidebar */}
      <div className="w-64 border-r bg-muted/40 p-4 flex flex-col">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold">AI Assistant</h2>
          <Button
            size="sm"
            onClick={createChat}
            disabled={creatingChat}
          >
            {creatingChat ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Plus className="h-4 w-4" />
            )}
          </Button>
        </div>

        <ScrollArea className="flex-1">
          <div className="space-y-2">
            {chats.map((chat) => (
              <div
                key={chat.id}
                className={`p-3 rounded-lg cursor-pointer hover:bg-muted transition-colors ${
                  selectedChat === chat.id ? 'bg-muted' : ''
                }`}
                onClick={() => setSelectedChat(chat.id)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">
                      {chat.title || 'New Chat'}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {chat._count.messages} messages
                    </p>
                  </div>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={(e) => {
                      e.stopPropagation();
                      deleteChat(chat.id);
                    }}
                  >
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>
      </div>

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col">
        {selectedChat ? (
          <>
            <ScrollArea className="flex-1 p-4">
              <div className="space-y-4 max-w-3xl mx-auto">
                {messages.map((message) => (
                  <div
                    key={message.id}
                    className={`flex ${
                      message.role === 'USER' ? 'justify-end' : 'justify-start'
                    }`}
                  >
                    <div
                      className={`max-w-[80%] rounded-lg p-3 ${
                        message.role === 'USER'
                          ? 'bg-primary text-primary-foreground'
                          : 'bg-muted'
                      }`}
                    >
                      <p className="text-sm whitespace-pre-wrap">
                        {message.content}
                      </p>
                    </div>
                  </div>
                ))}
                {loading && (
                  <div className="flex justify-start">
                    <div className="bg-muted rounded-lg p-3">
                      <Loader2 className="h-4 w-4 animate-spin" />
                    </div>
                  </div>
                )}
                <div ref={messagesEndRef} />
              </div>
            </ScrollArea>

            <div className="border-t p-4">
              <div className="max-w-3xl mx-auto flex gap-2">
                <Input
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      sendMessage();
                    }
                  }}
                  placeholder="Ask me anything about your contacts, campaigns, pipelines..."
                  disabled={loading}
                />
                <Button
                  onClick={sendMessage}
                  disabled={loading || !input.trim()}
                >
                  {loading ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Send className="h-4 w-4" />
                  )}
                </Button>
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <h3 className="text-lg font-semibold mb-2">
                No chat selected
              </h3>
              <p className="text-muted-foreground mb-4">
                Create a new chat to start talking with the AI assistant
              </p>
              <Button onClick={createChat} disabled={creatingChat}>
                {creatingChat ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />
                    Creating...
                  </>
                ) : (
                  <>
                    <Plus className="h-4 w-4 mr-2" />
                    New Chat
                  </>
                )}
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}



