import { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'AI Assistant | HIRO',
  description: 'Chat with AI assistant about your contacts, campaigns, and pipelines',
};

export default function AIAssistantLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}



