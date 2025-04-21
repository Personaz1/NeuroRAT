export interface ChatMessage {
  id?: string;
  role: 'user' | 'model' | 'agent' | 'tool' | 'terminal_input' | 'terminal_output' | 'system' | 'terminal';
  content: string;
  timestamp?: number;
} 