import { ChatMessage } from '../types/ChatMessage';
import { v4 as uuidv4 } from 'uuid';

// URL API сервера
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export class ChatService {
  // Функция для отправки сообщения на сервер
  static async sendMessage(messages: ChatMessage[]): Promise<ChatMessage[]> {
    try {
      const response = await fetch(`${API_URL}/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ messages }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return data.messages || [];
    } catch (error) {
      console.error('Error sending message:', error);
      // Создаем сообщение об ошибке
      return [
        {
          id: uuidv4(),
          role: 'system',
          content: `Ошибка при отправке сообщения: ${error instanceof Error ? error.message : String(error)}`,
          timestamp: new Date().toISOString(),
        },
      ];
    }
  }

  // Функция для создания нового сообщения пользователя
  static createUserMessage(content: string): ChatMessage {
    return {
      id: uuidv4(),
      role: 'user',
      content,
      timestamp: new Date().toISOString(),
    };
  }

  // Функция для создания системного сообщения
  static createSystemMessage(content: string): ChatMessage {
    return {
      id: uuidv4(),
      role: 'system',
      content,
      timestamp: new Date().toISOString(),
    };
  }

  // Функция для обработки потока SSE от сервера
  static async streamMessage(
    messages: ChatMessage[],
    onUpdate: (message: ChatMessage) => void,
    onComplete: (messages: ChatMessage[]) => void
  ): Promise<void> {
    try {
      const eventSource = new EventSource(`${API_URL}/chat/stream?messages=${encodeURIComponent(JSON.stringify(messages))}`);
      
      // ID текущего сообщения от агента
      let currentMessageId = uuidv4();
      let currentMessage: ChatMessage = {
        id: currentMessageId,
        role: 'agent',
        content: '',
        timestamp: new Date().toISOString(),
      };
      
      // Обработка получения новой части сообщения
      eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        if (data.role && data.role !== currentMessage.role) {
          // Если получено сообщение с новой ролью, завершаем текущее и создаем новое
          onUpdate({ ...currentMessage });
          
          currentMessageId = uuidv4();
          currentMessage = {
            id: currentMessageId,
            role: data.role,
            content: data.content || '',
            timestamp: new Date().toISOString(),
          };
        } else {
          // Добавляем содержимое к текущему сообщению
          currentMessage.content += data.content || '';
        }
        
        // Обновляем UI
        onUpdate({ ...currentMessage });
      };
      
      // Обработка завершения потока
      eventSource.addEventListener('complete', (event) => {
        const data = JSON.parse((event as MessageEvent).data);
        eventSource.close();
        onComplete(data.messages || []);
      });
      
      // Обработка ошибок
      eventSource.onerror = (error) => {
        console.error('SSE Error:', error);
        eventSource.close();
        
        // Создаем сообщение об ошибке
        const errorMessage = {
          id: uuidv4(),
          role: 'system',
          content: 'Произошла ошибка при получении данных от сервера.',
          timestamp: new Date().toISOString(),
        };
        
        onUpdate(errorMessage);
        onComplete([errorMessage]);
      };
    } catch (error) {
      console.error('Streaming error:', error);
      
      // Создаем сообщение об ошибке
      const errorMessage = {
        id: uuidv4(),
        role: 'system',
        content: `Ошибка при установке потокового соединения: ${error instanceof Error ? error.message : String(error)}`,
        timestamp: new Date().toISOString(),
      };
      
      onUpdate(errorMessage);
      onComplete([errorMessage]);
    }
  }
} 