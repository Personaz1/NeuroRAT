import React, { useState, useCallback } from 'react';
import MessageList, { Message } from '../components/Chat/MessageList';
import InputPanel from '../components/Chat/InputPanel';
import TerminalPanel from '../components/Terminal/TerminalPanel';
import axios from 'axios'; // Импортируем axios

const API_BASE_URL = 'http://localhost:8000'; // URL нашего бэкенда

const ChatPage: React.FC = () => {
  const [messages, setMessages] = useState<Message[]>([
    // Оставляем только стартовое системное сообщение
    {
      id: 'system-start',
      role: 'system',
      content: 'Сессия чата начата. Готов к работе.', // Убираем пример кода
      timestamp: Date.now(),
    },
  ]);
  const [isLoading, setIsLoading] = useState(false);
  const [includeTerminalHistory, setIncludeTerminalHistory] = useState(true); // Состояние для чекбокса

  // Функция для добавления нового сообщения в список
  const addMessage = useCallback((newMessage: Omit<Message, 'id' | 'timestamp'>) => {
    setMessages((prevMessages) => [
      ...prevMessages,
      {
        ...newMessage,
        id: crypto.randomUUID(), // Генерируем случайный ID
        timestamp: Date.now(),
      },
    ]);
  }, []);

  // Обработчик отправки сообщения пользователем
  const handleSendMessage = useCallback(
    async (userMessage: string) => {
      const userMsgObject: Omit<Message, 'id' | 'timestamp'> = {
          role: 'user',
          content: userMessage,
      };

      // 1. Готовим отфильтрованную историю ПЕРЕД обновлением состояния
      let historyForApi: { role: string; content: string }[] = [];
      setMessages(prevMessages => {
          // Фильтруем ПРЕДЫДУЩИЕ сообщения + НОВОЕ сообщение пользователя
          const messagesToSend = [
              ...prevMessages,
              { ...userMsgObject, id: 'temp-user', timestamp: Date.now() } // Добавляем временное новое сообщение
          ];
          historyForApi = messagesToSend
              .filter(msg =>
                  msg.role !== 'system' &&
                  (includeTerminalHistory || !['terminal_input', 'terminal_output'].includes(msg.role))
              )
              .map(({ role, content }) => ({ role, content }));
          // Обновляем состояние, добавляя НОВОЕ сообщение пользователя (уже без фильтрации)
          return [
              ...prevMessages,
              {
                  ...userMsgObject,
                  id: crypto.randomUUID(),
                  timestamp: Date.now(),
              },
          ];
      });

      // 2. Вызываем API с подготовленной И ПРАВИЛЬНО отфильтрованной историей
      setIsLoading(true);
      try {
        // Отправляем запрос на бэкенд
        const response = await axios.post(`${API_BASE_URL}/api/chat`, {
          prompt: userMessage, // Оставляем последнее сообщение как prompt
          mode: 'STANDARD',
          history: historyForApi, // <--- Используем ПРАВИЛЬНУЮ историю
        });

        if (response.data && response.data.content) {
          addMessage({ role: 'agent', content: response.data.content });
        } else {
           addMessage({ role: 'system', content: 'Получен пустой ответ от агента.' });
        }

      } catch (error) {
        console.error("Ошибка при отправке/получении сообщения:", error);
        let errorMessage = 'Ошибка получения ответа от агента.';
        if (axios.isAxiosError(error)) {
          errorMessage = `Ошибка сети или сервера: ${error.message}`;
          if (error.response) {
             errorMessage += ` (Статус: ${error.response.status})`;
          }
        }
        addMessage({ role: 'system', content: errorMessage });
      } finally {
        setIsLoading(false);
      }
    },
    [addMessage, includeTerminalHistory] // Зависимости корректны
  );

  // Обработчик для действий из терминала
  const handleTerminalAction = useCallback(
    (type: 'input' | 'output', content: string) => {
      if (!content.trim()) return; // Не добавляем пустые строки

      // Определяем роль для сообщения в истории чата
      const role: Message['role'] = type === 'input' ? 'terminal_input' : 'terminal_output';

      // Форматируем контент для отображения (например, добавляем префикс)
      // const displayContent = type === 'input' ? `$ ${content}` : content; // Убрал префикс $, т.к. терминал сам его ставит

      // Используем addMessage для добавления
      addMessage({ role, content }); // Используем оригинальный content

      // Важно: Здесь мы просто добавляем в ИСТОРИЮ ЧАТА.
      // Эта история будет учтена при СЛЕДУЮЩЕМ вызове /api/chat из InputPanel,
      // если включен чекбокс includeTerminalHistory.
      // Мы НЕ вызываем LLM напрямую после каждого действия в терминале.
    },
    [addMessage]
  );

  // --- СТИЛИ ---
  const chatPageStyle: React.CSSProperties = {
    display: 'flex',       // Используем Flexbox
    flexDirection: 'row',  // Располагаем элементы в строку (бок о бок)
    height: 'calc(100vh - 40px)', // Учитываем padding от MainContent
    maxHeight: 'calc(100vh - 40px)',
    width: '100%', // Занимаем всю ширину родителя
  };

  const chatAreaStyle: React.CSSProperties = {
      display: 'flex',
      flexDirection: 'column',
      flex: '2', // Чат занимает 2/3 ширины (или больше)
      // borderRight: '1px solid #333', // Убрал разделитель, т.к. терминал теперь часть чата
      overflow: 'hidden', // Чтобы внутренние компоненты не вылезали
      height: '100%', // Занимаем всю высоту
  };

  const messageListContainerStyle: React.CSSProperties = {
      flexGrow: 1, // Занимает все доступное верт. пространство
      overflowY: 'auto', // Позволяет прокручивать сообщения
      padding: '10px', // Добавил отступы
  };

  const terminalAreaStyle: React.CSSProperties = {
      flex: '1', // Терминал занимает 1/3 ширины
      display: 'flex', // Для управления внутренним компонентом
      flexDirection: 'column',
      overflow: 'hidden',
      height: '100%', // Занимаем всю высоту
      borderLeft: '1px solid #333', // Добавил разделитель слева
      backgroundColor: '#1a1a1a', // Фон для области терминала
  };

  const terminalHeaderStyle: React.CSSProperties = {
      padding: '5px 10px',
      background: '#2a2a2a',
      borderBottom: '1px solid #333',
      display: 'flex',
      alignItems: 'center',
      fontSize: '0.9em',
      color: '#ccc',
  };

  // --- КОМПОНЕНТЫ ---
  return (
    <div style={chatPageStyle}>
       {/* Левая часть: Чат */}
      <div style={chatAreaStyle}>
          <div style={messageListContainerStyle}>
              <MessageList messages={messages} loading={isLoading} />
          </div>
          <InputPanel onSendMessage={handleSendMessage} loading={isLoading} />
      </div>

      {/* Правая часть: Терминал с заголовком и чекбоксом */}
      <div style={terminalAreaStyle}>
          <div style={terminalHeaderStyle}>
            <input
              type="checkbox"
              id="includeTerminal"
              checked={includeTerminalHistory}
              onChange={(e) => setIncludeTerminalHistory(e.target.checked)}
              style={{ marginRight: '8px' }}
            />
            <label htmlFor="includeTerminal" style={{ cursor: 'pointer' }}>
              Включить историю терминала в контекст LLM
            </label>
          </div>
          {/* flexGrow: 1 нужен контейнеру вокруг TerminalPanel, чтобы он растянулся */}
          <div style={{ flexGrow: 1, overflow: 'hidden' }}>
            <TerminalPanel onTerminalAction={handleTerminalAction} />
          </div>
      </div>
    </div>
  );
};

export default ChatPage; 