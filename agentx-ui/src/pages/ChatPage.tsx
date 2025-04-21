import React, { useState, useCallback, useEffect } from 'react';
import MessageList, { Message } from '../components/Chat/MessageList';
import InputPanel from '../components/Chat/InputPanel';
import TerminalPanel from '../components/Terminal/TerminalPanel';
import ReasoningPanel from '../components/ReasoningPanel/ReasoningPanel';
import { Tabs, Tab, Box, IconButton, Typography, Button } from '@mui/material';
import PhotoCamera from '@mui/icons-material/PhotoCamera';

const API_BASE_URL = 'http://localhost:8000'; // URL нашего бэкенда

// Интерфейс TabPanelProps для компонента вкладок
interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

// Компонент панели вкладки
function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
      style={{ height: 'calc(100% - 48px)', overflow: 'hidden' }}
      {...other}
    >
      {value === index && (
        <div style={{ height: '100%' }}>
          {children}
        </div>
      )}
    </div>
  );
}

const ChatPage: React.FC = () => {
  // Инициализация сообщений с постоянным хранением в localStorage
  const [messages, setMessages] = useState<Message[]>(() => {
    try {
      const stored = localStorage.getItem('chat_messages');
      if (stored) {
        return JSON.parse(stored) as Message[];
      }
    } catch {
      // ignore JSON parse or localStorage errors
    }
    return [
      { id: 'system-start', role: 'system', content: 'Сессия чата начата. Готов к работе.', timestamp: Date.now() },
    ];
  });
  const [isLoading, setIsLoading] = useState(false);
  const [includeTerminalHistory, setIncludeTerminalHistory] = useState(true); // Состояние для чекбокса
  const [activeTab, setActiveTab] = useState(0); // Состояние для активной вкладки
  // Изображение ожидающее отправки
  const [pendingImage, setPendingImage] = useState<{ file: File; url: string } | null>(null);

  // Сохраняем сообщения в localStorage при каждом изменении
  useEffect(() => {
    try {
      localStorage.setItem('chat_messages', JSON.stringify(messages));
    } catch {
      // ignore localStorage write errors
    }
  }, [messages]);

  // Обработчик смены вкладки
  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  };

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

  // Обработчик загрузки изображения и генерации подписи
  const handleImageUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const url = URL.createObjectURL(file);
    setPendingImage({ file, url });
  }, []);

  // Обработчик отправки сообщения пользователем
  const handleSendMessage = useCallback(
    async (userMessage: string) => {
      if (pendingImage) {
        // Показываем изображение в чате как markdown
        addMessage({ role: 'user', content: `![изображение](${pendingImage.url})` });
        // Получаем BLIP-подпись через endpoint image_caption
        try {
          const capForm = new FormData();
          capForm.append('file', pendingImage.file);
          const capResp = await fetch(`${API_BASE_URL}/api/image_caption`, { method: 'POST', body: capForm });
          const capData = await capResp.json();
          if (capData.caption) {
            addMessage({ role: 'agent', content: capData.caption });
          }
        } catch (err) {
          addMessage({ role: 'system', content: `Ошибка подписи изображения: ${err}` });
        }
        // Также пытаемся извлечь текст через OCR
        try {
          const ocrForm = new FormData();
          ocrForm.append('file', pendingImage.file);
          const ocrResp = await fetch(`${API_BASE_URL}/api/ocr_image`, { method: 'POST', body: ocrForm });
          const ocrData = await ocrResp.json();
          if (ocrData.text) {
            addMessage({ role: 'agent', content: `Text: ${ocrData.text}` });
          }
        } catch (err) {
          addMessage({ role: 'system', content: `Ошибка OCR: ${err}` });
        }
        setPendingImage(null);
      }
      const userMsgObject: Omit<Message, 'id' | 'timestamp'> = {
        role: 'user',
        content: userMessage,
      };

      // 1. Готовим отфильтрованную историю ПЕРЕД обновлением состояния
      let historyForApi: { role: string; content: string }[] = [];
      setMessages(prevMessages => {
          // Формируем историю для API: предыдущие сообщения, изображение (если есть), новое сообщение
          const messagesForHistory = [...prevMessages];
          if (pendingImage) {
            messagesForHistory.push({ role: 'user', content: `![изображение](${pendingImage.url})`, id: 'temp-img', timestamp: Date.now() });
          }
          const newMsgTemp = { ...userMsgObject, id: 'temp-user', timestamp: Date.now() };
          messagesForHistory.push(newMsgTemp);
          historyForApi = messagesForHistory
              .filter(msg =>
                  msg.role !== 'system' &&
                  (includeTerminalHistory || !['terminal_input', 'terminal_output'].includes(msg.role))
              )
              .map(({ role, content }) => ({ role, content }));
          // Обновляем состояние, добавляя НОВОЕ сообщение пользователя (уже без фильтрации)
          return [
              ...prevMessages,
              { ...userMsgObject, id: crypto.randomUUID(), timestamp: Date.now() },
          ];
      });

      // 2. Вызываем API с подготовленной И ПРАВИЛЬНО отфильтрованной историей
      setIsLoading(true);
      try {
        // Отправляем POST-запрос и читаем SSE-стрим из response.body
        const response = await fetch(`${API_BASE_URL}/api/chat`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ prompt: userMessage, mode: 'STANDARD', history: historyForApi }),
        });
        if (!response.body) {
          throw new Error('Нет тела ответа от сервера');
        }
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let done = false;
        // Читаем данные построчно/по событиям SSE
        while (!done) {
          const { value, done: doneReading } = await reader.read();
          done = doneReading;
          const chunk = decoder.decode(value || new Uint8Array(), { stream: true });
          const events = chunk.split('\n\n');
          events.forEach(event => {
            if (event.startsWith('data:')) {
              const dataStr = event.replace(/^data:\s*/, '');
              try {
                const data = JSON.parse(dataStr);
                if (data.content) {
                  addMessage({ role: 'agent', content: data.content });
                } else if (data.error) {
                  addMessage({ role: 'system', content: `Ошибка: ${data.error}` });
                }
              } catch {
                // Игнорируем невалидные JSON
              }
            }
          });
        }
      } catch (error) {
        console.error("Ошибка при отправке/получении сообщения:", error);
        const errorMessage = error instanceof Error
          ? `Ошибка сети или сервера: ${error.message}`
          : 'Ошибка получения ответа от агента.';
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

  // Обработчик очистки истории чата
  const handleClearHistory = useCallback(() => {
    const initial: Message = { id: 'system-start', role: 'system', content: 'Сессия чата начата. Готов к работе.', timestamp: Date.now() };
    setMessages([initial]);
    try {
      localStorage.removeItem('chat_messages');
    } catch {
      // ignore errors when clearing storage
    }
  }, []);

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

  const rightAreaStyle: React.CSSProperties = {
      flex: '1', // Правая часть занимает 1/3 ширины
      display: 'flex', // Для управления внутренним компонентом
      flexDirection: 'column',
      overflow: 'hidden',
      height: '100%', // Занимаем всю высоту
      borderLeft: '1px solid #333', // Добавил разделитель слева
      backgroundColor: '#1a1a1a', // Фон для области
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
        {/* Кнопка очистки истории чата */}
        <Box sx={{ p: 1, display: 'flex', justifyContent: 'flex-end' }}>
          <Button variant="outlined" size="small" color="secondary" onClick={handleClearHistory}>
            Очистить историю
          </Button>
        </Box>
        {/* Превью загруженного изображения (до отправки) */}
        {pendingImage && (
          <Box sx={{ p: 1, textAlign: 'center' }}>
            <img src={pendingImage.url} style={{ maxWidth: '100%', maxHeight: '200px' }} alt="Preview" />
          </Box>
        )}
        <div style={messageListContainerStyle}>
            {/* Drop files here or click button below to upload image */}
            <div
              onDragOver={e => e.preventDefault()}
              onDrop={e => {
                e.preventDefault();
                const file = e.dataTransfer.files[0];
                if (file && file.type.startsWith('image/')) {
                  // reuse handleImageUpload logic
                  const fakeEvent = ({ target: { files: [file] } } as unknown) as React.ChangeEvent<HTMLInputElement>;
                  handleImageUpload(fakeEvent);
                }
              }}
              style={{ border: '2px dashed #555', borderRadius: '4px', padding: '20px', textAlign: 'center', marginBottom: '10px', color: '#777' }}
            >
              Перетащите изображение сюда
            </div>
            <MessageList messages={messages} loading={isLoading} />
        </div>
        <InputPanel onSendMessage={handleSendMessage} loading={isLoading} />
        {/* Кнопка для выбора изображения */}
        <Box sx={{ display: 'flex', alignItems: 'center', p: 1, borderTop: 1, borderColor: 'divider' }}>
          <input
            accept="image/*"
            id="image-upload-input"
            type="file"
            style={{ display: 'none' }}
            onChange={handleImageUpload}
          />
          <label htmlFor="image-upload-input">
            <IconButton color="primary" component="span">
              <PhotoCamera />
            </IconButton>
          </label>
          <Typography variant="body2" sx={{ ml: 1, color: 'text.secondary' }}>
            Добавить изображение
          </Typography>
        </Box>
    </div>

    {/* Правая часть: Табы с цепочкой рассуждений и терминалом */}
    <div style={rightAreaStyle}>
        <Tabs 
          value={activeTab} 
          onChange={handleTabChange} 
          aria-label="Панели инструментов"
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab label="Рассуждения" />
          <Tab label="Терминал" />
        </Tabs>
        
        {/* Вкладка с цепочкой рассуждений */}
        <TabPanel value={activeTab} index={0}>
          <ReasoningPanel messages={messages} />
        </TabPanel>
        
        {/* Вкладка с терминалом */}
        <TabPanel value={activeTab} index={1}>
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
          <div style={{ flexGrow: 1, overflow: 'hidden', height: 'calc(100% - 40px)' }}>
            <TerminalPanel onTerminalAction={handleTerminalAction} />
          </div>
        </TabPanel>
    </div>
  </div>
);
};

export default ChatPage; 