import React, { useEffect, useRef } from 'react';
import ReactMarkdown from 'react-markdown';
import rehypeHighlight from 'rehype-highlight';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
// Выбираем темную тему, например, vscDarkPlus или a11yDark
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { toast } from 'react-toastify';

// Определим тип для сообщения
export interface Message {
  id: string; // Уникальный ID
  role: 'user' | 'agent' | 'system' | 'tool' | 'terminal' | 'terminal_input' | 'terminal_output';
  content: string;
  timestamp: number;
}

// Тип для действий УДАЛЕН
// export type ChatActionType = 'copy' | 'codex' | 'terminal' | 'analyze' | 'chain';

interface MessageListProps {
  messages: Message[];
  loading: boolean;
  // onAction УДАЛЕН
}

const roleColors: Record<string, string> = {
  user: '#00bfff',    // Голубой
  agent: '#ffffff',   // Белый
  system: '#888888',  // Серый
  tool: '#ffeb3b',    // Желтый
  terminal: '#4caf50', // Зеленый
  terminal_input: '#aaaaaa', // Светло-серый для ввода
  terminal_output: '#4caf50', // Зеленый для вывода
};

// Стили для кнопки копирования сообщения
const copyMsgButtonStyle: React.CSSProperties = {
    fontSize: '12px',
    background: '#00bfff',
    color: '#121212',
    border: 'none',
    borderRadius: '4px',
    padding: '3px 8px',
    cursor: 'pointer',
    marginLeft: '10px', // Отступ от края сообщения
    opacity: 0.7, // Сделаем менее заметной
};

const copyCodeButtonStyle: React.CSSProperties = {
    position: 'absolute',
    top: '5px',
    right: '5px',
    fontSize: '11px',
    background: '#00bfff',
    color: '#121212',
    border: 'none',
    borderRadius: '4px',
    padding: '2px 6px',
    cursor: 'pointer',
    opacity: 0.7,
};

const MessageList: React.FC<MessageListProps> = ({ messages, loading }) => { // убран onAction
  const messagesEndRef = useRef<null | HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]); // Прокрутка при добавлении нового сообщения

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Скопировано!');
  };

  const listStyle: React.CSSProperties = {
    flexGrow: 1,
    overflowY: 'auto',
    padding: '10px',
  };

  const messageContainerStyle: React.CSSProperties = {
    marginBottom: '15px',
    display: 'flex',
    flexDirection: 'column',
  };

  const messageBubbleStyle: React.CSSProperties = {
    padding: '10px 15px',
    borderRadius: '8px',
    backgroundColor: '#2a2a2a',
    maxWidth: '80%',
    wordWrap: 'break-word',
    alignSelf: 'flex-start',
    position: 'relative', // Для позиционирования кнопки копирования
  };

  const userMessageBubbleStyle: React.CSSProperties = {
    ...messageBubbleStyle,
    backgroundColor: '#005f80', // Разный фон для user
    alignSelf: 'flex-end',
  };

  const roleStyle: React.CSSProperties = {
    fontSize: '0.8em',
    opacity: 0.7,
    marginBottom: '5px',
    textTransform: 'uppercase',
  };

  // actionsContainerStyle УДАЛЕН

  return (
    <div style={listStyle}>
      {messages.map((msg) => (
        <div
          key={msg.id}
          style={{
            ...messageContainerStyle,
            alignItems: msg.role === 'user' ? 'flex-end' : 'flex-start',
          }}
        >
          <div style={msg.role === 'user' ? userMessageBubbleStyle : messageBubbleStyle}>
            <div style={{ ...roleStyle, color: roleColors[msg.role] || '#fff' }}>{msg.role}</div>
            <ReactMarkdown
              rehypePlugins={[rehypeHighlight]}
              components={{
                img({ node, ...props }) {
                  const src = props.src as string;
                  if (!src || !src.startsWith('blob:')) return null;
                  return <img {...props} style={{ maxWidth: '100%', borderRadius: '6px' }} />;
                },
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                code({ inline, className, children, ...props }: any) {
                  const match = /language-(\w+)/.exec(className || '');
                  const codeContent = String(children).replace(/\n$/, '');
                  return !inline ? (
                    <div style={{ position: 'relative', margin: '10px 0' }}>
                      <SyntaxHighlighter
                        style={vscDarkPlus} // Используем выбранную тему
                        language={match?.[1]}
                        PreTag="div"
                        {...props}
                        customStyle={{ background: '#1e1e1e', borderRadius: '6px', padding: '10px', fontSize: '0.9em' }}
                      >
                        {codeContent}
                      </SyntaxHighlighter>
                      <button
                        style={copyCodeButtonStyle}
                        onClick={() => handleCopy(codeContent)}
                      >
                        Copy
                      </button>
                    </div>
                  ) : (
                    <code
                      style={{
                        background: '#3a3a3a',
                        color: '#eee',
                        borderRadius: '4px',
                        padding: '2px 4px',
                        fontSize: '0.9em'
                      }}
                      {...props}
                    >
                      {children}
                    </code>
                  );
                },
                pre({ children }) {
                    // Убираем стандартный pre, т.к. SyntaxHighlighter его оборачивает
                    return <>{children}</>;
                }
              }}
            >
              {msg.content}
            </ReactMarkdown>
             {/* Кнопка копирования всего сообщения */}
             <button
                style={copyMsgButtonStyle}
                onClick={() => handleCopy(msg.content)}
                title="Копировать сообщение"
              >
                ❐
              </button>
          </div>
          {/* Кнопки действий УДАЛЕНЫ */}
        </div>
      ))}
      {loading && (
        <div style={{ textAlign: 'center', color: '#ccc', marginTop: '10px' }}>
          Агент думает...
        </div>
      )}
      <div ref={messagesEndRef} /> {/* Элемент для автопрокрутки */}
    </div>
  );
};

export default MessageList; 