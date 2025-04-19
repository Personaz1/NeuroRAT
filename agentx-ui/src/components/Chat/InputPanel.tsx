import React, { useState } from 'react';

interface InputPanelProps {
  onSendMessage: (message: string) => void;
  loading: boolean;
}

const InputPanel: React.FC<InputPanelProps> = ({ onSendMessage, loading }) => {
  const [message, setMessage] = useState('');

  const handleSend = () => {
    if (message.trim() && !loading) {
      onSendMessage(message);
      setMessage('');
    }
  };

  const handleKeyPress = (event: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault(); // Предотвращаем перенос строки по Enter
      handleSend();
    }
  };

  const panelStyle: React.CSSProperties = {
    padding: '10px',
    borderTop: '1px solid #333',
    backgroundColor: '#1a1a1a',
    display: 'flex',
    alignItems: 'center',
  };

  const textareaStyle: React.CSSProperties = {
    flexGrow: 1,
    marginRight: '10px',
    borderRadius: '4px',
    border: '1px solid #444',
    backgroundColor: '#2a2a2a',
    color: '#fff',
    padding: '10px',
    minHeight: '40px',
    maxHeight: '150px',
    resize: 'none',
    fontFamily: 'inherit',
    fontSize: '1rem',
  };

  const buttonStyle: React.CSSProperties = {
    padding: '10px 20px',
    borderRadius: '4px',
    border: 'none',
    backgroundColor: loading ? '#555' : '#007bff',
    color: '#fff',
    cursor: loading ? 'not-allowed' : 'pointer',
  };

  return (
    <div style={panelStyle}>
      <textarea
        style={textareaStyle}
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        onKeyPress={handleKeyPress}
        placeholder="Введите сообщение... (Shift+Enter для переноса строки)"
        rows={1}
        disabled={loading}
      />
      <button style={buttonStyle} onClick={handleSend} disabled={loading}>
        {loading ? '...' : 'Отправить'}
      </button>
    </div>
  );
};

export default InputPanel; 