import React from 'react';
import { Box, Typography, Paper, Divider } from '@mui/material';
import { ChatMessage } from '../../types/ChatMessage';

interface ReasoningPanelProps {
  messages: ChatMessage[];
}

const ReasoningPanel: React.FC<ReasoningPanelProps> = ({ messages }) => {
  // Фильтруем сообщения, оставляем только 'model', 'agent' и 'tool'
  const reasoningMessages = messages.filter(
    (msg) => msg.role === 'model' || msg.role === 'agent' || msg.role === 'tool'
  );

  // Функция для рендеринга одного сообщения
  const renderMessage = (message: ChatMessage, index: number) => {
    let content = null;
    let title = '';
    
    if (message.role === 'model' || message.role === 'agent') {
      title = 'Агент думает/вызывает инструмент';
      // Пытаемся разделить мысль и вызов инструмента
      const toolCallMatch = message.content.match(/(\[\s*TOOL_CALL:\s*.*\s*\])/);
      const thought = toolCallMatch ? message.content.substring(0, toolCallMatch.index).trim() : message.content.trim();
      const toolCall = toolCallMatch ? toolCallMatch[0].trim() : null;

      content = (
        <>
          {thought && (
            <Typography variant="body2" sx={{ mb: toolCall ? 1 : 0, whiteSpace: 'pre-wrap' }}>
              {thought}
            </Typography>
          )}
          {toolCall && (
             <Paper variant="outlined" sx={{ p: 1, backgroundColor: 'grey.800', fontFamily: 'monospace', overflowX: 'auto' }}>
               <Typography variant="caption" display="block" sx={{ mb: 0.5, color: 'text.secondary' }}>
                 Вызов инструмента:
               </Typography>
               {toolCall}
             </Paper>
          )}
        </>
      );
    } else if (message.role === 'tool') {
        title = 'Результат инструмента';
        // Отображаем результат инструмента (предполагаем, что это JSON)
        content = (
          <Paper variant="outlined" sx={{ p: 1, backgroundColor: 'grey.700', fontFamily: 'monospace', overflowX: 'auto', whiteSpace: 'pre-wrap' }}>
            {message.content}
          </Paper>
        );
    }

    return (
      <Box key={message.id || index} sx={{ mb: 2 }}>
        <Typography variant="overline" display="block" sx={{ color: 'text.secondary' }}>
          {title}
        </Typography>
        {content}
        {index < reasoningMessages.length - 1 && <Divider sx={{ my: 2 }} />}
      </Box>
    );
  };

  return (
    <Box sx={{ p: 2, height: '100%', overflowY: 'auto' }}>
      <Typography variant="h6" gutterBottom>
        Цепочка рассуждений
      </Typography>
      {reasoningMessages.length === 0 ? (
        <Typography variant="body2" color="text.secondary">
          Пока нет данных для отображения. Начните диалог с агентом.
        </Typography>
      ) : (
        reasoningMessages.map(renderMessage)
      )}
    </Box>
  );
};

export default ReasoningPanel; 