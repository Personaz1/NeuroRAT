import React, { useState, useCallback, useEffect, useRef } from 'react';
// import { Xterm } from 'xterm-react'; // Убираем старый импорт
import { useXTerm } from 'react-xtermjs'; // Импортируем хук
import { ITerminalOptions } from '@xterm/xterm'; // Убираем импорт Terminal
import '@xterm/xterm/css/xterm.css';

const API_BASE_URL = 'http://localhost:8000';

// Добавляем пропс для колбэка
interface TerminalPanelProps {
  onTerminalAction?: (type: 'input' | 'output', content: string) => void;
}

const TerminalPanel: React.FC<TerminalPanelProps> = ({ onTerminalAction }) => {
  // Хук возвращает instance
  const { ref, instance } = useXTerm();
  // const [termInstance, setTermInstance] = useState<Terminal | null>(null); // Больше не нужно
  // const [currentCommand, setCurrentCommand] = useState(''); // Удаляем неиспользуемый state
  const [isLoading, setIsLoading] = useState(false);
  // Используем ref для хранения текущей команды, чтобы избежать лишних ререндеров
  const commandRef = useRef('');

  const sendCommandToBackend = useCallback(async (command: string) => {
    if (!command.trim() || !instance) return;
    setIsLoading(true);
    instance.write('\r\n'); // Перевод строки перед выполнением

    // Вызываем колбэк для введенной команды
    if (onTerminalAction) {
        onTerminalAction('input', command);
    }

    try {
      // Используем SSE через EventSource GET endpoint для реального стриминга
      const sseUrl = `${API_BASE_URL}/api/terminal/stream?command=${encodeURIComponent(command)}`;
      const source = new EventSource(sseUrl);
      source.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.done) {
            source.close();
            instance.write('\r\n$ ');
            commandRef.current = '';
            setIsLoading(false);
          } else if (payload.output) {
            const text = payload.output.replace(/\n/g, '\r\n');
            instance.write(text);
            if (onTerminalAction) onTerminalAction('output', payload.output);
          }
        } catch {
          // игнорируем некорректные данные
        }
      };
      source.onerror = () => {
        instance.write('\r\nError streaming command');
        source.close();
        setIsLoading(false);
      };
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      instance.write(`\r\nError: ${errMsg}`);
      if (onTerminalAction) onTerminalAction('output', `Error: ${errMsg}`);
      instance.write('\r\n$ ');
      commandRef.current = '';
      setIsLoading(false);
    }
  }, [instance, onTerminalAction]);

  // Настраиваем терминал и подписку на onData один раз
  useEffect(() => {
    if (instance) {
      instance.writeln('Welcome to AGENTX Terminal! (react-xtermjs)');
      instance.write('$ '); // Начальный промпт
      instance.focus();

      const onDataDisposable = instance.onData((data: string) => {
        // Не обрабатываем ввод во время загрузки
        if (isLoading) return;

        const code = data.charCodeAt(0);

        if (code === 13) { // Enter
          sendCommandToBackend(commandRef.current);
        }
        else if (code === 8 || code === 127) { // Backspace
          if (commandRef.current.length > 0) {
            instance.write('\b \b'); // Стираем символ
            commandRef.current = commandRef.current.slice(0, -1);
          }
        }
        else if (code >= 32 && code <= 126) { // Printable chars
          commandRef.current += data; // Обновляем ref
          instance.write(data); // Пишем символ в терминал
        }
      });

      // Очистка подписки
      return () => {
        onDataDisposable.dispose();
      };
    }
    // Зависимость только от instance и sendCommandToBackend
  }, [instance, sendCommandToBackend]); // Убираем isLoading и currentCommand из зависимостей

  // Убираем handleTermInit
  // const handleTermInit = (terminal: Terminal) => { ... };

  // const terminalContainerStyle: React.CSSProperties = { // Удаляем неиспользуемый стиль
  //   // height: '150px', // Убираем фиксированную высоту
  //   flexGrow: 1, // Позволяем терминалу занимать всю доступную высоту в своей колонке
  //   backgroundColor: '#000',
  //   padding: '5px',
  //   // borderTop: '1px solid #333', // Убираем верхнюю границу, т.к. он теперь сбоку
  //   display: 'flex', // Для внутреннего div
  //   flexDirection: 'column',
  // };

  // Опции передаются при инициализации хука, если он это поддерживает,
  const terminalOptions: ITerminalOptions = {
      cursorBlink: true,
      theme: {
        background: '#000000',
        foreground: '#00ff00',
        cursor: '#00ff00',
        selectionBackground: '#009900',
      },
      fontSize: 14,
      fontFamily: 'monospace',
      convertEol: true, // Важно для правильной обработки Enter
      scrollback: 1000,
  };

  // Применяем опции
  useEffect(() => {
    if (instance) {
      Object.entries(terminalOptions).forEach(([key, value]) => {
          try {
              // @ts-expect-error Опции применяются динамически, TypeScript не может проверить все ключи ITerminalOptions
              instance.options[key] = value;
          } catch (e) {
              console.warn(`Failed to set terminal option ${key}:`, e);
          }
      });
    }
  }, [instance]);

  return (
    // Используем div с ref из хука useXTerm
    // Обернем в дополнительный div, чтобы flexGrow работал корректно
    <div style={{ flexGrow: 1, backgroundColor: '#000'}}>
         <div ref={ref} style={{ height: '100%', width: '100%' }} /> 
    </div>
    /*
    <Xterm
      options={terminalOptions}
      onInit={handleTermInit}
      onData={handleTermData}
    />
    */
  );
};

export default TerminalPanel; 