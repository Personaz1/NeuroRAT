#!/bin/bash

echo "🔍 Начинаю исправление ошибок линтера в UI компонентах..."

# Переходим в директорию UI
cd agentx-ui || exit

# Проверяем и устанавливаем зависимости
echo "📦 Обновляем зависимости..."
npm install @chakra-ui/react@latest @emotion/react@latest @emotion/styled@latest framer-motion@latest

# Исправляем типы
echo "🛠️ Исправляем типы и импорты..."
npm install --save-dev @types/react@latest @types/react-dom@latest

# Исправляем ошибки линтера
echo "🧹 Запускаем линтер и автоисправление..."
npm run lint -- --fix

# Запускаем проверку типов
echo "✓ Запускаем проверку типов..."
npx tsc --noEmit

echo "✅ Исправление ошибок завершено!"
echo "➡️ Теперь запустите 'npm run dev' для проверки результата" 