import React from 'react';

interface MainContentProps {
  children: React.ReactNode;
}

const MainContent: React.FC<MainContentProps> = ({ children }) => {
  const mainContentStyle: React.CSSProperties = {
    flexGrow: 1,
    height: '100vh',
    overflowY: 'auto',
    padding: '20px',
    boxSizing: 'border-box',
    backgroundColor: '#121212', // Темный фон для контента
  };

  return (
    <div style={mainContentStyle}>
      {children}
    </div>
  );
};

export default MainContent; 