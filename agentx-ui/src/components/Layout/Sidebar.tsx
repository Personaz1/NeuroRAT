import React from 'react';

const Sidebar: React.FC = () => {
  const sidebarStyle: React.CSSProperties = {
    width: '240px',
    height: '100vh',
    backgroundColor: '#1a1a1a',
    color: '#fff',
    padding: '20px',
    boxSizing: 'border-box',
    borderRight: '1px solid #333',
  };

  const linkStyle: React.CSSProperties = {
    display: 'block',
    color: '#ccc',
    marginBottom: '10px',
    textDecoration: 'none',
  };

  return (
    <div style={sidebarStyle}>
      <h2>AGENTX Console</h2>
      <nav>
        {/* TODO: Заменить на реальные ссылки/роутинг */}
        <a href="#" style={linkStyle}>Dashboard</a>
        <a href="#" style={linkStyle}>Chat</a>
        <a href="#" style={linkStyle}>Zonds</a>
        <a href="#" style={linkStyle}>Builder</a>
        <a href="#" style={linkStyle}>Codex</a>
        <a href="#" style={linkStyle}>Settings</a>
      </nav>
    </div>
  );
};

export default Sidebar; 