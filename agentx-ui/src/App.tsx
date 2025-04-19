import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import './App.css';
import Sidebar from './components/Layout/Sidebar';
import MainContent from './components/Layout/MainContent';
import ChatPage from './pages/ChatPage'; // Импортируем страницу чата
import { ToastContainer } from 'react-toastify'; // <-- Импортируем ToastContainer
import 'react-toastify/dist/ReactToastify.css';

function App() {
  const appStyle: React.CSSProperties = {
    display: 'flex',
    height: '100vh',
    color: '#fff', // Общий цвет текста
  };

  const mainAreaStyle: React.CSSProperties = {
      display: 'flex',
      flexDirection: 'column',
      flexGrow: 1,
      height: '100vh',
  };

  return (
    <Router>
      <div style={appStyle}>
        <Sidebar />
        {/* Обертка для основной области и терминала */}
        <div style={mainAreaStyle}>
          <MainContent>
            <Routes>
              <Route path="/" element={<ChatPage />} />
              <Route path="/chat" element={<ChatPage />} />
              {/* <Route path="/zonds" element={<ZondsPage />} /> */}
              {/* <Route path="/codex" element={<CodexPage />} /> */}
              {/* <Route path="/settings" element={<SettingsPage />} /> */}
              {/* Добавьте другие маршруты здесь */}
            </Routes>
          </MainContent>
          {/* <TerminalPanel /> */} {/* Добавляем терминал под контентом */}
        </div>
        {/* Контейнер для уведомлений */}
        <ToastContainer
          position="bottom-right"
          autoClose={3000}
          hideProgressBar={false}
          newestOnTop={false}
          closeOnClick
          rtl={false}
          pauseOnFocusLoss
          draggable
          pauseOnHover
          theme="dark"
        />
      </div>
    </Router>
  );
}

export default App;
