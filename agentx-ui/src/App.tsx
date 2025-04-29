import { useState, useEffect } from 'react';
import { ChakraProvider, Box, Flex, VStack, Grid, theme, Text, Heading, Spinner, useToast } from '@chakra-ui/react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import axios from 'axios';

// Components
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import AgentsList from './pages/AgentsList';
import OperationsList from './pages/OperationsList';
import ExploitManager from './pages/ExploitManager';
import NetworkScanner from './pages/NetworkScanner';
import CryptoDrainer from './pages/CryptoDrainer';
import MevMonitor from './pages/MevMonitor';
import AutonomousAgent from './pages/AutonomousAgent';
import Settings from './pages/Settings';

// API Config
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

function App() {
  const [loading, setLoading] = useState(true);
  const [serverStatus, setServerStatus] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const toast = useToast();

  useEffect(() => {
    // Проверка соединения с сервером при загрузке
    const checkServerStatus = async () => {
      try {
        setLoading(true);
        const response = await axios.get(`${API_URL}/api/status`);
        setServerStatus(response.data);
        setError(null);
      } catch (err) {
        console.error('Failed to connect to server:', err);
        setError('Не удалось подключиться к серверу C2. Убедитесь, что сервер запущен.');
        toast({
          title: 'Ошибка соединения',
          description: 'Не удалось подключиться к серверу C2',
          status: 'error',
          duration: 5000,
          isClosable: true,
        });
      } finally {
        setLoading(false);
      }
    };

    checkServerStatus();
    
    // Периодическая проверка статуса сервера
    const intervalId = setInterval(checkServerStatus, 30000); // каждые 30 секунд
    
    return () => clearInterval(intervalId);
  }, [toast]);

  if (loading && !serverStatus) {
    return (
      <ChakraProvider theme={theme}>
        <Flex height="100vh" alignItems="center" justifyContent="center">
          <VStack spacing={8}>
            <Heading>AgentX Control Panel</Heading>
            <Spinner size="xl" />
            <Text>Подключение к серверу C2...</Text>
          </VStack>
        </Flex>
      </ChakraProvider>
    );
  }

  return (
    <ChakraProvider theme={theme}>
      <Router>
        <Flex height="100vh" overflow="hidden">
          <Sidebar serverStatus={serverStatus} />
          
          <Box flex="1" overflow="auto" bg="gray.50" p={4}>
            {error ? (
              <Box p={5} bg="red.50" borderRadius="md" borderWidth="1px" borderColor="red.200">
                <Heading size="md" color="red.500" mb={2}>Ошибка подключения</Heading>
                <Text>{error}</Text>
              </Box>
            ) : (
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/agents" element={<AgentsList />} />
                <Route path="/operations" element={<OperationsList />} />
                <Route path="/exploits" element={<ExploitManager />} />
                <Route path="/scanner" element={<NetworkScanner />} />
                <Route path="/crypto-drainer" element={<CryptoDrainer />} />
                <Route path="/mev-monitor" element={<MevMonitor />} />
                <Route path="/autonomous-agent" element={<AutonomousAgent />} />
                <Route path="/settings" element={<Settings />} />
              </Routes>
            )}
          </Box>
        </Flex>
      </Router>
    </ChakraProvider>
  );
}

export default App;
