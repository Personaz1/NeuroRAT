import { useState, useEffect } from 'react';
import {
  Box,
  Flex,
  Heading,
  Text,
  SimpleGrid,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  Badge,
  Spinner,
  Card,
  CardBody,
  CardHeader,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Icon,
} from '@chakra-ui/react';
import axios from 'axios';
import { MdCloudDone, MdComputer, MdRadar, MdSecurity, MdCurrencyBitcoin } from 'react-icons/md';

// API URL
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const Dashboard = () => {
  const [loading, setLoading] = useState(true);
  const [dashboardData, setDashboardData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        setLoading(true);
        
        // Fetch all required data in parallel
        const [statusRes, agentsRes, operationsRes] = await Promise.all([
          axios.get(`${API_URL}/api/status`),
          axios.get(`${API_URL}/api/agents`),
          axios.get(`${API_URL}/api/operations`),
        ]);
        
        // Combine all data
        setDashboardData({
          status: statusRes.data,
          agents: agentsRes.data.agents || [],
          operations: operationsRes.data?.operations || [],
        });
        
        setError(null);
      } catch (err) {
        console.error('Failed to fetch dashboard data:', err);
        setError('Не удалось загрузить данные для дашборда');
      } finally {
        setLoading(false);
      }
    };

    fetchDashboardData();
    
    // Refresh data every minute
    const intervalId = setInterval(fetchDashboardData, 60000);
    return () => clearInterval(intervalId);
  }, []);

  if (loading && !dashboardData) {
    return (
      <Flex height="100%" alignItems="center" justifyContent="center">
        <Spinner size="xl" />
      </Flex>
    );
  }

  if (error) {
    return (
      <Box p={5} bg="red.50" borderRadius="md">
        <Heading size="md" color="red.500" mb={2}>Ошибка загрузки данных</Heading>
        <Text>{error}</Text>
      </Box>
    );
  }

  // Stats for display
  const stats = [
    {
      label: 'Agents Online',
      value: dashboardData?.agents.filter((a: any) => a.status === 'online').length || 0,
      total: dashboardData?.agents.length || 0,
      icon: MdComputer,
      color: 'blue.500',
    },
    {
      label: 'Active Operations',
      value: dashboardData?.operations?.filter((o: any) => o.status === 'running').length || 0,
      total: dashboardData?.operations?.length || 0,
      icon: MdRadar,
      color: 'green.500',
    },
    {
      label: 'Exploits Available',
      value: '25+', // This would come from actual API in production
      icon: MdSecurity,
      color: 'red.500',
    },
    {
      label: 'Crypto Operations',
      value: dashboardData?.status?.crypto_operations || 0,
      icon: MdCurrencyBitcoin,
      color: 'orange.500',
    },
  ];

  // Recent operations for the table
  const recentOperations = dashboardData?.operations?.slice(0, 5) || [];

  return (
    <Box>
      <Flex mb={5} justifyContent="space-between" alignItems="center">
        <Box>
          <Heading size="lg">Dashboard</Heading>
          <Text color="gray.500">AgentX C2 Command & Control Center</Text>
        </Box>
        <Flex alignItems="center">
          <Box
            w="10px"
            h="10px"
            borderRadius="full"
            bg="green.400"
            mr={2}
          />
          <Text fontSize="sm">System Status: </Text>
          <Badge colorScheme="green" ml={2}>Operational</Badge>
        </Flex>
      </Flex>

      {/* Stats Grid */}
      <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={5} mb={8}>
        {stats.map((stat, index) => (
          <Card key={index} borderLeft="4px solid" borderLeftColor={stat.color}>
            <CardBody>
              <Flex justify="space-between">
                <Box>
                  <StatLabel color="gray.500">{stat.label}</StatLabel>
                  <StatNumber fontSize="2xl">{stat.value}</StatNumber>
                  {stat.total && (
                    <StatHelpText>
                      из {stat.total} всего
                    </StatHelpText>
                  )}
                </Box>
                <Flex
                  w="60px"
                  h="60px"
                  bg={`${stat.color}20`}
                  color={stat.color}
                  borderRadius="lg"
                  align="center"
                  justify="center"
                >
                  <Icon as={stat.icon} boxSize="30px" />
                </Flex>
              </Flex>
            </CardBody>
          </Card>
        ))}
      </SimpleGrid>

      {/* Recent Operations Table */}
      <Card mb={8}>
        <CardHeader>
          <Heading size="md">Recent Operations</Heading>
        </CardHeader>
        <CardBody>
          <Table variant="simple">
            <Thead>
              <Tr>
                <Th>ID</Th>
                <Th>Type</Th>
                <Th>Target</Th>
                <Th>Status</Th>
                <Th>Start Time</Th>
              </Tr>
            </Thead>
            <Tbody>
              {recentOperations.length > 0 ? (
                recentOperations.map((op: any) => (
                  <Tr key={op.id}>
                    <Td>{op.id.substring(0, 8)}...</Td>
                    <Td>{op.type}</Td>
                    <Td>{op.target || 'N/A'}</Td>
                    <Td>
                      <Badge
                        colorScheme={
                          op.status === 'completed' ? 'green' :
                          op.status === 'running' ? 'blue' :
                          op.status === 'failed' ? 'red' : 'gray'
                        }
                      >
                        {op.status}
                      </Badge>
                    </Td>
                    <Td>{new Date(op.start_time).toLocaleString()}</Td>
                  </Tr>
                ))
              ) : (
                <Tr>
                  <Td colSpan={5} textAlign="center">No recent operations</Td>
                </Tr>
              )}
            </Tbody>
          </Table>
        </CardBody>
      </Card>

      {/* System Info */}
      <Card>
        <CardHeader>
          <Heading size="md">System Information</Heading>
        </CardHeader>
        <CardBody>
          <SimpleGrid columns={{ base: 1, md: 2 }} spacing={5}>
            <Box>
              <Text fontWeight="bold" mb={1}>Server Time</Text>
              <Text>{new Date(dashboardData?.status?.server_time || Date.now()).toLocaleString()}</Text>
            </Box>
            <Box>
              <Text fontWeight="bold" mb={1}>API Status</Text>
              <Flex align="center">
                <Icon as={MdCloudDone} color="green.500" mr={2} />
                <Text>Online</Text>
              </Flex>
            </Box>
            <Box>
              <Text fontWeight="bold" mb={1}>Modules Status</Text>
              <Flex direction="column" gap={1}>
                <Badge colorScheme="green" width="fit-content">Web3 Drainer: Active</Badge>
                <Badge colorScheme="green" width="fit-content">MEV Monitor: Active</Badge>
                <Badge colorScheme="green" width="fit-content">Exploit Engine: Active</Badge>
                <Badge colorScheme="green" width="fit-content">Host Scanner: Active</Badge>
              </Flex>
            </Box>
            <Box>
              <Text fontWeight="bold" mb={1}>System Performance</Text>
              <Text>CPU: 12%</Text>
              <Text>RAM: 1.2GB / 8GB</Text>
              <Text>Disk: 45GB Free</Text>
            </Box>
          </SimpleGrid>
        </CardBody>
      </Card>
    </Box>
  );
};

export default Dashboard; 