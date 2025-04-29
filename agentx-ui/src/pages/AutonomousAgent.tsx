import { useState } from 'react';
import {
  Box,
  Button,
  Card,
  CardBody,
  CardHeader,
  Flex,
  FormControl,
  FormLabel,
  Heading,
  Input,
  Select,
  Textarea,
  Text,
  useToast,
  VStack,
  HStack,
  Slider,
  SliderTrack,
  SliderFilledTrack,
  SliderThumb,
  SliderMark,
  Switch,
  Badge,
  Divider,
  Code,
  NumberInput,
  NumberInputField,
  NumberInputStepper,
  NumberIncrementStepper,
  NumberDecrementStepper,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  Icon,
  Tooltip,
} from '@chakra-ui/react';
import { 
  MdSmartToy, 
  MdPlayArrow, 
  MdStop, 
  MdRadar, 
  MdSecurity, 
  MdStorefront, 
  MdTargetingReady, 
  MdAutoFixHigh,
  MdInfo
} from 'react-icons/md';
import axios from 'axios';

// API URL
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// Available objectives
const objectives = [
  { value: 'reconnaissance', label: 'Reconnaissance', description: 'Сканирование и сбор информации о целях', icon: MdRadar },
  { value: 'vulnerability_scan', label: 'Vulnerability Scan', description: 'Автоматический поиск уязвимостей', icon: MdSecurity },
  { value: 'exploitation', label: 'Exploitation', description: 'Эксплуатация найденных уязвимостей', icon: MdAutoFixHigh },
  { value: 'crypto_hunt', label: 'Crypto Hunt', description: 'Поиск криптовалютных активов', icon: MdStorefront },
  { value: 'full_chain', label: 'Full Chain', description: 'Полный цикл: от разведки до эксплуатации', icon: MdTargetingReady },
];

interface AgentOperation {
  id: string;
  type: string;
  status: string;
  start_time: string;
  end_time?: string;
  agent_id?: string;
  details?: any;
  results?: any;
  error?: string;
}

const AutonomousAgent = () => {
  const [targetRange, setTargetRange] = useState('');
  const [objective, setObjective] = useState('reconnaissance');
  const [operations, setOperations] = useState<AgentOperation[]>([]);
  const [loading, setLoading] = useState(false);
  const [aggressiveness, setAggressiveness] = useState(30);
  const [concurrentTargets, setConcurrentTargets] = useState(5);
  const [enableLearning, setEnableLearning] = useState(true);
  const [currentAgentId, setCurrentAgentId] = useState<string | null>(null);
  
  const toast = useToast();

  const selectedObjective = objectives.find(obj => obj.value === objective);

  const handleStartAgent = async () => {
    if (!targetRange) {
      toast({
        title: 'Ошибка',
        description: 'Укажите диапазон целей',
        status: 'error',
        duration: 3000,
        isClosable: true,
      });
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${API_URL}/api/agent/autonomous`, {
        target_range: targetRange,
        objective,
        aggressiveness,
        concurrent_targets: concurrentTargets,
        enable_learning: enableLearning,
      });

      const newOperation: AgentOperation = {
        id: response.data.operation_id,
        type: 'autonomous_agent',
        status: 'running',
        start_time: new Date().toISOString(),
      };

      setOperations([newOperation, ...operations]);
      setCurrentAgentId(response.data.agent_id);

      // Poll for operation status
      pollOperationStatus(response.data.operation_id);

      toast({
        title: 'Агент активирован',
        description: `ID операции: ${response.data.operation_id}`,
        status: 'success',
        duration: 5000,
        isClosable: true,
      });
    } catch (error) {
      console.error('Error starting autonomous agent:', error);
      toast({
        title: 'Ошибка',
        description: 'Не удалось запустить автономного агента',
        status: 'error',
        duration: 5000,
        isClosable: true,
      });
    } finally {
      setLoading(false);
    }
  };

  const handleStopAgent = async () => {
    if (!currentAgentId) {
      toast({
        title: 'Ошибка',
        description: 'Нет активного агента для остановки',
        status: 'error',
        duration: 3000,
        isClosable: true,
      });
      return;
    }

    setLoading(true);
    try {
      await axios.post(`${API_URL}/api/agent/stop`, {
        agent_id: currentAgentId,
      });

      // Update the operations list
      setOperations(prevOps => {
        return prevOps.map(op => {
          if (op.agent_id === currentAgentId) {
            return {
              ...op,
              status: 'stopped',
              end_time: new Date().toISOString(),
            };
          }
          return op;
        });
      });

      setCurrentAgentId(null);

      toast({
        title: 'Агент остановлен',
        description: 'Автономный агент успешно остановлен',
        status: 'success',
        duration: 5000,
        isClosable: true,
      });
    } catch (error) {
      console.error('Error stopping autonomous agent:', error);
      toast({
        title: 'Ошибка',
        description: 'Не удалось остановить агента',
        status: 'error',
        duration: 5000,
        isClosable: true,
      });
    } finally {
      setLoading(false);
    }
  };

  const pollOperationStatus = async (operationId: string) => {
    const interval = setInterval(async () => {
      try {
        const response = await axios.get(`${API_URL}/api/operations/${operationId}`);
        const updatedOperation = response.data;
        
        if (updatedOperation.status !== 'running') {
          // Operation completed or failed
          setOperations(prevOps => {
            return prevOps.map(op => {
              if (op.id === operationId) {
                return {
                  ...op,
                  status: updatedOperation.status,
                  end_time: updatedOperation.end_time,
                  results: updatedOperation.results,
                  error: updatedOperation.error,
                };
              }
              return op;
            });
          });
          
          if (updatedOperation.status === 'completed') {
            toast({
              title: 'Операция завершена',
              description: 'Автономный агент завершил задачу',
              status: 'success',
              duration: 5000,
              isClosable: true,
            });
            setCurrentAgentId(null);
          } else if (updatedOperation.status === 'failed') {
            toast({
              title: 'Операция не удалась',
              description: updatedOperation.error || 'Неизвестная ошибка',
              status: 'error',
              duration: 5000,
              isClosable: true,
            });
            setCurrentAgentId(null);
          }
          
          clearInterval(interval);
        } else if (updatedOperation.agent_id && !currentAgentId) {
          // Update agent ID if we get it from the operation
          setCurrentAgentId(updatedOperation.agent_id);
        }
      } catch (error) {
        console.error('Error polling operation status:', error);
        clearInterval(interval);
      }
    }, 3000); // Poll every 3 seconds
  };

  return (
    <Box>
      <Flex mb={5} justifyContent="space-between" alignItems="center">
        <Box>
          <Heading size="lg" display="flex" alignItems="center">
            <Icon as={MdSmartToy} color="purple.500" mr={2} />
            Autonomous Agent
          </Heading>
          <Text color="gray.500">ИИ-управляемый автономный агент для разведки и эксплуатации</Text>
        </Box>
        {currentAgentId ? (
          <Badge colorScheme="green" fontSize="md" p={2} borderRadius="md">
            Agent Active: {currentAgentId.substring(0, 8)}...
          </Badge>
        ) : (
          <Badge colorScheme="gray" fontSize="md" p={2} borderRadius="md">
            Agent Inactive
          </Badge>
        )}
      </Flex>

      <Tabs variant="enclosed" mb={8}>
        <TabList>
          <Tab>Configuration</Tab>
          <Tab>Results</Tab>
          <Tab>Advanced</Tab>
        </TabList>
        <TabPanels>
          <TabPanel>
            <Card>
              <CardHeader>
                <Heading size="md">Конфигурация агента</Heading>
              </CardHeader>
              <CardBody>
                <VStack spacing={6} align="stretch">
                  <FormControl isRequired>
                    <FormLabel>Диапазон целей</FormLabel>
                    <Input 
                      placeholder="192.168.1.0/24, example.com, 10.0.0.1-10.0.0.100" 
                      value={targetRange} 
                      onChange={(e) => setTargetRange(e.target.value)}
                    />
                    <Text fontSize="sm" color="gray.500" mt={1}>
                      Укажите IP-адреса, диапазоны CIDR, доменные имена или их комбинацию
                    </Text>
                  </FormControl>

                  <FormControl>
                    <FormLabel>Цель операции</FormLabel>
                    <Select 
                      value={objective} 
                      onChange={(e) => setObjective(e.target.value)}
                    >
                      {objectives.map((obj) => (
                        <option key={obj.value} value={obj.value}>{obj.label}</option>
                      ))}
                    </Select>
                    {selectedObjective && (
                      <Flex align="center" mt={2}>
                        <Icon as={selectedObjective.icon} color="purple.500" mr={2} />
                        <Text fontSize="sm" color="gray.600">{selectedObjective.description}</Text>
                      </Flex>
                    )}
                  </FormControl>

                  <FormControl>
                    <FormLabel display="flex" alignItems="center">
                      Агрессивность
                      <Tooltip label="Определяет интенсивность сканирования и скорость эксплуатации. Высокие значения могут быть обнаружены системами защиты.">
                        <Box as="span" ml={1} cursor="help">
                          <Icon as={MdInfo} />
                        </Box>
                      </Tooltip>
                    </FormLabel>
                    <Slider
                      value={aggressiveness}
                      onChange={setAggressiveness}
                      min={10}
                      max={100}
                      step={5}
                    >
                      <SliderTrack>
                        <SliderFilledTrack bg="purple.500" />
                      </SliderTrack>
                      <SliderThumb boxSize={6}>
                        <Box color="purple.500" as={MdAutoFixHigh} />
                      </SliderThumb>
                      <SliderMark
                        value={aggressiveness}
                        textAlign="center"
                        bg="purple.500"
                        color="white"
                        mt="-10"
                        ml="-5"
                        w="12"
                        fontSize="sm"
                        borderRadius="md"
                      >
                        {aggressiveness}%
                      </SliderMark>
                    </Slider>
                    <Flex justify="space-between" mt={2}>
                      <Text fontSize="xs">Скрытный</Text>
                      <Text fontSize="xs">Агрессивный</Text>
                    </Flex>
                  </FormControl>

                  <FormControl>
                    <FormLabel>Количество одновременных целей</FormLabel>
                    <NumberInput 
                      value={concurrentTargets} 
                      onChange={(_, value) => setConcurrentTargets(value)}
                      min={1} 
                      max={100}
                    >
                      <NumberInputField />
                      <NumberInputStepper>
                        <NumberIncrementStepper />
                        <NumberDecrementStepper />
                      </NumberInputStepper>
                    </NumberInput>
                    <Text fontSize="sm" color="gray.500" mt={1}>
                      Количество целей, обрабатываемых одновременно
                    </Text>
                  </FormControl>

                  <FormControl display="flex" alignItems="center">
                    <FormLabel htmlFor="enable-learning" mb="0">
                      ИИ-обучение на результатах
                    </FormLabel>
                    <Switch 
                      id="enable-learning" 
                      isChecked={enableLearning}
                      onChange={(e) => setEnableLearning(e.target.checked)}
                      colorScheme="purple"
                    />
                  </FormControl>

                  <Divider />

                  <HStack spacing={4}>
                    <Button 
                      colorScheme="purple"
                      leftIcon={<MdPlayArrow />}
                      onClick={handleStartAgent}
                      isLoading={loading && !currentAgentId}
                      loadingText="Запуск агента..."
                      isDisabled={!!currentAgentId}
                      flex={1}
                    >
                      Запустить
                    </Button>
                    <Button 
                      colorScheme="red"
                      variant="outline"
                      leftIcon={<MdStop />}
                      onClick={handleStopAgent}
                      isLoading={loading && !!currentAgentId}
                      loadingText="Остановка..."
                      isDisabled={!currentAgentId}
                      flex={1}
                    >
                      Остановить
                    </Button>
                  </HStack>
                </VStack>
              </CardBody>
            </Card>
          </TabPanel>
          
          <TabPanel>
            <Card>
              <CardHeader>
                <Heading size="md">Результаты операций</Heading>
              </CardHeader>
              <CardBody>
                <Table variant="simple">
                  <Thead>
                    <Tr>
                      <Th>ID операции</Th>
                      <Th>Цель</Th>
                      <Th>Статус</Th>
                      <Th>Начало</Th>
                      <Th>Окончание</Th>
                      <Th>Результаты</Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {operations.length > 0 ? (
                      operations.map((op) => (
                        <Tr key={op.id}>
                          <Td>{op.id.substring(0, 8)}...</Td>
                          <Td>{op.details?.objective || "reconnaissance"}</Td>
                          <Td>
                            <Badge
                              colorScheme={
                                op.status === 'completed' ? 'green' :
                                op.status === 'running' ? 'blue' :
                                op.status === 'stopped' ? 'yellow' :
                                op.status === 'failed' ? 'red' : 'gray'
                              }
                            >
                              {op.status}
                            </Badge>
                          </Td>
                          <Td>{new Date(op.start_time).toLocaleString()}</Td>
                          <Td>{op.end_time ? new Date(op.end_time).toLocaleString() : '-'}</Td>
                          <Td>
                            {op.results ? (
                              <Button size="sm" colorScheme="blue" variant="outline">
                                View Details
                              </Button>
                            ) : op.status === 'failed' ? (
                              <Text color="red.500" fontSize="sm">{op.error || 'Неизвестная ошибка'}</Text>
                            ) : (
                              '-'
                            )}
                          </Td>
                        </Tr>
                      ))
                    ) : (
                      <Tr>
                        <Td colSpan={6} textAlign="center">Нет активных или завершенных операций</Td>
                      </Tr>
                    )}
                  </Tbody>
                </Table>
              </CardBody>
            </Card>
          </TabPanel>
          
          <TabPanel>
            <Card>
              <CardHeader>
                <Heading size="md">Расширенные настройки</Heading>
              </CardHeader>
              <CardBody>
                <VStack spacing={4} align="stretch">
                  <Text>Расширенные настройки для тонкой настройки автономного агента.</Text>
                  
                  <FormControl>
                    <FormLabel>Стратегия сканирования</FormLabel>
                    <Select defaultValue="stealthy">
                      <option value="stealthy">Скрытная</option>
                      <option value="balanced">Сбалансированная</option>
                      <option value="aggressive">Агрессивная</option>
                      <option value="custom">Пользовательская</option>
                    </Select>
                  </FormControl>
                  
                  <FormControl>
                    <FormLabel>Приоритизация уязвимостей</FormLabel>
                    <Select defaultValue="impact">
                      <option value="impact">По воздействию</option>
                      <option value="cvss">По CVSS-оценке</option>
                      <option value="ease">По простоте эксплуатации</option>
                      <option value="mixed">Смешанная стратегия</option>
                    </Select>
                  </FormControl>
                  
                  <FormControl display="flex" alignItems="center">
                    <FormLabel htmlFor="c2-failover" mb="0">
                      Failover при потере связи с C2
                    </FormLabel>
                    <Switch id="c2-failover" defaultChecked colorScheme="purple" />
                  </FormControl>
                  
                  <FormControl display="flex" alignItems="center">
                    <FormLabel htmlFor="self-protection" mb="0">
                      Механизмы самозащиты
                    </FormLabel>
                    <Switch id="self-protection" defaultChecked colorScheme="purple" />
                  </FormControl>
                  
                  <FormControl display="flex" alignItems="center">
                    <FormLabel htmlFor="evasion-module" mb="0">
                      Модули обхода защиты
                    </FormLabel>
                    <Switch id="evasion-module" defaultChecked colorScheme="purple" />
                  </FormControl>
                  
                  <FormControl>
                    <FormLabel>Алгоритм принятия решений ИИ</FormLabel>
                    <Select defaultValue="default">
                      <option value="default">По умолчанию</option>
                      <option value="conservative">Консервативный</option>
                      <option value="opportunistic">Оппортунистический</option>
                      <option value="balanced">Сбалансированный</option>
                    </Select>
                    <Text fontSize="sm" color="gray.500" mt={1}>
                      Определяет, как ИИ-агент принимает решения при анализе и эксплуатации
                    </Text>
                  </FormControl>
                  
                  <FormControl>
                    <FormLabel>Временные ограничения</FormLabel>
                    <NumberInput defaultValue={0} min={0} max={24}>
                      <NumberInputField placeholder="Макс. время в часах (0 = без ограничений)" />
                      <NumberInputStepper>
                        <NumberIncrementStepper />
                        <NumberDecrementStepper />
                      </NumberInputStepper>
                    </NumberInput>
                    <Text fontSize="sm" color="gray.500" mt={1}>
                      Ограничение времени работы агента (0 = без ограничений)
                    </Text>
                  </FormControl>
                </VStack>
              </CardBody>
            </Card>
          </TabPanel>
        </TabPanels>
      </Tabs>
    </Box>
  );
};

export default AutonomousAgent; 