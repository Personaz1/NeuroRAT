import { Box, VStack, Icon, Text, Flex, Badge, Heading, Divider, Tooltip } from '@chakra-ui/react';
import { Link, useLocation } from 'react-router-dom';
import { 
  MdDashboard, 
  MdDevices, 
  MdSecurity, 
  MdCode, 
  MdRadar, 
  MdCurrencyBitcoin, 
  MdShowChart,
  MdSmartToy,
  MdSettings
} from 'react-icons/md';

interface NavItemProps {
  icon: React.ElementType;
  to: string;
  label: string;
  isActive?: boolean;
  badge?: string | number;
  badgeColor?: string;
}

interface SidebarProps {
  serverStatus: {
    status?: string;
    agents?: number;
    operations?: number;
  } | null;
}

const NavItem = ({ icon, to, label, isActive, badge, badgeColor = "green" }: NavItemProps) => {
  return (
    <Tooltip label={label} placement="right" hasArrow>
      <Link to={to}>
        <Flex
          align="center"
          p="3"
          mx="2"
          borderRadius="lg"
          role="group"
          cursor="pointer"
          _hover={{
            bg: 'cyan.400',
            color: 'white',
          }}
          bg={isActive ? 'cyan.400' : 'transparent'}
          color={isActive ? 'white' : 'gray.600'}
        >
          <Icon
            mr="3"
            fontSize="20"
            as={icon}
          />
          <Text fontSize="sm" fontWeight="medium">{label}</Text>
          {badge && (
            <Badge ml="auto" colorScheme={badgeColor} borderRadius="full" px="2">
              {badge}
            </Badge>
          )}
        </Flex>
      </Link>
    </Tooltip>
  );
};

const Sidebar = ({ serverStatus }: SidebarProps) => {
  const location = useLocation();
  const currentPath = location.pathname;

  return (
    <Box
      bg="white"
      borderRight="1px"
      borderRightColor="gray.200"
      w={{ base: '80px', md: '240px' }}
      pos="fixed"
      h="full"
      py="5"
      boxShadow="md"
    >
      <VStack spacing="10px" alignItems="flex-start">
        {/* Logo */}
        <Box px="4" pb="6">
          <Flex align="center">
            <Heading 
              fontSize={{ base: 'sm', md: 'xl' }} 
              fontWeight="bold" 
              color="cyan.600"
              display="flex"
              alignItems="center"
            >
              <Icon 
                as={MdSecurity} 
                color="red.500" 
                mr="2" 
                fontSize={{ base: '2xl', md: '3xl' }} 
              />
              <Box display={{ base: 'none', md: 'block' }}>
                AgentX C2
              </Box>
            </Heading>
          </Flex>
          
          {/* Status indicator */}
          {serverStatus && (
            <Flex mt="2" alignItems="center">
              <Box
                w="8px"
                h="8px"
                borderRadius="full"
                bg={serverStatus.status === 'operational' ? 'green.400' : 'red.400'}
                mr="2"
              />
              <Text
                fontSize="xs"
                color="gray.500"
                display={{ base: 'none', md: 'block' }}
              >
                {serverStatus.status === 'operational' ? 'Online' : 'Offline'}
              </Text>
            </Flex>
          )}
        </Box>

        <Divider />

        {/* Navigation Items */}
        <VStack w="full" spacing="1" align="stretch">
          <NavItem
            to="/"
            icon={MdDashboard}
            label="Dashboard"
            isActive={currentPath === '/'}
          />
          
          <NavItem
            to="/agents"
            icon={MdDevices}
            label="Agents"
            isActive={currentPath === '/agents'}
            badge={serverStatus?.agents || 0}
            badgeColor={serverStatus?.agents ? "green" : "gray"}
          />
          
          <NavItem
            to="/operations"
            icon={MdRadar}
            label="Operations"
            isActive={currentPath === '/operations'}
            badge={serverStatus?.operations || 0}
            badgeColor={serverStatus?.operations ? "blue" : "gray"}
          />
          
          <NavItem
            to="/exploits"
            icon={MdCode}
            label="Exploits"
            isActive={currentPath === '/exploits'}
          />
          
          <NavItem
            to="/scanner"
            icon={MdRadar}
            label="Network Scanner"
            isActive={currentPath === '/scanner'}
          />
        </VStack>

        <Box px="4" pt="4">
          <Text
            fontSize="xs"
            fontWeight="semibold"
            color="gray.400"
            letterSpacing="wider"
            textTransform="uppercase"
            display={{ base: 'none', md: 'block' }}
          >
            ADVANCED
          </Text>
        </Box>

        <VStack w="full" spacing="1" align="stretch">
          <NavItem
            to="/crypto-drainer"
            icon={MdCurrencyBitcoin}
            label="Crypto Drainer"
            isActive={currentPath === '/crypto-drainer'}
          />
          
          <NavItem
            to="/mev-monitor"
            icon={MdShowChart}
            label="MEV Monitor"
            isActive={currentPath === '/mev-monitor'}
          />
          
          <NavItem
            to="/autonomous-agent"
            icon={MdSmartToy}
            label="Autonomous Agent"
            isActive={currentPath === '/autonomous-agent'}
          />
        </VStack>

        <Box mt="auto" pt="6" w="full">
          <Divider />
          <NavItem
            to="/settings"
            icon={MdSettings}
            label="Settings"
            isActive={currentPath === '/settings'}
          />
        </Box>
      </VStack>
    </Box>
  );
};

export default Sidebar; 