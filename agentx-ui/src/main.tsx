import React from 'react'
import ReactDOM from 'react-dom/client'
import { ChakraProvider, extendTheme } from '@chakra-ui/react'
import App from './App'
import './index.css'
import 'react-toastify/dist/ReactToastify.css'

// Extend the theme to include custom colors, fonts, etc
const theme = extendTheme({
  colors: {
    brand: {
      50: '#e0f7ff',
      100: '#b8ddf0',
      200: '#8fc3e2',
      300: '#65a9d4',
      400: '#3c8fc6',
      500: '#2276ad',
      600: '#165c87',
      700: '#0b4262',
      800: '#00283d',
      900: '#000f19',
    },
  },
  fonts: {
    heading: '"Inter", system-ui, sans-serif',
    body: '"Inter", system-ui, sans-serif',
  },
  components: {
    Button: {
      defaultProps: {
        colorScheme: 'cyan',
      },
    },
  },
})

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <ChakraProvider theme={theme}>
      <App />
    </ChakraProvider>
  </React.StrictMode>,
)
