// test/setup.js

// Configuración global para Jest
jest.setTimeout(10000);

// Mock console para tests más limpios
global.console = {
  ...console,
  // Silenciar logs durante tests
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: console.warn,
  error: console.error,
};

// Variables globales para tests
global.testConfig = {
  JWT_SECRET: 'test_jwt_secret_key',
  TEST_PORT: 3001,
  TEST_DB_PATH: './test_database.db'
};

// Cleanup después de cada test
afterEach(() => {
  // Limpiar mocks
  jest.clearAllMocks();
});

// Configuración específica para tests de Socket.IO
global.socketTestConfig = {
  reconnection: false,
  timeout: 1000,
  forceNew: true
};