// test/integration.test.js

const request = require('supertest');
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const Client = require('socket.io-client');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const fs = require('fs');

describe('Pruebas de Integración del Chat', () => {
  let app;
  let server;
  let io;
  let db;
  let clientSocket1;
  let clientSocket2;
  
  const JWT_SECRET = global.testConfig.JWT_SECRET;
  const TEST_PORT = global.testConfig.TEST_PORT;
  const TEST_DB_PATH = './integration_test.db';

  beforeAll(async () => {
    // Configurar aplicación Express
    app = express();
    app.use(bodyParser.json());
    server = http.createServer(app);
    io = socketIo(server);

    // Eliminar base de datos de prueba si existe
    if (fs.existsSync(TEST_DB_PATH)) {
      fs.unlinkSync(TEST_DB_PATH);
    }

    // Crear base de datos de prueba
    db = new sqlite3.Database(TEST_DB_PATH);
    
    // Crear tablas
    await new Promise((resolve) => {
      db.serialize(() => {
        db.run(`CREATE TABLE users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE,
          password TEXT,
          publicKey TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        
        db.run(`CREATE TABLE messages (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          from_user TEXT,
          to_user TEXT,
          message TEXT,
          encrypted_message TEXT,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, resolve);
      });
    });

    // Middleware de autenticación
    const authenticateToken = (req, res, next) => {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1];

      if (!token) {
        return res.status(401).json({ message: 'Token de acceso requerido' });
      }

      jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
          return res.status(403).json({ message: 'Token inválido' });
        }
        req.user = user;
        next();
      });
    };

    // Rutas de autenticación
    app.post('/register', async (req, res) => {
      const { username, password } = req.body;
      if (!username || !password) {
        return res.status(400).json({ message: 'Usuario y contraseña son requeridos.' });
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (username, password) VALUES (?, ?)', 
          [username, hashedPassword], function(err) {
          if (err) {
            if (err.message.includes('UNIQUE constraint failed')) {
              return res.status(409).json({ message: 'El usuario ya existe.' });
            }
            return res.status(500).json({ message: 'Error interno del servidor.' });
          }
          res.status(201).json({ message: 'Usuario registrado exitosamente.', userId: this.lastID });
        });
      } catch (error) {
        res.status(500).json({ message: 'Error interno del servidor.' });
      }
    });

    app.post('/login', (req, res) => {
      const { username, password } = req.body;
      if (!username || !password) {
        return res.status(400).json({ message: 'Usuario y contraseña son requeridos.' });
      }

      db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
          return res.status(500).json({ message: 'Error interno del servidor.' });
        }
        if (!user) {
          return res.status(401).json({ message: 'Usuario o contraseña incorrectos.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return res.status(401).json({ message: 'Usuario o contraseña incorrectos.' });
        }

        const token = jwt.sign(
          { id: user.id, username: user.username }, 
          JWT_SECRET, 
          { expiresIn: '1h' }
        );
        res.json({ message: 'Login exitoso.', token, user: { id: user.id, username: user.username } });
      });
    });

    // Ruta para obtener mensajes
    app.get('/messages', authenticateToken, (req, res) => {
      const { username } = req.user;
      
      db.all(`SELECT * FROM messages 
              WHERE from_user = ? OR to_user = ? 
              ORDER BY timestamp ASC`, 
        [username, username], (err, messages) => {
        if (err) {
          return res.status(500).json({ message: 'Error al obtener mensajes.' });
        }
        res.json({ messages });
      });
    });

    // Configurar Socket.IO
    const connectedUsers = new Map();

    io.use((socket, next) => {
      const token = socket.handshake.auth.token;
      if (!token) {
        return next(new Error('Token requerido'));
      }

      jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
          return next(new Error('Token inválido'));
        }
        socket.userId = decoded.id;
        socket.username = decoded.username;
        next();
      });
    });

    io.on('connection', (socket) => {
      connectedUsers.set(socket.username, socket.id);
      
      // Notificar a otros usuarios que alguien se conectó
      socket.broadcast.emit('user_connected', { username: socket.username });

      socket.on('send_message', (data) => {
        const { to, message, encryptedMessage } = data;
        
        // Guardar mensaje en base de datos
        db.run(`INSERT INTO messages (from_user, to_user, message, encrypted_message) 
                VALUES (?, ?, ?, ?)`, 
          [socket.username, to, message || '', encryptedMessage || ''], 
          function(err) {
            if (err) {
              socket.emit('message_error', { error: 'Error al guardar mensaje' });
              return;
            }

            const messageData = {
              id: this.lastID,
              from: socket.username,
              to: to,
              message: message,
              encryptedMessage: encryptedMessage,
              timestamp: new Date().toISOString()
            };

            // Enviar a destinatario si está conectado
            const recipientSocketId = connectedUsers.get(to);
            if (recipientSocketId) {
              io.to(recipientSocketId).emit('receive_message', messageData);
            }

            // Confirmar envío al remitente
            socket.emit('message_sent', messageData);
          }
        );
      });

      socket.on('disconnect', () => {
        connectedUsers.delete(socket.username);
        socket.broadcast.emit('user_disconnected', { username: socket.username });
      });
    });

    // Iniciar servidor
    await new Promise((resolve) => {
      server.listen(TEST_PORT, resolve);
    });
  });

  afterAll(async () => {
    // Cerrar conexiones de clientes
    if (clientSocket1 && clientSocket1.connected) {
      clientSocket1.disconnect();
    }
    if (clientSocket2 && clientSocket2.connected) {
      clientSocket2.disconnect();
    }

    // Cerrar servidor
    if (server) {
      await new Promise((resolve) => {
        server.close(resolve);
      });
    }

    // Cerrar base de datos
    if (db) {
      await new Promise((resolve) => {
        db.close(resolve);
      });
    }
    
    // Eliminar archivo de base de datos
    if (fs.existsSync(TEST_DB_PATH)) {
      fs.unlinkSync(TEST_DB_PATH);
    }
  });

  describe('Flujo completo de autenticación y chat', () => {
    let user1Token, user2Token;
    const user1Data = { username: 'testuser1', password: 'password123' };
    const user2Data = { username: 'testuser2', password: 'password456' };

    test('debe registrar dos usuarios correctamente', async () => {
      // Registrar primer usuario
      const response1 = await request(app)
        .post('/register')
        .send(user1Data)
        .expect(201);
      
      expect(response1.body.message).toBe('Usuario registrado exitosamente.');

      // Registrar segundo usuario
      const response2 = await request(app)
        .post('/register')
        .send(user2Data)
        .expect(201);
      
      expect(response2.body.message).toBe('Usuario registrado exitosamente.');
    });

    test('debe autenticar ambos usuarios', async () => {
      // Login primer usuario
      const response1 = await request(app)
        .post('/login')
        .send(user1Data)
        .expect(200);
      
      expect(response1.body.token).toBeDefined();
      user1Token = response1.body.token;

      // Login segundo usuario
      const response2 = await request(app)
        .post('/login')
        .send(user2Data)
        .expect(200);
      
      expect(response2.body.token).toBeDefined();
      user2Token = response2.body.token;
    });

    test('debe conectar usuarios via WebSocket', async () => {
      // Conectar primer usuario
      clientSocket1 = new Client(`http://localhost:${TEST_PORT}`, {
        ...global.socketTestConfig,
        auth: { token: user1Token }
      });

      // Conectar segundo usuario
      clientSocket2 = new Client(`http://localhost:${TEST_PORT}`, {
        ...global.socketTestConfig,
        auth: { token: user2Token }
      });

      // Esperar conexiones
      await Promise.all([
        new Promise((resolve) => clientSocket1.on('connect', resolve)),
        new Promise((resolve) => clientSocket2.on('connect', resolve))
      ]);

      expect(clientSocket1.connected).toBe(true);
      expect(clientSocket2.connected).toBe(true);
    });

    test('debe enviar y recibir mensajes entre usuarios', async () => {
      const testMessage = 'Hola, este es un mensaje de prueba';
      let messageReceived = false;

      // Configurar listener en el segundo usuario para este test específico
      const messageListener = (data) => {
        if (data.message === testMessage) {
          expect(data.from).toBe(user1Data.username);
          expect(data.to).toBe(user2Data.username);
          expect(data.message).toBe(testMessage);
          expect(data.timestamp).toBeDefined();
          messageReceived = true;
        }
      };

      clientSocket2.on('receive_message', messageListener);

      // Enviar mensaje desde el primer usuario
      clientSocket1.emit('send_message', {
        to: user2Data.username,
        message: testMessage
      });

      // Esperar confirmación de envío
      await new Promise((resolve) => {
        const sentListener = (data) => {
          if (data.message === testMessage) {
            expect(data.from).toBe(user1Data.username);
            expect(data.message).toBe(testMessage);
            clientSocket1.off('message_sent', sentListener);
            resolve();
          }
        };
        clientSocket1.on('message_sent', sentListener);
      });

      // Dar tiempo para que llegue el mensaje
      await new Promise(resolve => setTimeout(resolve, 100));
      expect(messageReceived).toBe(true);
      
      // Limpiar listener
      clientSocket2.off('receive_message', messageListener);
    });

    test('debe guardar mensajes en la base de datos', async () => {
      // Obtener mensajes via API REST
      const response = await request(app)
        .get('/messages')
        .set('Authorization', `Bearer ${user1Token}`)
        .expect(200);

      expect(response.body.messages).toBeDefined();
      expect(response.body.messages.length).toBeGreaterThan(0);
      
      const lastMessage = response.body.messages[response.body.messages.length - 1];
      expect(lastMessage.from_user).toBe(user1Data.username);
      expect(lastMessage.to_user).toBe(user2Data.username);
    });

    test('debe manejar mensajes cifrados', async () => {
      const plainMessage = 'Mensaje secreto';
      const encryptedMessage = 'encrypted_' + plainMessage; // Simulación de cifrado
      let encryptedReceived = false;

      // Configurar listener específico para mensajes cifrados
      const encryptedListener = (data) => {
        if (data.message === plainMessage && data.encryptedMessage) {
          expect(data.from).toBe(user1Data.username);
          expect(data.to).toBe(user2Data.username);
          expect(data.message).toBe(plainMessage);
          expect(data.encryptedMessage).toBe(encryptedMessage);
          encryptedReceived = true;
        }
      };

      clientSocket2.on('receive_message', encryptedListener);

      // Enviar mensaje cifrado
      clientSocket1.emit('send_message', {
        to: user2Data.username,
        message: plainMessage,
        encryptedMessage: encryptedMessage
      });

      // Esperar confirmación de envío
      await new Promise((resolve) => {
        const sentListener = (data) => {
          if (data.message === plainMessage) {
            expect(data.from).toBe(user1Data.username);
            expect(data.message).toBe(plainMessage);
            expect(data.encryptedMessage).toBe(encryptedMessage);
            clientSocket1.off('message_sent', sentListener);
            resolve();
          }
        };
        clientSocket1.on('message_sent', sentListener);
      });

      // Dar tiempo para que llegue el mensaje
      await new Promise(resolve => setTimeout(resolve, 200));
      expect(encryptedReceived).toBe(true);
      
      // Limpiar listener
      clientSocket2.off('receive_message', encryptedListener);
    });

    test('debe manejar desconexiones correctamente', async () => {
      let disconnectionDetected = false;

      clientSocket2.on('user_disconnected', (data) => {
        expect(data.username).toBe(user1Data.username);
        disconnectionDetected = true;
      });

      // Desconectar primer usuario
      clientSocket1.disconnect();

      await new Promise(resolve => setTimeout(resolve, 100));
      expect(disconnectionDetected).toBe(true);
    });
  });

  describe('Manejo de errores en integración', () => {
    test('debe rechazar conexión WebSocket sin token', async () => {
      const invalidClient = new Client(`http://localhost:${TEST_PORT}`, {
        ...global.socketTestConfig
        // Sin token de autenticación
      });

      await new Promise((resolve) => {
        invalidClient.on('connect_error', (error) => {
          expect(error.message).toContain('Token requerido');
          resolve();
        });
      });

      invalidClient.disconnect();
    });

    test('debe manejar tokens JWT inválidos', async () => {
      const invalidToken = 'token_invalido';
      
      const invalidClient = new Client(`http://localhost:${TEST_PORT}`, {
        ...global.socketTestConfig,
        auth: { token: invalidToken }
      });

      await new Promise((resolve) => {
        invalidClient.on('connect_error', (error) => {
          expect(error.message).toContain('Token inválido');
          resolve();
        });
      });

      invalidClient.disconnect();
    });

    test('debe requerir autenticación para obtener mensajes', async () => {
      const response = await request(app)
        .get('/messages')
        .expect(401);

      expect(response.body.message).toBe('Token de acceso requerido');
    });
  });

  describe('Pruebas de rendimiento básicas', () => {
    test('debe manejar múltiples mensajes rápidamente', async () => {
      // Registrar y autenticar usuarios para esta prueba
      await request(app)
        .post('/register')
        .send({ username: 'speeduser1', password: 'pass123' });
      
      await request(app)
        .post('/register')
        .send({ username: 'speeduser2', password: 'pass123' });

      const login1 = await request(app)
        .post('/login')
        .send({ username: 'speeduser1', password: 'pass123' });

      const login2 = await request(app)
        .post('/login')
        .send({ username: 'speeduser2', password: 'pass123' });

      // Conectar usuarios
      const socket1 = new Client(`http://localhost:${TEST_PORT}`, {
        ...global.socketTestConfig,
        auth: { token: login1.body.token }
      });

      const socket2 = new Client(`http://localhost:${TEST_PORT}`, {
        ...global.socketTestConfig,
        auth: { token: login2.body.token }
      });

      await Promise.all([
        new Promise(resolve => socket1.on('connect', resolve)),
        new Promise(resolve => socket2.on('connect', resolve))
      ]);

      let messagesReceived = 0;
      const totalMessages = 10;

      socket2.on('receive_message', () => {
        messagesReceived++;
      });

      const startTime = Date.now();

      // Enviar múltiples mensajes
      for (let i = 0; i < totalMessages; i++) {
        socket1.emit('send_message', {
          to: 'speeduser2',
          message: `Mensaje rápido ${i + 1}`
        });
      }

      // Esperar a que se reciban todos los mensajes
      await new Promise((resolve) => {
        const checkMessages = () => {
          if (messagesReceived >= totalMessages) {
            resolve();
          } else {
            setTimeout(checkMessages, 10);
          }
        };
        checkMessages();
      });

      const endTime = Date.now();
      const duration = endTime - startTime;

      expect(messagesReceived).toBe(totalMessages);
      expect(duration).toBeLessThan(2000); // Debe completarse en menos de 2 segundos

      socket1.disconnect();
      socket2.disconnect();
    });
  });
});