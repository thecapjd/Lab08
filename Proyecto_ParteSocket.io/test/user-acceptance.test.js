// test/user-acceptance.test.js
/**
 * PRUEBAS DE ACEPTACIÓN Y USUARIO
 * Estas pruebas evalúan el sistema desde la perspectiva del usuario final,
 * validando casos de uso reales y la experiencia de usuario.
 */

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

describe('Pruebas de Aceptación del Usuario - Casos de Uso Reales', () => {
  let app, server, io, db;
  const JWT_SECRET = 'user_test_secret';
  const TEST_PORT = 3002;
  const TEST_DB_PATH = './user_acceptance_test.db';

  // Métricas de usabilidad
  const usabilityMetrics = {
    registrationTime: 0,
    loginTime: 0,
    messageDeliveryTime: 0,
    connectionTime: 0,
    userErrors: 0,
    successfulActions: 0
  };

  // Simulación de retroalimentación de usuario
  const userFeedback = {
    responses: [],
    addResponse: function(scenario, rating, comments) {
      this.responses.push({
        scenario,
        rating, // 1-5 escala
        comments,
        timestamp: new Date().toISOString()
      });
    },
    getAverageRating: function() {
      if (this.responses.length === 0) return 0;
      return this.responses.reduce((sum, r) => sum + r.rating, 0) / this.responses.length;
    }
  };

  beforeAll(async () => {
    // Configurar servidor para pruebas de usuario
    app = express();
    app.use(bodyParser.json());
    server = http.createServer(app);
    io = socketIo(server);

    if (fs.existsSync(TEST_DB_PATH)) {
      fs.unlinkSync(TEST_DB_PATH);
    }

    db = new sqlite3.Database(TEST_DB_PATH);
    
    await new Promise((resolve) => {
      db.serialize(() => {
        db.run(`CREATE TABLE users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE,
          password TEXT,
          publicKey TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          last_login DATETIME,
          message_count INTEGER DEFAULT 0
        )`);
        
        db.run(`CREATE TABLE messages (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          from_user TEXT,
          to_user TEXT,
          message TEXT,
          encrypted_message TEXT,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
          delivered BOOLEAN DEFAULT FALSE,
          read BOOLEAN DEFAULT FALSE
        )`);

        db.run(`CREATE TABLE user_sessions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT,
          session_start DATETIME DEFAULT CURRENT_TIMESTAMP,
          session_end DATETIME,
          actions_performed INTEGER DEFAULT 0
        )`, resolve);
      });
    });

    // Configurar rutas con métricas de usabilidad
    app.post('/register', async (req, res) => {
      const startTime = Date.now();
      const { username, password } = req.body;
      
      if (!username || !password) {
        usabilityMetrics.userErrors++;
        return res.status(400).json({ 
          message: 'Usuario y contraseña son requeridos.',
          usabilityHint: 'Asegúrate de completar ambos campos antes de enviar.'
        });
      }

      if (password.length < 6) {
        usabilityMetrics.userErrors++;
        return res.status(400).json({ 
          message: 'La contraseña debe tener al menos 6 caracteres.',
          usabilityHint: 'Usa una contraseña más segura para proteger tu cuenta.'
        });
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (username, password) VALUES (?, ?)', 
          [username, hashedPassword], function(err) {
          if (err) {
            usabilityMetrics.userErrors++;
            if (err.message.includes('UNIQUE constraint failed')) {
              return res.status(409).json({ 
                message: 'El usuario ya existe.',
                usabilityHint: 'Prueba con un nombre de usuario diferente.'
              });
            }
            return res.status(500).json({ message: 'Error interno del servidor.' });
          }
          
          usabilityMetrics.registrationTime = Date.now() - startTime;
          usabilityMetrics.successfulActions++;
          
          res.status(201).json({ 
            message: 'Usuario registrado exitosamente.',
            userId: this.lastID,
            usabilityInfo: {
              registrationTime: usabilityMetrics.registrationTime,
              tip: 'Ya puedes iniciar sesión con tus credenciales.'
            }
          });
        });
      } catch (error) {
        usabilityMetrics.userErrors++;
        res.status(500).json({ message: 'Error interno del servidor.' });
      }
    });

    app.post('/login', (req, res) => {
      const startTime = Date.now();
      const { username, password } = req.body;
      
      if (!username || !password) {
        usabilityMetrics.userErrors++;
        return res.status(400).json({ 
          message: 'Usuario y contraseña son requeridos.',
          usabilityHint: 'Completa ambos campos para acceder a tu cuenta.'
        });
      }

      db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
          usabilityMetrics.userErrors++;
          return res.status(500).json({ message: 'Error interno del servidor.' });
        }
        if (!user) {
          usabilityMetrics.userErrors++;
          return res.status(401).json({ 
            message: 'Usuario o contraseña incorrectos.',
            usabilityHint: 'Verifica que hayas escrito correctamente tu usuario y contraseña.'
          });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          usabilityMetrics.userErrors++;
          return res.status(401).json({ 
            message: 'Usuario o contraseña incorrectos.',
            usabilityHint: 'Si olvidaste tu contraseña, considera implementar recuperación de cuenta.'
          });
        }

        // Actualizar última conexión
        db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

        const token = jwt.sign(
          { id: user.id, username: user.username }, 
          JWT_SECRET, 
          { expiresIn: '1h' }
        );

        usabilityMetrics.loginTime = Date.now() - startTime;
        usabilityMetrics.successfulActions++;

        res.json({ 
          message: 'Login exitoso.', 
          token, 
          user: { id: user.id, username: user.username },
          usabilityInfo: {
            loginTime: usabilityMetrics.loginTime,
            welcomeMessage: `¡Bienvenido de vuelta, ${user.username}!`
          }
        });
      });
    });

    // Configurar Socket.IO con métricas
    const connectedUsers = new Map();

    io.use((socket, next) => {
      const token = socket.handshake.auth.token;
      if (!token) {
        return next(new Error('Token requerido para conectarse al chat'));
      }

      jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
          return next(new Error('Token inválido. Por favor, inicia sesión nuevamente.'));
        }
        socket.userId = decoded.id;
        socket.username = decoded.username;
        next();
      });
    });

    io.on('connection', (socket) => {
      const connectionStart = Date.now();
      connectedUsers.set(socket.username, socket.id);
      
      // Registrar sesión de usuario
      db.run('INSERT INTO user_sessions (username) VALUES (?)', [socket.username]);
      
      usabilityMetrics.connectionTime = Date.now() - connectionStart;
      
      socket.emit('connection_success', {
        message: 'Conectado al chat exitosamente',
        connectedUsers: Array.from(connectedUsers.keys()).filter(u => u !== socket.username),
        usabilityInfo: {
          connectionTime: usabilityMetrics.connectionTime,
          tip: 'Ahora puedes enviar mensajes a otros usuarios conectados'
        }
      });

      socket.broadcast.emit('user_connected', { 
        username: socket.username,
        message: `${socket.username} se ha unido al chat`
      });

      socket.on('send_message', (data) => {
        const messageStart = Date.now();
        const { to, message, encryptedMessage } = data;
        
        if (!to || (!message && !encryptedMessage)) {
          socket.emit('message_error', { 
            error: 'Destinatario y mensaje son requeridos',
            usabilityHint: 'Asegúrate de seleccionar un usuario y escribir un mensaje'
          });
          usabilityMetrics.userErrors++;
          return;
        }

        db.run(`INSERT INTO messages (from_user, to_user, message, encrypted_message) 
                VALUES (?, ?, ?, ?)`, 
          [socket.username, to, message || '', encryptedMessage || ''], 
          function(err) {
            if (err) {
              socket.emit('message_error', { 
                error: 'Error al enviar mensaje',
                usabilityHint: 'Intenta enviar el mensaje nuevamente'
              });
              usabilityMetrics.userErrors++;
              return;
            }

            // Actualizar contador de mensajes del usuario
            db.run('UPDATE users SET message_count = message_count + 1 WHERE username = ?', [socket.username]);

            const messageData = {
              id: this.lastID,
              from: socket.username,
              to: to,
              message: message,
              encryptedMessage: encryptedMessage,
              timestamp: new Date().toISOString(),
              delivered: false
            };

            // Intentar entrega inmediata
            const recipientSocketId = connectedUsers.get(to);
            if (recipientSocketId) {
              io.to(recipientSocketId).emit('receive_message', {
                ...messageData,
                delivered: true
              });
              
              // Marcar como entregado
              db.run('UPDATE messages SET delivered = TRUE WHERE id = ?', [this.lastID]);
            }

            usabilityMetrics.messageDeliveryTime = Date.now() - messageStart;
            usabilityMetrics.successfulActions++;

            socket.emit('message_sent', {
              ...messageData,
              delivered: !!recipientSocketId,
              usabilityInfo: {
                deliveryTime: usabilityMetrics.messageDeliveryTime,
                status: recipientSocketId ? 'Entregado' : 'Pendiente (usuario desconectado)'
              }
            });
          }
        );
      });

      socket.on('disconnect', () => {
        connectedUsers.delete(socket.username);
        
        // Actualizar sesión
        db.run(`UPDATE user_sessions 
                SET session_end = CURRENT_TIMESTAMP, actions_performed = ? 
                WHERE username = ? AND session_end IS NULL`, 
          [usabilityMetrics.successfulActions, socket.username]);

        socket.broadcast.emit('user_disconnected', { 
          username: socket.username,
          message: `${socket.username} ha salido del chat`
        });
      });
    });

    await new Promise((resolve) => {
      server.listen(TEST_PORT, resolve);
    });
  });

  afterAll(async () => {
  // Cerrar todas las conexiones socket primero
    if (io) {
        io.close();
    }
  
    if (server) {
        await new Promise((resolve) => {
        server.close(() => {
            setTimeout(resolve, 100); // Dar tiempo para cleanup
        });
        });
    }
  
    if (db) {
        await new Promise((resolve) => {
        db.close((err) => {
            resolve();
        });
        });
    }
  
    if (fs.existsSync(TEST_DB_PATH)) {
        try {
        fs.unlinkSync(TEST_DB_PATH);
        } catch (err) {
        // Ignorar errores de limpieza
        }
    }
    }, 15000);

  describe('Caso de Uso 1: Usuario Nuevo - Primer Contacto', () => {
    test('Escenario: María es nueva usuaria y quiere registrarse y enviar su primer mensaje', async () => {
      const startTime = Date.now();
      
      // PASO 1: María intenta registrarse
      const registrationResponse = await request(app)
        .post('/register')
        .send({
          username: 'maria_nueva',
          password: 'miPrimeraPassword123'
        })
        .expect(201);

      expect(registrationResponse.body.usabilityInfo).toBeDefined();
      expect(registrationResponse.body.usabilityInfo.tip).toContain('iniciar sesión');

      // PASO 2: María inicia sesión
      const loginResponse = await request(app)
        .post('/login')
        .send({
          username: 'maria_nueva',
          password: 'miPrimeraPassword123'
        })
        .expect(200);

expect(loginResponse.body.usabilityInfo.welcomeMessage).toContain('maria_nueva');

      // PASO 3: María se conecta al chat
      const mariaSocket = new Client(`http://localhost:${TEST_PORT}`, {
        reconnection: false,
        auth: { token: loginResponse.body.token }
      });

      await new Promise((resolve) => {
        mariaSocket.on('connection_success', (data) => {
          expect(data.usabilityInfo.tip).toContain('enviar mensajes');
          resolve();
        });
      });

      const totalTime = Date.now() - startTime;
      
      // Simulación de retroalimentación
      userFeedback.addResponse(
        'Usuario Nuevo - Primer Contacto',
        4, // Rating 4/5
        `El proceso de registro fue intuitivo. Tomó ${totalTime}ms completar todo el flujo. Las sugerencias de usabilidad fueron útiles.`
      );

      mariaSocket.disconnect();
      
      expect(totalTime).toBeLessThan(5000); // Debe completarse en menos de 5 segundos
    });
  });

  describe('Caso de Uso 2: Conversación Prolongada entre Amigos', () => {
    test('Escenario: Carlos y Ana mantienen una conversación de varios mensajes', async () => {
      // Preparar usuarios
      await request(app).post('/register').send({ username: 'carlos_chat', password: 'password123' });
      await request(app).post('/register').send({ username: 'ana_chat', password: 'password123' });

      const carlosLogin = await request(app).post('/login').send({ username: 'carlos_chat', password: 'password123' });
      const anaLogin = await request(app).post('/login').send({ username: 'ana_chat', password: 'password123' });

      const carlosSocket = new Client(`http://localhost:${TEST_PORT}`, {
        reconnection: false,
        auth: { token: carlosLogin.body.token }
      });

      const anaSocket = new Client(`http://localhost:${TEST_PORT}`, {
        reconnection: false,
        auth: { token: anaLogin.body.token }
      });

      await Promise.all([
        new Promise(resolve => carlosSocket.on('connection_success', resolve)),
        new Promise(resolve => anaSocket.on('connection_success', resolve))
      ]);

      const conversacion = [
        { de: 'carlos_chat', para: 'ana_chat', mensaje: '¡Hola Ana! ¿Cómo estás?' },
        { de: 'ana_chat', para: 'carlos_chat', mensaje: '¡Hola Carlos! Todo bien, ¿y tú?' },
        { de: 'carlos_chat', para: 'ana_chat', mensaje: 'Genial, ¿vamos al cine mañana?' },
        { de: 'ana_chat', para: 'carlos_chat', mensaje: '¡Perfecto! ¿A qué hora?' },
        { de: 'carlos_chat', para: 'ana_chat', mensaje: '¿Te parece a las 7 PM?' }
      ];

      let mensajesRecibidos = 0;
      const startTime = Date.now();

      // Configurar receptores
      carlosSocket.on('receive_message', (data) => {
        expect(data.from).toBe('ana_chat');
        mensajesRecibidos++;
        });

        anaSocket.on('receive_message', (data) => {
        expect(data.from).toBe('carlos_chat');  
        mensajesRecibidos++;
        });

      // Simular conversación natural con delays
      for (let i = 0; i < conversacion.length; i++) {
        const msg = conversacion[i];
        const socket = msg.de === 'carlos_chat' ? carlosSocket : anaSocket;
        
        socket.emit('send_message', {
          to: msg.para,
          message: msg.mensaje
        });

        // Delay natural entre mensajes
        await new Promise(resolve => setTimeout(resolve, 200));
      }

      // Esperar a que todos los mensajes sean procesados
      await new Promise(resolve => setTimeout(resolve, 1000));

      const conversationTime = Date.now() - startTime;
      
      expect(mensajesRecibidos).toBe(5); // Carlos recibe 2, Ana recibe 3
      let mensajesEnviados = 0;


      userFeedback.addResponse(
        'Conversación Prolongada',
        5, // Rating 5/5
        `La conversación fluyó naturalmente. Los mensajes se entregaron instantáneamente. Tiempo total: ${conversationTime}ms`
      );

      carlosSocket.disconnect();
      anaSocket.disconnect();
    });
  });

  describe('Caso de Uso 3: Manejo de Errores Comunes', () => {
    test('Escenario: Usuario comete errores típicos y recibe ayuda', async () => {
      let errorsWithHelp = 0;

      // Error 1: Registro con contraseña débil
      const weakPasswordResponse = await request(app)
        .post('/register')
        .send({
          username: 'usuario_error',
          password: '123' // Muy corta
        })
        .expect(400);

      expect(weakPasswordResponse.body.usabilityHint).toContain('segura');
      errorsWithHelp++;

      // Error 2: Login con credenciales incorrectas
      await request(app).post('/register').send({ username: 'usuario_real', password: 'password123' });
      
      const wrongPasswordResponse = await request(app)
        .post('/login')
        .send({
          username: 'usuario_real',
          password: 'password_incorrecta'
        })
        expect(wrongPasswordResponse.body.usabilityHint).toContain('olvidaste');


      expect(wrongPasswordResponse.body.usabilityHint).toContain('olvidaste');
      errorsWithHelp++;

      // Error 3: Conexión sin token
      const invalidSocket = new Client(`http://localhost:${TEST_PORT}`, {
        reconnection: false
      });

      await new Promise((resolve) => {
        invalidSocket.on('connect_error', (error) => {
          expect(error.message).toContain('Token requerido');
          errorsWithHelp++;
          resolve();
        });
      });

      userFeedback.addResponse(
        'Manejo de Errores',
        4, // Rating 4/5
        `El sistema proporciona mensajes de error claros y sugerencias útiles. Se detectaron ${errorsWithHelp} errores con ayuda apropiada.`
      );

      expect(errorsWithHelp).toBe(3);
      invalidSocket.disconnect();
    });
  });

  describe('Caso de Uso 4: Usuario Móvil con Conexión Intermitente', () => {
    test('Escenario: Usuario con conexión inestable recibe mensajes pendientes', async () => {
      // Simular usuario que se desconecta y reconecta
      await request(app).post('/register').send({ username: 'usuario_movil', password: 'password123' });
      await request(app).post('/register').send({ username: 'remitente', password: 'password123' });

      const movilLogin = await request(app).post('/login').send({ username: 'usuario_movil', password: 'password123' });
      const remitenteLogin = await request(app).post('/login').send({ username: 'remitente', password: 'password123' });

      // Usuario móvil se conecta brevemente y se desconecta
      const movilSocket = new Client(`http://localhost:${TEST_PORT}`, {
        reconnection: false,
        auth: { token: movilLogin.body.token }
      });

      await new Promise(resolve => movilSocket.on('connection_success', resolve));
      movilSocket.disconnect();

      // Remitente envía mensaje mientras móvil está desconectado
      const remitenteSocket = new Client(`http://localhost:${TEST_PORT}`, {
        reconnection: false,
        auth: { token: remitenteLogin.body.token }
      });

      await new Promise(resolve => remitenteSocket.on('connection_success', resolve));

      let mensajePendiente = false;
      remitenteSocket.on('message_sent', (data) => {
        expect(data.delivered).toBe(false);
        expect(data.usabilityInfo.status).toContain('Pendiente');
        mensajePendiente = true;
      });

      remitenteSocket.emit('send_message', {
        to: 'usuario_movil',
        message: 'Mensaje mientras estabas desconectado'
      });

      await new Promise(resolve => setTimeout(resolve, 500));
      expect(mensajePendiente).toBe(true);

      userFeedback.addResponse(
        'Conexión Intermitente',
        3, // Rating 3/5
        'El sistema maneja bien las desconexiones, pero sería útil tener notificaciones push para mensajes pendientes.'
      );

      remitenteSocket.disconnect();
    });
  });

  describe('Evaluación de Usabilidad y Retroalimentación', () => {
    test('debe recopilar métricas de usabilidad significativas', () => {
      expect(usabilityMetrics.registrationTime).toBeGreaterThan(0);
      expect(usabilityMetrics.loginTime).toBeGreaterThan(0);
      expect(usabilityMetrics.successfulActions).toBeGreaterThan(0);
      
      console.log('\n📊 MÉTRICAS DE USABILIDAD:');
      console.log(`⏱️  Tiempo promedio de registro: ${usabilityMetrics.registrationTime}ms`);
      console.log(`🔐 Tiempo promedio de login: ${usabilityMetrics.loginTime}ms`);
      console.log(`💬 Tiempo promedio de entrega de mensaje: ${usabilityMetrics.messageDeliveryTime}ms`);
      console.log(`🔌 Tiempo promedio de conexión: ${usabilityMetrics.connectionTime}ms`);
      console.log(`✅ Acciones exitosas: ${usabilityMetrics.successfulActions}`);
      console.log(`❌ Errores de usuario: ${usabilityMetrics.userErrors}`);
      console.log(`📈 Tasa de éxito: ${((usabilityMetrics.successfulActions / (usabilityMetrics.successfulActions + usabilityMetrics.userErrors)) * 100).toFixed(1)}%`);
    });

    test('debe generar reporte de retroalimentación simulada', () => {
      expect(userFeedback.responses.length).toBeGreaterThan(0);
      
      const averageRating = userFeedback.getAverageRating();
      expect(averageRating).toBeGreaterThan(0);
      expect(averageRating).toBeLessThanOrEqual(5);

      console.log('\n📝 RETROALIMENTACIÓN DE USUARIOS:');
      console.log(`⭐ Rating promedio: ${averageRating.toFixed(1)}/5`);
      console.log(`📊 Total de respuestas: ${userFeedback.responses.length}`);
      
      userFeedback.responses.forEach((response, index) => {
        console.log(`\n${index + 1}. ${response.scenario}:`);
        console.log(`   Rating: ${response.rating}/5`);
        console.log(`   Comentario: "${response.comments}"`);
      });

      console.log('\n🎯 RECOMENDACIONES BASADAS EN FEEDBACK:');
      if (averageRating >= 4.5) {
        console.log('✅ Excelente usabilidad. Mantener estándares actuales.');
      } else if (averageRating >= 3.5) {
        console.log('⚠️  Usabilidad buena. Considerar mejoras menores.');
      } else {
        console.log('🔄 Usabilidad necesita mejoras significativas.');
      }

      // Identificar áreas de mejora basadas en feedback
      const mejoras = [];
      if (usabilityMetrics.userErrors > usabilityMetrics.successfulActions * 0.2) {
        mejoras.push('Reducir errores de usuario con mejor UX');
      }
      if (usabilityMetrics.messageDeliveryTime > 1000) {
        mejoras.push('Optimizar tiempo de entrega de mensajes');
      }
      if (userFeedback.responses.some(r => r.comments.includes('notificaciones'))) {
        mejoras.push('Implementar sistema de notificaciones push');
      }

      if (mejoras.length > 0) {
        console.log('\n🔧 MEJORAS SUGERIDAS:');
        mejoras.forEach((mejora, i) => console.log(`${i + 1}. ${mejora}`));
      }
    });
  });
});