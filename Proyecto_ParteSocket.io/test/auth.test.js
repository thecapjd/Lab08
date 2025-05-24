// test/auth.test.js

const request = require('supertest');
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const fs = require('fs');

describe('Módulo de Autenticación', () => {
  let app;
  let db;
  const JWT_SECRET = 'test_jwt_secret';
  const TEST_DB_PATH = './auth_test.db';

  beforeAll(async () => {
    // Configurar aplicación Express
    app = express();
    app.use(bodyParser.json());

    // Eliminar base de datos de prueba si existe
    if (fs.existsSync(TEST_DB_PATH)) {
      fs.unlinkSync(TEST_DB_PATH);
    }

    // Crear base de datos de prueba
    db = new sqlite3.Database(TEST_DB_PATH);
    
    // Crear tabla de usuarios
    await new Promise((resolve) => {
      db.run(`CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        publicKey TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`, resolve);
    });

    // Configurar rutas
    app.post('/register', async (req, res) => {
      const { username, password } = req.body;
      if (!username || !password) {
        return res.status(400).json({ message: 'Usuario y contraseña son requeridos.' });
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function(err) {
          if (err) {
            if (err.message.includes('UNIQUE constraint failed')) {
              return res.status(409).json({ message: 'El usuario ya existe.' });
            }
            return res.status(500).json({ message: 'Error interno del servidor.' });
          }
          res.status(201).json({ message: 'Usuario registrado exitosamente.' });
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

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Login exitoso.', token });
      });
    });
  });

  afterAll(async () => {
    if (db) {
      await new Promise((resolve) => {
        db.close(resolve);
      });
    }
    
    if (fs.existsSync(TEST_DB_PATH)) {
      fs.unlinkSync(TEST_DB_PATH);
    }
  });

  describe('Registro de usuarios', () => {
    test('debe registrar usuario con datos válidos', async () => {
      const userData = {
        username: 'testuser1',
        password: 'password123'
      };

      const response = await request(app)
        .post('/register')
        .send(userData)
        .expect(201);

      expect(response.body.message).toBe('Usuario registrado exitosamente.');
    });

    test('debe rechazar usuario duplicado', async () => {
      const userData = {
        username: 'testuser1', // Usuario ya existe del test anterior
        password: 'password456'
      };

      const response = await request(app)
        .post('/register')
        .send(userData)
        .expect(409);

      expect(response.body.message).toBe('El usuario ya existe.');
    });

    test('debe rechazar datos faltantes', async () => {
      // Test sin username
      const response1 = await request(app)
        .post('/register')
        .send({ password: 'password123' })
        .expect(400);

      expect(response1.body.message).toBe('Usuario y contraseña son requeridos.');

      // Test sin password
      const response2 = await request(app)
        .post('/register')
        .send({ username: 'testuser2' })
        .expect(400);

      expect(response2.body.message).toBe('Usuario y contraseña son requeridos.');
    });

    test('debe hashear contraseña correctamente', async () => {
      const userData = {
        username: 'testuser3',
        password: 'plainpassword'
      };

      await request(app)
        .post('/register')
        .send(userData)
        .expect(201);

      // Verificar que la contraseña se hasheó en la BD
      await new Promise((resolve) => {
        db.get('SELECT password FROM users WHERE username = ?', [userData.username], (err, row) => {
          expect(err).toBeNull();
          expect(row).toBeDefined();
          expect(row.password).not.toBe(userData.password); // No debe ser texto plano
          expect(row.password.startsWith('$2a$')).toBe(true); // Debe ser hash bcrypt
          resolve();
        });
      });
    });
  });

  describe('Login de usuarios', () => {
    test('debe autenticar usuario válido', async () => {
      // Registrar usuario primero
      await request(app)
        .post('/register')
        .send({ username: 'logintest', password: 'password123' });

      // Intentar login
      const response = await request(app)
        .post('/login')
        .send({ username: 'logintest', password: 'password123' })
        .expect(200);

      expect(response.body.message).toBe('Login exitoso.');
      expect(response.body.token).toBeDefined();
    });

    test('debe rechazar credenciales incorrectas', async () => {
      const response = await request(app)
        .post('/login')
        .send({ username: 'logintest', password: 'wrongpassword' })
        .expect(401);

      expect(response.body.message).toBe('Usuario o contraseña incorrectos.');
      expect(response.body.token).toBeUndefined();
    });

    test('debe generar JWT válido', async () => {
      const response = await request(app)
        .post('/login')
        .send({ username: 'logintest', password: 'password123' })
        .expect(200);

      const token = response.body.token;
      expect(token).toBeDefined();

      // Verificar que el JWT es válido
      const decoded = jwt.verify(token, JWT_SECRET);
      expect(decoded.username).toBe('logintest');
      expect(decoded.id).toBeDefined();
      expect(decoded.exp).toBeDefined(); // Debe tener expiración
    });

    test('debe manejar usuario inexistente', async () => {
      const response = await request(app)
        .post('/login')
        .send({ username: 'nonexistentuser', password: 'password123' })
        .expect(401);

      expect(response.body.message).toBe('Usuario o contraseña incorrectos.');
      expect(response.body.token).toBeUndefined();
    });

    test('debe rechazar datos faltantes en login', async () => {
      // Test sin username
      const response1 = await request(app)
        .post('/login')
        .send({ password: 'password123' })
        .expect(400);

      expect(response1.body.message).toBe('Usuario y contraseña son requeridos.');

      // Test sin password
      const response2 = await request(app)
        .post('/login')
        .send({ username: 'testuser' })
        .expect(400);

      expect(response2.body.message).toBe('Usuario y contraseña son requeridos.');
    });
  });
});