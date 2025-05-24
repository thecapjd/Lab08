// server.js

const express = require('express');
const https = require('https');
const fs = require('fs');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Configuración HTTPS
const httpsOptions = {
    key: fs.readFileSync('./key.pem'),
    cert: fs.readFileSync('./cert.pem')
};

const server = https.createServer(httpsOptions, app);
const io = new Server(server);

// Base de datos SQLite
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('Error al abrir la base de datos', err.message);
    } else {
        console.log('Conectado a la base de datos SQLite.');
        
        // Tabla de usuarios
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            publicKey TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, (err) => {
            if (err) {
                console.error("Error al crear tabla 'users':", err.message);
            } else {
                console.log("Tabla 'users' verificada/creada.");
            }
        });

        // Tabla de solicitudes de amistad
        db.run(`CREATE TABLE IF NOT EXISTS friend_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester_username TEXT,
            receiver_username TEXT,
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (requester_username) REFERENCES users (username),
            FOREIGN KEY (receiver_username) REFERENCES users (username),
            UNIQUE(requester_username, receiver_username)
        )`, (err) => {
            if (err) {
                console.error("Error al crear tabla 'friend_requests':", err.message);
            } else {
                console.log("Tabla 'friend_requests' verificada/creada.");
            }
        });

        // Tabla de amistades confirmadas
        db.run(`CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user1_username TEXT,
            user2_username TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user1_username) REFERENCES users (username),
            FOREIGN KEY (user2_username) REFERENCES users (username),
            UNIQUE(user1_username, user2_username)
        )`, (err) => {
            if (err) {
                console.error("Error al crear tabla 'friendships':", err.message);
            } else {
                console.log("Tabla 'friendships' verificada/creada.");
            }
        });

        // Tabla de mensajes (modificada para incluir chat_id)
        db.run(`CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id TEXT,
            sender TEXT,
            receiver TEXT,
            encryptedMessage TEXT,
            iv TEXT,
            message_type TEXT DEFAULT 'text',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, (err) => {
            if (err) {
                console.error("Error al crear tabla 'messages':", err.message);
            } else {
                console.log("Tabla 'messages' verificada/creada.");
            }
        });
    }
});

// Middleware
app.use(express.static('public'));
app.use(bodyParser.json());

// Mapa de usuarios conectados
const connectedUsers = {};

// Función auxiliar para generar chat_id consistente
function generateChatId(user1, user2) {
    return [user1, user2].sort().join('_');
}

// --- Rutas HTTP ---
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
                console.error('Error al registrar usuario en DB:', err.message);
                return res.status(500).json({ message: 'Error interno del servidor.' });
            }
            res.status(201).json({ message: 'Usuario registrado exitosamente.' });
            console.log(`Usuario '${username}' registrado exitosamente.`);
        });
    } catch (error) {
        console.error('Error al hashear contraseña:', error);
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
            console.error('Error DB al buscar usuario para login:', err.message);
            return res.status(500).json({ message: 'Error interno del servidor.' });
        }
        if (!user) {
            console.warn(`Intento de login fallido: Usuario '${username}' no encontrado.`);
            return res.status(401).json({ message: 'Usuario o contraseña incorrectos.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.warn(`Intento de login fallido: Contraseña incorrecta para '${username}'.`);
            return res.status(401).json({ message: 'Usuario o contraseña incorrectos.' });
        }

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Login exitoso.', token });
        console.log(`Usuario '${username}' logueado exitosamente. Token emitido.`);
    });
});

// Middleware de autenticación para Socket.IO
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
        console.warn('Conexión Socket.IO denegada: No se proporcionó token.');
        return next(new Error('Autenticación requerida. No se proporcionó token.'));
    }
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            console.error('Error de verificación de token JWT para Socket.IO:', err.message);
            return next(new Error('Token inválido o expirado.'));
        }
        socket.user = decoded;
        next();
    });
});

// --- Lógica de Socket.IO ---
io.on('connection', (socket) => {
    console.log(`Usuario conectado: ${socket.user.username} (ID: ${socket.id})`);
    connectedUsers[socket.user.username] = socket.id;

    // Notifica usuarios online
    io.emit('online_users', Object.keys(connectedUsers));

    // Evento: Enviar clave pública
    socket.on('send_public_key', (publicKey) => {
        if (socket.user && socket.user.username && publicKey) {
            console.log(`Recibida clave pública de ${socket.user.username}. Almacenando en DB...`);
            db.run('UPDATE users SET publicKey = ? WHERE username = ?', [publicKey, socket.user.username], function(err) {
                if (err) {
                    console.error(`Error al guardar clave pública para ${socket.user.username} en DB:`, err.message);
                } else {
                    console.log(`Clave pública guardada exitosamente para ${socket.user.username}.`);
                }
            });
        }
    });

    // Evento: Buscar usuarios para agregar como amigos
    socket.on('search_users', (searchTerm) => {
        if (!searchTerm || searchTerm.length < 2) {
            socket.emit('search_results', []);
            return;
        }
        
        const currentUser = socket.user.username;
        db.all(`
            SELECT username FROM users 
            WHERE username LIKE ? AND username != ? 
            AND username NOT IN (
                SELECT user2_username FROM friendships WHERE user1_username = ?
                UNION
                SELECT user1_username FROM friendships WHERE user2_username = ?
            )
            AND username NOT IN (
                SELECT receiver_username FROM friend_requests 
                WHERE requester_username = ? AND status = 'pending'
            )
            LIMIT 10
        `, [`%${searchTerm}%`, currentUser, currentUser, currentUser, currentUser], (err, rows) => {
            if (err) {
                console.error('Error al buscar usuarios:', err.message);
                socket.emit('search_results', []);
            } else {
                const users = rows.map(row => row.username);
                socket.emit('search_results', users);
            }
        });
    });

    // Evento: Enviar solicitud de amistad
    socket.on('send_friend_request', (targetUsername) => {
        const requester = socket.user.username;
        
        if (requester === targetUsername) {
            socket.emit('error_message', 'No puedes enviarte una solicitud a ti mismo.');
            return;
        }

        // Verificar si ya existe una solicitud o amistad
        db.get(`
            SELECT * FROM friend_requests 
            WHERE (requester_username = ? AND receiver_username = ?) 
            OR (requester_username = ? AND receiver_username = ?)
        `, [requester, targetUsername, targetUsername, requester], (err, existingRequest) => {
            if (err) {
                console.error('Error al verificar solicitud existente:', err.message);
                socket.emit('error_message', 'Error al enviar solicitud.');
                return;
            }

            if (existingRequest) {
                socket.emit('error_message', 'Ya existe una solicitud de amistad con este usuario.');
                return;
            }

            // Verificar si ya son amigos
            db.get(`
                SELECT * FROM friendships 
                WHERE (user1_username = ? AND user2_username = ?) 
                OR (user1_username = ? AND user2_username = ?)
            `, [requester, targetUsername, targetUsername, requester], (err, friendship) => {
                if (err) {
                    console.error('Error al verificar amistad:', err.message);
                    socket.emit('error_message', 'Error al enviar solicitud.');
                    return;
                }

                if (friendship) {
                    socket.emit('error_message', 'Ya eres amigo de este usuario.');
                    return;
                }

                // Crear solicitud de amistad
                db.run('INSERT INTO friend_requests (requester_username, receiver_username) VALUES (?, ?)', 
                    [requester, targetUsername], function(err) {
                    if (err) {
                        console.error('Error al crear solicitud de amistad:', err.message);
                        socket.emit('error_message', 'Error al enviar solicitud.');
                    } else {
                        socket.emit('friend_request_sent', targetUsername);
                        
                        // Notificar al receptor si está online
                        if (connectedUsers[targetUsername]) {
                            io.to(connectedUsers[targetUsername]).emit('friend_request_received', {
                                requester: requester,
                                id: this.lastID
                            });
                        }
                        console.log(`Solicitud de amistad enviada de ${requester} a ${targetUsername}`);
                    }
                });
            });
        });
    });

    // Evento: Obtener solicitudes de amistad pendientes
    socket.on('get_friend_requests', () => {
        const username = socket.user.username;
        db.all('SELECT * FROM friend_requests WHERE receiver_username = ? AND status = "pending"', 
            [username], (err, rows) => {
            if (err) {
                console.error('Error al obtener solicitudes de amistad:', err.message);
                socket.emit('friend_requests_list', []);
            } else {
                socket.emit('friend_requests_list', rows);
            }
        });
    });

    // Evento: Responder solicitud de amistad
    socket.on('respond_friend_request', (data) => {
        const { requestId, accept } = data;
        const receiver = socket.user.username;

        db.get('SELECT * FROM friend_requests WHERE id = ? AND receiver_username = ?', 
            [requestId, receiver], (err, request) => {
            if (err || !request) {
                console.error('Error al buscar solicitud:', err);
                socket.emit('error_message', 'Solicitud no encontrada.');
                return;
            }

            if (accept) {
                // Aceptar solicitud: crear amistad
                const user1 = request.requester_username;
                const user2 = receiver;
                const sortedUsers = [user1, user2].sort();

                db.run('INSERT INTO friendships (user1_username, user2_username) VALUES (?, ?)',
                    [sortedUsers[0], sortedUsers[1]], function(err) {
                    if (err) {
                        console.error('Error al crear amistad:', err.message);
                        socket.emit('error_message', 'Error al aceptar solicitud.');
                        return;
                    }

                    // Actualizar estado de solicitud
                    db.run('UPDATE friend_requests SET status = "accepted" WHERE id = ?', [requestId]);
                    
                    socket.emit('friend_request_accepted', user1);
                    
                    // Notificar al solicitante
                    if (connectedUsers[user1]) {
                        io.to(connectedUsers[user1]).emit('friend_request_response', {
                            user: user2,
                            accepted: true
                        });
                    }

                    console.log(`Amistad creada entre ${user1} y ${user2}`);
                });
            } else {
                // Rechazar solicitud
                db.run('UPDATE friend_requests SET status = "rejected" WHERE id = ?', [requestId], (err) => {
                    if (err) {
                        console.error('Error al rechazar solicitud:', err.message);
                    } else {
                        socket.emit('friend_request_rejected', request.requester_username);
                        
                        // Notificar al solicitante
                        if (connectedUsers[request.requester_username]) {
                            io.to(connectedUsers[request.requester_username]).emit('friend_request_response', {
                                user: receiver,
                                accepted: false
                            });
                        }
                    }
                });
            }
        });
    });

    // Evento: Obtener lista de amigos
    socket.on('get_friends_list', () => {
        const username = socket.user.username;
        db.all(`
            SELECT 
                CASE 
                    WHEN user1_username = ? THEN user2_username 
                    ELSE user1_username 
                END as friend_username,
                created_at
            FROM friendships 
            WHERE user1_username = ? OR user2_username = ?
            ORDER BY created_at DESC
        `, [username, username, username], (err, rows) => {
            if (err) {
                console.error('Error al obtener lista de amigos:', err.message);
                socket.emit('friends_list', []);
            } else {
                const friends = rows.map(row => ({
                    username: row.friend_username,
                    isOnline: !!connectedUsers[row.friend_username],
                    created_at: row.created_at
                }));
                socket.emit('friends_list', friends);
            }
        });
    });

    // Evento: Solicitar clave pública (modificado para trabajar con amigos)
    socket.on('request_public_key', (targetUsername) => {
        console.log(`${socket.user.username} solicita clave pública de ${targetUsername}.`);
        
        // Verificar que son amigos
        const currentUser = socket.user.username;
        db.get(`
            SELECT * FROM friendships 
            WHERE (user1_username = ? AND user2_username = ?) 
            OR (user1_username = ? AND user2_username = ?)
        `, [currentUser, targetUsername, targetUsername, currentUser], (err, friendship) => {
            if (err) {
                console.error('Error al verificar amistad:', err.message);
                socket.emit('error_message', 'Error al verificar amistad.');
                return;
            }

            if (!friendship) {
                socket.emit('error_message', `No eres amigo de ${targetUsername}.`);
                return;
            }

            // Obtener clave pública
            db.get('SELECT publicKey FROM users WHERE username = ?', [targetUsername], (err, row) => {
                if (err) {
                    console.error(`Error DB al obtener clave pública para ${targetUsername}:`, err.message);
                    socket.emit('error_message', `Error al obtener clave pública para ${targetUsername}.`);
                    return;
                }
                if (row && row.publicKey) {
                    console.log(`Clave pública de ${targetUsername} encontrada. Enviando a ${socket.user.username}.`);
                    socket.emit('receive_public_key', { username: targetUsername, publicKey: row.publicKey });
                } else {
                    console.warn(`Clave pública no encontrada para ${targetUsername}.`);
                    socket.emit('error_message', `Clave pública no encontrada para ${targetUsername}.`);
                }
            });
        });
    });

    // Evento: Obtener historial de chat
    socket.on('get_chat_history', (friendUsername) => {
        const currentUser = socket.user.username;
        const chatId = generateChatId(currentUser, friendUsername);

        // Verificar amistad antes de obtener historial
        db.get(`
            SELECT * FROM friendships 
            WHERE (user1_username = ? AND user2_username = ?) 
            OR (user1_username = ? AND user2_username = ?)
        `, [currentUser, friendUsername, friendUsername, currentUser], (err, friendship) => {
            if (err || !friendship) {
                socket.emit('error_message', 'No tienes acceso a este chat.');
                return;
            }

            // Obtener mensajes del chat
            db.all(`
                SELECT * FROM messages 
                WHERE chat_id = ? 
                ORDER BY timestamp ASC 
                LIMIT 50
            `, [chatId], (err, messages) => {
                if (err) {
                    console.error('Error al obtener historial de chat:', err.message);
                    socket.emit('chat_history', []);
                } else {
                    socket.emit('chat_history', messages);
                }
            });
        });
    });

    // Evento: Mensaje privado (modificado para incluir chat_id)
    socket.on('private_message', async (data) => {
        const { receiver, encryptedMessage, iv } = data;
        const sender = socket.user.username;
        const chatId = generateChatId(sender, receiver);

        console.log(`Recibido private_message de ${sender} para ${receiver}. IV: ${iv}`);

        // Verificar amistad
        db.get(`
            SELECT * FROM friendships 
            WHERE (user1_username = ? AND user2_username = ?) 
            OR (user1_username = ? AND user2_username = ?)
        `, [sender, receiver, receiver, sender], (err, friendship) => {
            if (err || !friendship) {
                socket.emit('error_message', 'No puedes enviar mensajes a este usuario.');
                return;
            }

            // Enviar mensaje si el receptor está online
            if (connectedUsers[receiver]) {
                io.to(connectedUsers[receiver]).emit('private_message', {
                    sender: sender,
                    encryptedMessage: encryptedMessage,
                    iv: iv,
                    chatId: chatId
                });
                console.log(`Mensaje reenviado de ${sender} a ${receiver} (online).`);
            }

            // Guardar mensaje en la base de datos
            db.run('INSERT INTO messages (chat_id, sender, receiver, encryptedMessage, iv) VALUES (?, ?, ?, ?, ?)',
                [chatId, sender, receiver, encryptedMessage, iv], function(err) {
                if (err) {
                    console.error('Error al guardar mensaje en DB:', err.message);
                } else {
                    console.log(`Mensaje guardado en DB (ID: ${this.lastID}).`);
                }
            });
        });
    });

    // Evento: Desconexión
    socket.on('disconnect', () => {
        console.log(`Usuario desconectado: ${socket.user.username} (ID: ${socket.id})`);
        delete connectedUsers[socket.user.username];
        io.emit('online_users', Object.keys(connectedUsers));
        
        // Actualizar estado offline para amigos
        io.emit('user_offline', socket.user.username);
    });
});

// Iniciar servidor HTTPS
server.listen(port, () => {
    console.log(`Servidor HTTPS escuchando en https://localhost:${port}`);
    console.log(`Accede a la aplicación en tu navegador vía HTTPS para que la criptografía funcione.`);
    console.log(`Si estás en otra máquina, usa https://[TU_IP_LOCAL]:${port}`);
    console.log(`Recuerda aceptar la advertencia de seguridad del navegador por el certificado autofirmado.`);
});