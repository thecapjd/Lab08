// public/client.js

let authToken = null;
let socket = null;
let currentUser = null;

const authSection = document.getElementById('auth-section');
const chatSection = document.getElementById('chat-section');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const registerBtn = document.getElementById('register-btn');
const loginBtn = document.getElementById('login-btn');
const authMessage = document.getElementById('auth-message');
const currentUserSpan = document.getElementById('current-user');
const onlineUsersSpan = document.getElementById('online-users');

const searchUsersInput = document.getElementById('search-users');
const searchResultsDiv = document.getElementById('search-results');
const friendRequestsList = document.getElementById('friend-requests-list');
const friendsList = document.getElementById('friends-list');

const noChatSelected = document.getElementById('no-chat-selected');
const activeChat = document.getElementById('active-chat');
const chatPartnerSpan = document.getElementById('chat-partner');
const messagesDiv = document.getElementById('messages');
const messageInput = document.getElementById('message-input');
const sendMessageBtn = document.getElementById('send-message-btn');
const clearChatBtn = document.getElementById('clear-chat-btn');
const closeChatBtn = document.getElementById('close-chat-btn');

let currentChatPartner = null;
let rsaKeyPair = null;
let activeChatKeys = {};
let chatHistories = {};
let friendsData = {};
let keyExchangeInProgress = {};
let connectionRetries = 0;
const MAX_RETRIES = 3;

if (typeof window.crypto === 'undefined' || typeof window.crypto.subtle === 'undefined') {
    console.error("Web Crypto API no disponible");
    alert("Tu navegador no soporta la API de Criptografía Web. La aplicación no funcionará correctamente.");
}

async function generateRsaKeyPair() {
    if (!window.crypto || !window.crypto.subtle) {
        throw new Error("crypto.subtle no disponible");
    }
    rsaKeyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
    const publicKeyPem = await exportPublicKeyAsPem(rsaKeyPair.publicKey);
    return publicKeyPem;
}

async function exportPublicKeyAsPem(publicKey) {
    const spki = await window.crypto.subtle.exportKey("spki", publicKey);
    const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
    const pem = `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
    return pem;
}

async function importPublicKeyFromPem(pem) {
    const b64 = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n/g, '');
    const binaryDer = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return window.crypto.subtle.importKey(
        "spki",
        binaryDer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        true,
        ["encrypt", "wrapKey"]
    );
}

async function generateAesKey() {
    return window.crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256,
        },
        true,
        ["encrypt", "decrypt"]
    );
}

async function encryptAes(text, key) {
    const encoded = new TextEncoder().encode(text);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        encoded
    );
    return {
        encryptedMessage: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
        iv: btoa(String.fromCharCode(...new Uint8Array(iv)))
    };
}

async function decryptAes(encryptedBase64, ivBase64, key) {
    try {
        const encrypted = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
        const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));

        const decrypted = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv,
            },
            key,
            encrypted
        );
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        console.error("Error al descifrar:", e);
        return "[MENSAJE NO DESCIFRADO]";
    }
}

async function wrapAesKey(aesKeyToWrap, publicKeyRsa) {
    const wrappedKey = await window.crypto.subtle.wrapKey(
        "raw",
        aesKeyToWrap,
        publicKeyRsa,
        {
            name: "RSA-OAEP"
        }
    );
    return btoa(String.fromCharCode(...new Uint8Array(wrappedKey)));
}

async function unwrapAesKey(wrappedAesKeyBase64, privateKeyRsa) {
    const wrappedKey = Uint8Array.from(atob(wrappedAesKeyBase64), c => c.charCodeAt(0));
    return window.crypto.subtle.unwrapKey(
        "raw",
        wrappedKey,
        privateKeyRsa,
        {
            name: "RSA-OAEP",
        },
        {
            name: "AES-GCM",
            length: 256,
        },
        true,
        ["encrypt", "decrypt"]
    );
}

function showAuthSection() {
    authSection.style.display = 'block';
    chatSection.style.display = 'none';
}

function showChatSection() {
    authSection.style.display = 'none';
    chatSection.style.display = 'block';
}

function displayAuthMessage(message, isError = true) {
    authMessage.textContent = message;
    authMessage.style.color = isError ? '#e06c75' : '#98c379';
}

function appendMessage(sender, message, isSentByMe, isSystem = false) {
    const msgElem = document.createElement('div');
    msgElem.classList.add('message-item');
    
    if (isSystem) {
        msgElem.classList.add('system');
        msgElem.textContent = message;
    } else {
        msgElem.classList.add(isSentByMe ? 'sent' : 'received');
        msgElem.textContent = `${sender}: ${message}`;
    }
    
    messagesDiv.appendChild(msgElem);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function clearMessages() {
    messagesDiv.innerHTML = '';
}

function enableChatInput(enable) {
    messageInput.disabled = !enable;
    sendMessageBtn.disabled = !enable;
    if (enable) {
        messageInput.focus();
    }
}

function showChat(friendUsername) {
    currentChatPartner = friendUsername;
    chatPartnerSpan.textContent = friendUsername;
    noChatSelected.style.display = 'none';
    activeChat.style.display = 'flex';
    
    updateFriendsListUI();
    
    if (!activeChatKeys[friendUsername]) {
        if (keyExchangeInProgress[friendUsername]) {
            enableChatInput(false);
            return;
        }
        
        enableChatInput(false);
        clearMessages();
        appendMessage('Sistema', `Estableciendo conexión segura...`, false, true);
        keyExchangeInProgress[friendUsername] = true;
        
        setTimeout(() => {
            if (socket && socket.connected) {
                requestPublicKey(friendUsername);
            } else {
                appendMessage('Sistema', 'Error de conexión. Reconectando...', false, true);
                initializeSocket();
            }
        }, 500);
    } else {
        loadChatHistory(friendUsername);
        enableChatInput(true);
    }
}

function closeChat() {
    if (currentChatPartner) {
        keyExchangeInProgress[currentChatPartner] = false;
    }
    currentChatPartner = null;
    noChatSelected.style.display = 'block';
    activeChat.style.display = 'none';
    clearMessages();
    updateFriendsListUI();
}

function loadChatHistory(friendUsername) {
    clearMessages();
    
    if (socket && socket.connected && activeChatKeys[friendUsername]) {
        socket.emit('get_chat_history', friendUsername);
    }
}

function requestPublicKey(targetUsername) {
    if (socket && socket.connected) {
        console.log(`Solicitando clave pública de ${targetUsername}`);
        socket.emit('request_public_key', targetUsername);
    } else {
        console.error('Socket no conectado');
        appendMessage('Sistema', 'Error de conexión', false, true);
        keyExchangeInProgress[targetUsername] = false;
    }
}

function renderSearchResults(users) {
    searchResultsDiv.innerHTML = '';
    users.forEach(username => {
        const item = document.createElement('div');
        item.className = 'search-result-item';
        item.innerHTML = `
            <span>${username}</span>
            <button class="add-friend-btn" onclick="sendFriendRequest('${username}')">
                Agregar
            </button>
        `;
        searchResultsDiv.appendChild(item);
    });
}

function sendFriendRequest(targetUsername) {
    if (socket && socket.connected) {
        socket.emit('send_friend_request', targetUsername);
    }
}

function renderFriendRequests(requests) {
    friendRequestsList.innerHTML = '';
    requests.forEach(request => {
        const item = document.createElement('div');
        item.className = 'friend-request-item';
        item.innerHTML = `
            <div class="friend-name">${request.requester_username}</div>
            <div class="friend-actions">
                <button class="accept-btn" onclick="respondFriendRequest(${request.id}, true)">
                    Aceptar
                </button>
                <button class="reject-btn" onclick="respondFriendRequest(${request.id}, false)">
                    Rechazar
                </button>
            </div>
        `;
        friendRequestsList.appendChild(item);
    });
}

function respondFriendRequest(requestId, accept) {
    if (socket && socket.connected) {
        socket.emit('respond_friend_request', { requestId, accept });
    }
}

function renderFriendsList(friends) {
    friendsData = {};
    friends.forEach(friend => {
        friendsData[friend.username] = friend;
    });
    updateFriendsListUI();
}

function updateFriendsListUI() {
    friendsList.innerHTML = '';
    Object.values(friendsData).forEach(friend => {
        const item = document.createElement('div');
        item.className = `friend-item ${friend.isOnline ? 'online' : 'offline'}`;
        
        if (currentChatPartner === friend.username) {
            item.classList.add('active');
        }
        
        item.innerHTML = `
            <div class="friend-name">${friend.username}</div>
            <div class="friend-status ${friend.isOnline ? 'online' : 'offline'}">
                ${friend.isOnline ? 'En línea' : 'Desconectado'}
            </div>
        `;
        
        item.addEventListener('click', () => {
            showChat(friend.username);
        });
        
        friendsList.appendChild(item);
    });
}

registerBtn.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    
    if (!username || !password) {
        displayAuthMessage('Usuario y contraseña requeridos', true);
        return;
    }
    
    try {
        const response = await fetch('/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();
        displayAuthMessage(data.message, !response.ok);
    } catch (error) {
        displayAuthMessage('Error al registrarse', true);
    }
});

loginBtn.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    
    if (!username || !password) {
        displayAuthMessage('Usuario y contraseña requeridos', true);
        return;
    }
    
    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();
        if (response.ok) {
            authToken = data.token;
            currentUser = username;
            currentUserSpan.textContent = currentUser;
            showChatSection();
            
            try {
                await generateRsaKeyPair();
                initializeSocket();
            } catch (cryptoError) {
                displayAuthMessage("Error de criptografía: " + cryptoError.message, true);
                return;
            }
            
            displayAuthMessage(data.message, false);
        } else {
            displayAuthMessage(data.message, true);
        }
    } catch (error) {
        displayAuthMessage('Error al iniciar sesión', true);
    }
});

function initializeSocket() {
    if (socket) {
        socket.disconnect();
        socket = null;
    }

    connectionRetries = 0;
    connectSocket();
}

function connectSocket() {
    socket = io({
        auth: {
            token: authToken
        },
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000
    });

    socket.on('connect', async () => {
        console.log('Socket conectado');
        connectionRetries = 0;
        
        if (!rsaKeyPair || !rsaKeyPair.publicKey) {
            try {
                await generateRsaKeyPair();
            } catch (e) {
                console.error('Error generando claves:', e);
                return;
            }
        }
        
        try {
            const pem = await exportPublicKeyAsPem(rsaKeyPair.publicKey);
            socket.emit('send_public_key', pem);
        } catch (e) {
            console.error('Error enviando clave:', e);
        }
        
        setTimeout(() => {
            socket.emit('get_friend_requests');
            socket.emit('get_friends_list');
        }, 300);
    });

    socket.on('connect_error', (error) => {
        console.error('Error de conexión:', error);
        connectionRetries++;
        
        if (connectionRetries < MAX_RETRIES) {
            setTimeout(() => {
                console.log(`Reintentando conexión (${connectionRetries}/${MAX_RETRIES})`);
                connectSocket();
            }, 2000 * connectionRetries);
        } else {
            appendMessage('Sistema', 'Error de conexión persistente. Recarga la página.', false, true);
        }
    });

    socket.on('online_users', (users) => {
        const filteredUsers = users.filter(user => user !== currentUser);
        onlineUsersSpan.textContent = filteredUsers.join(', ');
        
        Object.keys(friendsData).forEach(friendUsername => {
            friendsData[friendUsername].isOnline = users.includes(friendUsername);
        });
        updateFriendsListUI();
    });

    socket.on('search_results', (users) => {
        renderSearchResults(users);
    });

    socket.on('friend_request_sent', (targetUsername) => {
        appendMessage('Sistema', `Solicitud enviada a ${targetUsername}`, false, true);
        searchResultsDiv.innerHTML = '';
        searchUsersInput.value = '';
    });

    socket.on('friend_request_received', (data) => {
        appendMessage('Sistema', `${data.requester} te envió solicitud`, false, true);
        socket.emit('get_friend_requests');
    });

    socket.on('friend_requests_list', (requests) => {
        renderFriendRequests(requests);
    });

    socket.on('friend_request_accepted', (friendUsername) => {
        appendMessage('Sistema', `Ahora eres amigo de ${friendUsername}`, false, true);
        socket.emit('get_friends_list');
        socket.emit('get_friend_requests');
    });

    socket.on('friend_request_rejected', () => {
        socket.emit('get_friend_requests');
    });

    socket.on('friend_request_response', (data) => {
        const message = data.accepted 
            ? `${data.user} aceptó tu solicitud`
            : `${data.user} rechazó tu solicitud`;
        appendMessage('Sistema', message, false, true);
        
        if (data.accepted) {
            socket.emit('get_friends_list');
        }
    });

    socket.on('friends_list', (friends) => {
        renderFriendsList(friends);
    });

    socket.on('user_offline', (username) => {
        if (friendsData[username]) {
            friendsData[username].isOnline = false;
            updateFriendsListUI();
        }
    });

    socket.on('receive_public_key', async (data) => {
        const { username, publicKey } = data;
        console.log(`Clave pública recibida de ${username}`);
        
        if (username === currentChatPartner) {
            if (!publicKey) {
                appendMessage('Sistema', `Error: Clave pública vacía de ${username}`, false, true);
                keyExchangeInProgress[username] = false;
                enableChatInput(false);
                return;
            }

            try {
                const importedPublicKey = await importPublicKeyFromPem(publicKey);
                const aesKey = await generateAesKey();
                activeChatKeys[username] = aesKey;

                const wrappedAesKey = await wrapAesKey(aesKey, importedPublicKey);

                socket.emit('private_message', {
                    receiver: currentChatPartner,
                    encryptedMessage: wrappedAesKey,
                    iv: 'KEY_EXCHANGE'
                });
                
                appendMessage('Sistema', `Conexión segura establecida`, false, true);
                keyExchangeInProgress[username] = false;
                enableChatInput(true);
                
                // Cargar historial después de establecer la clave
                setTimeout(() => {
                    loadChatHistory(username);
                }, 100);
                
            } catch (e) {
                console.error('Error en intercambio:', e);
                appendMessage('Sistema', `Error estableciendo chat seguro: ${e.message}`, false, true);
                keyExchangeInProgress[username] = false;
                enableChatInput(false);
            }
        }
    });

    socket.on('private_message', async (data) => {
        const { sender, encryptedMessage, iv } = data;

        if (iv === 'KEY_EXCHANGE') {
            if (friendsData[sender]) {
                try {
                    const aesKey = await unwrapAesKey(encryptedMessage, rsaKeyPair.privateKey);
                    activeChatKeys[sender] = aesKey;
                    keyExchangeInProgress[sender] = false;
                    
                    if (currentChatPartner === sender) {
                        appendMessage('Sistema', `Conexión segura establecida`, false, true);
                        enableChatInput(true);
                        // Cargar historial después de recibir la clave
                        setTimeout(() => {
                            loadChatHistory(sender);
                        }, 100);
                    }
                } catch (e) {
                    console.error('Error descifrado clave:', e);
                    keyExchangeInProgress[sender] = false;
                    if (currentChatPartner === sender) {
                        appendMessage('Sistema', `Error en chat seguro`, false, true);
                        enableChatInput(false);
                    }
                }
            }
            return;
        }

        if (friendsData[sender] && activeChatKeys[sender]) {
            try {
                const decryptedMessage = await decryptAes(encryptedMessage, iv, activeChatKeys[sender]);
                
                if (currentChatPartner === sender) {
                    appendMessage(sender, decryptedMessage, false);
                }
            } catch (e) {
                console.error('Error descifrado mensaje:', e);
                if (currentChatPartner === sender) {
                    appendMessage(sender, '[ERROR DESCIFRADO]', false);
                }
            }
        }
    });

    socket.on('chat_history', async (messages) => {
        if (!currentChatPartner) return;
        
        console.log(`Recibido historial de ${messages.length} mensajes para ${currentChatPartner}`);
        
        // Primero limpiar mensajes del sistema (excepto el de conexión establecida)
        const systemMessages = Array.from(messagesDiv.querySelectorAll('.system'));
        systemMessages.forEach(msg => {
            if (!msg.textContent.includes('Conexión segura establecida')) {
                msg.remove();
            }
        });
        
        const aesKey = activeChatKeys[currentChatPartner];
        if (!aesKey) {
            console.log('No hay clave AES para descifrar historial');
            return;
        }
        
        for (const msg of messages) {
            if (msg.iv === 'KEY_EXCHANGE') continue;
            
            try {
                const decryptedMessage = await decryptAes(msg.encryptedMessage, msg.iv, aesKey);
                const isSentByMe = msg.sender === currentUser;
                appendMessage(msg.sender, decryptedMessage, isSentByMe);
            } catch (e) {
                console.error('Error descifrando mensaje del historial:', e);
                appendMessage(msg.sender, '[ERROR DESCIFRADO]', msg.sender === currentUser);
            }
        }
    });

    socket.on('error_message', (message) => {
        console.error('Error servidor:', message);
        appendMessage('Sistema', `Error: ${message}`, false, true);
        
        if (message.includes('clave pública')) {
            setTimeout(async () => {
                if (rsaKeyPair && rsaKeyPair.publicKey) {
                    try {
                        const pem = await exportPublicKeyAsPem(rsaKeyPair.publicKey);
                        socket.emit('send_public_key', pem);
                    } catch (e) {
                        console.error('Error reenvío clave:', e);
                    }
                }
            }, 1000);
        }
    });

    socket.on('disconnect', (reason) => {
        console.log('Socket desconectado:', reason);
        
        Object.keys(keyExchangeInProgress).forEach(user => {
            keyExchangeInProgress[user] = false;
        });
        
        if (currentChatPartner) {
            enableChatInput(false);
        }
        
        if (reason === 'io server disconnect') {
            setTimeout(() => {
                if (authToken) {
                    connectSocket();
                }
            }, 2000);
        }
    });

    socket.on('reconnect', () => {
        console.log('Socket reconectado');
        if (currentChatPartner && !activeChatKeys[currentChatPartner]) {
            showChat(currentChatPartner);
        } else if (currentChatPartner && activeChatKeys[currentChatPartner]) {
            // Si ya tenemos la clave, solo recargar el historial
            loadChatHistory(currentChatPartner);
        }
    });
}

searchUsersInput.addEventListener('input', (e) => {
    const searchTerm = e.target.value.trim();
    if (searchTerm.length >= 2) {
        if (socket && socket.connected) {
            socket.emit('search_users', searchTerm);
        }
    } else {
        searchResultsDiv.innerHTML = '';
    }
});

sendMessageBtn.addEventListener('click', async () => {
    const message = messageInput.value.trim();
    if (message && currentChatPartner && activeChatKeys[currentChatPartner]) {
        try {
            const { encryptedMessage, iv } = await encryptAes(message, activeChatKeys[currentChatPartner]);
            socket.emit('private_message', {
                receiver: currentChatPartner,
                encryptedMessage: encryptedMessage,
                iv: iv
            });
            appendMessage(currentUser, message, true);
            messageInput.value = '';
        } catch (e) {
            appendMessage('Sistema', `Error enviando: ${e.message}`, false, true);
        }
    } else if (!activeChatKeys[currentChatPartner]) {
        appendMessage('Sistema', 'Conexión segura no establecida', false, true);
    }
});

messageInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        sendMessageBtn.click();
    }
});

clearChatBtn.addEventListener('click', () => {
    clearMessages();
    appendMessage('Sistema', 'Chat limpiado', false, true);
});

closeChatBtn.addEventListener('click', () => {
    closeChat();
});

document.addEventListener('DOMContentLoaded', () => {
    let logoutBtn = document.getElementById('logout-btn');
    if (!logoutBtn) {
        logoutBtn = document.createElement('button');
        logoutBtn.id = 'logout-btn';
        logoutBtn.className = 'logout-btn';
        logoutBtn.textContent = 'Cerrar Sesión';
        document.querySelector('.header').appendChild(logoutBtn);
    }
    
    logoutBtn.addEventListener('click', () => {
        if (socket) {
            socket.disconnect();
        }
        
        authToken = null;
        currentUser = null;
        currentChatPartner = null;
        rsaKeyPair = null;
        activeChatKeys = {};
        chatHistories = {};
        friendsData = {};
        keyExchangeInProgress = {};
        
        usernameInput.value = '';
        passwordInput.value = '';
        searchUsersInput.value = '';
        messageInput.value = '';
        clearMessages();
        searchResultsDiv.innerHTML = '';
        friendRequestsList.innerHTML = '';
        friendsList.innerHTML = '';
        
        showAuthSection();
        displayAuthMessage('Sesión cerrada', false);
    });
});

window.sendFriendRequest = sendFriendRequest;
window.respondFriendRequest = respondFriendRequest;

showAuthSection();