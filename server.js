const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.static('.'));
app.use(session({
    secret: 'argentina_corrupta_secret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// Función para leer users.json
function readUsers() {
    try {
        const data = fs.readFileSync(path.join(__dirname, 'users.json'), 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return { users: [] };
    }
}

// Función para escribir en users.json
function writeUsers(users) {
    fs.writeFileSync(
        path.join(__dirname, 'users.json'),
        JSON.stringify(users, null, 2),
        'utf8'
    );
}

// Ruta de registro
app.post('/register', (req, res) => {
    const { username, email, password } = req.body;
    const userData = readUsers();

    // Verificar si el usuario ya existe
    if (userData.users.some(user => user.username === username || user.email === email)) {
        return res.status(400).json({
            success: false,
            message: 'El usuario o email ya está registrado'
        });
    }

    // Crear nuevo usuario
    const newUser = {
        id: Date.now().toString(),
        username,
        email,
        password, // En producción, esto debería estar hasheado
        rank: 'user',
        createdAt: new Date().toISOString(),
        description: '',
        avatarUrl: '',
        isAdmin: false
    };

    userData.users.push(newUser);
    writeUsers(userData);

    res.json({
        success: true,
        message: 'Usuario registrado exitosamente'
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const userData = readUsers();
    const user = userData.users.find(u => 
        u.username === username && u.password === password
    );

    if (user) {
        // Crear sesión
        req.session.user = {
            id: user.id,
            username: user.username,
            rank: user.rank,
            isAdmin: user.isAdmin
        };

        // Establecer cookies
        res.cookie('username', user.username, { 
            maxAge: 24 * 60 * 60 * 1000,
            path: '/',
            httpOnly: false, // Cambiado a false para que JavaScript pueda acceder
            sameSite: 'lax'
        });

        if (user.isAdmin) {
            res.cookie('isAdmin', 'true', {
                maxAge: 24 * 60 * 60 * 1000,
                path: '/',
                httpOnly: false,
                sameSite: 'lax'
            });
        }

        res.json({
            success: true,
            user: {
                username: user.username,
                rank: user.rank,
                isAdmin: user.isAdmin
            }
        });
    } else {
        res.status(401).json({
            success: false,
            message: 'Usuario o contraseña incorrectos'
        });
    }
});

// Ruta para obtener información del usuario
app.get('/user/:username', (req, res) => {
    const { username } = req.params;
    const userData = readUsers();
    const user = userData.users.find(u => u.username === username);

    if (user) {
        const publicUserData = {
            username: user.username,
            rank: user.rank,
            createdAt: user.createdAt,
            description: user.description,
            avatarUrl: user.avatarUrl
        };
        res.json(publicUserData);
    } else {
        res.status(404).json({
            success: false,
            message: 'Usuario no encontrado'
        });
    }
});

// Ruta para actualizar perfil
app.put('/user/update', (req, res) => {
    const { description, avatarUrl } = req.body;
    const username = req.cookies.username;

    if (!username) {
        return res.status(401).json({
            success: false,
            message: 'No autorizado'
        });
    }

    const userData = readUsers();
    const userIndex = userData.users.findIndex(u => u.username === username);

    if (userIndex !== -1) {
        userData.users[userIndex] = {
            ...userData.users[userIndex],
            description,
            avatarUrl
        };

        writeUsers(userData);

        res.json({
            success: true,
            message: 'Perfil actualizado correctamente'
        });
    } else {
        res.status(404).json({
            success: false,
            message: 'Usuario no encontrado'
        });
    }
});

// Ruta para cerrar sesión
app.post('/logout', (req, res) => {
    req.session.destroy();
    res.clearCookie('username');
    res.json({
        success: true,
        message: 'Sesión cerrada correctamente'
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
});