const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();

// Configuración de middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.static('.'));
app.use(session({
    secret: 'argentina_corrupta_secret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));
app.use(passport.initialize());
app.use(passport.session());

// Configuración de nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'argentinacorrupta.soporte@gmail.com',
        pass: 'Joaco51016'
    }
});

// Configuración de Passport Google
passport.use(new GoogleStrategy({
    clientID: "848040731600-jsrflhafv0npm6kvmsmu5qstr7iocamp.apps.googleusercontent.com",
    clientSecret: "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",
    callbackURL: "http://localhost:3000/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const userData = readUsers();
        let user = userData.users.find(u => u.email === profile.emails[0].value);

        if (!user) {
            user = {
                id: Date.now().toString(),
                username: profile.displayName,
                email: profile.emails[0].value,
                password: crypto.randomBytes(16).toString('hex'),
                rank: 'user',
                createdAt: new Date().toISOString(),
                description: '',
                avatarUrl: profile.photos[0].value,
                isAdmin: false,
                emailVerified: true,
                birthDate: null,
                googleId: profile.id
            };
            userData.users.push(user);
            writeUsers(userData);
        }

        return done(null, user);
    } catch (error) {
        return done(error, null);
    }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
    const userData = readUsers();
    const user = userData.users.find(u => u.id === id);
    done(null, user);
});

// Funciones auxiliares
function readUsers() {
    try {
        const data = fs.readFileSync(path.join(__dirname, 'users.json'), 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return { users: [] };
    }
}

function writeUsers(users) {
    fs.writeFileSync(
        path.join(__dirname, 'users.json'),
        JSON.stringify(users, null, 2),
        'utf8'
    );
}

async function sendVerificationEmail(email, token) {
    const verificationLink = `http://localhost:3000/verify-email?token=${token}`;
    
    await transporter.sendMail({
        from: 'argentinacorrupta.soporte@gmail.com',
        to: email,
        subject: 'Verifica tu cuenta en Argentina Corrupta',
        html: `
            <h1>Bienvenido a Argentina Corrupta</h1>
            <p>Por favor, verifica tu cuenta haciendo clic en el siguiente enlace:</p>
            <a href="${verificationLink}">Verificar cuenta</a>
        `
    });
}

async function sendPasswordResetEmail(email, token) {
    const resetLink = `http://localhost:3000/reset-password?token=${token}`;
    
    await transporter.sendMail({
        from: 'argentinacorrupta.soporte@gmail.com',
        to: email,
        subject: 'Recuperación de contraseña - Argentina Corrupta',
        html: `
            <h1>Recuperación de contraseña</h1>
            <p>Has solicitado restablecer tu contraseña. Haz clic en el siguiente enlace:</p>
            <a href="${resetLink}">Restablecer contraseña</a>
            <p>Este enlace expirará en 1 hora.</p>
        `
    });
}

// Rutas de autenticación con Google
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        res.redirect('/forum.html');
    }
);

// Ruta de registro
app.post('/register', async (req, res) => {
    const { username, email, password, birthDate } = req.body;
    const userData = readUsers();

    if (userData.users.some(user => user.username === username || user.email === email)) {
        return res.status(400).json({
            success: false,
            message: 'El usuario o email ya está registrado'
        });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(32).toString('hex');

    const newUser = {
        id: Date.now().toString(),
        username,
        email,
        password: hashedPassword,
        rank: 'user',
        createdAt: new Date().toISOString(),
        description: '',
        avatarUrl: '',
        isAdmin: false,
        emailVerified: false,
        birthDate,
        verificationToken
    };

    userData.users.push(newUser);
    writeUsers(userData);

    try {
        await sendVerificationEmail(email, verificationToken);
        res.json({
            success: true,
            message: 'Usuario registrado. Por favor, verifica tu correo electrónico.'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Registrado con exito, No se pudo verificar tu correo electronico, Contacta a administracion'
        });
    }
});

// Ruta de verificación de email
app.get('/verify-email', (req, res) => {
    const { token } = req.query;
    const userData = readUsers();
    const user = userData.users.find(u => u.verificationToken === token);

    if (user) {
        user.emailVerified = true;
        user.verificationToken = undefined;
        writeUsers(userData);
        res.redirect('/login.html?verified=true');
    } else {
        res.status(400).send('Token de verificación inválido');
    }
});

// Ruta de login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const userData = readUsers();
    const user = userData.users.find(u => u.username === username);

    if (user && await bcrypt.compare(password, user.password)) {
        //if (!user.emailVerified) {
          //  return res.status(401).json({
            //    success: false,
             //   message: 'Por favor, verifica tu correo electrónico antes de iniciar sesión'
          //  });
       // }

        req.session.user = {
            id: user.id,
            username: user.username,
            rank: user.rank,
            isAdmin: user.isAdmin
        };

        res.cookie('username', user.username, {
            maxAge: 24 * 60 * 60 * 1000,
            path: '/',
            httpOnly: false,
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

// Ruta para solicitar restablecimiento de contraseña
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const userData = readUsers();
    const user = userData.users.find(u => u.email === email);

    if (!user) {
        return res.status(404).json({
            success: false,
            message: 'No existe una cuenta con ese correo electrónico'
        });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hora

    user.resetToken = resetToken;
    user.resetTokenExpiry = resetTokenExpiry;
    writeUsers(userData);

    try {
        await sendPasswordResetEmail(email, resetToken);
        res.json({
            success: true,
            message: 'Se ha enviado un correo con las instrucciones para restablecer tu contraseña'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error al enviar el correo de recuperación'
        });
    }
});

// Ruta para restablecer contraseña
app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    const userData = readUsers();
    const user = userData.users.find(u => 
        u.resetToken === token && 
        u.resetTokenExpiry > Date.now()
    );

    if (!user) {
        return res.status(400).json({
            success: false,
            message: 'Token inválido o expirado'
        });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    writeUsers(userData);

    res.json({
        success: true,
        message: 'Contraseña actualizada correctamente'
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
});