require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
// const db = require('./db'); // Koneksi ke database

const chromium = require('chrome-aws-lambda');
const puppeteer = require('puppeteer-core');

const app = express();
const PORT = 3000;

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

app.use(bodyParser.json());

// Middleware untuk memverifikasi API secret dan JWT token
function verifyApiSecret(req, res, next) {
    const apiSecret = req.headers['x-api-secret'];
    const token = req.headers['authorization']?.split(' ')[1]; // Bearer token

    if (apiSecret && apiSecret === process.env.API_SECRET) {
        if (token) {
            jwt.verify(token, JWT_SECRET, (err, user) => {
                if (err) return res.status(403).json({ error: 'Invalid token' });
                req.user = user;
                next();
            });
        } else {
            res.status(403).json({ error: 'Token required' });
        }
    } else {
        res.status(403).json({ error: 'Forbidden: Invalid API Secret' });
    }
}

function sanitizeClientId(email) {
    // Replace invalid characters with underscores or remove them
    return email.replace(/[^a-zA-Z0-9_-]/g, '_');
}

// Menyimpan klien untuk setiap pengguna
const clients = {};

// Fungsi untuk mengecek apakah sesi ada atau tidak
function sessionExists(email) {
    const sessionPath = path.join('/tmp', 'sessions', email);
    return fs.existsSync(sessionPath);
}

// Fungsi untuk membuat klien baru untuk setiap pengguna
function createClientForUser(email, res) {
    const sanitizedEmail = sanitizeClientId(email);

    const executablePath = await chromium.executablePath;

    const client = new Client({
        authStrategy: new LocalAuth({
            clientId: sanitizedEmail,
            dataPath: path.join('/tmp', 'sessions'),
        }),
        puppeteer: {
            args: [...chromium.args],
            executablePath, // ✅ sudah berupa string
            headless: true,
        },
    });

    let latestQr = null;

    client.on('qr', (qr) => {
        latestQr = qr;
        qrcode.toDataURL(qr, (err, url) => {
            if (err) {
                console.error('Error generating QR code:', err);
                res.status(500).json({ status: 'Error', message: 'Error generating QR code' });
            } else {
                res.json({ status: 'QR Code Generated', qrCodeUrl: url });
            }
        });
    });

    client.on('ready', () => {
        console.log(`Client untuk user ${email} siap!`);
        clients[email] = client;
        res.json({ status: 'Client Ready' });
    });

    client.on('authenticated', () => {
        console.log(`User ${email} terautentikasi.`);
    });

    client.on('auth_failure', msg => {
        console.error(`Autentikasi gagal untuk user ${email}: `, msg);
        res.json({ status: 'Auth Failure', message: msg });
    });

    client.on('disconnected', (reason) => {
        console.log(`Client untuk user ${email} terputus: `, reason);
        res.json({ status: 'Disconnected', reason });
        delete clients[email];
    });

    client.initialize();

    return client;
}

// Route untuk mengecek apakah sesi ada atau tidak
app.post('/session-exists', (req, res) => {
    const { email } = req.body;
    const exists = sessionExists(email);
    res.json({ status: exists ? 'Session exists' : 'Session does not exist' });
});

// Register Endpoint
app.post('/register', (req, res) => {
    const { name, email, password } = req.body;

    // Hash password
    const hashedPassword = bcrypt.hashSync(password, 8);

    db.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashedPassword], (err, results) => {
        if (err) {
            console.error('Error during database query: ', err);
            res.status(500).json({ error: 'Database query error' });
            return;
        }
        res.json({ status: 'User Registered', email });
    });
});

// Login Endpoint
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    // db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    //     if (err) {
    //         console.error('Error during database query: ', err);
    //         res.status(500).json({ error: 'Database query error' });
    //         return;
    //     }

    //     if (results.length === 0) {
    //         return res.status(401).json({ error: 'Invalid email or password' });
    //     }

    //     const user = results[0];

    //     // Verify password
    //     const passwordIsValid = bcrypt.compareSync(password, user.password);
    //     if (!passwordIsValid) {
    //         return res.status(401).json({ error: 'Invalid email or password' });
    //     }

    //     // Create JWT token
    //     const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
    //         expiresIn: '1h', // Token valid for 1 hour
    //     });

    //     res.json({ status: 'Login Successful', token });
    // });

    if (email == 'admin@mail.com' && password == 'P@ssw0rdLuqni') {
        const token = jwt.sign({ id: 1, email: email }, JWT_SECRET, {
            expiresIn: '1h', // Token valid for 1 hour
        });

        res.json({ status: 'Login Successful', token });
    }


});

// Endpoint untuk membuat klien baru
app.post('/create-client', verifyApiSecret, (req, res) => {
    const { email } = req.body;
    if (clients[email]) {
        return res.status(200).json({ status: 'Client already exists' });
    }
    createClientForUser(email, res);
});

// Endpoint untuk mengirim pesan, dilindungi oleh JWT
app.post('/send-message', verifyApiSecret, (req, res) => {
    const { email, to, message } = req.body;

    if (!clients[email]) {
        return res.status(404).json({ error: 'Client tidak ditemukan untuk pengguna ini. Pastikan pengguna telah login dan membuat sessi.' });
    }

    const client = clients[email];

    client.sendMessage(to, message).then(response => {
        res.json({ status: 'Message Sent', response });
    }).catch(err => {
        console.error('Error sending message:', err);
        res.status(500).json({ status: 'Error', message: 'Error sending message' });
    });
});

// Endpoint untuk validasi token
app.get('/validate-token', verifyApiSecret, (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Bearer token

    if (!token) {
        return res.status(400).json({ error: 'Token not provided' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }

        // Token valid
        res.json({ status: 'Token valid', user: decoded });
    });
});

app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});
