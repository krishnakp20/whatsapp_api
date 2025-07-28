const multer = require('multer');
const upload = multer({ dest: 'uploads/' });

const express = require('express');
const { Client, LocalAuth, MessageMedia } = require('whatsapp-web.js');
const qrcode = require('qrcode');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const mime = require('mime-types');
const cron = require('node-cron');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const swaggerDocument = YAML.load('./swagger.yaml');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const session = require('express-session');

const ADMIN_PASSWORD = "admin123";   // ✅ Change this to a strong password
const API_KEY = "123456"; // ✅ Change this too

// ✅ Session for dashboard login
app.use(session({
    secret: "whatsapp-dashboard-secret",
    resave: false,
    saveUninitialized: true
}));

// ✅ Middleware for dashboard login
function requireLogin(req, res, next) {
    if (req.session.loggedIn) {
        next();
    } else {
        res.redirect('/login');
    }
}

// ✅ Middleware for API auth
function requireApiKey(req, res, next) {
    const key = req.headers['x-api-key'];
    if (key === API_KEY) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized - Invalid API Key' });
    }
}





// ✅ Setup view engine and static files
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

const clients = {};   // Store all active WhatsApp sessions
const qrCodes = {};   // Store QR codes for dashboard
const scheduledJobs = {}; // Store scheduled jobs for each session

// ✅ Helper function to create or return a session
function createSession(sessionId) {
    if (clients[sessionId]) return clients[sessionId];

    const client = new Client({
        authStrategy: new LocalAuth({ clientId: sessionId }),
        puppeteer: { headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox'] }
    });

    client.on('qr', async (qr) => {
        qrCodes[sessionId] = await qrcode.toDataURL(qr);
        console.log(`📲 QR generated for session: ${sessionId}`);
    });

    client.on('ready', () => {
        console.log(`✅ Session ${sessionId} is ready!`);
        qrCodes[sessionId] = null; // QR disappears after login
    });

    client.on('disconnected', () => {
        console.log(`❌ Session ${sessionId} disconnected!`);
        delete clients[sessionId];
        qrCodes[sessionId] = null;
        fs.rmSync(path.join(__dirname, `.wwebjs_auth/session-${sessionId}`), { recursive: true, force: true });
    });

    // ✅ Listen for incoming messages (webhook support)
    client.on('message', msg => {
        console.log(`📩 Message from ${msg.from}: ${msg.body}`);
        // 👉 You could send this to your webhook endpoint here
    });

    client.initialize();
    clients[sessionId] = client;
    return client;
}

////////////////////  Login/////////////////////////
// ✅ Login Page
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});


// ✅ Login POST
app.post('/login', (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) {
        req.session.loggedIn = true;
        res.redirect('/');
    } else {
        res.render('login', { error: '❌ Wrong password. Try again.' });
    }
});


// ✅ Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});



//////////////////////////
// 📌 DASHBOARD ROUTES //
//////////////////////////

// ✅ Dashboard UI
app.get('/', requireLogin, (req, res) => {
    res.render('index', { 
        sessions: Object.keys(clients), 
        qrCodes,
        API_KEY   // ✅ Pass API_KEY to EJS template
    });
});


// ✅ Create New Session
app.post('/create-session', requireLogin, (req, res) => {
    const { sessionId } = req.body;
    if (!sessionId) return res.redirect('/');
    if (!clients[sessionId]) {
        createSession(sessionId);
    }
    res.redirect('/');
});

// ✅ Logout Session
app.post('/logout-session', requireLogin, async (req, res) => {
    const { sessionId } = req.body;
    if (!sessionId) return res.redirect('/');

    const client = clients[sessionId];
    if (client) {
        try {
            await client.logout();  // ✅ fixed typo here
            delete clients[sessionId];
            fs.rmSync(path.join(__dirname, `.wwebjs_auth/session-${sessionId}`), { recursive: true, force: true });
        } catch (err) {
            console.error(`❌ Error logging out session ${sessionId}:`, err);
        }
    }
    res.redirect('/');
});


//////////////////////
// 📌 API ROUTES //
//////////////////////

// ✅ Get QR Code for session
app.get('/get-qr/:sessionId', async (req, res) => {
    const sessionId = req.params.sessionId;
    if (!clients[sessionId]) createSession(sessionId);
    res.json({ sessionId, qr: qrCodes[sessionId] || '✅ Already logged in' });
});

// ✅ List active sessions
app.get('/sessions', (req, res) => {
    res.json({ activeSessions: Object.keys(clients) });
});

// ✅ Send text to a number
app.post('/send-text', async (req, res) => {
    const { sessionId, number, message } = req.body;
    if (!sessionId || !number || !message) return res.status(400).json({ error: "Missing parameters" });

    const client = clients[sessionId] || createSession(sessionId);
    try {
        const whatsappId = number.includes('@c.us') ? number : `${number}@c.us`;
        await client.sendMessage(whatsappId, message);
        res.json({ status: 'success', message: 'Text sent' });
    } catch (err) {
        res.status(500).json({ error: err.toString() });
    }
});

// ✅ Send text to a group

app.post('/send-text-group', async (req, res) => {
    const { sessionId, groupName, message } = req.body;
    if (!sessionId || !groupName || !message) return res.status(400).json({ error: "Missing parameters" });

    const client = clients[sessionId] || createSession(sessionId);
    try {
        const chats = await client.getChats();
        const group = chats.find(chat => chat.isGroup && chat.name === groupName);
        if (!group) return res.status(404).json({ error: "Group not found" });

        await client.sendMessage(group.id._serialized, message);
        res.json({ status: 'success', message: 'Text sent to group' });
    } catch (err) {
        res.status(500).json({ error: err.toString() });
    }
});

// ✅ Send media to a number
app.post('/send-media', upload.single('file'), async (req, res) => {
    const { sessionId, number, caption } = req.body;
    if (!req.file) return res.status(400).send("No file uploaded");

    const client = clients[sessionId] || createSession(sessionId);

    try {
        const filePath = path.join(__dirname, req.file.path);
        const mimeType = mime.lookup(filePath);
        const fileData = fs.readFileSync(filePath, { encoding: 'base64' });

        const media = new MessageMedia(mimeType, fileData, req.file.originalname);
        const whatsappId = number.includes('@c.us') ? number : `${number}@c.us`;

        await client.sendMessage(whatsappId, media, { caption: caption || '' });
        fs.unlinkSync(filePath); // delete after sending
        res.send({ status: 'success', message: 'Media sent!' });
    } catch (err) {
        res.status(500).send({ error: err.toString() });
    }
});


// ✅ Send media to a group
app.post('/send-media-group', upload.single('file'), async (req, res) => {
    const { sessionId, groupName, caption } = req.body;
    if (!req.file) return res.status(400).send("No file uploaded");
    if (!sessionId || !groupName) return res.status(400).send("Missing parameters");

    const client = clients[sessionId] || createSession(sessionId);

    try {
        const filePath = path.join(__dirname, req.file.path);
        const mimeType = mime.lookup(filePath);
        const fileData = fs.readFileSync(filePath, { encoding: 'base64' });

        const media = new MessageMedia(mimeType, fileData, req.file.originalname);

        const chats = await client.getChats();
        const group = chats.find(chat => chat.isGroup && chat.name === groupName);
        if (!group) {
            fs.unlinkSync(filePath);
            return res.status(404).send("Group not found");
        }

        await client.sendMessage(group.id._serialized, media, { caption: caption || '' });

        fs.unlinkSync(filePath); // cleanup
        res.send({ status: 'success', message: `Media sent to group ${groupName}` });
    } catch (err) {
        console.error(err);
        res.status(500).send(err.toString());
    }
});


// ✅ Create a new group
app.post('/create-group', async (req, res) => {
    const { sessionId, groupName, participants } = req.body;
    if (!sessionId || !groupName || !participants) {
        return res.status(400).json({ error: "Missing parameters" });
    }

    const client = clients[sessionId] || createSession(sessionId);

    try {
        // ✅ Split numbers by comma and clean them up
        const participantArray = participants.split(',').map(num => `${num.trim()}@c.us`);

        console.log("📞 Creating empty group:", groupName);

        // ✅ Step 1: Create empty group
        const group = await client.createGroup(groupName, []);
        console.log("✅ Group created:", group);

        // ✅ Step 2: Add members one by one (safe method)
        for (const member of participantArray) {
            try {
                console.log(`➕ Adding ${member}`);
                await group.addParticipants([member]);
                await new Promise(resolve => setTimeout(resolve, 2000)); // wait 2 sec to avoid rate-limit
            } catch (addErr) {
                console.error(`⚠️ Failed to add ${member}:`, addErr);
            }
        }

        res.json({ status: 'success', group, added: participantArray });
    } catch (err) {
        console.error("❌ Group creation failed:", err);
        res.status(500).json({ error: err.message || err.toString() });
    }
});


// ✅ Add member to a group
app.post('/add-member', async (req, res) => {
    const { sessionId, groupName, number } = req.body;
    if (!sessionId || !groupName || !number) return res.status(400).json({ error: "Missing parameters" });

    const client = clients[sessionId] || createSession(sessionId);
    try {
        const chats = await client.getChats();
        const group = chats.find(chat => chat.isGroup && chat.name === groupName);
        if (!group) return res.status(404).json({ error: "Group not found" });

        await group.addParticipants([`${number}@c.us`]);
        res.json({ status: 'success', message: 'Member added' });
    } catch (err) {
        res.status(500).json({ error: err.toString() });
    }
});

// ✅ Schedule a message
app.post('/schedule-message', async (req, res) => {
    const { sessionId, number, message, cronTime } = req.body;
    if (!sessionId || !number || !message || !cronTime) return res.status(400).json({ error: "Missing parameters" });

    const client = clients[sessionId] || createSession(sessionId);

    try {
        const job = cron.schedule(cronTime, async () => {
            const whatsappId = number.includes('@c.us') ? number : `${number}@c.us`;
            await client.sendMessage(whatsappId, message);
            console.log(`📆 Scheduled message sent via ${sessionId}`);
        });

        scheduledJobs[`${sessionId}-${number}`] = job;
        res.json({ status: 'success', message: 'Message scheduled' });
    } catch (err) {
        res.status(500).json({ error: err.toString() });
    }
});

////////////////////////   Swagger API with auth key 

// ✅ Send text to a number
app.post('/api/send-text', requireApiKey, async (req, res) => {
    const { sessionId, number, message } = req.body;
    if (!sessionId || !number || !message) {
        return res.status(400).json({ error: "Missing parameters" });
    }

    // 🔄 Create session if missing
    const client = clients[sessionId] || createSession(sessionId);

    try {
        // ✅ WAIT until client is ready
        if (!client.info) {
            console.log(`⏳ Waiting for session ${sessionId} to be ready...`);
            await new Promise((resolve, reject) => {
                const timeout = setTimeout(() => reject(new Error("❌ Client not ready in 30s")), 30000);

                client.once('ready', () => {
                    clearTimeout(timeout);
                    resolve();
                });
            });
        }

        // ✅ Format number
        const whatsappId = number.includes('@c.us') ? number : `${number}@c.us`;

        // ✅ Send message
        await client.sendMessage(whatsappId, message);

        res.json({ status: 'success', message: 'Text sent' });
    } catch (err) {
        console.error("❌ Error in /api/send-text:", err);
        res.status(500).json({ error: err.toString() });
    }
});

// ✅ Send text to a group

app.post('/api/send-text-group', requireApiKey, async (req, res) => {
    const { sessionId, groupName, message } = req.body;
    if (!sessionId || !groupName || !message) return res.status(400).json({ error: "Missing parameters" });

    const client = clients[sessionId] || createSession(sessionId);
    try {
        const chats = await client.getChats();
        const group = chats.find(chat => chat.isGroup && chat.name === groupName);
        if (!group) return res.status(404).json({ error: "Group not found" });

        await client.sendMessage(group.id._serialized, message);
        res.json({ status: 'success', message: 'Text sent to group' });
    } catch (err) {
        res.status(500).json({ error: err.toString() });
    }
});

// ✅ Send media to a number
app.post('/api/send-media', requireApiKey, upload.single('file'), async (req, res) => {
    const { sessionId, number, caption } = req.body;
    if (!req.file) return res.status(400).send("No file uploaded");

    const client = clients[sessionId] || createSession(sessionId);

    try {
        // ✅ Wait for client to be ready before sending media
        if (!client.info) {
            console.log(`⏳ Waiting for session ${sessionId} to be ready before sending media...`);
            await new Promise((resolve, reject) => {
                const timeout = setTimeout(() => reject(new Error("❌ Client not ready in 30s")), 30000);

                client.once('ready', () => {
                    clearTimeout(timeout);
                    resolve();
                });
            });
        }

        // ✅ Read uploaded file
        const filePath = path.join(__dirname, req.file.path);
        const mimeType = mime.lookup(filePath);
        const fileData = fs.readFileSync(filePath, { encoding: 'base64' });

        const media = new MessageMedia(mimeType, fileData, req.file.originalname);
        const whatsappId = number.includes('@c.us') ? number : `${number}@c.us`;

        // ✅ Send media
        await client.sendMessage(whatsappId, media, { caption: caption || '' });

        fs.unlinkSync(filePath); // 🗑 delete after sending
        res.send({ status: 'success', message: '✅ Media sent!' });

    } catch (err) {
        console.error("❌ Error sending media:", err);
        res.status(500).send({ error: err.toString() });
    }
});



// ✅ Send media to a group
app.post('/api/send-media-group', requireApiKey, upload.single('file'), async (req, res) => {
    const { sessionId, groupName, caption } = req.body;
    if (!req.file) return res.status(400).send("No file uploaded");
    if (!sessionId || !groupName) return res.status(400).send("Missing parameters");

    const client = clients[sessionId] || createSession(sessionId);

    try {
        const filePath = path.join(__dirname, req.file.path);
        const mimeType = mime.lookup(filePath);
        const fileData = fs.readFileSync(filePath, { encoding: 'base64' });

        const media = new MessageMedia(mimeType, fileData, req.file.originalname);

        const chats = await client.getChats();
        const group = chats.find(chat => chat.isGroup && chat.name === groupName);
        if (!group) {
            fs.unlinkSync(filePath);
            return res.status(404).send("Group not found");
        }

        await client.sendMessage(group.id._serialized, media, { caption: caption || '' });

        fs.unlinkSync(filePath); // cleanup
        res.send({ status: 'success', message: `Media sent to group ${groupName}` });
    } catch (err) {
        console.error(err);
        res.status(500).send(err.toString());
    }
});


// ✅ Create a new group
app.post('/api/create-group', requireApiKey, async (req, res) => {
    const { sessionId, groupName, participants } = req.body;
    if (!sessionId || !groupName || !participants) {
        return res.status(400).json({ error: "Missing parameters" });
    }

    const client = clients[sessionId] || createSession(sessionId);

    try {
        // ✅ Split numbers by comma and clean them up
        const participantArray = participants.split(',').map(num => `${num.trim()}@c.us`);

        console.log("📞 Creating empty group:", groupName);

        // ✅ Step 1: Create empty group
        const group = await client.createGroup(groupName, []);
        console.log("✅ Group created:", group);

        // ✅ Step 2: Add members one by one (safe method)
        for (const member of participantArray) {
            try {
                console.log(`➕ Adding ${member}`);
                await group.addParticipants([member]);
                await new Promise(resolve => setTimeout(resolve, 2000)); // wait 2 sec to avoid rate-limit
            } catch (addErr) {
                console.error(`⚠️ Failed to add ${member}:`, addErr);
            }
        }

        res.json({ status: 'success', group, added: participantArray });
    } catch (err) {
        console.error("❌ Group creation failed:", err);
        res.status(500).json({ error: err.message || err.toString() });
    }
});


// ✅ Add member to a group
app.post('/api/add-member', requireApiKey, async (req, res) => {
    const { sessionId, groupName, number } = req.body;
    if (!sessionId || !groupName || !number) return res.status(400).json({ error: "Missing parameters" });

    const client = clients[sessionId] || createSession(sessionId);
    try {
        const chats = await client.getChats();
        const group = chats.find(chat => chat.isGroup && chat.name === groupName);
        if (!group) return res.status(404).json({ error: "Group not found" });

        await group.addParticipants([`${number}@c.us`]);
        res.json({ status: 'success', message: 'Member added' });
    } catch (err) {
        res.status(500).json({ error: err.toString() });
    }
});

// ✅ Schedule a message
app.post('/api/schedule-message', requireApiKey, async (req, res) => {
    const { sessionId, number, message, cronTime } = req.body;
    if (!sessionId || !number || !message || !cronTime) return res.status(400).json({ error: "Missing parameters" });

    const client = clients[sessionId] || createSession(sessionId);

    try {
        const job = cron.schedule(cronTime, async () => {
            const whatsappId = number.includes('@c.us') ? number : `${number}@c.us`;
            await client.sendMessage(whatsappId, message);
            console.log(`📆 Scheduled message sent via ${sessionId}`);
        });

        scheduledJobs[`${sessionId}-${number}`] = job;
        res.json({ status: 'success', message: 'Message scheduled' });
    } catch (err) {
        res.status(500).json({ error: err.toString() });
    }
});


////////////////End Swager          




// ✅ Get all groups
app.get('/groups/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    const client = clients[sessionId] || createSession(sessionId);
    try {
        const chats = await client.getChats();
        const groups = chats.filter(chat => chat.isGroup).map(chat => chat.name);
        res.json(groups);
    } catch (err) {
        res.status(500).json({ error: err.toString() });
    }
});

// ✅ Get all contacts
app.get('/contacts/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    const client = clients[sessionId] || createSession(sessionId);
    try {
        const contacts = await client.getContacts();
        res.json(contacts.map(c => ({
            name: c.name || c.pushname || c.number,
            number: c.number
        })));
    } catch (err) {
        res.status(500).json({ error: err.toString() });
    }
});

app.get('/api/groups/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    const client = clients[sessionId] || createSession(sessionId);
    try {
        const chats = await client.getChats();
        const groups = chats.filter(chat => chat.isGroup).map(chat => chat.name);
        res.json(groups);
    } catch (err) {
        res.status(500).json({ error: err.toString() });
    }
});

app.get('/api/contacts/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    const client = clients[sessionId] || createSession(sessionId);
    try {
        const contacts = await client.getContacts();
        res.json(contacts.map(c => ({
            name: c.name || c.pushname || c.number,
            number: c.number
        })));
    } catch (err) {
        res.status(500).json({ error: err.toString() });
    }
});

app.get('/api-docs', (req, res) => {
    res.json({
        auth: "All API calls require header: x-api-key",
        api_key: API_KEY,
        endpoints: {
            "POST /send-text": { body: "{ sessionId, number, message }" },
            "POST /send-text-group": { body: "{ sessionId, groupName, message }" },
            "POST /send-media": { body: "{ sessionId, number, mediaUrl, caption }" },
            "POST /send-media-group": { body: "{ sessionId, groupName, mediaUrl, caption }" },
            "POST /create-group": { body: "{ sessionId, groupName, participants }" },
            "POST /add-member": { body: "{ sessionId, groupName, number }" },
            "GET /api/groups/:sessionId": "Returns all groups",
            "GET /api/contacts/:sessionId": "Returns all contacts"
        }
    });
});

app.use('/swagger', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

//////////////////////////////////
// 🚀 START SERVER
//////////////////////////////////
app.listen(3001, () => console.log('🚀 Full WhatsApp API + Dashboard running at http://localhost:3001'));
