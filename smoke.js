const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode');
const path = require('path');

const SESSION_ID = 'smoke1';

function log(...a){ console.log(new Date().toISOString(), ...a); }

async function waitUntilConnected(client, timeoutMs = 90000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const state = await client.getState(); // 'CONNECTED' | 'OPENING' | ...
      log('state =', state);
      if (state === 'CONNECTED') return;
    } catch (e) { /* ignore */ }
    await new Promise(r => setTimeout(r, 1000));
  }
  throw new Error('Timed out waiting for CONNECTED');
}

const client = new Client({
  authStrategy: new LocalAuth({
    clientId: SESSION_ID,
    dataPath: path.join(__dirname, '.wwebjs_auth'),
  }),
  webVersionCache: {
    type: 'remote',
    remotePath: 'https://raw.githubusercontent.com/wppconnect-team/wa-version/main/last.json'
  },
    puppeteer: {
    headless: 'new',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-extensions',
      '--disable-gpu',
      '--no-first-run',
      '--no-zygote'
    ]
  }, 

  takeoverOnConflict: true,
  takeoverTimeoutMs: 0,
  qrTimeoutMs: 0,
  authTimeoutMs: 0,
});

client.on('qr', async (qr) => {
  const dataUrl = await qrcode.toDataURL(qr);
  log('QR data-url (copy the whole line into a browser tab and scan):');
  log(dataUrl);
});

client.on('authenticated', () => log('🔐 authenticated'));
client.on('remote_session_saved', () => log('💾 remote session saved'));
client.on('loading_screen', (p, t) => log(`⏳ loading ${p}% of ${t}`));
client.on('change_state', s => log('🔄 change_state:', s));
client.on('ready', () => log('✅ ready (event fired)'));
client.on('disconnected', r => log('❌ disconnected:', r));
client.on('auth_failure', m => log('🚫 auth_failure:', m));
client.on('message', m => log('📩 incoming from', m.from, ':', (m.body||'').slice(0, 60)));

(async () => {
  await client.initialize();
  log('initialized, waiting for CONNECTED...');
  await waitUntilConnected(client, 90000);
  log('🎉 CONNECTED. sending a self-test message in 3s...');
  await new Promise(r => setTimeout(r, 3000));

  // TODO: replace with your own full phone (no +), e.g. 91XXXXXXXXXX
  const YOUR_NUMBER = '917290093903';
  const wid = `${YOUR_NUMBER}@c.us`;
  await client.sendMessage(wid, 'hello from smoke test ✅');
  log('✅ sent test message. keep this running for a minute to observe events.');
})();
