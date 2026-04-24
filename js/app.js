// ==========================================
// 1. Anti-Clickjacking Fallback (JS Base)
// ==========================================
if (self !== top) { top.location = self.location; }

// ==========================================
// 2. State & Config
// ==========================================
const DOM = {
    setupView: document.getElementById('setup-view'), chatView: document.getElementById('chat-view'),
    idDisplay: document.getElementById('my-id-display'), qrContainer: document.getElementById('qrcode-container'),
    targetInput: document.getElementById('target-id'), btnConnect: document.getElementById('btn-connect'),
    toggleReceive: document.getElementById('toggle-receive'), receiveStatus: document.getElementById('receive-status'),
    toggleHighSec: document.getElementById('toggle-high-sec'),
    connectedId: document.getElementById('connected-peer-id'), safetyCodeDisplay: document.getElementById('safety-code-display'),
    msgArea: document.getElementById('messages-container'), msgInput: document.getElementById('msg-input'),
    btnSend: document.getElementById('btn-send'), btnAttach: document.getElementById('btn-attach'),
    fileInput: document.getElementById('file-input'), btnDisconnect: document.getElementById('btn-disconnect'),
    authModal: document.getElementById('auth-modal'), callerId: document.getElementById('caller-id'),
    btnAccept: document.getElementById('btn-accept'), btnReject: document.getElementById('btn-reject'),
    toast: document.getElementById('toast')
};

let peer = null; let conn = null; let MY_ID = '';
let isReceiveMode = false; let receiveModeTimer = null;
let isHighSec = false; let isAuth = false;

// DoS Protection Configuration
const MAX_RX_FILE = 500 * 1024 * 1024; // 500MB Receiver Limit
let rateLimitMap = new Map(); // Tracks connection attempts per ID

// File Transfer State
let rxMeta = null, rxBuf = [], rxBytes = 0;

// ==========================================
// 3. Security Helper Functions
// ==========================================
function getSecureRandomStr(len, onlyDigits = false) {
    const chars = onlyDigits ? '0123456789' : 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
    const arr = new Uint32Array(len);
    window.crypto.getRandomValues(arr);
    let result = '';
    for (let i = 0; i < len; i++) result += chars[arr[i] % chars.length];
    return result;
}

function isRateLimited(peerId) {
    let now = Date.now();
    let attempts = rateLimitMap.get(peerId) || [];
    attempts = attempts.filter(t => now - t < 60000); // Only keep attempts in last 60s
    attempts.push(now);
    rateLimitMap.set(peerId, attempts);
    return attempts.length > 5; // Block if more than 5 attempts per minute
}

async function generateSafetyCode(saltHex, id1, id2) {
    const sorted = [id1, id2].sort().join('|');
    const data = new TextEncoder().encode(saltHex + '|' + sorted);
    const hashBuf = await window.crypto.subtle.digest('SHA-256', data);
    const hashArr = Array.from(new Uint8Array(hashBuf));
    const emojis = ['🐶','🐱','🦊','🐻','🐼','🦁','🐸','🐵','🐧','🐦','🦆','🦉','🐺','🐴','🦄','🐝','🐛','🦋','🐢','🐍','🐙','🐡','🐟','🐬','🐳','🐅','🦍','🐘','🐪','🦒'];
    let code = '';
    for(let i=0; i<4; i++) code += emojis[hashArr[i] % emojis.length];
    return code;
}

// Strict DOM Builder (Zero innerHTML)
function safeAppend(parent, tag, text, className) {
    const el = document.createElement(tag);
    if(text) el.textContent = text;
    if(className) el.className = className;
    parent.appendChild(el);
    return el;
}

// ==========================================
// 4. Initialization & UI Toggles
// ==========================================
function initPeer() {
    if(peer) peer.destroy();
    MY_ID = getSecureRandomStr(isHighSec ? 12 : 6, !isHighSec);
    DOM.idDisplay.textContent = MY_ID;
    
    DOM.qrContainer.innerHTML = ''; // Only time innerHTML is safe (empty string)
    new QRCode(DOM.qrContainer, { text: MY_ID, width: 128, height: 128, colorDark: "#00e5ff", colorLight: "#ffffff" });

    peer = new Peer(MY_ID, { debug: 0 });

    peer.on('connection', (c) => {
        // [SECURITY] 1. Reject if Receive Mode is off
        if(!isReceiveMode) {
            c.send({ type: 'sys', msg: 'المستلم لا يسمح بالاتصالات الواردة حالياً.' });
            setTimeout(()=>c.close(), 500);
            return;
        }
        // [SECURITY] 2. Rate Limiting DoS Prevention
        if(isRateLimited(c.peer)) {
            c.send({ type: 'sys', msg: 'تم حظرك مؤقتاً بسبب كثرة الطلبات.' });
            setTimeout(()=>c.close(), 500);
            return;
        }

        // Prompt Auth Modal
        DOM.callerId.textContent = c.peer;
        DOM.authModal.style.display = 'flex';

        DOM.btnAccept.onclick = () => {
            DOM.authModal.style.display = 'none';
            conn = c;
            setupConnection();
            conn.send({ type: 'auth-res', ok: true });
        };
        DOM.btnReject.onclick = () => {
            DOM.authModal.style.display = 'none';
            c.send({ type: 'auth-res', ok: false });
            setTimeout(()=>c.close(), 500);
        };
    });

    peer.on('error', (err) => showToast('حدث خطأ في الشبكة: ' + err.type));
}

DOM.toggleHighSec.addEventListener('change', (e) => {
    isHighSec = e.target.checked;
    initPeer();
    showToast(isHighSec ? 'تم تفعيل وضع الأمان المعزز' : 'وضع المعرّف العادي');
});

DOM.toggleReceive.addEventListener('change', (e) => {
    isReceiveMode = e.target.checked;
    if(isReceiveMode) {
        DOM.receiveStatus.textContent = "مفتوح (يغلق تلقائياً بعد 5 دقائق)";
        DOM.receiveStatus.className = "status-online";
        clearTimeout(receiveModeTimer);
        receiveModeTimer = setTimeout(() => {
            isReceiveMode = false;
            DOM.toggleReceive.checked = false;
            DOM.receiveStatus.textContent = "مغلق (للحماية من الإزعاج)";
            DOM.receiveStatus.className = "status-offline";
            showToast("تم إغلاق وضع الاستقبال تلقائياً لحمايتك.");
        }, 300000);
    } else {
        DOM.receiveStatus.textContent = "مغلق (للحماية من الإزعاج)";
        DOM.receiveStatus.className = "status-offline";
        clearTimeout(receiveModeTimer);
    }
});

// ==========================================
// 5. Connection & Protocol Handling
// ==========================================
DOM.btnConnect.addEventListener('click', () => {
    const t = DOM.targetInput.value.trim();
    if(!t || t === MY_ID) return showToast('معرّف غير صالح');
    
    conn = peer.connect(t, { reliable: true });
    showToast('جاري طلب الاتصال...');
    
    conn.on('open', () => {
        // Wait for auth-res from receiver
    });
    setupConnection(true);
});

function setupConnection(isInitiator = false) {
    conn.on('data', async (d) => {
        if(d.type === 'auth-res') {
            if(d.ok) {
                isAuth = true;
                enterChat();
                // Initiator generates MITM Salt
                if(isInitiator) {
                    const salt = getSecureRandomStr(16);
                    conn.send({ type: 'mitm-salt', val: salt });
                    DOM.safetyCodeDisplay.textContent = await generateSafetyCode(salt, MY_ID, conn.peer);
                }
            } else {
                showToast('تم رفض الاتصال من الطرف الآخر');
                conn.close();
            }
        }
        else if (d.type === 'mitm-salt') {
            DOM.safetyCodeDisplay.textContent = await generateSafetyCode(d.val, MY_ID, conn.peer);
        }
        else if (d.type === 'chat') {
            appendMsg(d.msg, 'msg-peer');
        }
        else if (d.type === 'sys') {
            appendMsg(d.msg, 'msg-sys');
        }
        else if (d.type === 'file-start') {
            // [SECURITY] Receiver DoS protection
            if(d.meta.size > MAX_RX_FILE) {
                appendMsg(`❌ تم حظر استلام ملف (${d.meta.name}) لتجاوزه الحد المسموح للأمان (500MB).`, 'msg-sys');
                conn.send({ type: 'sys', msg: 'الطرف الآخر رفض الملف لأن حجمه ضخم جداً.' });
                rxMeta = null; return;
            }
            rxMeta = d.meta; rxBuf = []; rxBytes = 0;
            appendMsg(`جاري استلام ملف: ${rxMeta.name}...`, 'msg-sys');
        }
        else if (d.type === 'file-chunk') {
            if(!rxMeta) return; // Ignore if rejected
            rxBytes += d.chunk.byteLength;
            // [SECURITY] Double check during stream
            if(rxBytes > MAX_RX_FILE) {
                appendMsg('❌ تم إيقاف الاستلام. محاولة ضخ بيانات خبيثة تجاوزت الحجم المسموح.', 'msg-sys');
                rxMeta = null; rxBuf = []; return;
            }
            rxBuf.push(d.chunk);
            if(rxBytes === rxMeta.size) {
                const blob = new Blob(rxBuf, { type: rxMeta.type });
                const url = URL.createObjectURL(blob);
                appendFileMsg(rxMeta.name, url, 'msg-peer');
                rxMeta = null; rxBuf = [];
            }
        }
    });

    conn.on('close', leaveChat);
}

// ==========================================
// 6. UI Navigation & Messaging
// ==========================================
function enterChat() {
    DOM.setupView.classList.remove('active');
    DOM.chatView.classList.add('active');
    DOM.connectedId.textContent = conn.peer;
    DOM.msgArea.innerHTML = ''; // reset chat
    appendMsg('تم تأسيس قناة مشفرة (E2EE) 🔒. يرجى مطابقة رمز الأمان.', 'msg-sys');
}

function leaveChat() {
    isAuth = false; conn = null;
    DOM.chatView.classList.remove('active');
    DOM.setupView.classList.add('active');
    DOM.safetyCodeDisplay.textContent = '⏳';
    showToast('تم إنهاء الاتصال');
}

DOM.btnDisconnect.addEventListener('click', () => { if(conn) conn.close(); leaveChat(); });

// Send Text
DOM.btnSend.addEventListener('click', () => {
    const text = DOM.msgInput.value.trim();
    if(!text || !isAuth) return;
    conn.send({ type: 'chat', msg: text });
    appendMsg(text, 'msg-self');
    DOM.msgInput.value = '';
});

// Safe UI Appender (XSS Proof)
function appendMsg(text, typeClass) {
    const div = document.createElement('div');
    div.className = `msg-bubble ${typeClass}`;
    div.textContent = text; // DOM Text injection only
    DOM.msgArea.appendChild(div);
    DOM.msgArea.scrollTop = DOM.msgArea.scrollHeight;
}

function appendFileMsg(filename, url, typeClass) {
    const div = document.createElement('div');
    div.className = `msg-bubble ${typeClass} file-card`;
    
    const icon = safeAppend(div, 'span', '📄');
    const link = safeAppend(div, 'a', filename);
    link.href = url;
    link.download = filename;
    link.style.color = 'var(--primary)';
    link.style.textDecoration = 'none';

    DOM.msgArea.appendChild(div);
    DOM.msgArea.scrollTop = DOM.msgArea.scrollHeight;
}

// ==========================================
// 7. File Handling (Sender Side)
// ==========================================
DOM.btnAttach.addEventListener('click', () => DOM.fileInput.click());
DOM.fileInput.addEventListener('change', async (e) => {
    const f = e.target.files[0];
    if(!f || !isAuth) return;
    
    if(f.size > MAX_RX_FILE) {
        if(!confirm('الملف ضخم جداً (> 500MB)، قد يرفضه الطرف الآخر. هل تود المتابعة؟')) return;
    }

    appendMsg(`بدء إرسال: ${f.name}...`, 'msg-sys');
    conn.send({ type: 'file-start', meta: { name: f.name, size: f.size, type: f.type } });

    const CHUNK_SIZE = 65536;
    let offset = 0;
    
    // File Reader with Backpressure
    const readSlice = (o) => {
        const slice = f.slice(o, o + CHUNK_SIZE);
        const reader = new FileReader();
        reader.onload = (evt) => {
            conn.send({ type: 'file-chunk', chunk: evt.target.result });
            offset += CHUNK_SIZE;
            
            if(offset < f.size) {
                // Backpressure to prevent flooding WebRTC buffer
                if(conn.dataChannel.bufferedAmount > 1024 * 1024 * 2) {
                    setTimeout(() => readSlice(offset), 50);
                } else {
                    readSlice(offset);
                }
            } else {
                appendMsg('تم إرسال الملف بنجاح ✅', 'msg-self');
            }
        };
        reader.readAsArrayBuffer(slice);
    };
    readSlice(0);
});

// Utilities
DOM.idDisplay.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(MY_ID); showToast('تم نسخ المعرّف'); } catch(e){}
});
function showToast(msg) {
    DOM.toast.textContent = msg; DOM.toast.classList.add('show');
    setTimeout(() => DOM.toast.classList.remove('show'), 3000);
}

// Boot
initPeer();
