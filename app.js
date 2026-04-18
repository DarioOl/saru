// =====================================================
// Claude PWA — client mobile pour l'API Anthropic
// Tout est stocké localement (localStorage). La clé API
// est chiffrée avec AES-GCM à partir du PIN (PBKDF2).
// =====================================================

// ---------- Config modèles ----------
const MODELS = [
  {
    id: 'claude-opus-4-7',
    name: 'Claude Opus 4.7',
    short: 'Opus 4.7',
    desc: 'Le plus capable — raisonnement complexe, coding agentique',
  },
  {
    id: 'claude-sonnet-4-6',
    name: 'Claude Sonnet 4.6',
    short: 'Sonnet 4.6',
    desc: 'Équilibre vitesse / intelligence — usage quotidien',
  },
  {
    id: 'claude-haiku-4-5',
    name: 'Claude Haiku 4.5',
    short: 'Haiku 4.5',
    desc: 'Le plus rapide et le moins cher',
  },
];
const DEFAULT_MODEL_ID = 'claude-opus-4-7';
const API_URL = 'https://api.anthropic.com/v1/messages';
const MAX_IMAGE_BYTES = 5 * 1024 * 1024; // 5 MB par image

// ---------- Storage keys ----------
const LS = {
  ENC_KEY: 'claude_pwa.enc_apikey',   // { ciphertext, iv, salt, iterations }
  CONVS: 'claude_pwa.conversations',  // [{ id, title, model, messages, createdAt, updatedAt }]
  CURRENT_CONV: 'claude_pwa.current_conv',
  MODEL: 'claude_pwa.model',
  SYSTEM_PROMPT: 'claude_pwa.system_prompt',
  MAX_TOKENS: 'claude_pwa.max_tokens',
  LOCKED: 'claude_pwa.locked', // si l'API a renvoyé 401/403, on bloque tout
};

// ---------- Crypto (PIN → clé AES) ----------
const PBKDF2_ITERATIONS = 600000;

async function deriveKey(pin, salt) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(pin),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function randomBytes(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}

function bytesToB64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
function b64ToBytes(b64) {
  const s = atob(b64);
  const a = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
  return a;
}

async function encryptApiKey(apiKey, pin) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveKey(pin, salt);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(apiKey)
  );
  return {
    ciphertext: bytesToB64(new Uint8Array(ct)),
    iv: bytesToB64(iv),
    salt: bytesToB64(salt),
    iterations: PBKDF2_ITERATIONS,
  };
}

async function decryptApiKey(blob, pin) {
  const salt = b64ToBytes(blob.salt);
  const iv = b64ToBytes(blob.iv);
  const ct = b64ToBytes(blob.ciphertext);
  const key = await deriveKey(pin, salt);
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new TextDecoder().decode(pt);
  } catch {
    throw new Error('PIN incorrect');
  }
}

// ---------- Storage helpers ----------
function lsGet(key, fallback = null) {
  try {
    const v = localStorage.getItem(key);
    return v === null ? fallback : JSON.parse(v);
  } catch {
    return fallback;
  }
}
function lsSet(key, value) {
  localStorage.setItem(key, JSON.stringify(value));
}
function lsDel(key) {
  localStorage.removeItem(key);
}

// ---------- État global ----------
const state = {
  apiKey: null,          // clé déchiffrée en mémoire uniquement
  conversations: lsGet(LS.CONVS, []),
  currentConvId: lsGet(LS.CURRENT_CONV, null),
  modelId: lsGet(LS.MODEL, DEFAULT_MODEL_ID),
  systemPrompt: lsGet(LS.SYSTEM_PROMPT, ''),
  maxTokens: lsGet(LS.MAX_TOKENS, 4096),
  attachments: [],       // { dataUrl, mediaType, name }
  streaming: false,
  abortCtrl: null,
  locked: !!lsGet(LS.LOCKED, false), // bloqué par erreur API
};

// ---------- DOM ----------
const $ = (sel) => document.querySelector(sel);
const lockScreen = $('#lock-screen');
const apikeyScreen = $('#apikey-screen');
const appScreen = $('#app-screen');
const pinForm = $('#pin-form');
const pinInput = $('#pin-input');
const pinConfirm = $('#pin-confirm');
const pinSubmit = $('#pin-submit');
const lockError = $('#lock-error');
const lockTitle = $('#lock-title');
const lockSubtitle = $('#lock-subtitle');
const apikeyForm = $('#apikey-form');
const apikeyInput = $('#apikey-input');
const apikeyError = $('#apikey-error');
const resetAppBtn = $('#reset-app');
const chatEl = $('#chat');
const composerInput = $('#composer-input');
const sendBtn = $('#send-btn');
const stopBtn = $('#stop-btn');
const attachBtn = $('#attach-btn');
const fileInput = $('#file-input');
const attachmentsEl = $('#attachments');
const modelPicker = $('#model-picker');
const modelLabel = $('#model-label');
const modelModal = $('#model-modal');
const modelList = $('#model-list');
const convTitle = $('#conv-title');
const newChatBtn = $('#new-chat-btn');
const menuBtn = $('#menu-btn');
const sidebar = $('#sidebar');
const convListEl = $('#conv-list');
const settingsBtn = $('#settings-btn');
const settingsModal = $('#settings-modal');
const lockBtn = $('#lock-btn');
const systemPromptInput = $('#system-prompt');
const maxTokensInput = $('#max-tokens');
const changeKeyBtn = $('#change-key-btn');
const changePinBtn = $('#change-pin-btn');
const wipeBtn = $('#wipe-btn');
const toastEl = $('#toast');

// ---------- Toast ----------
let toastTimer;
function toast(msg, { error = false, duration = 2500 } = {}) {
  toastEl.textContent = msg;
  toastEl.classList.toggle('error', error);
  toastEl.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toastEl.hidden = true; }, duration);
}

// ---------- Conversations ----------
function getCurrentConv() {
  return state.conversations.find((c) => c.id === state.currentConvId) || null;
}
function saveConversations() {
  lsSet(LS.CONVS, state.conversations);
}
function newConversation() {
  const conv = {
    id: crypto.randomUUID(),
    title: 'Nouvelle conversation',
    model: state.modelId,
    messages: [],
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  state.conversations.unshift(conv);
  state.currentConvId = conv.id;
  lsSet(LS.CURRENT_CONV, conv.id);
  saveConversations();
  renderChat();
  renderConvList();
  renderTitle();
  return conv;
}
function deleteConversation(id) {
  state.conversations = state.conversations.filter((c) => c.id !== id);
  saveConversations();
  if (state.currentConvId === id) {
    state.currentConvId = state.conversations[0]?.id || null;
    lsSet(LS.CURRENT_CONV, state.currentConvId);
  }
  renderConvList();
  renderChat();
  renderTitle();
}
function selectConversation(id) {
  state.currentConvId = id;
  lsSet(LS.CURRENT_CONV, id);
  renderChat();
  renderConvList();
  renderTitle();
  closeSidebar();
}

// ---------- Rendu chat ----------
// Mini-parseur Markdown light (gras, italique, code inline, blocs code, listes, paragraphes)
function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}
function renderMarkdown(text) {
  if (!text) return '';
  // Extract code blocks first
  const codeBlocks = [];
  text = text.replace(/```(\w+)?\n?([\s\S]*?)```/g, (_, lang, code) => {
    const i = codeBlocks.length;
    codeBlocks.push(`<pre><code${lang ? ` class="lang-${escapeHtml(lang)}"` : ''}>${escapeHtml(code.replace(/\n$/, ''))}</code></pre>`);
    return `\u0000CODEBLOCK${i}\u0000`;
  });
  let html = escapeHtml(text);
  // Inline code
  html = html.replace(/`([^`\n]+)`/g, '<code>$1</code>');
  // Bold **text**
  html = html.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>');
  // Italics *text*
  html = html.replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em>$2</em>');
  // Headings
  html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
  html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
  html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');
  // Paragraphs / line breaks
  const paragraphs = html.split(/\n{2,}/).map((p) => {
    if (/^<(h\d|pre|ul|ol|blockquote)/.test(p.trim())) return p;
    return `<p>${p.replace(/\n/g, '<br>')}</p>`;
  });
  html = paragraphs.join('\n');
  // Restore code blocks
  html = html.replace(/\u0000CODEBLOCK(\d+)\u0000/g, (_, i) => codeBlocks[Number(i)]);
  return html;
}

function renderChat() {
  chatEl.innerHTML = '';
  const conv = getCurrentConv();
  if (!conv || conv.messages.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.innerHTML = `<h2>Bonjour</h2><p>Démarre la conversation en écrivant un message.</p>`;
    chatEl.appendChild(empty);
    return;
  }
  for (const msg of conv.messages) {
    chatEl.appendChild(buildMsgEl(msg));
  }
  scrollToBottom();
}

function buildMsgEl(msg) {
  const el = document.createElement('div');
  el.className = `msg ${msg.role}`;
  if (msg.role === 'error') {
    const b = document.createElement('div');
    b.className = 'msg-bubble';
    b.textContent = msg.text;
    el.appendChild(b);
    return el;
  }
  if (msg.images && msg.images.length) {
    const imgs = document.createElement('div');
    imgs.className = 'msg-images';
    for (const img of msg.images) {
      const i = document.createElement('img');
      i.src = img.dataUrl;
      i.alt = img.name || '';
      imgs.appendChild(i);
    }
    el.appendChild(imgs);
  }
  const b = document.createElement('div');
  b.className = 'msg-bubble';
  const content = document.createElement('div');
  content.className = 'msg-content';
  if (msg.role === 'assistant') {
    content.innerHTML = renderMarkdown(msg.text || '');
    if (!msg.text) {
      content.innerHTML = `<div class="typing"><span></span><span></span><span></span></div>`;
    }
  } else {
    content.textContent = msg.text || '';
  }
  b.appendChild(content);
  el.appendChild(b);
  return el;
}

function scrollToBottom() {
  requestAnimationFrame(() => {
    chatEl.scrollTop = chatEl.scrollHeight;
  });
}

function renderTitle() {
  const conv = getCurrentConv();
  convTitle.textContent = conv ? conv.title : 'Nouvelle conversation';
}

function renderConvList() {
  convListEl.innerHTML = '';
  if (state.conversations.length === 0) {
    const li = document.createElement('li');
    li.className = 'conv-item';
    li.innerHTML = `<span class="conv-item-title muted">Aucune conversation</span>`;
    convListEl.appendChild(li);
    return;
  }
  for (const c of state.conversations) {
    const li = document.createElement('li');
    li.className = 'conv-item' + (c.id === state.currentConvId ? ' active' : '');
    const title = document.createElement('span');
    title.className = 'conv-item-title';
    title.textContent = c.title;
    title.addEventListener('click', () => selectConversation(c.id));
    const del = document.createElement('button');
    del.className = 'conv-item-delete';
    del.type = 'button';
    del.textContent = '✕';
    del.setAttribute('aria-label', 'Supprimer');
    del.addEventListener('click', (e) => {
      e.stopPropagation();
      if (confirm('Supprimer cette conversation ?')) deleteConversation(c.id);
    });
    li.appendChild(title);
    li.appendChild(del);
    convListEl.appendChild(li);
  }
}

function renderModelLabel() {
  const m = MODELS.find((x) => x.id === state.modelId) || MODELS[0];
  modelLabel.textContent = m.short;
}

// ---------- API Anthropic ----------
function buildApiMessages(conv) {
  // Convertit nos messages internes (qui peuvent contenir images) en format Anthropic
  const out = [];
  for (const m of conv.messages) {
    if (m.role === 'error') continue;
    if (m.role === 'user') {
      const content = [];
      if (m.images && m.images.length) {
        for (const img of m.images) {
          content.push({
            type: 'image',
            source: {
              type: 'base64',
              media_type: img.mediaType,
              data: img.dataUrl.split(',')[1],
            },
          });
        }
      }
      content.push({ type: 'text', text: m.text || '' });
      out.push({ role: 'user', content });
    } else if (m.role === 'assistant') {
      if (!m.text) continue; // message en cours, on ne l'envoie pas
      out.push({ role: 'assistant', content: m.text });
    }
  }
  return out;
}

async function* streamFromAnthropic({ apiKey, model, messages, system, maxTokens, signal }) {
  const body = {
    model,
    max_tokens: maxTokens,
    messages,
    stream: true,
  };
  if (system && system.trim()) body.system = system.trim();

  const res = await fetch(API_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'anthropic-dangerous-direct-browser-access': 'true',
    },
    body: JSON.stringify(body),
    signal,
  });

  if (!res.ok) {
    let message = `Erreur HTTP ${res.status}`;
    try {
      const data = await res.json();
      if (data?.error?.message) message = data.error.message;
    } catch {}
    const err = new Error(message);
    err.status = res.status;
    throw err;
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    // Parse SSE
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';
    for (const line of lines) {
      if (!line.startsWith('data:')) continue;
      const data = line.slice(5).trim();
      if (!data) continue;
      try {
        const evt = JSON.parse(data);
        if (evt.type === 'content_block_delta' && evt.delta?.type === 'text_delta') {
          yield { type: 'delta', text: evt.delta.text };
        } else if (evt.type === 'message_stop') {
          yield { type: 'done' };
        } else if (evt.type === 'error') {
          const err = new Error(evt.error?.message || 'Stream error');
          err.status = 0;
          throw err;
        }
      } catch (e) {
        if (e instanceof SyntaxError) continue;
        throw e;
      }
    }
  }
}

// ---------- Envoi message ----------
async function sendMessage() {
  if (state.streaming) return;
  if (state.locked) {
    toast('App verrouillée par sécurité. Change ta clé API.', { error: true });
    return;
  }
  const text = composerInput.value.trim();
  if (!text && state.attachments.length === 0) return;

  let conv = getCurrentConv();
  if (!conv) conv = newConversation();

  const userMsg = {
    role: 'user',
    text,
    images: state.attachments.slice(),
    createdAt: Date.now(),
  };
  conv.messages.push(userMsg);

  // Titre auto = premier message
  if (conv.messages.length === 1 && text) {
    conv.title = text.slice(0, 40) + (text.length > 40 ? '…' : '');
  }
  conv.updatedAt = Date.now();
  conv.model = state.modelId;
  saveConversations();

  // Reset composer
  composerInput.value = '';
  autoResizeComposer();
  state.attachments = [];
  renderAttachments();
  updateSendState();
  renderTitle();
  renderConvList();

  // Placeholder assistant
  const assistantMsg = { role: 'assistant', text: '', createdAt: Date.now() };
  conv.messages.push(assistantMsg);
  renderChat();

  state.streaming = true;
  state.abortCtrl = new AbortController();
  sendBtn.hidden = true;
  stopBtn.hidden = false;

  const lastAssistantEl = chatEl.lastElementChild;
  const contentEl = lastAssistantEl.querySelector('.msg-content');

  try {
    const apiMessages = buildApiMessages({ messages: conv.messages.slice(0, -1) });
    let gotAnyText = false;
    for await (const evt of streamFromAnthropic({
      apiKey: state.apiKey,
      model: state.modelId,
      messages: apiMessages,
      system: state.systemPrompt,
      maxTokens: state.maxTokens,
      signal: state.abortCtrl.signal,
    })) {
      if (evt.type === 'delta') {
        assistantMsg.text += evt.text;
        gotAnyText = true;
        contentEl.innerHTML = renderMarkdown(assistantMsg.text);
        scrollToBottom();
      }
    }
    if (!gotAnyText) {
      assistantMsg.text = '(réponse vide)';
      contentEl.innerHTML = renderMarkdown(assistantMsg.text);
    }
    saveConversations();
  } catch (err) {
    console.error(err);
    if (err.name === 'AbortError') {
      if (!assistantMsg.text) assistantMsg.text = '_(interrompu)_';
      contentEl.innerHTML = renderMarkdown(assistantMsg.text);
      saveConversations();
    } else {
      // Retire le placeholder vide
      conv.messages.pop();
      const errMsg = {
        role: 'error',
        text: formatApiError(err),
        createdAt: Date.now(),
      };
      conv.messages.push(errMsg);
      saveConversations();
      renderChat();

      // Si 401/403 → on verrouille l'app : plus aucun appel tant que la clé n'est pas changée
      if (err.status === 401 || err.status === 403) {
        state.locked = true;
        lsSet(LS.LOCKED, true);
        toast('Clé API invalide ou révoquée. App verrouillée.', { error: true, duration: 5000 });
      } else {
        toast(formatApiError(err), { error: true, duration: 4000 });
      }
    }
  } finally {
    state.streaming = false;
    state.abortCtrl = null;
    sendBtn.hidden = false;
    stopBtn.hidden = true;
    updateSendState();
  }
}

function formatApiError(err) {
  if (err.status === 401) return 'Clé API invalide (401). Vérifie la clé dans les paramètres.';
  if (err.status === 403) return 'Accès refusé (403). Ta clé n\'a peut-être pas accès à ce modèle ou a été révoquée.';
  if (err.status === 429) return 'Limite de taux atteinte (429). Réessaie dans quelques secondes.';
  if (err.status === 400) return 'Requête invalide (400) : ' + (err.message || '');
  if (err.status === 529) return 'API surchargée (529). Réessaie plus tard.';
  if (err.status >= 500) return `Erreur serveur Anthropic (${err.status}).`;
  if (!navigator.onLine) return 'Pas de connexion internet.';
  return err.message || 'Erreur inconnue';
}

// ---------- Attachments (Vision) ----------
async function handleFiles(files) {
  for (const file of files) {
    if (!file.type.startsWith('image/')) {
      toast(`${file.name} n'est pas une image`, { error: true });
      continue;
    }
    if (file.size > MAX_IMAGE_BYTES) {
      toast(`${file.name} dépasse 5 MB`, { error: true });
      continue;
    }
    const dataUrl = await new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.onerror = reject;
      r.readAsDataURL(file);
    });
    state.attachments.push({
      dataUrl,
      mediaType: file.type,
      name: file.name,
    });
  }
  renderAttachments();
  updateSendState();
}

function renderAttachments() {
  if (state.attachments.length === 0) {
    attachmentsEl.hidden = true;
    attachmentsEl.innerHTML = '';
    return;
  }
  attachmentsEl.hidden = false;
  attachmentsEl.innerHTML = '';
  state.attachments.forEach((a, idx) => {
    const item = document.createElement('div');
    item.className = 'attachment-item';
    const img = document.createElement('img');
    img.src = a.dataUrl;
    img.alt = a.name;
    const rm = document.createElement('button');
    rm.className = 'attachment-remove';
    rm.textContent = '✕';
    rm.type = 'button';
    rm.addEventListener('click', () => {
      state.attachments.splice(idx, 1);
      renderAttachments();
      updateSendState();
    });
    item.appendChild(img);
    item.appendChild(rm);
    attachmentsEl.appendChild(item);
  });
}

// ---------- UI helpers ----------
function updateSendState() {
  const hasContent = composerInput.value.trim() || state.attachments.length > 0;
  sendBtn.disabled = !hasContent || state.streaming || state.locked;
}

function autoResizeComposer() {
  composerInput.style.height = 'auto';
  composerInput.style.height = Math.min(composerInput.scrollHeight, 140) + 'px';
}

function openSidebar() { sidebar.hidden = false; renderConvList(); }
function closeSidebar() { sidebar.hidden = true; }

function openModelPicker() {
  modelList.innerHTML = '';
  for (const m of MODELS) {
    const li = document.createElement('li');
    li.className = 'model-item' + (m.id === state.modelId ? ' selected' : '');
    li.innerHTML = `<span class="model-item-name">${m.name}</span><span class="model-item-desc">${m.desc}</span>`;
    li.addEventListener('click', () => {
      state.modelId = m.id;
      lsSet(LS.MODEL, state.modelId);
      renderModelLabel();
      modelModal.hidden = true;
    });
    modelList.appendChild(li);
  }
  modelModal.hidden = false;
}

function openSettings() {
  systemPromptInput.value = state.systemPrompt;
  maxTokensInput.value = state.maxTokens;
  settingsModal.hidden = false;
}

function closeModals() {
  modelModal.hidden = true;
  settingsModal.hidden = true;
}

// ---------- PIN / unlock flow ----------
function hasEncKey() { return !!lsGet(LS.ENC_KEY, null); }

function showScreen(name) {
  lockScreen.hidden = name !== 'lock';
  apikeyScreen.hidden = name !== 'apikey';
  appScreen.hidden = name !== 'app';
}

async function initUnlockFlow() {
  if (!hasEncKey()) {
    // Premier lancement : créer PIN + clé API
    lockTitle.textContent = 'Créer un PIN';
    lockSubtitle.textContent = 'Choisis un code (4 à 12 chiffres). Il chiffrera ta clé API.';
    pinConfirm.hidden = false;
    pinSubmit.textContent = 'Créer';
    showScreen('lock');
    pinForm.dataset.mode = 'create';
  } else {
    lockTitle.textContent = 'Déverrouiller';
    lockSubtitle.textContent = 'Entre ton code PIN';
    pinConfirm.hidden = true;
    pinSubmit.textContent = 'Valider';
    showScreen('lock');
    pinForm.dataset.mode = 'unlock';
  }
  pinInput.value = '';
  pinConfirm.value = '';
  lockError.hidden = true;
  setTimeout(() => pinInput.focus(), 100);
}

pinForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  lockError.hidden = true;
  const pin = pinInput.value;
  const mode = pinForm.dataset.mode;

  if (mode === 'create') {
    const confirm = pinConfirm.value;
    if (pin.length < 4) { showLockError('Le PIN doit faire au moins 4 chiffres.'); return; }
    if (pin !== confirm) { showLockError('Les PINs ne correspondent pas.'); return; }
    // On passe à l'écran clé API, on mémorise le PIN en mémoire temporaire
    state._pendingPin = pin;
    showScreen('apikey');
    apikeyInput.value = '';
    apikeyError.hidden = true;
    setTimeout(() => apikeyInput.focus(), 100);
  } else {
    pinSubmit.disabled = true;
    try {
      const blob = lsGet(LS.ENC_KEY);
      const apiKey = await decryptApiKey(blob, pin);
      state.apiKey = apiKey;
      state._pinInMemory = pin;
      enterApp();
    } catch {
      showLockError('PIN incorrect.');
    } finally {
      pinSubmit.disabled = false;
    }
  }
});

function showLockError(msg) {
  lockError.textContent = msg;
  lockError.hidden = false;
}

apikeyForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  apikeyError.hidden = true;
  const key = apikeyInput.value.trim();
  if (!key.startsWith('sk-ant-')) {
    apikeyError.textContent = 'La clé devrait commencer par sk-ant-';
    apikeyError.hidden = false;
    return;
  }

  // Deux modes possibles :
  //  - _pendingPin : premier setup (création du PIN + première clé)
  //  - _pinInMemory : utilisateur déjà déverrouillé qui change sa clé
  const pinForEncryption = state._pendingPin || state._pinInMemory;
  if (!pinForEncryption) {
    apikeyError.textContent = 'Session expirée, reviens à l\'accueil.';
    apikeyError.hidden = false;
    return;
  }

  try {
    const enc = await encryptApiKey(key, pinForEncryption);
    lsSet(LS.ENC_KEY, enc);
    state.apiKey = key;
    state.locked = false;
    lsDel(LS.LOCKED);

    const wasSetup = !!state._pendingPin;
    state._pendingPin = null;
    state._pinInMemory = pinForEncryption; // garder en mémoire pour prochains changements

    if (wasSetup) {
      enterApp();
    } else {
      toast('Clé API mise à jour');
      showScreen('app');
    }
  } catch (err) {
    apikeyError.textContent = 'Erreur chiffrement : ' + err.message;
    apikeyError.hidden = false;
  }
});

function enterApp() {
  showScreen('app');
  // Si aucune conv, en créer une
  if (state.conversations.length === 0) newConversation();
  renderChat();
  renderConvList();
  renderTitle();
  renderModelLabel();
  updateSendState();
  if (state.locked) {
    toast('App verrouillée : change la clé API dans les paramètres.', { error: true, duration: 5000 });
  }
}

resetAppBtn.addEventListener('click', () => {
  if (confirm('Effacer toutes les données (clé API + conversations) ?')) {
    localStorage.clear();
    location.reload();
  }
});

// ---------- Changement clé / PIN ----------
async function promptChangeApiKey() {
  // On demande le PIN actuel pour le re-chiffrement
  const pin = prompt('Confirme ton PIN actuel :');
  if (!pin) return;
  try {
    const blob = lsGet(LS.ENC_KEY);
    await decryptApiKey(blob, pin);
    state._pinInMemory = pin;
    settingsModal.hidden = true;
    apikeyInput.value = '';
    apikeyError.hidden = true;
    showScreen('apikey');
    setTimeout(() => apikeyInput.focus(), 100);
  } catch {
    toast('PIN incorrect', { error: true });
  }
}

async function promptChangePin() {
  const oldPin = prompt('PIN actuel :');
  if (!oldPin) return;
  try {
    const blob = lsGet(LS.ENC_KEY);
    const apiKey = await decryptApiKey(blob, oldPin);
    const newPin = prompt('Nouveau PIN (4-12 chiffres) :');
    if (!newPin || newPin.length < 4) { toast('PIN trop court', { error: true }); return; }
    const confirm = prompt('Confirme le nouveau PIN :');
    if (newPin !== confirm) { toast('Les PINs ne correspondent pas', { error: true }); return; }
    const enc = await encryptApiKey(apiKey, newPin);
    lsSet(LS.ENC_KEY, enc);
    toast('PIN changé');
  } catch {
    toast('PIN actuel incorrect', { error: true });
  }
}

// ---------- Events ----------
composerInput.addEventListener('input', () => {
  autoResizeComposer();
  updateSendState();
});
composerInput.addEventListener('keydown', (e) => {
  // Sur desktop : Ctrl/Cmd+Enter pour envoyer. Sur mobile : bouton.
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    sendMessage();
  }
});
sendBtn.addEventListener('click', sendMessage);
stopBtn.addEventListener('click', () => {
  if (state.abortCtrl) state.abortCtrl.abort();
});
attachBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', async (e) => {
  await handleFiles(e.target.files);
  fileInput.value = '';
});

// Drag & drop images (bonus desktop)
appScreen.addEventListener('dragover', (e) => { e.preventDefault(); });
appScreen.addEventListener('drop', async (e) => {
  e.preventDefault();
  if (e.dataTransfer?.files?.length) await handleFiles(e.dataTransfer.files);
});

// Paste images (bonus desktop)
composerInput.addEventListener('paste', async (e) => {
  const items = e.clipboardData?.items || [];
  const files = [];
  for (const item of items) {
    if (item.kind === 'file') {
      const f = item.getAsFile();
      if (f) files.push(f);
    }
  }
  if (files.length) { e.preventDefault(); await handleFiles(files); }
});

modelPicker.addEventListener('click', openModelPicker);
newChatBtn.addEventListener('click', () => { newConversation(); });
menuBtn.addEventListener('click', openSidebar);
settingsBtn.addEventListener('click', () => { closeSidebar(); openSettings(); });
lockBtn.addEventListener('click', () => {
  state.apiKey = null;
  state._pinInMemory = null;
  initUnlockFlow();
});

changeKeyBtn.addEventListener('click', promptChangeApiKey);
changePinBtn.addEventListener('click', promptChangePin);
wipeBtn.addEventListener('click', () => {
  if (confirm('Effacer toutes les données (clé API + conversations + paramètres) ?')) {
    localStorage.clear();
    location.reload();
  }
});

// Save settings on change
systemPromptInput.addEventListener('input', () => {
  state.systemPrompt = systemPromptInput.value;
  lsSet(LS.SYSTEM_PROMPT, state.systemPrompt);
});
maxTokensInput.addEventListener('change', () => {
  const v = parseInt(maxTokensInput.value, 10);
  if (!isNaN(v) && v >= 256 && v <= 8192) {
    state.maxTokens = v;
    lsSet(LS.MAX_TOKENS, v);
  } else {
    maxTokensInput.value = state.maxTokens;
  }
});

// Fermer modales / sidebar via overlay ou data-close
document.addEventListener('click', (e) => {
  const t = e.target;
  if (t.matches('[data-close]')) {
    if (t.closest('#sidebar')) closeSidebar();
    if (t.closest('.modal')) closeModals();
  }
});

// Échap pour fermer modales/sidebar
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    if (!modelModal.hidden || !settingsModal.hidden) closeModals();
    else if (!sidebar.hidden) closeSidebar();
  }
});

// ---------- Boot ----------
(function boot() {
  renderModelLabel();
  initUnlockFlow();
})();
