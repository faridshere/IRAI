/* ================================================================
   IRAI Security Chat — Browser-native app (GitHub Pages edition)
   Calls OpenAI API directly from the browser.
   API key is stored only in localStorage, never sent anywhere else.
   ================================================================ */

(() => {
  'use strict';

  // ── System prompts per mode ──────────────────────────────────
  const SYSTEM_PROMPTS = {
    cortex: `You are an expert security analyst specializing in Palo Alto Networks Cortex XDR.
You help with:
- Writing and debugging XQL (Cortex XQL) queries
- Creating and optimizing Cortex XDR detection rules (BIOC and BIOC-R)
- Incident investigation workflows and playbooks
- Alert triage and threat hunting using Cortex XDR
- Converting Sigma rules to Cortex XDR / XQL format
- Best practices for Cortex XDR deployment and configuration
When providing XQL queries or rules, always format them in code blocks and explain what they do.`,

    qradar: `You are an expert security analyst specializing in IBM QRadar SIEM.
You help with:
- Writing AQL (Ariel Query Language) queries for QRadar
- Creating and tuning QRadar correlation rules and building blocks
- Log source configuration and parsing (DSM)
- Offense investigation and threat hunting in QRadar
- Converting Sigma rules to QRadar AQL or correlation rule format
- QRadar reference sets, reference maps, and custom properties
- Best practices for QRadar deployment and tuning
When providing AQL queries or rules, always format them in code blocks and explain what they do.`,

    sigma: `You are an expert in Sigma rules and security detection engineering.
You help with:
- Writing Sigma rules from scratch following the official specification
- Converting Sigma rules to platform-specific formats:
  * Cortex XDR / XQL queries
  * QRadar AQL queries and correlation rules
  * Splunk SPL, Elastic EQL, and other SIEM formats
- Validating and improving existing Sigma rules
- Explaining Sigma rule logic and detection coverage
- Mapping detections to MITRE ATT&CK techniques
Always output well-formatted YAML for Sigma rules and properly indented code blocks for converted queries.`,

    general: `You are IRAI, an intelligent security assistant specializing in Security Operations and SIEM platforms.
You have deep expertise in:
- Cortex XDR by Palo Alto Networks (XQL queries, BIOC rules, incident response)
- IBM QRadar SIEM (AQL queries, correlation rules, DSM configuration)
- Sigma rules and detection engineering
- Threat hunting and incident investigation
- MITRE ATT&CK framework
- General cybersecurity, SOC operations, and threat intelligence
Be concise, accurate, and always provide practical, actionable answers.
When writing queries or rules, use proper code blocks and explain the logic.`,
  };

  const MODE_META = {
    general: { icon: '🔍', name: 'General Security' },
    cortex:  { icon: '⚡', name: 'Cortex XDR' },
    qradar:  { icon: '📡', name: 'QRadar SIEM' },
    sigma:   { icon: 'Σ',  name: 'Sigma Rules'  },
  };

  const LS_KEY     = 'irai_openai_key';
  const LS_CONVS   = 'irai_conversations';
  const LS_MODE    = 'irai_mode';
  const LS_ACTIVE  = 'irai_active';

  // ── State ────────────────────────────────────────────────────
  let currentMode    = 'general';
  let conversations  = [];
  let activeConvId   = null;
  let pendingImageFile    = null;
  let pendingImageDataUrl = null;
  let isLoading      = false;

  // ── DOM refs ─────────────────────────────────────────────────
  const $ = id => document.getElementById(id);
  const sidebar          = $('sidebar');
  const sidebarToggle    = $('sidebarToggle');
  const newChatBtn       = $('newChatBtn');
  const modeBtns         = document.querySelectorAll('.mode-btn');
  const historyList      = $('historyList');
  const currentModeIcon  = $('currentModeIcon');
  const currentModeName  = $('currentModeName');
  const clearChatBtn     = $('clearChatBtn');
  const chatContainer    = $('chatContainer');
  const welcomeScreen    = $('welcomeScreen');
  const messagesEl       = $('messages');
  const typingIndicator  = $('typingIndicator');
  const imageInput       = $('imageInput');
  const imagePreviewBar  = $('imagePreviewBar');
  const imagePreviewThumb= $('imagePreviewThumb');
  const imageFileName    = $('imageFileName');
  const removeImageBtn   = $('removeImageBtn');
  const messageInput     = $('messageInput');
  const sendBtn          = $('sendBtn');
  const keyStatus        = $('keyStatus');
  // Settings modal
  const settingsBtn      = $('settingsBtn');
  const settingsModal    = $('settingsModal');
  const settingsCloseBtn = $('settingsCloseBtn');
  const apiKeyInput      = $('apiKeyInput');
  const toggleKeyVis     = $('toggleKeyVisibility');
  const saveKeyBtn       = $('saveKeyBtn');
  const clearKeyBtn      = $('clearKeyBtn');
  // No-key modal
  const noKeyModal       = $('noKeyModal');
  const noKeyOpenSettings= $('noKeyOpenSettings');

  // ── marked.js config ────────────────────────────────────────
  if (window.marked) {
    marked.setOptions({ breaks: true, gfm: true });
  }

  // ── API key helpers ──────────────────────────────────────────
  function getApiKey() {
    return localStorage.getItem(LS_KEY) || '';
  }
  function saveApiKey(key) {
    if (key) {
      localStorage.setItem(LS_KEY, key);
    } else {
      localStorage.removeItem(LS_KEY);
    }
    updateKeyStatusIndicator();
  }
  function updateKeyStatusIndicator() {
    const hasKey = !!getApiKey();
    keyStatus.classList.toggle('active', hasKey);
    keyStatus.title = hasKey ? 'API key configured' : 'No API key';
  }

  // ── Direct OpenAI API call ───────────────────────────────────
  async function callOpenAI(messages) {
    const apiKey = getApiKey();
    if (!apiKey) throw new ApiKeyError('No API key configured');

    const res = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: 'gpt-4o',
        messages,
        max_tokens: 4096,
        temperature: 0.2,
      }),
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      const msg = body.error?.message || `HTTP ${res.status}`;
      if (res.status === 401) throw new ApiKeyError('Invalid API key — please check your key in API Settings.');
      if (res.status === 429) throw new Error('Rate limit exceeded. Please wait a moment and try again.');
      if (res.status === 402 || res.status === 403) throw new Error('API quota exceeded. Check your OpenAI billing at platform.openai.com.');
      throw new Error(msg);
    }

    const data = await res.json();
    return data.choices[0].message.content;
  }

  function ApiKeyError(msg) {
    this.message = msg;
    this.isApiKeyError = true;
  }
  ApiKeyError.prototype = Object.create(Error.prototype);

  // ── Build OpenAI messages array ──────────────────────────────
  function buildMessages(conv, userText, imageDataUrl) {
    const system = SYSTEM_PROMPTS[conv.mode] || SYSTEM_PROMPTS.general;
    const msgs = [{ role: 'system', content: system }];

    // History (last 20 exchanges, excluding current message)
    const history = conv.messages.slice(-40, -1); // up to 40 stored, send last 20 pairs
    for (const m of history.slice(-20)) {
      msgs.push({ role: m.role, content: m.content });
    }

    // Current user message
    if (imageDataUrl) {
      const content = [
        { type: 'image_url', image_url: { url: imageDataUrl } },
        { type: 'text', text: userText || 'Please analyze this image.' },
      ];
      msgs.push({ role: 'user', content });
    } else {
      msgs.push({ role: 'user', content: userText });
    }

    return msgs;
  }

  // ── Conversation management ──────────────────────────────────
  function createConversation(mode, firstMessage = '') {
    const id = Date.now().toString();
    const title = firstMessage
      ? firstMessage.slice(0, 48) + (firstMessage.length > 48 ? '…' : '')
      : 'New conversation';
    const conv = { id, mode, title, messages: [] };
    conversations.unshift(conv);
    activeConvId = id;
    saveState();
    renderHistoryList();
    return conv;
  }

  function getActiveConv() {
    return conversations.find(c => c.id === activeConvId) || null;
  }

  function loadConversation(id) {
    const conv = conversations.find(c => c.id === id);
    if (!conv) return;
    activeConvId = id;
    setMode(conv.mode, false);
    messagesEl.innerHTML = '';
    welcomeScreen.style.display = 'none';
    messagesEl.style.display = 'flex';
    conv.messages.forEach(m => renderMessage(m, false));
    scrollToBottom();
    renderHistoryList();
    saveState();
  }

  function startNewChat() {
    activeConvId = null;
    messagesEl.innerHTML = '';
    messagesEl.style.display = 'none';
    welcomeScreen.style.display = 'flex';
    clearImageAttachment();
    renderHistoryList();
    messageInput.focus();
    saveState();
  }

  // ── Mode ─────────────────────────────────────────────────────
  function setMode(mode, persist = true) {
    currentMode = mode;
    modeBtns.forEach(btn => btn.classList.toggle('active', btn.dataset.mode === mode));
    const m = MODE_META[mode] || MODE_META.general;
    currentModeIcon.textContent = m.icon;
    currentModeName.textContent = m.name;
    if (persist) saveState();
  }

  // ── State persistence ────────────────────────────────────────
  function loadState() {
    try {
      const c = localStorage.getItem(LS_CONVS);
      if (c) conversations = JSON.parse(c);
      const m = localStorage.getItem(LS_MODE);
      if (m) setMode(m, false);
      const a = localStorage.getItem(LS_ACTIVE);
      if (a && conversations.find(c => c.id === a)) loadConversation(a);
    } catch { /* ignore */ }
  }

  function saveState() {
    try {
      localStorage.setItem(LS_CONVS, JSON.stringify(conversations));
      localStorage.setItem(LS_MODE, currentMode);
      if (activeConvId) localStorage.setItem(LS_ACTIVE, activeConvId);
      else localStorage.removeItem(LS_ACTIVE);
    } catch { /* quota exceeded */ }
  }

  // ── Render history list ──────────────────────────────────────
  function renderHistoryList() {
    if (conversations.length === 0) {
      historyList.innerHTML = '<p class="empty-history">No conversations yet</p>';
      return;
    }
    historyList.innerHTML = '';
    conversations.slice(0, 50).forEach(conv => {
      const btn = document.createElement('button');
      btn.className = 'history-item' + (conv.id === activeConvId ? ' active' : '');
      btn.title = conv.title;
      btn.textContent = `${MODE_META[conv.mode]?.icon || '💬'} ${conv.title}`;
      btn.addEventListener('click', () => {
        loadConversation(conv.id);
        if (window.innerWidth <= 768) sidebar.classList.remove('open');
      });
      historyList.appendChild(btn);
    });
  }

  // ── Render a message ─────────────────────────────────────────
  function renderMessage(msg, animate = true) {
    welcomeScreen.style.display = 'none';
    messagesEl.style.display = 'flex';

    const wrap = document.createElement('div');
    wrap.className = `message ${msg.role}`;
    if (!animate) wrap.style.animation = 'none';

    const imgHtml = msg.imageUrl
      ? `<img class="message-image" src="${msg.imageUrl}" alt="Attached image" />`
      : '';

    const bodyHtml = msg.role === 'assistant'
      ? renderMarkdown(msg.content)
      : escapeHtml(msg.content || '').replace(/\n/g, '<br>');

    wrap.innerHTML = `
      <div class="message-avatar">${msg.role === 'user' ? 'You' : 'AI'}</div>
      <div class="message-body">
        <div class="message-meta">
          <span class="message-role">${msg.role === 'user' ? 'You' : 'IRAI'}</span>
          <span class="message-time">${msg.time || formatTime()}</span>
        </div>
        <div class="message-content">${imgHtml}${bodyHtml}</div>
      </div>`;

    messagesEl.appendChild(wrap);

    wrap.querySelectorAll('pre code').forEach(block => {
      if (window.hljs) hljs.highlightElement(block);
      wrapWithCopyBtn(block.closest('pre'));
    });

    if (animate) scrollToBottom();
  }

  function wrapWithCopyBtn(preEl) {
    if (!preEl || preEl.parentElement?.classList.contains('code-block-wrapper')) return;
    const wrapper = document.createElement('div');
    wrapper.className = 'code-block-wrapper';
    preEl.parentNode.insertBefore(wrapper, preEl);
    wrapper.appendChild(preEl);

    const btn = document.createElement('button');
    btn.className = 'copy-code-btn';
    btn.textContent = 'Copy';
    wrapper.appendChild(btn);

    btn.addEventListener('click', async () => {
      const code = preEl.querySelector('code')?.innerText || '';
      try {
        await navigator.clipboard.writeText(code);
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
      } catch {
        btn.textContent = 'Error';
      }
      setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
    });
  }

  function renderMarkdown(text) {
    if (!window.marked) return escapeHtml(text).replace(/\n/g, '<br>');
    try { return marked.parse(text); } catch { return escapeHtml(text).replace(/\n/g, '<br>'); }
  }

  function escapeHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }

  function formatTime() {
    return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function scrollToBottom() {
    chatContainer.scrollTop = chatContainer.scrollHeight;
  }

  // ── Send message ─────────────────────────────────────────────
  async function sendMessage() {
    if (isLoading) return;

    const text = messageInput.value.trim();
    if (!text && !pendingImageFile) return;

    // Require API key
    if (!getApiKey()) {
      noKeyModal.style.display = 'flex';
      return;
    }

    isLoading = true;
    sendBtn.disabled = true;
    messageInput.disabled = true;

    // Create conversation if needed
    let conv = getActiveConv();
    if (!conv) conv = createConversation(currentMode, text);

    const userMsg = {
      role: 'user',
      content: text,
      imageUrl: pendingImageDataUrl || null,
      time: formatTime(),
    };
    conv.messages.push(userMsg);
    renderMessage(userMsg);

    const sentText    = text;
    const sentImageDU = pendingImageDataUrl;
    messageInput.value = '';
    resizeTextarea();
    clearImageAttachment();
    saveState();

    typingIndicator.style.display = 'flex';
    scrollToBottom();

    try {
      const messages = buildMessages(conv, sentText, sentImageDU);
      const reply = await callOpenAI(messages);

      typingIndicator.style.display = 'none';
      const aiMsg = { role: 'assistant', content: reply, time: formatTime() };
      conv.messages.push(aiMsg);
      renderMessage(aiMsg);

      // Update title from first message
      if (conv.messages.filter(m => m.role === 'user').length === 1 && sentText) {
        conv.title = sentText.slice(0, 48) + (sentText.length > 48 ? '…' : '');
        renderHistoryList();
      }
      saveState();
    } catch (err) {
      typingIndicator.style.display = 'none';
      if (err.isApiKeyError) {
        showError(err.message + ' <a href="#" id="errOpenSettings" style="color:var(--accent)">Open Settings</a>');
        document.getElementById('errOpenSettings')?.addEventListener('click', e => {
          e.preventDefault();
          openSettings();
        });
      } else {
        showError(err.message || 'An unexpected error occurred. Please try again.');
      }
      console.error('IRAI error:', err);
    } finally {
      isLoading = false;
      sendBtn.disabled = false;
      messageInput.disabled = false;
      updateSendBtn();
      messageInput.focus();
    }
  }

  function showError(htmlMsg) {
    const banner = document.createElement('div');
    banner.className = 'error-banner';
    banner.innerHTML = `⚠️ ${htmlMsg}`;
    messagesEl.appendChild(banner);
    scrollToBottom();
    setTimeout(() => banner.remove(), 10000);
  }

  // ── Image attachment ─────────────────────────────────────────
  function handleImageSelect(file) {
    if (!file || !file.type.startsWith('image/')) return;
    pendingImageFile = file;
    const reader = new FileReader();
    reader.onload = e => {
      pendingImageDataUrl = e.target.result;
      imagePreviewThumb.src = pendingImageDataUrl;
      imageFileName.textContent = file.name;
      imagePreviewBar.style.display = 'flex';
      updateSendBtn();
    };
    reader.readAsDataURL(file);
  }

  function clearImageAttachment() {
    pendingImageFile = null;
    pendingImageDataUrl = null;
    imagePreviewBar.style.display = 'none';
    imagePreviewThumb.src = '';
    imageInput.value = '';
    updateSendBtn();
  }

  function updateSendBtn() {
    sendBtn.disabled = !(messageInput.value.trim() || pendingImageFile);
  }

  function resizeTextarea() {
    messageInput.style.height = 'auto';
    messageInput.style.height = Math.min(messageInput.scrollHeight, 180) + 'px';
  }

  // ── Settings modal ───────────────────────────────────────────
  function openSettings() {
    apiKeyInput.value = getApiKey();
    settingsModal.style.display = 'flex';
    setTimeout(() => apiKeyInput.focus(), 50);
  }
  function closeSettings() {
    settingsModal.style.display = 'none';
  }

  // ── Event bindings ───────────────────────────────────────────
  function bindEvents() {
    // Sidebar
    sidebarToggle.addEventListener('click', () => sidebar.classList.toggle('open'));
    document.addEventListener('click', e => {
      if (window.innerWidth <= 768 && sidebar.classList.contains('open') &&
          !sidebar.contains(e.target) && e.target !== sidebarToggle) {
        sidebar.classList.remove('open');
      }
    });

    newChatBtn.addEventListener('click', startNewChat);

    modeBtns.forEach(btn => btn.addEventListener('click', () => setMode(btn.dataset.mode)));

    clearChatBtn.addEventListener('click', () => {
      if (!activeConvId) return;
      if (!confirm('Clear this conversation?')) return;
      const idx = conversations.findIndex(c => c.id === activeConvId);
      if (idx > -1) conversations.splice(idx, 1);
      startNewChat();
    });

    // Image
    imageInput.addEventListener('change', e => handleImageSelect(e.target.files[0]));
    removeImageBtn.addEventListener('click', clearImageAttachment);

    // Drag & drop
    chatContainer.addEventListener('dragover', e => e.preventDefault());
    chatContainer.addEventListener('drop', e => {
      e.preventDefault();
      const file = e.dataTransfer.files[0];
      if (file?.type.startsWith('image/')) handleImageSelect(file);
    });

    // Textarea
    messageInput.addEventListener('input', () => { resizeTextarea(); updateSendBtn(); });
    messageInput.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        if (!sendBtn.disabled && !isLoading) sendMessage();
      }
    });

    sendBtn.addEventListener('click', sendMessage);

    // Settings modal
    settingsBtn.addEventListener('click', openSettings);
    settingsCloseBtn.addEventListener('click', closeSettings);
    settingsModal.addEventListener('click', e => { if (e.target === settingsModal) closeSettings(); });

    saveKeyBtn.addEventListener('click', () => {
      const key = apiKeyInput.value.trim();
      if (key && !key.startsWith('sk-')) {
        apiKeyInput.style.borderColor = 'var(--red)';
        setTimeout(() => { apiKeyInput.style.borderColor = ''; }, 2000);
        return;
      }
      saveApiKey(key);
      closeSettings();
    });

    clearKeyBtn.addEventListener('click', () => {
      apiKeyInput.value = '';
      saveApiKey('');
    });

    toggleKeyVis.addEventListener('click', () => {
      const isPass = apiKeyInput.type === 'password';
      apiKeyInput.type = isPass ? 'text' : 'password';
      toggleKeyVis.innerHTML = isPass
        ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`
        : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
    });

    // No-key modal
    noKeyModal.addEventListener('click', e => { if (e.target === noKeyModal) noKeyModal.style.display = 'none'; });
    noKeyOpenSettings.addEventListener('click', () => {
      noKeyModal.style.display = 'none';
      openSettings();
    });

    // Suggestion cards
    document.querySelectorAll('.suggestion-card').forEach(card => {
      card.addEventListener('click', () => {
        const mode = card.dataset.mode;
        const msg  = card.dataset.msg;
        if (mode) setMode(mode);
        if (msg) {
          messageInput.value = msg;
          resizeTextarea();
          updateSendBtn();
          sendMessage();
        }
      });
    });

    // Enter on API key input
    apiKeyInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') saveKeyBtn.click();
    });
  }

  // ── Init ─────────────────────────────────────────────────────
  function init() {
    loadState();
    updateKeyStatusIndicator();
    bindEvents();

    // Prompt for API key on first visit
    if (!getApiKey()) {
      setTimeout(() => { noKeyModal.style.display = 'flex'; }, 300);
    }
  }

  init();
})();
