/* ================================================================
   IRAI Security Chat — Frontend Application
   ================================================================ */

(() => {
  'use strict';

  // ── State ──────────────────────────────────────────────────────
  let currentMode = 'general';
  let conversations = []; // [{ id, mode, title, messages: [{role,content,imageUrl,time}] }]
  let activeConvId = null;
  let pendingImageFile = null;
  let pendingImageDataUrl = null;
  let isLoading = false;

  // ── DOM refs ───────────────────────────────────────────────────
  const sidebar         = document.getElementById('sidebar');
  const sidebarToggle   = document.getElementById('sidebarToggle');
  const newChatBtn      = document.getElementById('newChatBtn');
  const modeBtns        = document.querySelectorAll('.mode-btn');
  const historyList     = document.getElementById('historyList');
  const currentModeIcon = document.getElementById('currentModeIcon');
  const currentModeName = document.getElementById('currentModeName');
  const clearChatBtn    = document.getElementById('clearChatBtn');
  const chatContainer   = document.getElementById('chatContainer');
  const welcomeScreen   = document.getElementById('welcomeScreen');
  const messagesEl      = document.getElementById('messages');
  const typingIndicator = document.getElementById('typingIndicator');
  const imageInput      = document.getElementById('imageInput');
  const imagePreviewBar = document.getElementById('imagePreviewBar');
  const imagePreviewThumb = document.getElementById('imagePreviewThumb');
  const imageFileName   = document.getElementById('imageFileName');
  const removeImageBtn  = document.getElementById('removeImageBtn');
  const messageInput    = document.getElementById('messageInput');
  const sendBtn         = document.getElementById('sendBtn');
  const configModal     = document.getElementById('configModal');
  const modalCloseBtn   = document.getElementById('modalCloseBtn');

  const MODE_META = {
    general: { icon: '🔍', name: 'General Security' },
    cortex:  { icon: '⚡', name: 'Cortex XDR' },
    qradar:  { icon: '📡', name: 'QRadar SIEM' },
    sigma:   { icon: 'Σ',  name: 'Sigma Rules' },
  };

  // ── Configure marked.js ────────────────────────────────────────
  if (window.marked) {
    marked.setOptions({
      breaks: true,
      gfm: true,
    });
  }

  // ── Initialise ─────────────────────────────────────────────────
  async function init() {
    loadState();
    renderHistoryList();
    bindEvents();
    checkHealth();
  }

  async function checkHealth() {
    try {
      const res = await fetch('/api/health');
      const data = await res.json();
      if (!data.configured) {
        configModal.style.display = 'flex';
      }
    } catch {
      // server may not be reachable in static preview — ignore
    }
  }

  // ── State persistence ──────────────────────────────────────────
  function loadState() {
    try {
      const saved = localStorage.getItem('irai_conversations');
      if (saved) conversations = JSON.parse(saved);
      const savedMode = localStorage.getItem('irai_mode');
      if (savedMode) setMode(savedMode, false);
      const savedActive = localStorage.getItem('irai_active');
      if (savedActive && conversations.find(c => c.id === savedActive)) {
        loadConversation(savedActive);
      }
    } catch { /* ignore parse errors */ }
  }

  function saveState() {
    try {
      localStorage.setItem('irai_conversations', JSON.stringify(conversations));
      localStorage.setItem('irai_mode', currentMode);
      if (activeConvId) localStorage.setItem('irai_active', activeConvId);
    } catch { /* quota exceeded — ignore */ }
  }

  // ── Mode ───────────────────────────────────────────────────────
  function setMode(mode, persist = true) {
    currentMode = mode;
    modeBtns.forEach(btn => {
      btn.classList.toggle('active', btn.dataset.mode === mode);
    });
    const meta = MODE_META[mode] || MODE_META.general;
    currentModeIcon.textContent = meta.icon;
    currentModeName.textContent = meta.name;
    if (persist) saveState();
  }

  // ── Conversation management ────────────────────────────────────
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

  function getActiveConversation() {
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
    conv.messages.forEach(msg => renderMessage(msg, false));
    scrollToBottom();
    renderHistoryList();
    saveState();
  }

  function startNewChat() {
    activeConvId = null;
    messagesEl.innerHTML = '';
    messagesEl.style.display = 'none';
    welcomeScreen.style.display = 'flex';
    renderHistoryList();
    messageInput.focus();
  }

  // ── Render history sidebar ─────────────────────────────────────
  function renderHistoryList() {
    if (conversations.length === 0) {
      historyList.innerHTML = '<p class="empty-history">No conversations yet</p>';
      return;
    }
    historyList.innerHTML = '';
    conversations.slice(0, 40).forEach(conv => {
      const btn = document.createElement('button');
      btn.className = 'history-item' + (conv.id === activeConvId ? ' active' : '');
      btn.title = conv.title;
      const icon = MODE_META[conv.mode]?.icon || '💬';
      btn.textContent = `${icon} ${conv.title}`;
      btn.addEventListener('click', () => {
        loadConversation(conv.id);
        if (window.innerWidth <= 768) sidebar.classList.remove('open');
      });
      historyList.appendChild(btn);
    });
  }

  // ── Render a message ───────────────────────────────────────────
  function renderMessage(msg, animate = true) {
    welcomeScreen.style.display = 'none';
    messagesEl.style.display = 'flex';

    const wrap = document.createElement('div');
    wrap.className = `message ${msg.role}`;
    if (!animate) wrap.style.animation = 'none';

    const avatarText = msg.role === 'user' ? 'You' : 'AI';
    const roleName   = msg.role === 'user' ? 'You' : 'IRAI';

    let imageHtml = '';
    if (msg.imageUrl) {
      imageHtml = `<img class="message-image" src="${msg.imageUrl}" alt="Attached image" />`;
    }

    let contentHtml = '';
    if (msg.role === 'assistant') {
      contentHtml = renderMarkdown(msg.content);
    } else {
      contentHtml = escapeHtml(msg.content || '').replace(/\n/g, '<br>');
    }

    wrap.innerHTML = `
      <div class="message-avatar">${avatarText}</div>
      <div class="message-body">
        <div class="message-meta">
          <span class="message-role">${roleName}</span>
          <span class="message-time">${msg.time || formatTime()}</span>
        </div>
        <div class="message-content">
          ${imageHtml}
          ${contentHtml}
        </div>
      </div>`;

    messagesEl.appendChild(wrap);

    // Syntax highlighting for code blocks
    wrap.querySelectorAll('pre code').forEach(block => {
      if (window.hljs) hljs.highlightElement(block);
      addCopyButton(block.closest('pre'));
    });

    if (animate) scrollToBottom();
  }

  function addCopyButton(preEl) {
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
        setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
      } catch {
        btn.textContent = 'Error';
        setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
      }
    });
  }

  function renderMarkdown(text) {
    if (!window.marked) return escapeHtml(text).replace(/\n/g, '<br>');
    try {
      return marked.parse(text);
    } catch {
      return escapeHtml(text).replace(/\n/g, '<br>');
    }
  }

  function escapeHtml(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function formatTime() {
    return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function scrollToBottom() {
    chatContainer.scrollTop = chatContainer.scrollHeight;
  }

  // ── Send a message ─────────────────────────────────────────────
  async function sendMessage() {
    if (isLoading) return;

    const text = messageInput.value.trim();
    if (!text && !pendingImageFile) return;

    isLoading = true;
    sendBtn.disabled = true;
    messageInput.disabled = true;

    // Create conversation if needed
    let conv = getActiveConversation();
    if (!conv) {
      conv = createConversation(currentMode, text);
    }

    const time = formatTime();
    const userMsg = {
      role: 'user',
      content: text,
      imageUrl: pendingImageDataUrl || null,
      time,
    };
    conv.messages.push(userMsg);
    renderMessage(userMsg);

    // Reset input
    const sentText = text;
    const sentFile = pendingImageFile;
    messageInput.value = '';
    resizeTextarea();
    clearImageAttachment();
    saveState();

    // Show typing
    typingIndicator.style.display = 'flex';
    scrollToBottom();

    try {
      const formData = new FormData();
      formData.append('message', sentText);
      formData.append('mode', currentMode);
      // Send the last 30 messages as history (excluding the one we just added)
      const historySlice = conv.messages.slice(0, -1).slice(-30).map(m => ({
        role: m.role,
        content: m.content,
      }));
      formData.append('history', JSON.stringify(historySlice));
      if (sentFile) formData.append('image', sentFile);

      const res = await fetch('/api/chat', { method: 'POST', body: formData });
      const data = await res.json();

      typingIndicator.style.display = 'none';

      if (!res.ok) {
        showError(data.error || 'An error occurred');
      } else {
        const aiMsg = { role: 'assistant', content: data.reply, time: formatTime() };
        conv.messages.push(aiMsg);
        renderMessage(aiMsg);
        // Update conversation title from first user message
        if (conv.messages.filter(m => m.role === 'user').length === 1 && sentText) {
          conv.title = sentText.slice(0, 48) + (sentText.length > 48 ? '…' : '');
          renderHistoryList();
        }
        saveState();
      }
    } catch (err) {
      typingIndicator.style.display = 'none';
      showError('Network error — please check your connection.');
      console.error(err);
    } finally {
      isLoading = false;
      sendBtn.disabled = false;
      messageInput.disabled = false;
      messageInput.focus();
    }
  }

  function showError(msg) {
    const banner = document.createElement('div');
    banner.className = 'error-banner';
    banner.innerHTML = `⚠️ ${escapeHtml(msg)}`;
    messagesEl.appendChild(banner);
    scrollToBottom();
    setTimeout(() => banner.remove(), 8000);
  }

  // ── Image attachment ───────────────────────────────────────────
  function handleImageSelect(file) {
    if (!file) return;
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
    const hasContent = messageInput.value.trim().length > 0 || !!pendingImageFile;
    sendBtn.disabled = !hasContent;
  }

  function resizeTextarea() {
    messageInput.style.height = 'auto';
    messageInput.style.height = Math.min(messageInput.scrollHeight, 180) + 'px';
  }

  // ── Suggestion cards ───────────────────────────────────────────
  document.querySelectorAll('.suggestion-card').forEach(card => {
    card.addEventListener('click', () => {
      const mode = card.dataset.mode;
      const msg  = card.dataset.msg;
      if (mode) setMode(mode);
      if (msg) {
        messageInput.value = msg;
        resizeTextarea();
        updateSendBtn();
        messageInput.focus();
        sendMessage();
      }
    });
  });

  // ── Event bindings ─────────────────────────────────────────────
  function bindEvents() {
    // Sidebar toggle (mobile)
    sidebarToggle.addEventListener('click', () => sidebar.classList.toggle('open'));
    document.addEventListener('click', e => {
      if (window.innerWidth <= 768 &&
          sidebar.classList.contains('open') &&
          !sidebar.contains(e.target) &&
          e.target !== sidebarToggle) {
        sidebar.classList.remove('open');
      }
    });

    // New chat
    newChatBtn.addEventListener('click', startNewChat);

    // Mode buttons
    modeBtns.forEach(btn => {
      btn.addEventListener('click', () => setMode(btn.dataset.mode));
    });

    // Clear chat
    clearChatBtn.addEventListener('click', () => {
      if (!activeConvId) return;
      if (!confirm('Clear this conversation?')) return;
      const idx = conversations.findIndex(c => c.id === activeConvId);
      if (idx > -1) conversations.splice(idx, 1);
      startNewChat();
      saveState();
    });

    // Image input
    imageInput.addEventListener('change', e => handleImageSelect(e.target.files[0]));
    removeImageBtn.addEventListener('click', clearImageAttachment);

    // Drag and drop on chat area
    chatContainer.addEventListener('dragover', e => e.preventDefault());
    chatContainer.addEventListener('drop', e => {
      e.preventDefault();
      const file = e.dataTransfer.files[0];
      if (file && file.type.startsWith('image/')) handleImageSelect(file);
    });

    // Textarea: auto-resize + send on Enter
    messageInput.addEventListener('input', () => { resizeTextarea(); updateSendBtn(); });
    messageInput.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        if (!sendBtn.disabled && !isLoading) sendMessage();
      }
    });

    // Send button
    sendBtn.addEventListener('click', sendMessage);

    // Modal
    modalCloseBtn.addEventListener('click', () => { configModal.style.display = 'none'; });
  }

  // ── Start ──────────────────────────────────────────────────────
  init();
})();
