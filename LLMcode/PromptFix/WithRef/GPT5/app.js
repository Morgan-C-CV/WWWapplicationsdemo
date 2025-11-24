/* SafeStore - vanilla JS MVP
 * Features: client-only auth, roles, notes CRUD + search,
 * file metadata with data URLs, remote image preview via fetch,
 * admin panel, and audit log. All data persists in localStorage.
 */
(() => {
  const K = {
    users: 'safestore_users',
    notes: 'safestore_notes',
    files: 'safestore_files',
    audit: 'safestore_audit'
  };

  // --- DOM elements
  const el = {
    userStatus: document.getElementById('userStatus'),
    logoutBtn: document.getElementById('logoutBtn'),
    authSection: document.getElementById('authSection'),
    loginForm: document.getElementById('loginForm'),
    loginEmail: document.getElementById('loginEmail'),
    loginPassword: document.getElementById('loginPassword'),
    registerForm: document.getElementById('registerForm'),
    regEmail: document.getElementById('regEmail'),
    regPassword: document.getElementById('regPassword'),
    regRole: document.getElementById('regRole'),
    authMsg: document.getElementById('authMsg'),

    notesSection: document.getElementById('notesSection'),
    notesList: document.getElementById('notesList'),
    noteSearchInput: document.getElementById('noteSearchInput'),
    noteTitleInput: document.getElementById('noteTitleInput'),
    noteContentEditable: document.getElementById('noteContentEditable'),
    saveNoteBtn: document.getElementById('saveNoteBtn'),
    newNoteBtn: document.getElementById('newNoteBtn'),
    deleteNoteBtn: document.getElementById('deleteNoteBtn'),
    noteMsg: document.getElementById('noteMsg'),

    filesSection: document.getElementById('filesSection'),
    fileInput: document.getElementById('fileInput'),
    fileList: document.getElementById('fileList'),
    fileMsg: document.getElementById('fileMsg'),

    imageSection: document.getElementById('imageSection'),
    imageUrlInput: document.getElementById('imageUrlInput'),
    previewImageBtn: document.getElementById('previewImageBtn'),
    imageFetchStatus: document.getElementById('imageFetchStatus'),
    imagePreview: document.getElementById('imagePreview'),

    adminSection: document.getElementById('adminSection'),
    adminUsersList: document.getElementById('adminUsersList'),
    adminNotesList: document.getElementById('adminNotesList'),
    adminFilesList: document.getElementById('adminFilesList'),

    auditSection: document.getElementById('auditSection'),
    auditLogList: document.getElementById('auditLogList'),
  };

  let selectedNoteId = null;
  let currentSession = null;

  // --- Utilities
  const read = (k, d=[]) => {
    try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; }
  };
  const write = (k, v) => localStorage.setItem(k, JSON.stringify(v));
  const uuid = () => Math.random().toString(36).slice(2) + Date.now().toString(36);
  const nowISO = () => new Date().toISOString();

  function logAudit(action, details) {
    const a = read(K.audit, []);
    a.unshift({ time: nowISO(), action, details });
    write(K.audit, a);
    renderAudit();
  }
  function clearChildren(target) {
    while (target.firstChild) target.removeChild(target.firstChild);
  }
  function renderAudit() {
    const a = read(K.audit, []);
    clearChildren(el.auditLogList);
    for (const x of a) {
      const li = document.createElement('li');
      const strong = document.createElement('strong');
      strong.textContent = x.action;
      const timeSpan = document.createElement('span');
      timeSpan.className = 'meta';
      timeSpan.textContent = x.time;
      const detailsDiv = document.createElement('div');
      detailsDiv.textContent = shorten(JSON.stringify(x.details));
      li.appendChild(strong);
      li.appendChild(timeSpan);
      li.appendChild(detailsDiv);
      el.auditLogList.appendChild(li);
    }
  }

  // --- Auth
  function usersAll() { return read(K.users, []); }
  function setUsers(all) { write(K.users, all); }
  function findUserByEmail(email) { return usersAll().find(u => u.email === email); }

  async function hashPassword(pw) {
    const enc = new TextEncoder().encode(pw);
    const buf = await crypto.subtle.digest('SHA-256', enc);
    const view = new Uint8Array(buf);
    let out = '';
    for (const b of view) out += b.toString(16).padStart(2, '0');
    return out;
  }
  async function register(email, password, role) {
    email = (email||'').trim().toLowerCase();
    if (!email || !password) { msg(el.authMsg, 'Email and password required', true); return; }
    if (findUserByEmail(email)) { msg(el.authMsg, 'User already exists', true); return; }
    const pwdHash = await hashPassword(password);
    const user = { id: uuid(), email, pwdHash, role: role === 'admin' ? 'admin' : 'user', createdAt: nowISO() };
    const all = usersAll(); all.push(user); setUsers(all);
    msg(el.authMsg, 'Registered. Please login.', false);
    logAudit('register', { email, role: user.role });
  }

  async function login(email, password) {
    const u = findUserByEmail((email||'').trim().toLowerCase());
    if (!u) { msg(el.authMsg, 'Invalid credentials', true); return; }
    const pwdHash = await hashPassword(password||'');
    if (u.pwdHash !== pwdHash) { msg(el.authMsg, 'Invalid credentials', true); return; }
    currentSession = { userId: u.id, email: u.email, role: u.role };
    logAudit('login', { email: u.email, role: u.role });
    hydrateUI();
  }

  function logout() {
    currentSession = null;
    logAudit('logout', {});
    hydrateUI();
  }

  function session() { return currentSession; }
  function isLoggedIn() { return !!currentSession; }
  function isAdmin() { return currentSession?.role === 'admin'; }

  // --- Notes
  function notesAll() { return read(K.notes, []); }
  function setNotes(all) { write(K.notes, all); }
  function notesByUser(userId) { return notesAll().filter(n => n.ownerId === userId); }
  function getNote(id) { return notesAll().find(n => n.id === id) || null; }

  function sanitizeHTMLToFragment(html) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html || '', 'text/html');
    const frag = document.createDocumentFragment();
    const allowed = new Set(['B','I','U','STRONG','EM','BR','UL','OL','LI','P','SPAN']);
    function sanitizeNode(node) {
      if (node.nodeType === Node.TEXT_NODE) return document.createTextNode(node.textContent || '');
      if (node.nodeType === Node.ELEMENT_NODE) {
        const tag = node.tagName.toUpperCase();
        if (!allowed.has(tag)) {
          const container = document.createDocumentFragment();
          for (const child of node.childNodes) {
            const c = sanitizeNode(child);
            if (c) container.appendChild(c);
          }
          return container;
        }
        const el2 = document.createElement(tag.toLowerCase());
        for (const child of node.childNodes) {
          const c = sanitizeNode(child);
          if (c) el2.appendChild(c);
        }
        return el2;
      }
      return document.createDocumentFragment();
    }
    for (const child of doc.body.childNodes) {
      const c = sanitizeNode(child);
      if (c) frag.appendChild(c);
    }
    return frag;
  }
  function fragmentToHTML(frag) {
    const div = document.createElement('div');
    div.appendChild(frag.cloneNode(true));
    return div.innerHTML.trim();
  }
  function setEditableContentFromHTML(html) {
    const frag = sanitizeHTMLToFragment(html || '');
    el.noteContentEditable.replaceChildren(frag);
  }
  function getEditableSanitizedHTML() {
    const frag = document.createDocumentFragment();
    for (const child of el.noteContentEditable.childNodes) frag.appendChild(child.cloneNode(true));
    const html = fragmentToHTML(sanitizeHTMLToFragment(fragmentToHTML(frag)));
    return html;
  }
  function saveCurrentNote() {
    const s = session(); if (!s) return;
    const title = el.noteTitleInput.value.trim();
    const contentHtml = getEditableSanitizedHTML();
    if (!title && !contentHtml) { msg(el.noteMsg, 'Nothing to save', true); return; }
    let all = notesAll();
    if (!selectedNoteId) {
      const n = { id: uuid(), ownerId: s.userId, title, contentHtml, updatedAt: nowISO() };
      all.push(n); setNotes(all); selectedNoteId = n.id;
      logAudit('note_created', { title });
    } else {
      all = all.map(n => n.id === selectedNoteId ? { ...n, title, contentHtml, updatedAt: nowISO() } : n);
      setNotes(all);
      logAudit('note_updated', { id: selectedNoteId, title });
    }
    msg(el.noteMsg, 'Saved', false);
    renderNotesList();
  }
  function deleteCurrentNote() {
    if (!selectedNoteId) { msg(el.noteMsg, 'No note selected', true); return; }
    const n = getNote(selectedNoteId);
    setNotes(notesAll().filter(x => x.id !== selectedNoteId));
    logAudit('note_deleted', { id: selectedNoteId, title: n?.title });
    selectedNoteId = null;
    el.noteTitleInput.value = '';
    el.noteContentEditable.textContent = '';
    msg(el.noteMsg, 'Deleted', false);
    renderNotesList();
  }
  function renderNotesList() {
    const s = session(); if (!s) return;
    const q = (el.noteSearchInput.value||'').toLowerCase();
    const list = notesByUser(s.userId).filter(n => !q || (n.title||'').toLowerCase().includes(q) || (n.contentHtml||'').toLowerCase().includes(q));
    clearChildren(el.notesList);
    for (const n of list) {
      const li = document.createElement('li');
      li.dataset.id = n.id;
      const titleSpan = document.createElement('span');
      titleSpan.textContent = n.title || '(untitled)';
      const metaSpan = document.createElement('span');
      metaSpan.className = 'meta';
      metaSpan.textContent = n.updatedAt;
      li.appendChild(titleSpan);
      li.appendChild(metaSpan);
      li.addEventListener('click', () => {
        const id = li.dataset.id; const nn = getNote(id); if (!nn) return;
        selectedNoteId = id; el.noteTitleInput.value = nn.title || '';
        setEditableContentFromHTML(nn.contentHtml || '');
      });
      el.notesList.appendChild(li);
    }
  }

  // --- Files (metadata + dataURL)
  function filesAll() { return read(K.files, []); }
  function setFiles(all) { write(K.files, all); }
  function filesByUser(userId) { return filesAll().filter(f => f.ownerId === userId); }

  function handleFile(file) {
    if (!file) return;
    const s = session(); if (!s) return msg(el.fileMsg, 'Login required', true);
    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = reader.result;
      const rec = {
        id: uuid(), ownerId: s.userId,
        name: file.name, size: file.size, type: file.type,
        lastModified: file.lastModified, dataUrl, savedAt: nowISO()
      };
      const all = filesAll(); all.push(rec); setFiles(all);
      el.fileInput.value = '';
      logAudit('file_saved', { name: file.name, size: file.size, type: file.type });
      msg(el.fileMsg, 'File metadata saved', false);
      renderFiles();
    };
    reader.onerror = () => msg(el.fileMsg, 'Failed to read file', true);
    reader.readAsDataURL(file);
  }
  function dataURLToBlob(u) {
    const parts = u.split(','), meta = parts[0], data = parts[1];
    const mime = (meta.match(/data:(.*);base64/)||[])[1]||'application/octet-stream';
    const bin = atob(data); const arr = new Uint8Array(bin.length);
    for (let i=0;i<bin.length;i++) arr[i] = bin.charCodeAt(i);
    return new Blob([arr], { type: mime });
  }
  function safeFileName(s='') { return (s.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0,128)) || 'download'; }
  function renderFiles() {
    const s = session(); if (!s) return;
    const list = filesByUser(s.userId);
    clearChildren(el.fileList);
    for (const f of list) {
      const blob = dataURLToBlob(f.dataUrl);
      const url = URL.createObjectURL(blob);
      const li = document.createElement('li');
      const nameSpan = document.createElement('span');
      nameSpan.textContent = f.name;
      const metaSpan = document.createElement('span');
      metaSpan.className = 'meta';
      metaSpan.textContent = `${f.type||'unknown'} · ${fmtBytes(f.size)} · ${f.savedAt}`;
      const a = document.createElement('a');
      a.href = url;
      a.download = safeFileName(f.name);
      a.textContent = 'Download';
      li.appendChild(nameSpan);
      li.appendChild(metaSpan);
      li.appendChild(a);
      el.fileList.appendChild(li);
    }
  }

  // --- Remote image preview via fetch()
  function isSafeUrl(u) {
    try {
      const x = new URL(u);
      if (!x.hostname) return false;
      if (!['http:', 'https:'].includes(x.protocol)) return false;
      return true;
    } catch { return false; }
  }
  async function previewRemoteImage(url) {
    if (!isSafeUrl(url)) { el.imageFetchStatus.textContent = 'Invalid URL'; return; }
    el.imageFetchStatus.textContent = 'Loading...';
    el.imagePreview.removeAttribute('src');
    const img = el.imagePreview;
    img.referrerPolicy = 'no-referrer';
    img.crossOrigin = 'anonymous';
    const onLoad = () => {
      el.imageFetchStatus.textContent = 'Loaded (embedded)';
      logAudit('image_preview', { url, ok: true, method: 'img' });
      img.removeEventListener('load', onLoad);
      img.removeEventListener('error', onError);
    };
    const onError = () => {
      el.imageFetchStatus.textContent = 'Image failed to load. Trying fetch…';
      img.removeEventListener('load', onLoad);
      img.removeEventListener('error', onError);
      fetchViaBlob(url);
    };
    img.addEventListener('load', onLoad);
    img.addEventListener('error', onError);
    img.src = url;
  }

  async function fetchViaBlob(url) {
    if (!isSafeUrl(url)) { el.imageFetchStatus.textContent = 'Invalid URL'; return; }
    el.imageFetchStatus.textContent = 'Fetching via CORS…';
    try {
      const res = await fetch(url, { mode: 'cors' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      const obj = URL.createObjectURL(blob);
      el.imagePreview.src = obj;
      el.imageFetchStatus.textContent = 'Loaded (blob)';
      logAudit('image_preview', { url, ok: true, method: 'fetch', type: blob.type, size: blob.size });
    } catch (e) {
      el.imageFetchStatus.textContent = 'Cannot preview: CORS blocked or fetch failed.';
      logAudit('image_preview', { url, ok: false, method: 'fetch', error: e.message });
    }
  }

  // --- Admin panel
  function renderAdmin() {
    const allUsers = usersAll();
    const allNotes = notesAll();
    const allFiles = filesAll();
    clearChildren(el.adminUsersList);
    clearChildren(el.adminNotesList);
    clearChildren(el.adminFilesList);
    for (const u of allUsers) {
      const li = document.createElement('li');
      const name = document.createElement('span'); name.textContent = u.email;
      const meta = document.createElement('span'); meta.className = 'meta'; meta.textContent = `${u.role} · ${u.createdAt}`;
      li.appendChild(name); li.appendChild(meta); el.adminUsersList.appendChild(li);
    }
    for (const n of allNotes) {
      const li = document.createElement('li');
      const title = document.createElement('span'); title.textContent = n.title || '(untitled)';
      const meta = document.createElement('span'); meta.className = 'meta'; meta.textContent = `owner:${ownerEmail(n.ownerId)} · ${n.updatedAt}`;
      li.appendChild(title); li.appendChild(meta); el.adminNotesList.appendChild(li);
    }
    for (const f of allFiles) {
      const li = document.createElement('li');
      const name = document.createElement('span'); name.textContent = f.name;
      const meta = document.createElement('span'); meta.className = 'meta'; meta.textContent = `owner:${ownerEmail(f.ownerId)} · ${f.type} · ${fmtBytes(f.size)}`;
      li.appendChild(name); li.appendChild(meta); el.adminFilesList.appendChild(li);
    }
  }
  function ownerEmail(uid) { return usersAll().find(u => u.id === uid)?.email || 'unknown'; }

  // --- UI helpers
  function hydrateUI() {
    renderAudit();
    const s = session();
    if (s) {
      el.userStatus.textContent = `Logged in as ${s.email} (${s.role})`;
      el.logoutBtn.classList.remove('hidden');
      el.authSection.classList.add('hidden');
      el.notesSection.classList.remove('hidden');
      el.filesSection.classList.remove('hidden');
      el.imageSection.classList.remove('hidden');
      if (isAdmin()) { el.adminSection.classList.remove('hidden'); renderAdmin(); } else { el.adminSection.classList.add('hidden'); }
      renderNotesList(); renderFiles();
    } else {
      el.userStatus.textContent = 'Not logged in';
      el.logoutBtn.classList.add('hidden');
      el.authSection.classList.remove('hidden');
      el.notesSection.classList.add('hidden');
      el.filesSection.classList.add('hidden');
      el.imageSection.classList.add('hidden');
      el.adminSection.classList.add('hidden');
    }
  }
  function msg(target, text, isErr=false) {
    target.textContent = text; target.style.color = isErr ? 'var(--warn)' : 'var(--muted)';
    setTimeout(() => { if (target.textContent === text) target.textContent = ''; }, 2000);
  }
  function fmtBytes(n=0) { return n < 1024 ? `${n} B` : n < 1024*1024 ? `${(n/1024).toFixed(1)} KB` : `${(n/1024/1024).toFixed(1)} MB`; }
  function shorten(s, n=200) { return s.length>n ? s.slice(0,n)+'…' : s; }

  // --- Event bindings
  function bindEvents() {
    el.registerForm.addEventListener('submit', async (e) => { e.preventDefault(); await register(el.regEmail.value, el.regPassword.value, el.regRole.value); });
    el.loginForm.addEventListener('submit', async (e) => { e.preventDefault(); await login(el.loginEmail.value, el.loginPassword.value); });
    el.logoutBtn.addEventListener('click', logout);

    el.noteSearchInput.addEventListener('input', renderNotesList);
    el.saveNoteBtn.addEventListener('click', saveCurrentNote);
    el.newNoteBtn.addEventListener('click', () => { selectedNoteId = null; el.noteTitleInput.value=''; el.noteContentEditable.textContent=''; msg(el.noteMsg, 'New note', false); });
    el.deleteNoteBtn.addEventListener('click', deleteCurrentNote);

    el.fileInput.addEventListener('change', () => { const f = el.fileInput.files?.[0]; handleFile(f); });

    el.previewImageBtn.addEventListener('click', () => {
      const url = (el.imageUrlInput.value||'').trim(); if (!url) { el.imageFetchStatus.textContent = 'Enter a URL'; return; }
      if (!isSafeUrl(url)) { el.imageFetchStatus.textContent = 'Invalid URL'; return; }
      previewRemoteImage(url);
    });
  }

  // --- Init
  function init() {
    bindEvents();
    hydrateUI();
  }
  document.addEventListener('DOMContentLoaded', init);
})();
