/* SafeStore - vanilla JS MVP
 * Features: client-only auth, roles, notes CRUD + search,
 * file metadata with data URLs, remote image preview via fetch,
 * admin panel, and audit log. All data persists in localStorage.
 */
(() => {
  'use strict';
  // --- Storage keys
  const K = {
    users: 'safestore_users',
    notes: 'safestore_notes',
    files: 'safestore_files',
    session: 'safestore_session',
    audit: 'safestore_audit'
  };
  Object.freeze(K);

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

  // --- In-memory state
  let selectedNoteId = null;
  let lastObjectURLs = [];

  // --- Utilities
  const read = (k, d=[]) => {
    try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; }
  };
  const write = (k, v) => localStorage.setItem(k, JSON.stringify(v));
  const uuid = () => {
    const b = new Uint8Array(16); crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
    const h = [...b].map(v => v.toString(16).padStart(2,'0')).join('');
    return h.slice(0,8)+'-'+h.slice(8,12)+'-'+h.slice(12,16)+'-'+h.slice(16,20)+'-'+h.slice(20);
  };
  const nowISO = () => new Date().toISOString();

  async function hashPassword(p) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(p||''));
    return [...new Uint8Array(buf)].map(v=>v.toString(16).padStart(2,'0')).join('');
  }

  function isValidEmail(email) {
    const e = (email||'').trim().toLowerCase();
    return e.includes('@') && e.length <= 254;
  }
  function isStrongPassword(p) { return (p||'').length >= 8; }

  function isSafeUrl(url) {
    try { const u = new URL(url); return u.protocol === 'https:' && !u.username && !u.password; } catch { return false; }
  }

  function sanitizeHTML(input='') {
    const parser = new DOMParser();
    const doc = parser.parseFromString(input, 'text/html');
    const allowed = new Set(['b','i','strong','em','u','p','br','ol','ul','li','code','pre','blockquote','a','span']);
    const allowedAttrs = { a: ['href'] };
    function clean(n) {
      if (n.nodeType === Node.TEXT_NODE) return document.createTextNode(n.textContent);
      if (n.nodeType !== Node.ELEMENT_NODE) return document.createTextNode('');
      const tag = n.tagName.toLowerCase();
      if (!allowed.has(tag)) return document.createTextNode('');
      const el2 = document.createElement(tag);
      for (const attr of [...n.attributes]) {
        const name = attr.name.toLowerCase();
        if (name.startsWith('on') || name === 'style') continue;
        if (tag === 'a' && name === 'href') {
          const href = attr.value.trim();
          if (isSafeHref(href)) {
            el2.setAttribute('href', href);
            el2.setAttribute('rel','noopener noreferrer');
            el2.setAttribute('target','_blank');
          }
          continue;
        }
        if ((allowedAttrs[tag]||[]).includes(name)) el2.setAttribute(name, attr.value);
      }
      for (const child of [...n.childNodes]) el2.appendChild(clean(child));
      return el2;
    }
    function isSafeHref(href) {
      try { const u = new URL(href, 'https://example.com'); const ok = ['http:','https:'].includes(u.protocol) || href.startsWith('#') || href.startsWith('mailto:'); return ok; } catch { return href.startsWith('#'); }
    }
    const tmp = document.createElement('div');
    for (const c of [...doc.body.childNodes]) tmp.appendChild(clean(c));
    return tmp.innerHTML;
  }

  // --- Audit logging
  function logAudit(action, details) {
    const a = read(K.audit, []);
    a.unshift({ time: nowISO(), action, details });
    write(K.audit, a);
    renderAudit();
  }
  function renderAudit() {
    const a = read(K.audit, []);
    const ul = el.auditLogList; ul.textContent = '';
    const frag = document.createDocumentFragment();
    for (const x of a) {
      const li = document.createElement('li');
      const s1 = document.createElement('strong'); s1.textContent = x.action;
      const meta = document.createElement('span'); meta.className = 'meta'; meta.textContent = x.time;
      const br = document.createElement('br');
      const d = document.createElement('span'); d.textContent = shorten(JSON.stringify(x.details));
      li.appendChild(s1); li.appendChild(meta); li.appendChild(br); li.appendChild(d);
      frag.appendChild(li);
    }
    ul.appendChild(frag);
  }

  // --- Auth
  function usersAll() { return read(K.users, []); }
  function setUsers(all) { write(K.users, all); }
  function findUserByEmail(email) { return usersAll().find(u => u.email === email); }

  async function register(email, password, role) {
    email = (email||'').trim().toLowerCase();
    if (!isValidEmail(email) || !isStrongPassword(password)) return msg(el.authMsg, 'Invalid email or weak password (min 8 chars)', true);
    if (findUserByEmail(email)) return msg(el.authMsg, 'User already exists', true);
    const passwordHash = await hashPassword(password);
    const user = { id: uuid(), email, passwordHash, role: role === 'admin' ? 'admin' : 'user', createdAt: nowISO() };
    const all = usersAll(); all.push(user); setUsers(all);
    msg(el.authMsg, 'Registered. Please login.', false);
    logAudit('register', { email, role: user.role });
  }

  async function login(email, password) {
    const u = findUserByEmail((email||'').trim().toLowerCase());
    if (!u) return msg(el.authMsg, 'Invalid credentials', true);
    const passwordHash = await hashPassword(password||'');
    if (u.passwordHash !== passwordHash) {
      if (u.password && u.password === (password||'')) {
        u.passwordHash = await hashPassword(u.password);
        delete u.password;
        const all = usersAll().map(x => x.id === u.id ? u : x); setUsers(all);
        logAudit('password_migrated', { email: u.email });
      } else {
        return msg(el.authMsg, 'Invalid credentials', true);
      }
    }
    const token = { token: uuid(), userId: u.id, email: u.email, role: u.role, createdAt: nowISO() };
    write(K.session, token);
    logAudit('login', { email: u.email, role: u.role });
    hydrateUI();
  }

  function logout() {
    localStorage.removeItem(K.session);
    logAudit('logout', {});
    hydrateUI();
  }

  function session() {
    try { return JSON.parse(localStorage.getItem(K.session)); } catch { return null; }
  }
  function isLoggedIn() { return !!session(); }
  function isAdmin() { return session()?.role === 'admin'; }

  // --- Notes
  function notesAll() { return read(K.notes, []); }
  function setNotes(all) { write(K.notes, all); }
  function notesByUser(userId) { return notesAll().filter(n => n.ownerId === userId); }
  function getNote(id) { return notesAll().find(n => n.id === id) || null; }

  function saveCurrentNote() {
    const s = session(); if (!s) return;
    const title = el.noteTitleInput.value.trim();
    const contentHtml = sanitizeHTML(el.noteContentEditable.innerHTML.trim());
    if (!title && !contentHtml) return msg(el.noteMsg, 'Nothing to save', true);
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
    if (!selectedNoteId) return msg(el.noteMsg, 'No note selected', true);
    const n = getNote(selectedNoteId);
    setNotes(notesAll().filter(x => x.id !== selectedNoteId));
    logAudit('note_deleted', { id: selectedNoteId, title: n?.title });
    selectedNoteId = null;
    el.noteTitleInput.value = '';
    el.noteContentEditable.innerHTML = '';
    msg(el.noteMsg, 'Deleted', false);
    renderNotesList();
  }
  function renderNotesList() {
    const s = session(); if (!s) return;
    const q = (el.noteSearchInput.value||'').toLowerCase();
    const list = notesByUser(s.userId).filter(n => !q || (n.title||'').toLowerCase().includes(q) || (n.contentHtml||'').toLowerCase().includes(q));
    const ul = el.notesList; ul.textContent = '';
    const frag = document.createDocumentFragment();
    for (const n of list) {
      const li = document.createElement('li');
      li.dataset.id = n.id;
      const t = document.createElement('span'); t.textContent = n.title || '(untitled)';
      const meta = document.createElement('span'); meta.className = 'meta'; meta.textContent = n.updatedAt;
      li.appendChild(t); li.appendChild(meta);
      li.addEventListener('click', () => {
        const id = li.dataset.id; const nn = getNote(id); if (!nn) return;
        selectedNoteId = id; el.noteTitleInput.value = nn.title || '';
        el.noteContentEditable.innerHTML = sanitizeHTML(nn.contentHtml || '');
      });
      frag.appendChild(li);
    }
    ul.appendChild(frag);
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
  function renderFiles() {
    const s = session(); if (!s) return;
    for (const u of lastObjectURLs) try { URL.revokeObjectURL(u); } catch {}
    lastObjectURLs = [];
    const list = filesByUser(s.userId);
    const ul = el.fileList; ul.textContent = '';
    const frag = document.createDocumentFragment();
    for (const f of list) {
      const li = document.createElement('li');
      const name = document.createElement('span'); name.textContent = f.name;
      const meta = document.createElement('span'); meta.className = 'meta'; meta.textContent = `${f.type||'unknown'} · ${fmtBytes(f.size)} · ${f.savedAt}`;
      const blob = dataURLToBlob(f.dataUrl);
      const url = URL.createObjectURL(blob); lastObjectURLs.push(url);
      const a = document.createElement('a'); a.href = url; a.download = escapeAttr(f.name);
      a.textContent = 'Download';
      li.appendChild(name); li.appendChild(meta); li.appendChild(a);
      frag.appendChild(li);
    }
    ul.appendChild(frag);
  }

  // --- Remote image preview via fetch()
  async function previewRemoteImage(url) {
    if (!isSafeUrl(url)) { el.imageFetchStatus.textContent = 'Enter a valid https:// URL'; logAudit('image_preview', { url, ok: false, error: 'invalid_url' }); return; }
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
    el.imageFetchStatus.textContent = 'Fetching via CORS…';
    try {
      const res = await fetch(url, { mode: 'cors' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      if (!String(blob.type||'').startsWith('image/')) throw new Error('not_image');
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
    const uUl = el.adminUsersList; uUl.textContent='';
    const nUl = el.adminNotesList; nUl.textContent='';
    const fUl = el.adminFilesList; fUl.textContent='';
    const uf = document.createDocumentFragment();
    for (const u of allUsers) { const li=document.createElement('li'); const s1=document.createElement('span'); s1.textContent=u.email; const meta=document.createElement('span'); meta.className='meta'; meta.textContent=`${u.role} · ${u.createdAt}`; li.appendChild(s1); li.appendChild(meta); uf.appendChild(li);} uUl.appendChild(uf);
    const nf = document.createDocumentFragment();
    for (const n of allNotes) { const li=document.createElement('li'); const s1=document.createElement('span'); s1.textContent=n.title||'(untitled)'; const meta=document.createElement('span'); meta.className='meta'; meta.textContent=`owner:${ownerEmail(n.ownerId)} · ${n.updatedAt}`; li.appendChild(s1); li.appendChild(meta); nf.appendChild(li);} nUl.appendChild(nf);
    const ff = document.createDocumentFragment();
    for (const f of allFiles) { const li=document.createElement('li'); const s1=document.createElement('span'); s1.textContent=f.name; const meta=document.createElement('span'); meta.className='meta'; meta.textContent=`owner:${ownerEmail(f.ownerId)} · ${f.type} · ${fmtBytes(f.size)}`; li.appendChild(s1); li.appendChild(meta); ff.appendChild(li);} fUl.appendChild(ff);
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
  function escapeHTML(s='') { return s.replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
  function escapeAttr(s='') { return s.replace(/["']/g, ''); }
  function fmtBytes(n=0) { return n < 1024 ? `${n} B` : n < 1024*1024 ? `${(n/1024).toFixed(1)} KB` : `${(n/1024/1024).toFixed(1)} MB`; }
  function shorten(s, n=200) { return s.length>n ? s.slice(0,n)+'…' : s; }

  // --- Event bindings
  function bindEvents() {
    el.registerForm.addEventListener('submit', async (e) => { e.preventDefault(); await register(el.regEmail.value, el.regPassword.value, el.regRole.value); });
    el.loginForm.addEventListener('submit', async (e) => { e.preventDefault(); await login(el.loginEmail.value, el.loginPassword.value); });
    el.logoutBtn.addEventListener('click', logout);

    el.noteSearchInput.addEventListener('input', renderNotesList);
    el.saveNoteBtn.addEventListener('click', saveCurrentNote);
    el.newNoteBtn.addEventListener('click', () => { selectedNoteId = null; el.noteTitleInput.value=''; el.noteContentEditable.innerHTML=''; msg(el.noteMsg, 'New note', false); });
    el.deleteNoteBtn.addEventListener('click', deleteCurrentNote);

    el.fileInput.addEventListener('change', () => { const f = el.fileInput.files?.[0]; handleFile(f); });

    el.previewImageBtn.addEventListener('click', () => {
      const url = (el.imageUrlInput.value||'').trim(); if (!url) { el.imageFetchStatus.textContent = 'Enter a URL'; return; }
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
