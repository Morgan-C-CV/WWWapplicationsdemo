// SafeStore - Client-side Secure Storage Application

// Storage keys
const STORAGE_KEYS = {
    USERS: 'safestore_users',
    NOTES: 'safestore_notes',
    FILES: 'safestore_files',
    AUDIT_LOG: 'safestore_audit_log',
    SESSION: 'safestore_session'
};

// Application state
let currentUser = null;
let currentNoteId = null;
let notes = [];
let files = [];
let auditLog = [];

// DOM Elements
const elements = {
    authSection: document.getElementById('auth-section'),
    appSection: document.getElementById('app-section'),
    loginForm: document.getElementById('login-form'),
    registerForm: document.getElementById('register-form'),
    userEmail: document.getElementById('user-email'),
    userRole: document.getElementById('user-role'),
    logoutBtn: document.getElementById('logout-btn'),
    notesList: document.getElementById('notes-list'),
    noteEditor: document.getElementById('note-editor'),
    noteTitle: document.getElementById('note-title'),
    noteContent: document.getElementById('note-content'),
    filesList: document.getElementById('files-list'),
    auditLogContainer: document.getElementById('audit-log'),
    usersList: document.getElementById('users-list'),
    allNotesList: document.getElementById('all-notes-list'),
    allFilesList: document.getElementById('all-files-list'),
    searchInput: document.getElementById('search-input'),
    imagePreview: document.getElementById('image-preview'),
    previewStatus: document.getElementById('preview-status')
};

// Initialize application
function initApp() {
    loadData();
    checkSession();
    setupEventListeners();
    addAuditLog('Application initialized', 'info');
}

// Load data from localStorage
function loadData() {
    notes = JSON.parse(localStorage.getItem(STORAGE_KEYS.NOTES) || '[]');
    files = JSON.parse(localStorage.getItem(STORAGE_KEYS.FILES) || '[]');
    auditLog = JSON.parse(localStorage.getItem(STORAGE_KEYS.AUDIT_LOG) || '[]');
}

// Save data to localStorage
function saveData() {
    localStorage.setItem(STORAGE_KEYS.NOTES, JSON.stringify(notes));
    localStorage.setItem(STORAGE_KEYS.FILES, JSON.stringify(files));
    localStorage.setItem(STORAGE_KEYS.AUDIT_LOG, JSON.stringify(auditLog));
}

// Check if user has active session
function checkSession() {
    const session = JSON.parse(localStorage.getItem(STORAGE_KEYS.SESSION) || 'null');
    if (session && session.expires > Date.now()) {
        currentUser = session.user;
        showApp();
    } else {
        showAuth();
        localStorage.removeItem(STORAGE_KEYS.SESSION);
    }
}

// Show authentication section
function showAuth() {
    elements.authSection.style.display = 'block';
    elements.appSection.style.display = 'none';
}

// Show main application section
function showApp() {
    elements.authSection.style.display = 'none';
    elements.appSection.style.display = 'block';
    
    elements.userEmail.textContent = currentUser.email;
    elements.userRole.textContent = `(${currentUser.role})`;
    
    // Show admin tab if user is admin
    const adminTab = document.querySelector('.admin-only');
    if (adminTab) {
        adminTab.style.display = currentUser.role === 'admin' ? 'block' : 'none';
    }
    
    renderNotes();
    renderFiles();
    renderAuditLog();
    
    if (currentUser.role === 'admin') {
        renderAdminPanel();
    }
}

// Setup event listeners
function setupEventListeners() {
    // Auth forms
    document.getElementById('login').addEventListener('submit', handleLogin);
    document.getElementById('register').addEventListener('submit', handleRegister);
    document.getElementById('show-register').addEventListener('click', showRegisterForm);
    document.getElementById('show-login').addEventListener('click', showLoginForm);
    
    // Navigation
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', handleTabChange);
    });
    
    // Notes
    document.getElementById('new-note-btn').addEventListener('click', createNewNote);
    document.getElementById('save-note').addEventListener('click', saveNote);
    document.getElementById('cancel-edit').addEventListener('click', cancelEdit);
    
    // Files
    document.getElementById('upload-btn').addEventListener('click', handleFileUpload);
    
    // Remote images
    document.getElementById('preview-btn').addEventListener('click', previewRemoteImage);
    
    // Search
    elements.searchInput.addEventListener('input', handleSearch);
    
    // Logout
    elements.logoutBtn.addEventListener('click', handleLogout);
}

// Auth handlers
function handleLogin(e) {
    e.preventDefault();
    
    const email = sanitizeInput(document.getElementById('login-email').value);
    const password = document.getElementById('login-password').value;
    
    const users = JSON.parse(localStorage.getItem(STORAGE_KEYS.USERS) || '[]');
    const user = users.find(u => u.email === email && validatePassword(u.password, password));
    
    if (user) {
        // Create session
        currentUser = { email: user.email, role: user.role };
        const session = {
            user: currentUser,
            expires: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
        };
        
        localStorage.setItem(STORAGE_KEYS.SESSION, JSON.stringify(session));
        showApp();
        addAuditLog('User logged in', 'success', { email });
    } else {
        alert('Invalid email or password');
        addAuditLog('Failed login attempt', 'error', { email });
    }
}

function handleRegister(e) {
    e.preventDefault();
    
    const email = sanitizeInput(document.getElementById('register-email').value);
    const password = document.getElementById('register-password').value;
    const isAdmin = document.getElementById('register-admin').checked;
    
    if (!isValidEmail(email)) {
        alert('Please enter a valid email address');
        return;
    }
    
    if (!isValidPassword(password)) {
        alert('Password must be at least 8 characters long');
        return;
    }
    
    const users = JSON.parse(localStorage.getItem(STORAGE_KEYS.USERS) || '[]');
    
    if (users.some(u => u.email === email)) {
        alert('Email already registered');
        return;
    }
    
    const newUser = {
        email,
        password: hashPassword(password),
        role: isAdmin ? 'admin' : 'user',
        createdAt: new Date().toISOString()
    };
    
    users.push(newUser);
    localStorage.setItem(STORAGE_KEYS.USERS, JSON.stringify(users));
    
    // Auto-login after registration
    currentUser = { email: newUser.email, role: newUser.role };
    const session = {
        user: currentUser,
        expires: Date.now() + (24 * 60 * 60 * 1000)
    };
    
    localStorage.setItem(STORAGE_KEYS.SESSION, JSON.stringify(session));
    showApp();
    addAuditLog('New user registered', 'success', { email, role: newUser.role });
}

function showRegisterForm(e) {
    e.preventDefault();
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('register-form').style.display = 'block';
}

function showLoginForm(e) {
    e.preventDefault();
    document.getElementById('register-form').style.display = 'none';
    document.getElementById('login-form').style.display = 'block';
}

function handleLogout() {
    currentUser = null;
    localStorage.removeItem(STORAGE_KEYS.SESSION);
    showAuth();
    addAuditLog('User logged out', 'info', { email: currentUser?.email });
}

function handleTabChange(e) {
    const tabName = e.target.dataset.tab;
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.style.display = 'none';
    });
    document.getElementById(tabName).style.display = 'block';
    
    // Update active tab styling
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    e.target.classList.add('active');
}

function handleSearch() {
    renderNotes();
}

// Notes functionality
function renderNotes() {
    const searchTerm = elements.searchInput.value.toLowerCase();
    const userNotes = notes.filter(note => note.owner === currentUser.email);
    const filteredNotes = searchTerm 
        ? userNotes.filter(note => 
            note.title.toLowerCase().includes(searchTerm) || 
            note.content.toLowerCase().includes(searchTerm))
        : userNotes;
    
    // Clear existing content safely
    clearElement(elements.notesList);
    
    if (filteredNotes.length === 0) {
        const noNotes = document.createElement('p');
        noNotes.textContent = 'No notes found. Create your first note!';
        elements.notesList.appendChild(noNotes);
        return;
    }
    
    filteredNotes.forEach(note => {
        const noteItem = document.createElement('div');
        noteItem.className = 'note-item';
        noteItem.dataset.noteId = note.id;
        
        const title = document.createElement('h4');
        title.textContent = note.title;
        
        const content = document.createElement('p');
        content.textContent = note.content.substring(0, 100) + '...';
        
        const timestamp = document.createElement('small');
        timestamp.textContent = `Last updated: ${new Date(note.updatedAt).toLocaleString()}`;
        
        noteItem.appendChild(title);
        noteItem.appendChild(content);
        noteItem.appendChild(timestamp);
        
        noteItem.addEventListener('click', () => editNote(note.id));
        elements.notesList.appendChild(noteItem);
    });
}

function createNewNote() {
    currentNoteId = null;
    elements.noteTitle.value = '';
    clearElement(elements.noteContent);
    elements.noteEditor.style.display = 'block';
    document.getElementById('editor-title').textContent = 'New Note';
}

function editNote(noteId) {
    const note = notes.find(n => n.id === noteId);
    if (note && note.owner === currentUser.email) {
        currentNoteId = noteId;
        elements.noteTitle.value = note.title;
        clearElement(elements.noteContent);
        elements.noteContent.textContent = note.content;
        elements.noteEditor.style.display = 'block';
        document.getElementById('editor-title').textContent = 'Edit Note';
    }
}

function saveNote() {
    const title = sanitizeInput(elements.noteTitle.value.trim());
    const content = sanitizeInput(elements.noteContent.textContent.trim());
    
    if (!title) {
        alert('Please enter a title');
        return;
    }
    
    const now = new Date().toISOString();
    
    if (currentNoteId) {
        // Update existing note
        const noteIndex = notes.findIndex(n => n.id === currentNoteId);
        if (noteIndex !== -1) {
            notes[noteIndex].title = title;
            notes[noteIndex].content = content;
            notes[noteIndex].updatedAt = now;
        }
    } else {
        // Create new note
        const newNote = {
            id: generateId(),
            title: title,
            content: content,
            owner: currentUser.email,
            createdAt: now,
            updatedAt: now
        };
        notes.push(newNote);
    }
    
    saveData();
    renderNotes();
    elements.noteEditor.style.display = 'none';
    addAuditLog('Note saved', 'success', { noteId: currentNoteId, title });
}

function cancelEdit() {
    elements.noteEditor.style.display = 'none';
}

// Files functionality
function renderFiles() {
    const userFiles = files.filter(file => file.owner === currentUser.email);
    
    // Clear existing content safely
    clearElement(elements.filesList);
    
    if (userFiles.length === 0) {
        const noFiles = document.createElement('p');
        noFiles.textContent = 'No files uploaded yet.';
        elements.filesList.appendChild(noFiles);
        return;
    }
    
    userFiles.forEach(file => {
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item';
        
        const fileName = document.createElement('h4');
        fileName.textContent = file.name;
        
        const fileInfo = document.createElement('p');
        fileInfo.textContent = `Size: ${formatFileSize(file.size)} • Type: ${file.type}`;
        
        const uploadTime = document.createElement('p');
        uploadTime.textContent = `Uploaded: ${new Date(file.uploadedAt).toLocaleString()}`;
        
        const downloadLink = document.createElement('a');
        downloadLink.href = file.dataUrl;
        downloadLink.className = 'download-btn';
        downloadLink.textContent = 'Download';
        downloadLink.download = file.name;
        
        fileItem.appendChild(fileName);
        fileItem.appendChild(fileInfo);
        fileItem.appendChild(uploadTime);
        fileItem.appendChild(downloadLink);
        
        elements.filesList.appendChild(fileItem);
    });
}

function handleFileUpload() {
    const fileInput = document.getElementById('file-input');
    const file = fileInput.files[0];
    
    if (!file) {
        alert('Please select a file');
        return;
    }
    
    // Validate file type and size
    if (!isValidFileType(file.type)) {
        alert('Please select a valid file type (images, documents, archives)');
        return;
    }
    
    if (file.size > 10 * 1024 * 1024) { // 10MB limit
        alert('File size must be less than 10MB');
        return;
    }
    
    const reader = new FileReader();
    reader.onload = function(e) {
        const newFile = {
            id: generateId(),
            name: file.name,
            type: file.type,
            size: file.size,
            dataUrl: e.target.result,
            owner: currentUser.email,
            uploadedAt: new Date().toISOString()
        };
        
        files.push(newFile);
        saveData();
        renderFiles();
        addAuditLog('File uploaded', 'success', { fileName: file.name, size: file.size });
        
        // Clear file input
        fileInput.value = '';
    };
    
    reader.readAsDataURL(file);
}

// Remote image preview
async function previewRemoteImage() {
    const imageUrl = sanitizeInput(document.getElementById('image-url').value.trim());
    
    if (!imageUrl) {
        alert('Please enter an image URL');
        return;
    }
    
    // Validate URL format
    if (!isValidUrl(imageUrl)) {
        alert('Please enter a valid URL');
        return;
    }
    
    // Validate URL domain (basic check)
    if (!isAllowedDomain(imageUrl)) {
        alert('Only images from trusted domains are allowed');
        return;
    }
    
    elements.previewStatus.textContent = 'Loading...';
    elements.previewStatus.className = 'status-loading';
    clearElement(elements.imagePreview);
    
    try {
        elements.previewStatus.textContent = 'Loading image...';
        elements.previewStatus.className = 'status-loading';
        clearElement(elements.imagePreview);
        
        // Use fetch API with proper error handling
        const response = await fetch(imageUrl, {
            method: 'GET',
            mode: 'cors',
            headers: {
                'Accept': 'image/*'
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const blob = await response.blob();
        
        if (!blob.type.startsWith('image/')) {
            throw new Error('URL does not point to a valid image');
        }
        
        const img = document.createElement('img');
        img.src = URL.createObjectURL(blob);
        img.style.maxWidth = '100%';
        img.style.maxHeight = '400px';
        img.alt = 'Remote image preview';
        
        clearElement(elements.imagePreview);
        elements.imagePreview.appendChild(img);
        elements.previewStatus.textContent = 'Image loaded successfully';
        elements.previewStatus.className = 'status-success';
        addAuditLog('Remote image preview', 'success', { imageUrl });
        
    } catch (error) {
        elements.previewStatus.textContent = `Error: ${error.message}`;
        elements.previewStatus.className = 'status-error';
        
        const errorMessage = document.createElement('p');
        errorMessage.textContent = '无法加载图片。请确保：';
        
        const list = document.createElement('ul');
        const items = [
            'URL是正确的图片链接',
            '图片服务器允许跨域访问',
            '或通过本地服务器运行应用'
        ];
        
        items.forEach(item => {
            const li = document.createElement('li');
            li.textContent = item;
            list.appendChild(li);
        });
        
        clearElement(elements.imagePreview);
        elements.imagePreview.appendChild(errorMessage);
        elements.imagePreview.appendChild(list);
        
        addAuditLog('Remote image preview failed', 'error', { imageUrl, error: error.message });
    }
}

// Admin panel
function renderAdminPanel() {
    if (currentUser.role !== 'admin') return;
    
    // Users list
    const users = JSON.parse(localStorage.getItem(STORAGE_KEYS.USERS) || '[]');
    clearElement(elements.usersList);
    
    users.forEach(user => {
        const userItem = document.createElement('div');
        userItem.className = 'admin-item';
        
        const email = document.createElement('strong');
        email.textContent = user.email;
        
        const role = document.createTextNode(` (${user.role})`);
        
        const br = document.createElement('br');
        
        const createdAt = document.createElement('small');
        createdAt.textContent = `Created: ${new Date(user.createdAt).toLocaleString()}`;
        
        userItem.appendChild(email);
        userItem.appendChild(role);
        userItem.appendChild(br);
        userItem.appendChild(createdAt);
        
        elements.usersList.appendChild(userItem);
    });
    
    // All notes
    clearElement(elements.allNotesList);
    notes.forEach(note => {
        const noteItem = document.createElement('div');
        noteItem.className = 'admin-item';
        
        const title = document.createElement('strong');
        title.textContent = note.title;
        
        const owner = document.createTextNode(` by ${note.owner}`);
        
        const br = document.createElement('br');
        
        const updatedAt = document.createElement('small');
        updatedAt.textContent = `Last updated: ${new Date(note.updatedAt).toLocaleString()}`;
        
        noteItem.appendChild(title);
        noteItem.appendChild(owner);
        noteItem.appendChild(br);
        noteItem.appendChild(updatedAt);
        
        elements.allNotesList.appendChild(noteItem);
    });
    
    // All files
    clearElement(elements.allFilesList);
    files.forEach(file => {
        const fileItem = document.createElement('div');
        fileItem.className = 'admin-item';
        
        const name = document.createElement('strong');
        name.textContent = file.name;
        
        const owner = document.createTextNode(` by ${file.owner}`);
        
        const br = document.createElement('br');
        
        const fileInfo = document.createElement('small');
        fileInfo.textContent = `Size: ${formatFileSize(file.size)} • Uploaded: ${new Date(file.uploadedAt).toLocaleString()}`;
        
        fileItem.appendChild(name);
        fileItem.appendChild(owner);
        fileItem.appendChild(br);
        fileItem.appendChild(fileInfo);
        
        elements.allFilesList.appendChild(fileItem);
    });
}

// Audit log
function renderAuditLog() {
    // Clear existing content safely
    clearElement(elements.auditLogContainer);
    
    if (auditLog.length === 0) {
        const noEntries = document.createElement('p');
        noEntries.textContent = 'No audit entries yet.';
        elements.auditLogContainer.appendChild(noEntries);
        return;
    }
    
    // Show latest 20 entries
    const recentLogs = auditLog.slice(-20).reverse();
    
    recentLogs.forEach(entry => {
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry ${entry.type}`;
        
        const time = document.createElement('div');
        time.className = 'log-time';
        time.textContent = new Date(entry.timestamp).toLocaleString();
        
        const message = document.createElement('div');
        message.className = 'log-message';
        message.textContent = entry.message;
        
        logEntry.appendChild(time);
        logEntry.appendChild(message);
        
        if (entry.details) {
            const details = document.createElement('div');
            details.className = 'log-details';
            details.textContent = JSON.stringify(entry.details, null, 2);
            logEntry.appendChild(details);
        }
        
        elements.auditLogContainer.appendChild(logEntry);
    });
}

function addAuditLog(message, type = 'info', details = null) {
    const logEntry = {
        id: generateId(),
        message: sanitizeInput(message),
        type,
        details: details ? sanitizeObject(details) : null,
        timestamp: new Date().toISOString(),
        user: currentUser?.email || 'system'
    };
    
    auditLog.push(logEntry);
    saveData();
}

// Utility functions
function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Security utility functions
function sanitizeInput(text) {
    if (typeof text !== 'string') return '';
    
    // Remove potentially dangerous characters
    return text
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/<[^>]*>/g, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+\s*=/gi, '')
        .trim();
}

function sanitizeObject(obj) {
    if (typeof obj !== 'object' || obj === null) return obj;
    
    const sanitized = {};
    for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
            const value = obj[key];
            if (typeof value === 'string') {
                sanitized[key] = sanitizeInput(value);
            } else if (typeof value === 'object' && value !== null) {
                sanitized[key] = sanitizeObject(value);
            } else {
                sanitized[key] = value;
            }
        }
    }
    return sanitized;
}

function clearElement(element) {
    while (element.firstChild) {
        element.removeChild(element.firstChild);
    }
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function isValidPassword(password) {
    return password.length >= 8;
}

function hashPassword(password) {
    // Simple hash for demonstration - in production use proper hashing like bcrypt
    let hash = 0;
    for (let i = 0; i < password.length; i++) {
        const char = password.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32bit integer
    }
    return hash.toString();
}

function validatePassword(hashedPassword, inputPassword) {
    return hashPassword(inputPassword) === hashedPassword;
}

function isValidFileType(fileType) {
    const allowedTypes = [
        'image/',
        'text/',
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.',
        'application/zip',
        'application/x-rar-compressed'
    ];
    
    return allowedTypes.some(allowed => fileType.startsWith(allowed));
}

function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

function isAllowedDomain(url) {
    try {
        const parsedUrl = new URL(url);
        const allowedDomains = [
            'localhost',
            '127.0.0.1',
            'trusted-cdn.com',
            'example.com'
        ];
        
        return allowedDomains.some(domain => parsedUrl.hostname === domain || parsedUrl.hostname.endsWith('.' + domain));
    } catch {
        return false;
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', initApp);