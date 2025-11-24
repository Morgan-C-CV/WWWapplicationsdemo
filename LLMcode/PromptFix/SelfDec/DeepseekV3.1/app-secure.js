// SafeStore - Secure Client-side Storage Application

// Security configuration
const SECURITY_CONFIG = {
    SESSION_TIMEOUT: 24 * 60 * 60 * 1000, // 24 hours
    PASSWORD_MIN_LENGTH: 8,
    MAX_FILE_SIZE: 10 * 1024 * 1024, // 10MB
    ALLOWED_FILE_TYPES: ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain']
};

// Storage keys with versioning for future migrations
const STORAGE_KEYS = {
    USERS: 'safestore_v1_users',
    NOTES: 'safestore_v1_notes',
    FILES: 'safestore_v1_files',
    AUDIT_LOG: 'safestore_v1_audit_log',
    SESSION: 'safestore_v1_session'
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
    imagePreview: document.getElementById('image-previews'),
    previewStatus: document.getElementById('preview-status')
};

// Security Utilities
const SecurityUtils = {
    // Secure hash function for passwords (simple implementation for demo)
    async hashPassword(password) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password + 'safestore_salt_2024'); // Add salt
        const hash = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(hash))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    },

    // Validate email format
    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    },

    // Validate password strength
    isStrongPassword(password) {
        return password.length >= SECURITY_CONFIG.PASSWORD_MIN_LENGTH;
    },

    // Sanitize HTML content
    sanitizeHtml(html) {
        const temp = document.createElement('div');
        temp.textContent = html;
        return temp.innerHTML;
    },

    // Escape HTML for text content
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    // Validate file type and size
    isValidFile(file) {
        if (file.size > SECURITY_CONFIG.MAX_FILE_SIZE) {
            return { valid: false, error: 'File size too large' };
        }
        
        if (!SECURITY_CONFIG.ALLOWED_FILE_TYPES.includes(file.type)) {
            return { valid: false, error: 'File type not allowed' };
        }
        
        return { valid: true };
    }
};

// Initialize application
function initApp() {
    loadData();
    checkSession();
    setupEventListeners();
    addAuditLog('Application initialized', 'info');
}

// Load data from localStorage with validation
function loadData() {
    try {
        notes = JSON.parse(localStorage.getItem(STORAGE_KEYS.NOTES) || '[]');
        files = JSON.parse(localStorage.getItem(STORAGE_KEYS.FILES) || '[]');
        auditLog = JSON.parse(localStorage.getItem(STORAGE_KEYS.AUDIT_LOG) || '[]');
        
        // Validate loaded data structure
        if (!Array.isArray(notes)) notes = [];
        if (!Array.isArray(files)) files = [];
        if (!Array.isArray(auditLog)) auditLog = [];
        
    } catch (error) {
        console.error('Error loading data:', error);
        notes = [];
        files = [];
        auditLog = [];
        addAuditLog('Data corruption detected - resetting storage', 'error');
    }
}

// Save data to localStorage with error handling
function saveData() {
    try {
        localStorage.setItem(STORAGE_KEYS.NOTES, JSON.stringify(notes));
        localStorage.setItem(STORAGE_KEYS.FILES, JSON.stringify(files));
        localStorage.setItem(STORAGE_KEYS.AUDIT_LOG, JSON.stringify(auditLog));
    } catch (error) {
        console.error('Error saving data:', error);
        addAuditLog('Failed to save data to storage', 'error');
    }
}

// Check if user has active session with validation
function checkSession() {
    try {
        const sessionData = localStorage.getItem(STORAGE_KEYS.SESSION);
        if (!sessionData) {
            showAuth();
            return;
        }
        
        const session = JSON.parse(sessionData);
        
        // Validate session structure
        if (!session || !session.user || !session.expires) {
            localStorage.removeItem(STORAGE_KEYS.SESSION);
            showAuth();
            return;
        }
        
        // Check session expiration
        if (session.expires > Date.now()) {
            currentUser = session.user;
            showApp();
        } else {
            localStorage.removeItem(STORAGE_KEYS.SESSION);
            showAuth();
        }
        
    } catch (error) {
        console.error('Session check error:', error);
        localStorage.removeItem(STORAGE_KEYS.SESSION);
        showAuth();
    }
}

// Show authentication section
function showAuth() {
    elements.authSection.style.display = 'block';
    elements.appSection.style.display = 'none';
    
    // Clear sensitive form data
    document.getElementById('login-email').value = '';
    document.getElementById('login-password').value = '';
    document.getElementById('register-email').value = '';
    document.getElementById('register-password').value = '';
}

// Show main application section
function showApp() {
    elements.authSection.style.display = 'none';
    elements.appSection.style.display = 'block';
    
    elements.userEmail.textContent = SecurityUtils.escapeHtml(currentUser.email);
    elements.userRole.textContent = `(${SecurityUtils.escapeHtml(currentUser.role)})`;
    
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
async function handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;
    
    // Input validation
    if (!SecurityUtils.isValidEmail(email)) {
        showError('Please enter a valid email address');
        addAuditLog('Invalid email format during login', 'warning', { email });
        return;
    }
    
    if (!password) {
        showError('Please enter your password');
        return;
    }
    
    try {
        const users = JSON.parse(localStorage.getItem(STORAGE_KEYS.USERS) || '[]');
        const hashedPassword = await SecurityUtils.hashPassword(password);
        const user = users.find(u => u.email === email && u.passwordHash === hashedPassword);
        
        if (user) {
            // Create secure session
            currentUser = { email: user.email, role: user.role };
            const session = {
                user: currentUser,
                expires: Date.now() + SECURITY_CONFIG.SESSION_TIMEOUT,
                sessionId: generateSecureId()
            };
            
            localStorage.setItem(STORAGE_KEYS.SESSION, JSON.stringify(session));
            showApp();
            addAuditLog('User logged in successfully', 'success', { email });
        } else {
            showError('Invalid email or password');
            addAuditLog('Failed login attempt', 'warning', { email });
        }
    } catch (error) {
        console.error('Login error:', error);
        showError('An error occurred during login');
        addAuditLog('Login system error', 'error', { email, error: error.message });
    }
}

async function handleRegister(e) {
    e.preventDefault();
    
    const email = document.getElementById('register-email').value.trim();
    const password = document.getElementById('register-password').value;
    const isAdmin = document.getElementById('register-admin').checked;
    
    // Input validation
    if (!SecurityUtils.isValidEmail(email)) {
        showError('Please enter a valid email address');
        return;
    }
    
    if (!SecurityUtils.isStrongPassword(password)) {
        showError(`Password must be at least ${SECURITY_CONFIG.PASSWORD_MIN_LENGTH} characters long`);
        return;
    }
    
    try {
        const users = JSON.parse(localStorage.getItem(STORAGE_KEYS.USERS) || '[]');
        
        if (users.some(u => u.email === email)) {
            showError('Email already registered');
            return;
        }
        
        // Hash password before storage
        const passwordHash = await SecurityUtils.hashPassword(password);
        
        const newUser = {
            email,
            passwordHash, // Store hash, not plain text
            role: isAdmin ? 'admin' : 'user',
            createdAt: new Date().toISOString(),
            lastLogin: null
        };
        
        users.push(newUser);
        localStorage.setItem(STORAGE_KEYS.USERS, JSON.stringify(users));
        
        // Auto-login after registration
        currentUser = { email: newUser.email, role: newUser.role };
        const session = {
            user: currentUser,
            expires: Date.now() + SECURITY_CONFIG.SESSION_TIMEOUT,
            sessionId: generateSecureId()
        };
        
        localStorage.setItem(STORAGE_KEYS.SESSION, JSON.stringify(session));
        showApp();
        addAuditLog('New user registered successfully', 'success', { 
            email, 
            role: newUser.role 
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        showError('An error occurred during registration');
        addAuditLog('Registration system error', 'error', { email, error: error.message });
    }
}

function showRegisterForm(e) {
    e.preventDefault();
    elements.loginForm.style.display = 'none';
    elements.registerForm.style.display = 'block';
}

function showLoginForm(e) {
    e.preventDefault();
    elements.registerForm.style.display = 'none';
    elements.loginForm.style.display = 'block';
}

function handleLogout() {
    addAuditLog('User logged out', 'info', { email: currentUser.email });
    localStorage.removeItem(STORAGE_KEYS.SESSION);
    currentUser = null;
    showAuth();
}

// Tab navigation
function handleTabChange(e) {
    const tabName = e.target.dataset.tab;
    
    // Update active tab
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    e.target.classList.add('active');
    
    // Show corresponding content
    document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
    document.getElementById(`${tabName}-tab`).classList.add('active');
    
    // Refresh admin panel if needed
    if (tabName === 'admin' && currentUser.role === 'admin') {
        renderAdminPanel();
    }
}

// Notes functionality
function renderNotes() {
    const userNotes = notes.filter(note => note.owner === currentUser.email);
    const filteredNotes = searchNotes(userNotes);
    
    if (filteredNotes.length === 0) {
        elements.notesList.innerHTML = '<p>No notes found. Create your first note!</p>';
        return;
    }
    
    elements.notesList.innerHTML = filteredNotes.map(note => `
        <div class="note-item" data-note-id="${SecurityUtils.escapeHtml(note.id)}">
            <h4>${SecurityUtils.escapeHtml(note.title)}</h4>
            <p>${SecurityUtils.escapeHtml(note.content.substring(0, 100))}...</p>
            <small>Last updated: ${new Date(note.updatedAt).toLocaleString()}</small>
        </div>
    `).join('');
    
    // Add click listeners to note items
    elements.notesList.querySelectorAll('.note-item').forEach(item => {
        item.addEventListener('click', () => editNote(item.dataset.noteId));
    });
}

function createNewNote() {
    currentNoteId = null;
    elements.noteTitle.value = '';
    elements.noteContent.textContent = ''; // Use textContent instead of innerHTML
    elements.noteEditor.style.display = 'block';
    document.getElementById('editor-title').textContent = 'New Note';
}

function editNote(noteId) {
    const note = notes.find(n => n.id === noteId);
    if (note && note.owner === currentUser.email) {
        currentNoteId = noteId;
        elements.noteTitle.value = SecurityUtils.escapeHtml(note.title);
        elements.noteContent.textContent = note.content; // Use textContent for safety
        elements.noteEditor.style.display = 'block';
        document.getElementById('editor-title').textContent = 'Edit Note';
    }
}

function saveNote() {
    const title = elements.noteTitle.value.trim();
    const content = elements.noteContent.textContent.trim(); // Get text content, not HTML
    
    if (!title) {
        showError('Please enter a title');
        return;
    }
    
    const now = new Date().toISOString();
    
    try {
        if (currentNoteId) {
            // Update existing note
            const noteIndex = notes.findIndex(n => n.id === currentNoteId);
            if (noteIndex !== -1) {
                notes[noteIndex] = {
                    ...notes[noteIndex],
                    title: SecurityUtils.sanitizeHtml(title),
                    content: SecurityUtils.sanitizeHtml(content),
                    updatedAt: now
                };
                addAuditLog('Note updated', 'success', { noteId: currentNoteId, title });
            }
        } else {
            // Create new note
            const newNote = {
                id: generateSecureId(),
                title: SecurityUtils.sanitizeHtml(title),
                content: SecurityUtils.sanitizeHtml(content),
                owner: currentUser.email,
                createdAt: now,
                updatedAt: now
            };
            notes.push(newNote);
            addAuditLog('Note created', 'success', { noteId: newNote.id, title });
        }
        
        saveData();
        cancelEdit();
        renderNotes();
        
    } catch (error) {
        console.error('Error saving note:', error);
        showError('Failed to save note');
        addAuditLog('Note save error', 'error', { error: error.message });
    }
}

function cancelEdit() {
    elements.noteEditor.style.display = 'none';
    currentNoteId = null;
}

function searchNotes(notesList) {
    const searchTerm = elements.searchInput.value.toLowerCase();
    if (!searchTerm) return notesList;
    
    return notesList.filter(note => 
        note.title.toLowerCase().includes(searchTerm) ||
        note.content.toLowerCase().includes(searchTerm)
    );
}

function handleSearch() {
    renderNotes();
}

// Files functionality
function renderFiles() {
    const userFiles = files.filter(file => file.owner === currentUser.email);
    
    if (userFiles.length === 0) {
        elements.filesList.innerHTML = '<p>No files uploaded yet.</p>';
        return;
    }
    
    elements.filesList.innerHTML = userFiles.map(file => `
        <div class="file-item">
            <h4>${SecurityUtils.escapeHtml(file.name)}</h4>
            <p>Size: ${formatFileSize(file.size)} • Type: ${SecurityUtils.escapeHtml(file.type)}</p>
            <p>Uploaded: ${new Date(file.uploadedAt).toLocaleString()}</p>
            <a href="${SecurityUtils.escapeHtml(file.dataUrl)}" class="download-btn" download="${SecurityUtils.escapeHtml(file.name)}">Download</a>
        </div>
    `).join('');
}

function handleFileUpload() {
    const fileInput = document.getElementById('file-input');
    const file = fileInput.files[0];
    
    if (!file) {
        showError('Please select a file');
        return;
    }
    
    // Validate file
    const validation = SecurityUtils.isValidFile(file);
    if (!validation.valid) {
        showError(validation.error);
        return;
    }
    
    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const newFile = {
                id: generateSecureId(),
                name: SecurityUtils.sanitizeHtml(file.name),
                type: file.type,
                size: file.size,
                dataUrl: e.target.result,
                owner: currentUser.email,
                uploadedAt: new Date().toISOString()
            };
            
            files.push(newFile);
            saveData();
            renderFiles();
            addAuditLog('File uploaded successfully', 'success', { 
                fileName: file.name, 
                size: file.size 
            });
            
            // Clear file input
            fileInput.value = '';
            
        } catch (error) {
            console.error('File upload error:', error);
            showError('Failed to upload file');
            addAuditLog('File upload error', 'error', { 
                fileName: file.name, 
                error: error.message 
            });
        }
    };
    
    reader.onerror = function() {
        showError('Error reading file');
        addAuditLog('File read error', 'error', { fileName: file.name });
    };
    
    reader.readAsDataURL(file);
}

// Remote image preview with security enhancements
async function previewRemoteImage() {
    const imageUrl = document.getElementById('image-url').value.trim();
    
    if (!imageUrl) {
        showError('Please enter an image URL');
        return;
    }
    
    // Basic URL validation
    if (!isValidUrl(imageUrl)) {
        showError('Please enter a valid URL');
        return;
    }
    
    elements.previewStatus.textContent = 'Loading...';
    elements.previewStatus.className = 'status-loading';
    elements.imagePreview.innerHTML = '';
    
    try {
        // Use fetch API with timeout and security headers
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);
        
        const response = await fetch(imageUrl, {
            method: 'GET',
            signal: controller.signal,
            headers: {
                'Accept': 'image/*'
            }
        });
        
        clearTimeout(timeout);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.startsWith('image/')) {
            throw new Error('URL does not point to an image');
        }
        
        const blob = await response.blob();
        
        // Validate image size
        if (blob.size > SECURITY_CONFIG.MAX_FILE_SIZE) {
            throw new Error('Image is too large');
        }
        
        const objectUrl = URL.createObjectURL(blob);
        
        const img = document.createElement('img');
        img.src = objectUrl;
        img.style.maxWidth = '100%';
        img.style.maxHeight = '400px';
        img.alt = 'Remote image preview';
        
        // Clean up object URL when image loads or errors
        img.onload = function() {
            URL.revokeObjectURL(objectUrl);
        };
        
        img.onerror = function() {
            URL.revokeObjectURL(objectUrl);
            throw new Error('Failed to load image');
        };
        
        elements.imagePreview.innerHTML = '';
        elements.imagePreview.appendChild(img);
        elements.previewStatus.textContent = 'Image loaded successfully';
        elements.previewStatus.className = 'status-success';
        addAuditLog('Remote image preview successful', 'success', { imageUrl });
        
    } catch (error) {
        console.error('Image preview error:', error);
        elements.previewStatus.textContent = `Error: ${error.message}`;
        elements.previewStatus.className = 'status-error';
        elements.imagePreview.innerHTML = `
            <div class="error-message">
                <p>Failed to load image:</p>
                <p>${SecurityUtils.escapeHtml(error.message)}</p>
                <p>Please ensure the URL is correct and accessible.</p>
            </div>
        `;
        addAuditLog('Remote image preview failed', 'error', { 
            imageUrl, 
            error: error.message 
        });
    }
}

// Admin panel
function renderAdminPanel() {
    if (currentUser.role !== 'admin') return;
    
    try {
        // Users list
        const users = JSON.parse(localStorage.getItem(STORAGE_KEYS.USERS) || '[]');
        elements.usersList.innerHTML = users.map(user => `
            <div class="admin-item">
                <strong>${SecurityUtils.escapeHtml(user.email)}</strong> (${user.role})
                <br><small>Created: ${new Date(user.createdAt).toLocaleString()}</small>
            </div>
        `).join('');
        
        // All notes
        elements.allNotesList.innerHTML = notes.map(note => `
            <div class="admin-item">
                <strong>${SecurityUtils.escapeHtml(note.title)}</strong> by ${SecurityUtils.escapeHtml(note.owner)}
                <br><small>Last updated: ${new Date(note.updatedAt).toLocaleString()}</small>
            </div>
        `).join('');
        
        // All files
        elements.allFilesList.innerHTML = files.map(file => `
            <div class="admin-item">
                <strong>${SecurityUtils.escapeHtml(file.name)}</strong> by ${SecurityUtils.escapeHtml(file.owner)}
                <br><small>Size: ${formatFileSize(file.size)} • Uploaded: ${new Date(file.uploadedAt).toLocaleString()}</small>
            </div>
        `).join('');
        
    } catch (error) {
        console.error('Admin panel error:', error);
        elements.usersList.innerHTML = '<p>Error loading admin data</p>';
        addAuditLog('Admin panel load error', 'error', { error: error.message });
    }
}

// Audit log
function renderAuditLog() {
    if (auditLog.length === 0) {
        elements.auditLogContainer.innerHTML = '<p>No audit entries yet.</p>';
        return;
    }
    
    // Show latest 20 entries
    const recentLogs = auditLog.slice(-20).reverse();
    
    elements.auditLogContainer.innerHTML = recentLogs.map(entry => `
        <div class="log-entry ${SecurityUtils.escapeHtml(entry.type)}">
            <div class="log-time">${new Date(entry.timestamp).toLocaleString()}</div>
            <div class="log-message">${SecurityUtils.escapeHtml(entry.message)}</div>
            ${entry.details ? `<div class="log-details">${SecurityUtils.escapeHtml(JSON.stringify(entry.details, null, 2))}</div>` : ''}
        </div>
    `).join('');
}

function addAuditLog(message, type = 'info', details = null) {
    const entry = {
        timestamp: new Date().toISOString(),
        message,
        type,
        details
    };
    
    auditLog.push(entry);
    
    // Keep audit log size reasonable
    if (auditLog.length > 1000) {
        auditLog = auditLog.slice(-1000);
    }
    
    saveData();
    
    // Only update UI if we're on the audit log tab
    if (elements.auditLogContainer.parentElement.classList.contains('active')) {
        renderAuditLog();
    }
}

// Utility functions
function generateSecureId() {
    return crypto.randomUUID ? crypto.randomUUID() : 
        Date.now().toString(36) + Math.random().toString(36).substr(2);
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

function showError(message) {
    // Create a simple error notification
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-notification';
    errorDiv.textContent = message;
    errorDiv.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #ff4757;
        color: white;
        padding: 15px;
        border-radius: 5px;
        z-index: 1000;
        max-width: 300px;
    `;
    
    document.body.appendChild(errorDiv);
    
    setTimeout(() => {
        if (errorDiv.parentNode) {
            errorDiv.parentNode.removeChild(errorDiv);
        }
    }, 5000);
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', initApp);