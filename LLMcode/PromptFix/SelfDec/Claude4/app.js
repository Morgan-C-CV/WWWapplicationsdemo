class SafeStore {
    constructor() {
        this.currentUser = null;
        this.currentNote = null;
        this.init();
    }

    init() {
        this.loadUser();
        this.bindEvents();
        this.updateUI();
        this.loadAuditLog();
    }

    async hashPassword(password) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hash = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(hash))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email) && email.length <= 254;
    }

    validatePassword(password) {
        return password.length >= 8 && password.length <= 128;
    }

    sanitizeText(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    loadUser() {
        try {
            const userData = localStorage.getItem('safestore_user');
            if (userData) {
                const parsed = JSON.parse(userData);
                if (parsed && parsed.id && parsed.email && parsed.role) {
                    this.currentUser = parsed;
                }
            }
        } catch (e) {
            localStorage.removeItem('safestore_user');
        }
    }

    async register(email, password, isAdmin = false) {
        if (!this.validateEmail(email)) {
            this.showMessage('Invalid email format', 'error');
            return false;
        }

        if (!this.validatePassword(password)) {
            this.showMessage('Password must be 8-128 characters', 'error');
            return false;
        }

        const users = this.getUsers();
        
        if (users.find(u => u.email === email)) {
            this.showMessage('User already exists', 'error');
            return false;
        }

        const passwordHash = await this.hashPassword(password);

        const user = {
            id: Date.now().toString() + Math.random().toString(36).substring(2, 11),
            email: email,
            passwordHash: passwordHash,
            role: isAdmin ? 'admin' : 'user',
            createdAt: new Date().toISOString()
        };

        users.push(user);
        localStorage.setItem('safestore_users', JSON.stringify(users));
        
        this.logAction('User registered', { email: this.sanitizeText(email), role: user.role });
        this.showMessage('Registration successful', 'success');
        return true;
    }

    async login(email, password) {
        if (!this.validateEmail(email)) {
            this.showMessage('Invalid email format', 'error');
            return false;
        }

        const users = this.getUsers();
        const passwordHash = await this.hashPassword(password);
        const user = users.find(u => u.email === email && u.passwordHash === passwordHash);
        
        if (user) {
            this.currentUser = {
                id: user.id,
                email: user.email,
                role: user.role,
                createdAt: user.createdAt
            };
            localStorage.setItem('safestore_user', JSON.stringify(this.currentUser));
            this.logAction('User logged in', { email: this.sanitizeText(email) });
            this.showMessage('Login successful', 'success');
            this.updateUI();
            return true;
        }
        
        this.showMessage('Invalid credentials', 'error');
        return false;
    }

    logout() {
        if (this.currentUser) {
            this.logAction('User logged out', { email: this.sanitizeText(this.currentUser.email) });
        }
        this.currentUser = null;
        localStorage.removeItem('safestore_user');
        this.updateUI();
        this.showMessage('Logged out successfully', 'success');
    }

    getUsers() {
        try {
            return JSON.parse(localStorage.getItem('safestore_users') || '[]');
        } catch (e) {
            return [];
        }
    }

    getNotes() {
        try {
            return JSON.parse(localStorage.getItem('safestore_notes') || '[]');
        } catch (e) {
            return [];
        }
    }

    validateNoteTitle(title) {
        return typeof title === 'string' && title.trim().length > 0 && title.length <= 200;
    }

    validateNoteContent(content) {
        return typeof content === 'string' && content.trim().length > 0 && content.length <= 10000;
    }

    saveNote(title, content) {
        if (!this.currentUser) {
            this.showMessage('Unauthorized', 'error');
            return;
        }

        const sanitizedTitle = this.sanitizeText(title.trim());
        const sanitizedContent = this.sanitizeText(content.trim());

        if (!this.validateNoteTitle(sanitizedTitle)) {
            this.showMessage('Invalid title (1-200 characters)', 'error');
            return;
        }

        if (!this.validateNoteContent(sanitizedContent)) {
            this.showMessage('Invalid content (1-10000 characters)', 'error');
            return;
        }

        const notes = this.getNotes();
        
        if (this.currentNote) {
            const index = notes.findIndex(n => n.id === this.currentNote.id && n.userId === this.currentUser.id);
            if (index !== -1) {
                notes[index] = { 
                    ...notes[index], 
                    title: sanitizedTitle, 
                    content: sanitizedContent, 
                    updatedAt: new Date().toISOString() 
                };
                this.logAction('Note updated', { noteId: this.currentNote.id });
            }
        } else {
            const note = {
                id: Date.now().toString() + Math.random().toString(36).substring(2, 9),
                title: sanitizedTitle,
                content: sanitizedContent,
                userId: this.currentUser.id,
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            };
            notes.push(note);
            this.logAction('Note created', { noteId: note.id });
        }
        
        localStorage.setItem('safestore_notes', JSON.stringify(notes));
        this.currentNote = null;
        this.renderNotes();
        this.hideNoteEditor();
        this.showMessage('Note saved successfully', 'success');
    }

    deleteNote(noteId) {
        if (!this.currentUser) return;

        const notes = this.getNotes();
        const noteIndex = notes.findIndex(n => n.id === noteId && n.userId === this.currentUser.id);
        
        if (noteIndex !== -1) {
            notes.splice(noteIndex, 1);
            localStorage.setItem('safestore_notes', JSON.stringify(notes));
            this.logAction('Note deleted', { noteId });
            this.renderNotes();
            this.showMessage('Note deleted', 'success');
        }
    }

    searchNotes(query) {
        if (!this.currentUser) return [];

        const notes = this.getNotes();
        const userNotes = notes.filter(n => n.userId === this.currentUser.id);
        
        if (!query || typeof query !== 'string') return userNotes;
        
        const sanitizedQuery = query.toLowerCase().substring(0, 100);
        
        return userNotes.filter(note => 
            note.title.toLowerCase().includes(sanitizedQuery) ||
            note.content.toLowerCase().includes(sanitizedQuery)
        );
    }

    getFiles() {
        try {
            return JSON.parse(localStorage.getItem('safestore_files') || '[]');
        } catch (e) {
            return [];
        }
    }

    validateFile(file) {
        const MAX_FILE_SIZE = 5 * 1024 * 1024;
        const ALLOWED_TYPES = [
            'image/jpeg', 'image/png', 'image/gif', 'image/webp',
            'application/pdf',
            'text/plain', 'text/csv',
            'application/json'
        ];

        if (file.size > MAX_FILE_SIZE) {
            return { valid: false, error: 'File too large (max 5MB)' };
        }

        if (!ALLOWED_TYPES.includes(file.type)) {
            return { valid: false, error: 'File type not allowed' };
        }

        return { valid: true };
    }

    saveFileMetadata(file) {
        if (!this.currentUser) {
            return Promise.reject(new Error('Unauthorized'));
        }

        const validation = this.validateFile(file);
        if (!validation.valid) {
            return Promise.reject(new Error(validation.error));
        }

        const files = this.getFiles();
        
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            
            reader.onerror = () => {
                reject(new Error('Failed to read file'));
            };

            reader.onload = (e) => {
                const fileData = {
                    id: Date.now().toString() + Math.random().toString(36).substring(2, 9),
                    name: this.sanitizeText(file.name.substring(0, 255)),
                    size: file.size,
                    type: file.type,
                    userId: this.currentUser.id,
                    dataUrl: e.target.result,
                    uploadedAt: new Date().toISOString()
                };
                
                files.push(fileData);
                localStorage.setItem('safestore_files', JSON.stringify(files));
                this.logAction('File uploaded', { fileId: fileData.id, fileSize: file.size });
                resolve(fileData);
            };
            
            reader.readAsDataURL(file);
        });
    }

    downloadFile(fileId) {
        if (!this.currentUser) return;

        const files = this.getFiles();
        const file = files.find(f => f.id === fileId && f.userId === this.currentUser.id);
        
        if (file) {
            const link = document.createElement('a');
            link.href = file.dataUrl;
            link.download = file.name;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            this.logAction('File downloaded', { fileId });
        }
    }

    validateURL(urlString) {
        try {
            const url = new URL(urlString);
            return url.protocol === 'https:';
        } catch (e) {
            return false;
        }
    }

    async previewImage(url) {
        const statusEl = document.getElementById('image-status');
        const previewEl = document.getElementById('image-preview');
        
        if (!this.validateURL(url)) {
            statusEl.textContent = 'Error: Only HTTPS URLs are allowed';
            statusEl.className = 'status-message error';
            previewEl.textContent = '';
            return;
        }

        statusEl.textContent = 'Loading image...';
        statusEl.className = 'status-message';
        previewEl.textContent = '';
        
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000);

            const response = await fetch(url, { 
                mode: 'cors',
                signal: controller.signal,
                headers: {
                    'Accept': 'image/*'
                }
            });
            
            clearTimeout(timeoutId);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const contentType = response.headers.get('content-type');
            if (!contentType || !contentType.startsWith('image/')) {
                throw new Error('URL does not point to an image');
            }
            
            const blob = await response.blob();

            if (blob.size > 10 * 1024 * 1024) {
                throw new Error('Image too large (max 10MB)');
            }
            
            const img = document.createElement('img');
            const objectURL = URL.createObjectURL(blob);
            
            img.onload = () => {
                URL.revokeObjectURL(objectURL);
                statusEl.textContent = 'Image loaded successfully';
                statusEl.className = 'status-message success';
            };

            img.onerror = () => {
                URL.revokeObjectURL(objectURL);
                statusEl.textContent = 'Error: Failed to load image';
                statusEl.className = 'status-message error';
            };

            img.src = objectURL;
            img.alt = 'Remote image preview';
            previewEl.appendChild(img);
            
            this.logAction('Image previewed', {});
            
        } catch (error) {
            const errorMsg = error.name === 'AbortError' ? 
                'Request timeout' : 
                this.sanitizeText(error.message);
            statusEl.textContent = `Error: ${errorMsg}`;
            statusEl.className = 'status-message error';
        }
    }

    isAdmin() {
        return this.currentUser && this.currentUser.role === 'admin';
    }

    getAllNotes() {
        if (!this.isAdmin()) return [];
        return this.getNotes();
    }

    getAllFiles() {
        if (!this.isAdmin()) return [];
        return this.getFiles();
    }

    logAction(action, details = {}) {
        try {
            const logs = JSON.parse(localStorage.getItem('safestore_audit') || '[]');
            
            const sanitizedDetails = {};
            for (const key in details) {
                if (details.hasOwnProperty(key)) {
                    const value = details[key];
                    if (typeof value === 'string') {
                        sanitizedDetails[key] = this.sanitizeText(value.substring(0, 100));
                    } else if (typeof value === 'number') {
                        sanitizedDetails[key] = value;
                    }
                }
            }

            const logEntry = {
                id: Date.now().toString() + Math.random().toString(36).substring(2, 9),
                timestamp: new Date().toISOString(),
                action: this.sanitizeText(action.substring(0, 100)),
                user: this.currentUser ? this.sanitizeText(this.currentUser.email) : 'Anonymous',
                details: sanitizedDetails
            };
            
            logs.unshift(logEntry);
            
            if (logs.length > 100) {
                logs.splice(100);
            }
            
            localStorage.setItem('safestore_audit', JSON.stringify(logs));
        } catch (e) {
        }
    }

    getAuditLog() {
        try {
            return JSON.parse(localStorage.getItem('safestore_audit') || '[]');
        } catch (e) {
            return [];
        }
    }

    // UI Methods
    updateUI() {
        const authSection = document.getElementById('auth-section');
        const mainApp = document.getElementById('main-app');
        const userInfo = document.getElementById('user-info');
        const currentUserEl = document.getElementById('current-user');
        const adminTab = document.getElementById('admin-tab');

        if (this.currentUser) {
            authSection.classList.add('hidden');
            mainApp.classList.remove('hidden');
            userInfo.classList.remove('hidden');
            currentUserEl.textContent = `${this.currentUser.email} (${this.currentUser.role})`;
            
            if (this.isAdmin()) {
                adminTab.classList.remove('hidden');
            } else {
                adminTab.classList.add('hidden');
            }
            
            this.renderNotes();
            this.renderFiles();
            this.loadAuditLog();
        } else {
            authSection.classList.remove('hidden');
            mainApp.classList.add('hidden');
            userInfo.classList.add('hidden');
        }
    }

    renderNotes() {
        const notesList = document.getElementById('notes-list');
        const searchQuery = document.getElementById('search-input').value;
        const notes = this.searchNotes(searchQuery);
        
        notesList.textContent = '';
        
        notes.forEach(note => {
            const noteEl = document.createElement('div');
            noteEl.className = 'note-item';

            const titleDiv = document.createElement('div');
            titleDiv.className = 'note-title';
            titleDiv.textContent = note.title;

            const previewDiv = document.createElement('div');
            previewDiv.className = 'note-preview';
            const previewText = note.content.substring(0, 100);
            previewDiv.textContent = previewText + (note.content.length > 100 ? '...' : '');

            const actionsDiv = document.createElement('div');
            actionsDiv.className = 'note-actions';

            const editBtn = document.createElement('button');
            editBtn.className = 'btn btn-primary';
            editBtn.textContent = 'Edit';
            editBtn.addEventListener('click', () => this.editNote(note.id));

            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'btn btn-danger';
            deleteBtn.textContent = 'Delete';
            deleteBtn.addEventListener('click', () => this.deleteNote(note.id));

            actionsDiv.appendChild(editBtn);
            actionsDiv.appendChild(deleteBtn);

            noteEl.appendChild(titleDiv);
            noteEl.appendChild(previewDiv);
            noteEl.appendChild(actionsDiv);
            
            notesList.appendChild(noteEl);
        });
    }

    renderFiles() {
        const filesList = document.getElementById('files-list');
        const files = this.getFiles().filter(f => f.userId === this.currentUser.id);
        
        filesList.textContent = '';
        
        files.forEach(file => {
            const fileEl = document.createElement('div');
            fileEl.className = 'file-item';

            const fileInfo = document.createElement('div');
            fileInfo.className = 'file-info';

            const fileName = document.createElement('div');
            fileName.className = 'file-name';
            fileName.textContent = file.name;

            const fileMeta = document.createElement('div');
            fileMeta.className = 'file-meta';
            fileMeta.textContent = `${this.formatFileSize(file.size)} • ${new Date(file.uploadedAt).toLocaleDateString()}`;

            fileInfo.appendChild(fileName);
            fileInfo.appendChild(fileMeta);

            const downloadBtn = document.createElement('button');
            downloadBtn.className = 'btn btn-primary';
            downloadBtn.textContent = 'Download';
            downloadBtn.addEventListener('click', () => this.downloadFile(file.id));

            fileEl.appendChild(fileInfo);
            fileEl.appendChild(downloadBtn);
            filesList.appendChild(fileEl);
        });
    }

    renderAdminContent(type) {
        const adminContent = document.getElementById('admin-content');
        
        if (!this.isAdmin()) {
            adminContent.textContent = '';
            const p = document.createElement('p');
            p.textContent = 'Access denied. Admin role required.';
            adminContent.appendChild(p);
            return;
        }
        
        adminContent.textContent = '';
        const listDiv = document.createElement('div');
        listDiv.className = 'admin-list';
        
        switch (type) {
            case 'users':
                const users = this.getUsers();
                users.forEach(user => {
                    const itemDiv = document.createElement('div');
                    itemDiv.className = 'admin-item';

                    const strong = document.createElement('strong');
                    strong.textContent = `${user.email} (${user.role})`;
                    
                    const br = document.createElement('br');
                    
                    const small = document.createElement('small');
                    small.textContent = `Registered: ${new Date(user.createdAt).toLocaleDateString()}`;

                    itemDiv.appendChild(strong);
                    itemDiv.appendChild(br);
                    itemDiv.appendChild(small);
                    listDiv.appendChild(itemDiv);
                });
                break;
                
            case 'notes':
                const allNotes = this.getAllNotes();
                allNotes.forEach(note => {
                    const user = this.getUsers().find(u => u.id === note.userId);
                    const itemDiv = document.createElement('div');
                    itemDiv.className = 'admin-item';

                    const strong = document.createElement('strong');
                    strong.textContent = note.title;
                    
                    const br1 = document.createElement('br');
                    
                    const small = document.createElement('small');
                    small.textContent = `By: ${user ? user.email : 'Unknown'} • ${new Date(note.createdAt).toLocaleDateString()}`;

                    const br2 = document.createElement('br');

                    const preview = document.createTextNode(
                        note.content.substring(0, 100) + (note.content.length > 100 ? '...' : '')
                    );

                    itemDiv.appendChild(strong);
                    itemDiv.appendChild(br1);
                    itemDiv.appendChild(small);
                    itemDiv.appendChild(br2);
                    itemDiv.appendChild(preview);
                    listDiv.appendChild(itemDiv);
                });
                break;
                
            case 'files':
                const allFiles = this.getAllFiles();
                allFiles.forEach(file => {
                    const user = this.getUsers().find(u => u.id === file.userId);
                    const itemDiv = document.createElement('div');
                    itemDiv.className = 'admin-item';

                    const strong = document.createElement('strong');
                    strong.textContent = file.name;
                    
                    const br = document.createElement('br');
                    
                    const small = document.createElement('small');
                    small.textContent = `By: ${user ? user.email : 'Unknown'} • ${this.formatFileSize(file.size)} • ${new Date(file.uploadedAt).toLocaleDateString()}`;

                    itemDiv.appendChild(strong);
                    itemDiv.appendChild(br);
                    itemDiv.appendChild(small);
                    listDiv.appendChild(itemDiv);
                });
                break;
        }
        
        adminContent.appendChild(listDiv);
    }

    loadAuditLog() {
        const auditLog = document.getElementById('audit-log');
        const logs = this.getAuditLog();
        
        auditLog.textContent = '';
        
        logs.forEach(log => {
            const logEl = document.createElement('div');
            logEl.className = 'audit-entry';

            const timestamp = document.createElement('div');
            timestamp.className = 'audit-timestamp';
            timestamp.textContent = new Date(log.timestamp).toLocaleString();

            const action = document.createElement('div');
            action.className = 'audit-action';
            action.textContent = log.action;

            const details = document.createElement('div');
            details.className = 'audit-details';
            let detailsText = `User: ${log.user}`;
            if (log.details && Object.keys(log.details).length > 0) {
                const detailsStr = Object.entries(log.details)
                    .map(([key, value]) => `${key}: ${value}`)
                    .join(', ');
                detailsText += ` • ${detailsStr}`;
            }
            details.textContent = detailsText;

            logEl.appendChild(timestamp);
            logEl.appendChild(action);
            logEl.appendChild(details);
            auditLog.appendChild(logEl);
        });
    }

    editNote(noteId) {
        if (!this.currentUser) return;

        const notes = this.getNotes();
        const note = notes.find(n => n.id === noteId && n.userId === this.currentUser.id);
        
        if (note) {
            this.currentNote = note;
            document.getElementById('note-title').value = note.title;
            document.getElementById('note-content').textContent = note.content;
            this.showNoteEditor();
        }
    }

    showNoteEditor() {
        document.getElementById('note-editor').classList.remove('hidden');
        document.getElementById('note-title').focus();
    }

    hideNoteEditor() {
        document.getElementById('note-editor').classList.add('hidden');
        document.getElementById('note-title').value = '';
        document.getElementById('note-content').textContent = '';
        this.currentNote = null;
    }

    showMessage(message, type) {
        const messageEl = document.getElementById('message');
        messageEl.textContent = message;
        messageEl.className = `message ${type}`;
        messageEl.classList.add('show');
        
        setTimeout(() => {
            messageEl.classList.remove('show');
        }, 3000);
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // Event Binding
    bindEvents() {
        // Auth tabs
        document.getElementById('login-tab').addEventListener('click', () => {
            document.getElementById('login-form').classList.remove('hidden');
            document.getElementById('register-form').classList.add('hidden');
            document.getElementById('login-tab').classList.add('active');
            document.getElementById('register-tab').classList.remove('active');
        });

        document.getElementById('register-tab').addEventListener('click', () => {
            document.getElementById('register-form').classList.remove('hidden');
            document.getElementById('login-form').classList.add('hidden');
            document.getElementById('register-tab').classList.add('active');
            document.getElementById('login-tab').classList.remove('active');
        });

        // Auth forms
        document.getElementById('login-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('login-email').value;
            const password = document.getElementById('login-password').value;
            await this.login(email, password);
        });

        document.getElementById('register-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('register-email').value;
            const password = document.getElementById('register-password').value;
            const isAdmin = document.getElementById('admin-role').checked;
            
            const ok = await this.register(email, password, isAdmin);
            if (ok) {
                document.getElementById('login-tab').click();
                document.getElementById('login-email').value = email;
            }
        });

        // Logout
        document.getElementById('logout-btn').addEventListener('click', () => {
            this.logout();
        });

        // Navigation tabs
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const targetId = e.target.id.replace('-tab', '-section');
                
                // Update active tab
                document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                
                // Show target section
                document.querySelectorAll('.section').forEach(s => s.classList.add('hidden'));
                document.getElementById(targetId).classList.remove('hidden');
                
                // Load admin content if admin tab
                if (targetId === 'admin-section') {
                    this.renderAdminContent('users');
                    document.getElementById('admin-users-tab').classList.add('active');
                    document.getElementById('admin-notes-tab').classList.remove('active');
                    document.getElementById('admin-files-tab').classList.remove('active');
                }
            });
        });

        // Notes
        document.getElementById('new-note-btn').addEventListener('click', () => {
            this.currentNote = null;
            this.showNoteEditor();
        });

        document.getElementById('save-note-btn').addEventListener('click', () => {
            const title = document.getElementById('note-title').value.trim();
            const content = document.getElementById('note-content').textContent.trim();
            
            if (title && content) {
                this.saveNote(title, content);
            } else {
                this.showMessage('Please enter both title and content', 'error');
            }
        });

        document.getElementById('cancel-edit-btn').addEventListener('click', () => {
            this.hideNoteEditor();
        });

        document.getElementById('search-input').addEventListener('input', () => {
            this.renderNotes();
        });

        document.getElementById('file-input').addEventListener('change', async (e) => {
            const files = Array.from(e.target.files);
            
            if (files.length === 0) return;

            let successCount = 0;
            let errorCount = 0;

            for (const file of files) {
                try {
                    await this.saveFileMetadata(file);
                    successCount++;
                } catch (error) {
                    errorCount++;
                    this.showMessage(error.message, 'error');
                }
            }
            
            this.renderFiles();
            
            if (successCount > 0) {
                this.showMessage(`${successCount} file(s) uploaded successfully`, 'success');
            }
            
            e.target.value = '';
        });

        // Image preview
        document.getElementById('preview-btn').addEventListener('click', () => {
            const url = document.getElementById('image-url').value.trim();
            if (url) {
                this.previewImage(url);
            } else {
                this.showMessage('Please enter an image URL', 'error');
            }
        });

        // Admin tabs
        document.getElementById('admin-users-tab').addEventListener('click', () => {
            this.renderAdminContent('users');
            document.querySelectorAll('.admin-tabs .tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById('admin-users-tab').classList.add('active');
        });

        document.getElementById('admin-notes-tab').addEventListener('click', () => {
            this.renderAdminContent('notes');
            document.querySelectorAll('.admin-tabs .tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById('admin-notes-tab').classList.add('active');
        });

        document.getElementById('admin-files-tab').addEventListener('click', () => {
            this.renderAdminContent('files');
            document.querySelectorAll('.admin-tabs .tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById('admin-files-tab').classList.add('active');
        });
    }
}

// Initialize the application
const app = new SafeStore();
