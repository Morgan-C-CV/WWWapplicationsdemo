// SafeStore Application - Main JavaScript File

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
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Authentication Methods
    loadUser() {
        const userData = localStorage.getItem('safestore_user');
        if (userData) {
            this.currentUser = JSON.parse(userData);
        }
    }

    async register(email, password, isAdmin = false) {
        const users = this.getUsers();
        
        if (users.find(u => u.email === email)) {
            this.showMessage('User already exists', 'error');
            return false;
        }

        const passwordHash = await this.hashPassword(password);

        const user = {
            id: Date.now().toString(),
            email,
            passwordHash,
            role: isAdmin ? 'admin' : 'user',
            createdAt: new Date().toISOString()
        };

        users.push(user);
        localStorage.setItem('safestore_users', JSON.stringify(users));
        
        this.logAction('User registered', { email, role: user.role });
        this.showMessage('Registration successful', 'success');
        return true;
    }

    async login(email, password) {
        const users = this.getUsers();
        const passwordHash = await this.hashPassword(password);
        const user = users.find(u => u.email === email && u.passwordHash === passwordHash);
        
        if (user) {
            const userSession = {
                id: user.id,
                email: user.email,
                role: user.role,
                createdAt: user.createdAt
            };
            this.currentUser = userSession;
            localStorage.setItem('safestore_user', JSON.stringify(userSession));
            this.logAction('User logged in', { email });
            this.showMessage('Login successful', 'success');
            this.updateUI();
            return true;
        }
        
        this.showMessage('Invalid credentials', 'error');
        return false;
    }

    logout() {
        this.logAction('User logged out', { email: this.currentUser.email });
        this.currentUser = null;
        localStorage.removeItem('safestore_user');
        this.updateUI();
        this.showMessage('Logged out successfully', 'success');
    }

    getUsers() {
        return JSON.parse(localStorage.getItem('safestore_users') || '[]');
    }

    // Notes Methods
    getNotes() {
        return JSON.parse(localStorage.getItem('safestore_notes') || '[]');
    }

    saveNote(title, content) {
        const notes = this.getNotes();
        
        const sanitizedTitle = this.sanitizeText(title);
        const sanitizedContent = this.sanitizeText(content);
        
        if (this.currentNote) {
            const index = notes.findIndex(n => n.id === this.currentNote.id);
            if (index !== -1) {
                notes[index] = { ...notes[index], title: sanitizedTitle, content: sanitizedContent, updatedAt: new Date().toISOString() };
                this.logAction('Note updated', { title: sanitizedTitle, noteId: this.currentNote.id });
            }
        } else {
            const note = {
                id: Date.now().toString(),
                title: sanitizedTitle,
                content: sanitizedContent,
                userId: this.currentUser.id,
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            };
            notes.push(note);
            this.logAction('Note created', { title: sanitizedTitle, noteId: note.id });
        }
        
        localStorage.setItem('safestore_notes', JSON.stringify(notes));
        this.currentNote = null;
        this.renderNotes();
        this.hideNoteEditor();
        this.showMessage('Note saved successfully', 'success');
    }

    deleteNote(noteId) {
        const notes = this.getNotes();
        const noteIndex = notes.findIndex(n => n.id === noteId);
        
        if (noteIndex !== -1) {
            const note = notes[noteIndex];
            notes.splice(noteIndex, 1);
            localStorage.setItem('safestore_notes', JSON.stringify(notes));
            this.logAction('Note deleted', { title: note.title, noteId });
            this.renderNotes();
            this.showMessage('Note deleted', 'success');
        }
    }

    searchNotes(query) {
        const notes = this.getNotes();
        const userNotes = notes.filter(n => n.userId === this.currentUser.id);
        
        if (!query) return userNotes;
        
        return userNotes.filter(note => 
            note.title.toLowerCase().includes(query.toLowerCase()) ||
            note.content.toLowerCase().includes(query.toLowerCase())
        );
    }

    // File Methods
    getFiles() {
        return JSON.parse(localStorage.getItem('safestore_files') || '[]');
    }

    saveFileMetadata(file) {
        const files = this.getFiles();
        
        return new Promise((resolve) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                const fileData = {
                    id: Date.now().toString(),
                    name: file.name,
                    size: file.size,
                    type: file.type,
                    userId: this.currentUser.id,
                    dataUrl: e.target.result,
                    uploadedAt: new Date().toISOString()
                };
                
                files.push(fileData);
                localStorage.setItem('safestore_files', JSON.stringify(files));
                this.logAction('File uploaded', { fileName: file.name, fileSize: file.size });
                resolve(fileData);
            };
            reader.readAsDataURL(file);
        });
    }

    downloadFile(fileId) {
        const files = this.getFiles();
        const file = files.find(f => f.id === fileId);
        
        if (file) {
            const link = document.createElement('a');
            link.href = file.dataUrl;
            link.download = file.name;
            link.click();
            this.logAction('File downloaded', { fileName: file.name, fileId });
        }
    }

    validateImageUrl(url) {
        try {
            const parsedUrl = new URL(url);
            const allowedProtocols = ['http:', 'https:'];
            
            if (!allowedProtocols.includes(parsedUrl.protocol)) {
                throw new Error('Only HTTP and HTTPS protocols are allowed');
            }
            
            if (parsedUrl.hostname === 'localhost' || parsedUrl.hostname === '127.0.0.1' || parsedUrl.hostname.startsWith('192.168.') || parsedUrl.hostname.startsWith('10.')) {
                throw new Error('Local network URLs are not allowed');
            }
            
            return true;
        } catch (error) {
            throw new Error('Invalid URL format');
        }
    }

    async previewImage(url) {
        const statusEl = document.getElementById('image-status');
        const previewEl = document.getElementById('image-preview');
        
        statusEl.textContent = 'Loading image...';
        statusEl.className = 'status-message';
        while (previewEl.firstChild) {
            previewEl.removeChild(previewEl.firstChild);
        }
        
        try {
            this.validateImageUrl(url);
            
            const response = await fetch(url, { 
                mode: 'cors',
                redirect: 'follow',
                referrerPolicy: 'no-referrer'
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const blob = await response.blob();
            
            if (!blob.type.startsWith('image/')) {
                throw new Error('URL does not point to an image');
            }
            
            const img = document.createElement('img');
            img.src = URL.createObjectURL(blob);
            img.onload = () => URL.revokeObjectURL(img.src);
            img.alt = 'Preview image';
            
            previewEl.appendChild(img);
            statusEl.textContent = 'Image loaded successfully';
            statusEl.className = 'status-message success';
            
            this.logAction('Image previewed', { url: this.sanitizeText(url) });
            
        } catch (error) {
            statusEl.textContent = `Error: ${this.sanitizeText(error.message)}`;
            statusEl.className = 'status-message error';
        }
    }

    // Admin Methods
    isAdmin() {
        return this.currentUser && this.currentUser.role === 'admin';
    }

    getAllNotes() {
        return this.getNotes();
    }

    getAllFiles() {
        return this.getFiles();
    }

    // Audit Log Methods
    logAction(action, details = {}) {
        const logs = JSON.parse(localStorage.getItem('safestore_audit') || '[]');
        
        const logEntry = {
            id: Date.now().toString(),
            timestamp: new Date().toISOString(),
            action,
            user: this.currentUser ? this.currentUser.email : 'Anonymous',
            details
        };
        
        logs.unshift(logEntry); // Add to beginning
        
        // Keep only last 100 entries
        if (logs.length > 100) {
            logs.splice(100);
        }
        
        localStorage.setItem('safestore_audit', JSON.stringify(logs));
    }

    getAuditLog() {
        return JSON.parse(localStorage.getItem('safestore_audit') || '[]');
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
        
        while (notesList.firstChild) {
            notesList.removeChild(notesList.firstChild);
        }
        
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
        
        while (filesList.firstChild) {
            filesList.removeChild(filesList.firstChild);
        }
        
        files.forEach(file => {
            const fileEl = document.createElement('div');
            fileEl.className = 'file-item';
            
            const fileInfoDiv = document.createElement('div');
            fileInfoDiv.className = 'file-info';
            
            const fileNameDiv = document.createElement('div');
            fileNameDiv.className = 'file-name';
            fileNameDiv.textContent = file.name;
            
            const fileMetaDiv = document.createElement('div');
            fileMetaDiv.className = 'file-meta';
            fileMetaDiv.textContent = `${this.formatFileSize(file.size)} • ${new Date(file.uploadedAt).toLocaleDateString()}`;
            
            fileInfoDiv.appendChild(fileNameDiv);
            fileInfoDiv.appendChild(fileMetaDiv);
            
            const downloadBtn = document.createElement('button');
            downloadBtn.className = 'btn btn-primary';
            downloadBtn.textContent = 'Download';
            downloadBtn.addEventListener('click', () => this.downloadFile(file.id));
            
            fileEl.appendChild(fileInfoDiv);
            fileEl.appendChild(downloadBtn);
            
            filesList.appendChild(fileEl);
        });
    }

    renderAdminContent(type) {
        const adminContent = document.getElementById('admin-content');
        
        while (adminContent.firstChild) {
            adminContent.removeChild(adminContent.firstChild);
        }
        
        if (!this.isAdmin()) {
            const deniedP = document.createElement('p');
            deniedP.textContent = 'Access denied. Admin role required.';
            adminContent.appendChild(deniedP);
            return;
        }
        
        const adminList = document.createElement('div');
        adminList.className = 'admin-list';
        
        switch (type) {
            case 'users':
                const users = this.getUsers();
                users.forEach(user => {
                    const itemDiv = document.createElement('div');
                    itemDiv.className = 'admin-item';
                    
                    const emailStrong = document.createElement('strong');
                    emailStrong.textContent = user.email;
                    
                    const roleText = document.createTextNode(` (${user.role})`);
                    
                    const br = document.createElement('br');
                    
                    const dateSmall = document.createElement('small');
                    dateSmall.textContent = `Registered: ${new Date(user.createdAt).toLocaleDateString()}`;
                    
                    itemDiv.appendChild(emailStrong);
                    itemDiv.appendChild(roleText);
                    itemDiv.appendChild(br);
                    itemDiv.appendChild(dateSmall);
                    
                    adminList.appendChild(itemDiv);
                });
                break;
                
            case 'notes':
                const allNotes = this.getAllNotes();
                allNotes.forEach(note => {
                    const user = this.getUsers().find(u => u.id === note.userId);
                    const itemDiv = document.createElement('div');
                    itemDiv.className = 'admin-item';
                    
                    const titleStrong = document.createElement('strong');
                    titleStrong.textContent = note.title;
                    
                    const br1 = document.createElement('br');
                    
                    const metaSmall = document.createElement('small');
                    metaSmall.textContent = `By: ${user ? user.email : 'Unknown'} • ${new Date(note.createdAt).toLocaleDateString()}`;
                    
                    const br2 = document.createElement('br');
                    
                    const contentText = document.createTextNode(note.content.substring(0, 100) + (note.content.length > 100 ? '...' : ''));
                    
                    itemDiv.appendChild(titleStrong);
                    itemDiv.appendChild(br1);
                    itemDiv.appendChild(metaSmall);
                    itemDiv.appendChild(br2);
                    itemDiv.appendChild(contentText);
                    
                    adminList.appendChild(itemDiv);
                });
                break;
                
            case 'files':
                const allFiles = this.getAllFiles();
                allFiles.forEach(file => {
                    const user = this.getUsers().find(u => u.id === file.userId);
                    const itemDiv = document.createElement('div');
                    itemDiv.className = 'admin-item';
                    
                    const nameStrong = document.createElement('strong');
                    nameStrong.textContent = file.name;
                    
                    const br = document.createElement('br');
                    
                    const metaSmall = document.createElement('small');
                    metaSmall.textContent = `By: ${user ? user.email : 'Unknown'} • ${this.formatFileSize(file.size)} • ${new Date(file.uploadedAt).toLocaleDateString()}`;
                    
                    itemDiv.appendChild(nameStrong);
                    itemDiv.appendChild(br);
                    itemDiv.appendChild(metaSmall);
                    
                    adminList.appendChild(itemDiv);
                });
                break;
        }
        
        adminContent.appendChild(adminList);
    }

    loadAuditLog() {
        const auditLog = document.getElementById('audit-log');
        const logs = this.getAuditLog();
        
        while (auditLog.firstChild) {
            auditLog.removeChild(auditLog.firstChild);
        }
        
        logs.forEach(log => {
            const logEl = document.createElement('div');
            logEl.className = 'audit-entry';
            
            const timestampDiv = document.createElement('div');
            timestampDiv.className = 'audit-timestamp';
            timestampDiv.textContent = new Date(log.timestamp).toLocaleString();
            
            const actionDiv = document.createElement('div');
            actionDiv.className = 'audit-action';
            actionDiv.textContent = log.action;
            
            const detailsDiv = document.createElement('div');
            detailsDiv.className = 'audit-details';
            const detailsText = `User: ${log.user}${Object.keys(log.details).length ? ' • ' + JSON.stringify(log.details) : ''}`;
            detailsDiv.textContent = detailsText;
            
            logEl.appendChild(timestampDiv);
            logEl.appendChild(actionDiv);
            logEl.appendChild(detailsDiv);
            
            auditLog.appendChild(logEl);
        });
    }

    editNote(noteId) {
        const notes = this.getNotes();
        const note = notes.find(n => n.id === noteId);
        
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
    
    sanitizeText(text) {
        if (typeof text !== 'string') return '';
        return text.replace(/[<>]/g, '');
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
            
            if (await this.register(email, password, isAdmin)) {
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

        // Files
        document.getElementById('file-input').addEventListener('change', async (e) => {
            const files = Array.from(e.target.files);
            
            for (const file of files) {
                await this.saveFileMetadata(file);
            }
            
            this.renderFiles();
            this.showMessage(`${files.length} file(s) uploaded successfully`, 'success');
            e.target.value = ''; // Reset input
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