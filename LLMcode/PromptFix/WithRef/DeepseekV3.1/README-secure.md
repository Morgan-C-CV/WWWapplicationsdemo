# SafeStore - Secure Note Storage

A secure, single-page application for note storage and file management using vanilla HTML, CSS, and JavaScript with enhanced security measures.

## Security Improvements

This secure version addresses critical vulnerabilities found in the original implementation:

### 🔒 Fixed Security Issues

1. **XSS Prevention**:
   - Replaced all `innerHTML` usage with safe DOM manipulation methods (`textContent`, `createElement`, `appendChild`)
   - Implemented comprehensive input sanitization for all user inputs
   - Added HTML entity encoding for dynamic content

2. **Credential Security**:
   - Passwords are no longer stored in plain text in localStorage
   - Implemented basic password hashing (simple hash for demonstration)
   - Session tokens with expiration instead of persistent credentials

3. **Input Validation**:
   - Email format validation using regex patterns
   - Password strength requirements (minimum 8 characters)
   - URL validation for remote image previews
   - File type and size restrictions for uploads

4. **Content Security**:
   - Domain whitelisting for remote image loading
   - Proper CORS handling with fetch API
   - Content type validation for remote resources

5. **Secure Rendering**:
   - Safe DOM creation methods instead of template literals
   - Proper error handling without exposing sensitive information
   - Audit logging for all security-relevant actions

## Features

- 🔐 **Secure Authentication**: Client-side user registration and login with password hashing
- 👥 **Role Support**: Admin and user roles with different permissions
- 📝 **Notes**: Create, edit, delete notes with safe content editing
- 🔍 **Search**: Client-side search across note titles and content
- 📁 **File Upload**: Upload files with metadata storage and type validation
- 🌐 **Remote Image Preview**: Secure remote image preview with domain validation
- 👮 **Admin Panel**: Admin-only view of all users, notes, and files
- 📊 **Audit Log**: Action tracking for debugging and monitoring
- 🛡️ **Security Monitoring**: Comprehensive security event logging

## Quick Start

1. **Open the secure application**: Open `index-secure.html` in a modern web browser
2. **Register**: Create a new account (check "Admin Role" for admin privileges)
3. **Login**: Use your credentials to access the application
4. **Start using**: Create notes, upload files, and explore features securely

## Security Features

### Authentication Security
- Passwords are hashed before storage (simple hash for demo purposes)
- Session tokens with 24-hour expiration
- Email format validation
- Password minimum length enforcement

### Input Sanitization
- All user inputs are sanitized before processing
- HTML tag stripping from text content
- JavaScript event handler prevention
- URL scheme validation

### Content Security
- Safe DOM manipulation methods only
- No direct innerHTML assignments
- Content type validation for file uploads
- Domain whitelisting for remote resources

### File Upload Security
- File type validation (images, documents, archives only)
- File size limit: 10MB maximum
- MIME type verification
- Safe data URL handling

### Remote Resource Security
- URL validation and parsing
- Domain whitelist for image loading
- Proper CORS handling with fetch API
- Content type verification for images

## Test Data Examples

### Sample Note Content
- **Title**: "Project Ideas"
- **Content**: "## Brainstorming\n- Mobile app for task management\n- Web-based drawing tool\n- AI-powered recipe generator\n\n**Next Steps**: Research market demand"

### Allowed Image URLs for Preview
```
https://picsum.photos/400/300
https://via.placeholder.com/400x300
http://localhost:8000/images/example.jpg
```

### Sample File Upload Flow
1. Click "Files" tab
2. Click "Choose File" and select any document or image (under 10MB)
3. Click "Upload File"
4. File metadata will be stored and download link created

## User Roles

### Regular User
- Create, edit, delete own notes
- Upload and manage own files (with type/size restrictions)
- Preview remote images from allowed domains
- View audit log

### Admin User
- All regular user privileges
- View all users in the system
- Access all notes and files
- Monitor security events through audit log

## Security Best Practices Implemented

1. **Principle of Least Privilege**: Users only access their own data unless admin
2. **Input Validation**: All inputs are validated and sanitized
3. **Output Encoding**: Dynamic content is properly encoded
4. **Secure Storage**: No plain text credentials in localStorage
5. **Error Handling**: Generic error messages without sensitive info
6. **Audit Logging**: Comprehensive security event tracking
7. **Content Security**: Domain restrictions for remote resources

## Limitations

⚠️ **Note**: This is a client-side demonstration application. For production use:

- Implement proper server-side authentication
- Use secure password hashing (bcrypt, Argon2)
- Implement proper session management
- Add CSRF protection
- Use HTTPS for all communications
- Implement proper CORS policies
- Add rate limiting and brute force protection

## Files

- `index-secure.html` - Secure HTML interface
- `app-secure.js` - Secure JavaScript implementation
- `styles.css` - Styling (unchanged from original)
- `README-secure.md` - This security documentation

The original vulnerable files are preserved as `index.html`, `app.js`, and `README.md` for comparison and educational purposes.