# Security Code Review Guide for LLMs
## Based on OWASP Top 10 Proactive Controls 2024

This guide provides a structured approach for LLMs to identify potential security vulnerabilities when reviewing code. Use these guidelines to systematically analyze code for security issues based on the OWASP Top 10 Proactive Controls.

## C1: Implement Access Control

When reviewing code, look for:

- **Missing authorization checks**: Ensure sensitive operations verify user permissions before execution
- **Insecure direct object references**: Check if IDs or references are properly validated before access
- **Broken access control patterns**: Look for authorization checks that can be bypassed
- **Hardcoded roles or permissions**: Identify hardcoded access rules that should be configurable
- **Missing principle of least privilege**: Verify operations use minimal required permissions
- **Lack of role separation**: Check if administrative and regular user functions are properly separated
- **Insecure API endpoints**: Ensure all API endpoints implement proper access controls

Example issues:
```go
// Missing authorization check
func DeleteUser(userID int) error {
    return userRepository.Delete(userID) // No verification if the current user has permission
}

// Insecure direct object reference
func GetDocument(w http.ResponseWriter, r *http.Request) {
    docID := mux.Vars(r)["docId"]
    doc, _ := documentRepository.FindByID(docID) // No ownership verification
    json.NewEncoder(w).Encode(doc)
}
```

## C2: Use Cryptography to Protect Data

When reviewing code, look for:

- **Weak or outdated cryptographic algorithms**: Identify usage of MD5, SHA1, DES, etc.
- **Hardcoded cryptographic keys**: Look for keys, passwords, or secrets in source code
- **Improper key management**: Check if keys are properly generated, stored, and rotated
- **Insufficient encryption strength**: Verify appropriate key lengths for algorithms
- **Missing data encryption**: Identify sensitive data stored or transmitted without encryption
- **Insecure random number generation**: Look for non-cryptographically secure RNG usage
- **Lack of integrity verification**: Check if data integrity is verified (e.g., missing HMAC)

Example issues:
```go
// Weak cryptographic algorithm
func HashPassword(password string) string {
    h := md5.Sum([]byte(password)) // MD5 is cryptographically broken
    return hex.EncodeToString(h[:])
}

// Hardcoded secret
const EncryptionKey = "1234567890abcdef" // Never hardcode keys

// Insecure random number generation
func GenerateToken() string {
    rand.Seed(time.Now().Unix()) // Not cryptographically secure
    return fmt.Sprintf("%d", rand.Int()) // Predictable tokens
}
```

## C3: Validate all Input & Handle Exceptions

When reviewing code, look for:

- **Missing input validation**: Check if user inputs are validated before use
- **Improper error handling**: Look for sensitive information in error messages
- **Uncaught exceptions**: Identify code paths where exceptions aren't handled
- **SQL/NoSQL injection vulnerabilities**: Check for direct use of user input in queries
- **Command injection**: Look for user input passed to system commands
- **XSS vulnerabilities**: Identify unescaped user input in HTML/JS contexts
- **Overly broad exception handling**: Look for catch blocks that hide important errors

Example issues:
```go
// SQL injection vulnerability
func GetUser(username string) (*User, error) {
    query := "SELECT * FROM users WHERE username = '" + username + "'" // User input directly in query
    rows, err := db.Query(query)
    // ... rest of function
}

// Improper error handling
func ProcessRequest(w http.ResponseWriter, r *http.Request) {
    data, err := processData()
    if err != nil {
        http.Error(w, err.Error(), 500) // Sends detailed error to client
    }
}

// Missing input validation
func SetUsername(username string) {
    u.Username = username // No validation of username format or length
}
```

```javascript
// React component with missing input validation
function UserForm() {
    const [username, setUsername] = useState('');
    
    const handleSubmit = () => {
        // No client-side validation before sending to server
        submitUser({ username }); // Sends any input directly
    };
    
    return (
        <input 
            value={username}
            onChange={(e) => setUsername(e.target.value)} // No sanitization
        />
    );
}
```

## C4: Address Security from the Start

When reviewing code, look for:

- **Missing security requirements**: Check if security concerns are addressed in core functionality
- **Insecure design patterns**: Identify architectural flaws that create security risks
- **Lack of threat modeling**: Look for code that doesn't account for potential attack vectors
- **Security as an afterthought**: Identify security controls added as patches rather than by design
- **Missing security testing**: Check for absence of security-focused tests

Example issues:
```go
// Insecure design pattern
type UserSession struct {
    IsAdmin bool // Public field can be modified by any code
    UserID  int
    // No validation or immutability
}

// Missing security requirement
func ProcessPayment(payment PaymentDetails) error {
    // No fraud detection or transaction limits
    // No audit logging for financial transactions
    return processTransaction(payment)
}
```

## C5: Secure By Default Configurations

When reviewing code, look for:

- **Insecure default settings**: Check if default configurations prioritize security
- **Excessive permissions**: Look for overly permissive default access
- **Debug/development features in production**: Identify testing features left enabled
- **Unnecessary features or services**: Look for components that should be disabled by default
- **Missing security headers**: Check for absence of security-related HTTP headers
- **Verbose error messages**: Identify overly detailed errors in default configuration

Example issues:
```go
// Insecure default settings
type Config struct {
    Debug       bool `default:"true"`  // Debug enabled by default
    RequireAuth bool `default:"false"` // Authentication disabled by default
    LogLevel    string `default:"debug"` // Verbose logging by default
}

// Missing security headers middleware
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // No Content-Security-Policy, X-Content-Type-Options, etc.
        next.ServeHTTP(w, r)
    })
}

// Insecure default permissions
func NewServer() *Server {
    return &Server{
        AllowAllOrigins: true,  // CORS allows all origins by default
        MaxFileSize:     0,     // No file upload limits
        Timeout:         0,     // No request timeouts
    }
}
```

## C6: Keep your Components Secure

When reviewing code, look for:

- **Outdated dependencies**: Check for old versions with known vulnerabilities
- **Unnecessary dependencies**: Identify unused libraries that increase attack surface
- **Insecure third-party integrations**: Look for risky external service usage
- **Missing dependency scanning**: Check if there's a process to verify dependency security
- **Vulnerable components**: Identify components with known security issues
- **Lack of update mechanism**: Look for absence of dependency update processes

Example issues:
```go
// In go.mod - outdated dependencies
module myapp

go 1.16 // Outdated Go version

require (
    github.com/gorilla/mux v1.6.0 // Outdated version with known issues
    github.com/dgrijalva/jwt-go v3.2.0+incompatible // Deprecated package
)

// Unnecessary dependency
import _ "github.com/unused/package" // Imported but never used
```

## C7: Secure Digital Identities

When reviewing code, look for:

- **Weak authentication mechanisms**: Check for insufficient password requirements
- **Missing multi-factor authentication**: Identify lack of MFA for sensitive operations
- **Insecure credential storage**: Look for passwords stored in plaintext or weak hashing
- **Insecure session management**: Check for session fixation or insufficient timeout
- **Credential exposure**: Identify credentials in logs, URLs, or error messages
- **Missing account lockout**: Look for absence of brute force protection
- **Insecure password reset**: Check for vulnerable password recovery flows

Example issues:
```go
// Weak password hashing
func HashPassword(password string) string {
    h := md5.Sum([]byte(password)) // Should use bcrypt/Argon2 instead
    return hex.EncodeToString(h[:])
}

// Missing account lockout
func Login(username, password string) error {
    // No limit on failed attempts
    if checkCredentials(username, password) {
        // Login success
        return nil
    }
    return errors.New("invalid credentials")
}

// Insecure session management
type SessionConfig struct {
    Secret   string
    MaxAge   time.Duration
    Secure   bool // Not using secure cookies
    HttpOnly bool
}

func NewSessionConfig() *SessionConfig {
    return &SessionConfig{
        Secret:   "hardcoded-secret", // Hardcoded session secret
        MaxAge:   0,                  // Sessions never expire
        Secure:   false,              // Not requiring HTTPS
        HttpOnly: false,              // Accessible via JavaScript
    }
}
```

## C8: Leverage Browser Security Features

When reviewing code, look for:

- **Missing Content Security Policy**: Check if CSP headers are properly implemented
- **Insecure cookie attributes**: Look for cookies without Secure/HttpOnly flags
- **Cross-Origin Resource Sharing issues**: Identify overly permissive CORS settings
- **Missing clickjacking protection**: Check for absence of X-Frame-Options
- **Insecure form submissions**: Look for forms without CSRF protection
- **Missing Subresource Integrity**: Check if external scripts use integrity attributes
- **Absence of security headers**: Identify missing headers like X-Content-Type-Options

Example issues:
```go
// Insecure cookie settings
func SetSessionCookie(w http.ResponseWriter, sessionID string) {
    cookie := &http.Cookie{
        Name:  "sessionId",
        Value: sessionID,
        // Missing Secure and HttpOnly flags
    }
    http.SetCookie(w, cookie)
}

// Overly permissive CORS
func CORSMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*") // Allows any origin
        w.Header().Set("Access-Control-Allow-Credentials", "true") // Allows credentials with any origin
        next.ServeHTTP(w, r)
    })
}

// Missing CSRF protection
func TransferHandler(w http.ResponseWriter, r *http.Request) {
    // No CSRF token validation
    amount := r.FormValue("amount")
    destination := r.FormValue("destination")
    processTransfer(amount, destination)
}

// Missing security headers
func BasicHandler(w http.ResponseWriter, r *http.Request) {
    // Missing X-Content-Type-Options, X-Frame-Options, CSP headers
    w.Write([]byte("Hello World"))
}
```

```javascript
// React component with XSS vulnerability
function UserProfile({ userBio }) {
    return (
        <div>
            <h1>User Profile</h1>
            {/* Dangerous: renders raw HTML without sanitization */}
            <div dangerouslySetInnerHTML={{__html: userBio}} />
        </div>
    );
}

// React component missing CSRF token
function TransferForm() {
    const [amount, setAmount] = useState('');
    const [destination, setDestination] = useState('');
    
    const handleSubmit = (e) => {
        e.preventDefault();
        // Missing CSRF token in request
        fetch('/transfer', {
            method: 'POST',
            body: JSON.stringify({ amount, destination })
        });
    };
    
    return (
        <form onSubmit={handleSubmit}>
            {/* No CSRF token field */}
            <input value={amount} onChange={(e) => setAmount(e.target.value)} />
            <input value={destination} onChange={(e) => setDestination(e.target.value)} />
            <button type="submit">Transfer</button>
        </form>
    );
}
```

## C9: Implement Security Logging and Monitoring

When reviewing code, look for:

- **Insufficient logging**: Check if security-relevant events are logged
- **Missing audit trails**: Look for absence of logs for sensitive operations
- **Insecure log handling**: Identify logs containing sensitive data
- **Lack of monitoring hooks**: Check if critical functions have monitoring capabilities
- **Inadequate error logging**: Look for exceptions that aren't properly logged
- **Missing log correlation**: Check if logs include correlation IDs for tracing
- **Tamperable logs**: Identify logs that could be modified by attackers

Example issues:
```go
// Insufficient logging
func DeleteAccount(userID int) error {
    return userRepository.Delete(userID) // No logging of this critical action
}

// Insecure log handling
func Login(username, password string) error {
    log.Printf("User login: %s with password: %s", username, password) // Logging sensitive data
    return authenticate(username, password)
}

// Missing correlation
func ProcessTransaction(tx Transaction) error {
    // No request ID or correlation ID in logs
    log.Println("Processing transaction")
    return processPayment(tx)
}
```

## C10: Stop Server Side Request Forgery

When reviewing code, look for:

- **Unvalidated URLs**: Check if user-provided URLs are validated before use
- **Server-to-server requests with user input**: Identify requests using user-controlled data
- **Missing URL allowlisting**: Look for absence of URL validation against allowed patterns
- **Lack of network segmentation**: Check if internal services are accessible
- **Insufficient URL validation**: Identify weak URL validation that can be bypassed
- **Insecure redirects**: Look for redirects based on user input
- **Metadata service access**: Check for potential access to cloud metadata services

Example issues:
```go
// Unvalidated URL in request
func FetchData(url string) ([]byte, error) {
    resp, err := http.Get(url) // User can provide any URL, including internal services
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    return ioutil.ReadAll(resp.Body)
}

// Insecure redirect
func RedirectHandler(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    http.Redirect(w, r, url, http.StatusFound) // No validation of redirect URL
}

// Metadata service access
func GetUserData() ([]byte, error) {
    resp, err := http.Get("http://169.254.169.254/latest/user-data") // Could access cloud metadata
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    return ioutil.ReadAll(resp.Body)
}
```

## General Code Review Checklist

When reviewing any code, also look for:

1. **Hardcoded secrets**: API keys, passwords, tokens in source code
2. **Insecure defaults**: Security features disabled by default
3. **Missing validation**: User input used without proper validation
4. **Excessive permissions**: Code running with unnecessary privileges
5. **Race conditions**: Time-of-check to time-of-use vulnerabilities
6. **Logic flaws**: Business logic that can be manipulated
7. **Insecure serialization**: Unsafe deserialization of user data
8. **Side-channel leaks**: Information disclosure via timing, errors, etc.
9. **Insecure file operations**: Path traversal, unsafe file handling
10. **Missing security tests**: Absence of tests for security controls

## Conclusion

This guide provides a starting point for identifying security issues during code review. Always consider the specific context of the application and its threat model. Security is a continuous process that requires ongoing attention throughout the development lifecycle.

Remember that this guide is based on the OWASP Top 10 Proactive Controls, which represent fundamental security practices. For a more comprehensive security review, consider additional resources like the OWASP Application Security Verification Standard (ASVS).