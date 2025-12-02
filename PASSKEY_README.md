# Passkey (WebAuthn) Authentication - Implementation Guide

**Status**: ✅ Implementation Complete  
**Service**: fks_auth  
**Feature**: Passwordless authentication using FIDO2/WebAuthn standards

---

## 🎯 Overview

Passkey support has been added to fks_auth service, enabling passwordless authentication using WebAuthn/FIDO2 standards. Users can register passkeys (biometric or security keys) and authenticate without passwords.

---

## ✨ Features

- ✅ **Passkey Registration**: Register new passkeys for users
- ✅ **Passkey Authentication**: Authenticate using passkeys
- ✅ **JWT Integration**: Returns JWT tokens after successful passkey authentication
- ✅ **Multi-Device Support**: Users can register multiple passkeys
- ✅ **Device Naming**: Optional device names for passkey management

---

## 📦 Dependencies

Added to `Cargo.toml`:
```toml
webauthn-rs = "0.4"
base64 = "0.22"
url = "2.5"
```

**Note**: `webauthn-rs` requires OpenSSL development libraries at build time. These are typically available in Docker containers.

---

## 🔧 Configuration

### Environment Variables

```bash
# WebAuthn/Passkey Configuration
WEBAUTHN_ORIGIN=http://localhost:8009        # Origin URL (must match your domain)
WEBAUTHN_RP_ID=localhost                     # Relying Party ID (domain without protocol)
WEBAUTHN_RP_NAME="FKS Trading Platform"      # Relying Party Name (display name)
```

**Important**: 
- `WEBAUTHN_ORIGIN` must match the actual origin (protocol + domain + port)
- `WEBAUTHN_RP_ID` should be the domain only (e.g., "localhost" or "fkstrading.xyz")
- For production, use your actual domain

---

## 📡 API Endpoints

### Registration Flow

#### 1. Start Registration
**Endpoint**: `POST /passkey/register/start`

**Request**:
```json
{
  "username": "jordan",
  "device_name": "My MacBook"  // Optional
}
```

**Response**:
```json
{
  "challenge": {
    "publicKey": {
      "rp": {
        "name": "FKS Trading Platform",
        "id": "localhost"
      },
      "user": {
        "id": "base64-encoded-user-id",
        "name": "jordan",
        "displayName": "jordan"
      },
      "challenge": "base64-encoded-challenge",
      "pubKeyCredParams": [...],
      "timeout": 60000,
      "authenticatorSelection": {
        "userVerification": "preferred"
      },
      "attestation": "none"
    }
  },
  "session_id": "uuid-session-id"
}
```

**Usage**:
1. Client calls this endpoint
2. Receives challenge and session_id
3. Calls browser WebAuthn API with challenge: `navigator.credentials.create({ publicKey: challenge.publicKey })`
4. Sends result to complete endpoint

#### 2. Complete Registration
**Endpoint**: `POST /passkey/register/complete`

**Request**:
```json
{
  "session_id": "uuid-from-start",
  "username": "jordan",
  "credential": {
    "id": "credential-id",
    "rawId": "base64-encoded-id",
    "response": {
      "clientDataJSON": "base64-encoded",
      "attestationObject": "base64-encoded"
    },
    "type": "public-key"
  },
  "device_name": "My MacBook"  // Optional
}
```

**Response**:
```json
{
  "success": true,
  "message": "Passkey registered successfully"
}
```

---

### Authentication Flow

#### 1. Start Authentication
**Endpoint**: `POST /passkey/authenticate/start`

**Request**:
```json
{
  "username": "jordan"
}
```

**Response**:
```json
{
  "challenge": {
    "publicKey": {
      "challenge": "base64-encoded-challenge",
      "timeout": 60000,
      "rpId": "localhost",
      "allowCredentials": [
        {
          "id": "credential-id",
          "type": "public-key"
        }
      ],
      "userVerification": "preferred"
    }
  },
  "session_id": "uuid-session-id"
}
```

**Usage**:
1. Client calls this endpoint with username
2. Receives challenge and session_id
3. Calls browser WebAuthn API: `navigator.credentials.get({ publicKey: challenge.publicKey })`
4. Sends result to complete endpoint

#### 2. Complete Authentication
**Endpoint**: `POST /passkey/authenticate/complete`

**Request**:
```json
{
  "session_id": "uuid-from-start",
  "username": "jordan",
  "credential": {
    "id": "credential-id",
    "rawId": "base64-encoded-id",
    "response": {
      "clientDataJSON": "base64-encoded",
      "authenticatorData": "base64-encoded",
      "signature": "base64-encoded",
      "userHandle": "base64-encoded"
    },
    "type": "public-key"
  }
}
```

**Response**:
```json
{
  "success": true,
  "access_token": "jwt-access-token",
  "refresh_token": "jwt-refresh-token",
  "token_type": "Bearer",
  "username": "jordan",
  "display_name": "jordan",
  "expires_at": 1234567890,
  "message": "Authentication successful"
}
```

**Usage**: 
- Use `access_token` for authenticated requests (same as password login)
- Use `refresh_token` to get new access tokens

---

## 🔐 Security Features

- ✅ **Challenge-Response**: Prevents replay attacks
- ✅ **Public Key Cryptography**: No secrets stored server-side
- ✅ **Counter Protection**: Prevents cloned credential reuse
- ✅ **Session-Based**: Temporary session IDs for challenges
- ✅ **User Verification**: Supports biometric authentication

---

## 💾 Storage

Currently uses in-memory storage (`HashMap`). For production:

1. **Recommended**: Store passkey credentials in database
2. **Store**:
   - `cred_id` (credential identifier)
   - `counter` (signature counter)
   - `credential` (full Passkey object from webauthn-rs)
   - `device_name` (optional)
   - `registration_time`
   - `user_id` (link to user)

3. **Session Storage**: Registration/auth challenges stored in-memory (expire after timeout)

---

## 🔄 Integration with Existing Auth

Passkey authentication integrates seamlessly:

- ✅ Uses same JWT token format as password login
- ✅ Same token expiration and refresh flow
- ✅ Works with existing `/me`, `/verify`, `/refresh` endpoints
- ✅ Can be used alongside password authentication

---

## 🧪 Testing

### Manual Testing

1. **Start Registration**:
   ```bash
   curl -X POST http://localhost:8009/passkey/register/start \
     -H "Content-Type: application/json" \
     -d '{"username":"jordan","device_name":"Test Device"}'
   ```

2. **Complete Registration**: Use browser WebAuthn API with challenge

3. **Start Authentication**:
   ```bash
   curl -X POST http://localhost:8009/passkey/authenticate/start \
     -H "Content-Type: application/json" \
     -d '{"username":"jordan"}'
   ```

4. **Complete Authentication**: Use browser WebAuthn API with challenge

### Browser Client Example

```javascript
// Start registration
const response = await fetch('http://localhost:8009/passkey/register/start', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'jordan', device_name: 'My Device' })
});
const { challenge, session_id } = await response.json();

// Create credential
const credential = await navigator.credentials.create({
  publicKey: challenge.publicKey
});

// Complete registration
await fetch('http://localhost:8009/passkey/register/complete', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    session_id,
    username: 'jordan',
    credential: {
      id: credential.id,
      rawId: arrayBufferToBase64(credential.rawId),
      response: {
        clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
        attestationObject: arrayBufferToBase64(credential.response.attestationObject)
      },
      type: credential.type
    },
    device_name: 'My Device'
  })
});
```

---

## 📝 Implementation Files

- `src/passkey.rs` - Passkey module with registration and authentication logic
- `src/lib.rs` - Main service with passkey routes integrated
- `Cargo.toml` - Dependencies added

---

## 🚀 Deployment Notes

### Docker Build

OpenSSL development libraries are required. Ensure Dockerfile includes:
```dockerfile
RUN apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config
```

### Production Configuration

1. Set `WEBAUTHN_ORIGIN` to your production domain
2. Set `WEBAUTHN_RP_ID` to your domain (no protocol/port)
3. Use HTTPS (required for WebAuthn in production)
4. Configure database storage for passkey credentials

---

## 🔗 Resources

- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [webauthn-rs Documentation](https://docs.rs/webauthn-rs/)
- [MDN WebAuthn Guide](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)

---

**Status**: ✅ Implementation complete, ready for testing and refinement
