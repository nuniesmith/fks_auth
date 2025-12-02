# Passkey (WebAuthn) Implementation Guide

**Status**: In Progress  
**Library**: `webauthn-rs` v0.4  
**Framework**: Axum

---

## Overview

This document describes the passkey/WebAuthn implementation for fks_auth service. Passkeys provide passwordless authentication using FIDO2/WebAuthn standards.

---

## Dependencies Added

```toml
webauthn-rs = { version = "0.4", features = ["danger-allow-testing"] }
base64 = "0.22"
url = "2.5"
```

---

## Implementation Status

The passkey module has been created but needs testing and refinement based on actual webauthn-rs API. The basic structure is in place:

- ✅ Module structure created (`src/passkey.rs`)
- ✅ Dependencies added to Cargo.toml
- ✅ Routes integrated into main router
- ⏳ Needs API signature verification
- ⏳ Needs testing

---

## Endpoints

### Registration

1. **Start Registration**: `POST /passkey/register/start`
   - Request: `{ "username": "user", "device_name": "My Device" }`
   - Response: `{ "challenge": {...}, "session_id": "..." }`

2. **Complete Registration**: `POST /passkey/register/complete`
   - Request: `{ "session_id": "...", "username": "user", "credential": {...}, "device_name": "..." }`
   - Response: `{ "success": true, "message": "..." }`

### Authentication

1. **Start Authentication**: `POST /passkey/authenticate/start`
   - Request: `{ "username": "user" }`
   - Response: `{ "challenge": {...}, "session_id": "..." }`

2. **Complete Authentication**: `POST /passkey/authenticate/complete`
   - Request: `{ "session_id": "...", "username": "user", "credential": {...} }`
   - Response: `{ "success": true, "access_token": "...", "refresh_token": "...", ... }`

---

## Environment Variables

```bash
WEBAUTHN_ORIGIN=http://localhost:8009  # Origin URL
WEBAUTHN_RP_ID=localhost               # Relying Party ID
WEBAUTHN_RP_NAME="FKS Trading Platform" # Relying Party Name
```

---

## Next Steps

1. Test compilation with actual webauthn-rs API
2. Verify API signatures match library version
3. Test passkey registration flow
4. Test passkey authentication flow
5. Document client-side integration

---

**Note**: The implementation structure is complete but may need API signature adjustments based on the exact webauthn-rs version and API.
