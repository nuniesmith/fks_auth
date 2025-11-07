# shared_rust

Shared Rust crate for FKS services (config/env loader, risk utils, shared domain types).

## Usage (path dependency)

In a service `Cargo.toml`:

```toml
shared_rust = { path = "../repo/shared/rust" }
```

```rust
use shared_rust::{env::get_var, risk::risk_threshold};
let risk = risk_threshold(10_000.0);
```

## Environment Variables

Same set as python module: APP_ENV, LOG_LEVEL, RISK_MAX_PER_TRADE, DEBUG_MODE.

Loads `.env` if present using `dotenvy` (called lazily on first access).
