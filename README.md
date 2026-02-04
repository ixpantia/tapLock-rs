# tapLock

<a><img src="https://storage.googleapis.com/ix-paquetes-internos/logo-tapLock.png" align="right" width="30%"></a>

tapLock is a high-performance authentication ecosystem designed to secure applications with OpenID Connect and OAuth 2.0. It provides a consistent, secure, and easy-to-use interface for integrating identity providers like Google, Microsoft Entra ID (Azure), and Keycloak across different programming environments.

At its heart, tapLock features a robust **Rust core** that handles the heavy lifting of cryptographic validation, token exchange, and session management, which is then exposed through native wrappers for Python and R.

## Project Structure

This repository is organized into several sub-packages depending on your target language:

### 🦀 [Rust Core (rs/taplock)](rs/taplock/README.md)
The foundational library. It includes the logic for OAuth2 flows and an optional **Axum** integration for building secure Rust web services.
- **Go to:** [Rust Documentation](rs/taplock/README.md)

### 🐍 [Python Wrapper (py/taplock)](py/taplock/README.md)
A high-performance wrapper for Python, specifically optimized for **FastAPI**. It includes middleware and dependency injection utilities to secure your APIs with minimal code.
- **Go to:** [Python Documentation](py/taplock/README.md)

### 📊 [R Wrapper (r/taplock)](r/taplock/README.md)
An R package designed for data scientists using **Shiny** and **Plumber**. It allows securing interactive dashboards and data APIs using a middleware-based approach that protects your application before a single WebSocket connection is even established.
- **Go to:** [R Documentation](r/taplock/README.md)

## Key Features

- **Unified Configuration**: Use consistent environment variables across Rust, Python, and R.
- **Secure by Default**: Automatically manages `HttpOnly` and `Secure` cookies for session persistence.
- **Zero-Trust for Shiny**: Prevents unauthenticated users from accessing even the UI portion of your R applications.
- **Automatic Refresh**: Transparently handles OAuth2 refresh tokens to keep user sessions alive.

## Supported Providers

- **Google**
- **Microsoft Entra ID (Azure)**
- **Keycloak**

---

Copyright (c) 2026 ixpantia, S.A.