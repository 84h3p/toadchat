# Toadchat

Native XMPP messenger prototype in Rust, with an intentionally quiet, Apple-inspired desktop interface. The UI is built with egui/eframe using WGPU for rendering; XMPP transport uses the xmpp-rs high-level client and TLS-enabled StartTLS connection.

## Run

Install a recent stable Rust toolchain, then run `cargo run` from the project directory. On Linux, eframe needs its usual X11/Wayland system libraries.

The app uses WGPU with the Vulkan backend on Linux, avoiding both Glutin's `NoGlutinConfigs` issue and WGPU's GLES/EGL initialization panic on affected systems. It requires a working graphical display and Vulkan ICD/adapter (the app does not currently fall back to GLES).

## Included

- Connect to an XMPP account using JID and password (password is used in memory only).
- Direct chat messages, contact list presentation, search, unread counters, and demo mode.
- Server roster synchronization and starting a conversation by JID.
- XEP-0363 file upload to a configured server upload component, followed by sending the resulting URL in chat.
- Explicit TLS status and security explanation.

## Security and feature status

The transport is protected by TLS when the server negotiates StartTLS. This is **not** end-to-end encryption. OMEMO key management, device verification, and encrypted message handling are not implemented; the interface says so rather than implying otherwise. Do not use this prototype for sensitive conversations.

The audio/video call controls are visual placeholders and disabled. XMPP Jingle, voice messages, audio/video playback, message history synchronization, and persistent account storage are not implemented yet. File upload requires an XEP-0363 service address provided by the XMPP server administrator. The demo mode is local-only and does not send anything over the network.

## Development

Format and check with `cargo fmt --check` and `cargo check`. The XMPP dependency is the xmpp-rs high-level API; message events and file-upload results are handled by the transport module.
