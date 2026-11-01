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
- Experimental Conversations legacy OMEMO for direct chats: per-chat opt-in, device/bundle PubSub, manual fingerprint trust, encrypted account/ratchet persistence, and decrypt-side identity pinning.
- Explicit TLS/OMEMO status and security explanation.

## Security and feature status

OMEMO support is experimental and limited to the old Conversations wire protocol (`eu.siacs.conversations.axolotl`) implemented by `dziber-omemo` 0.0.3. This is **not** the current XEP-0384 OMEMO 2 namespace/protocol and will interoperate only with clients supporting this legacy format. It has not been independently audited; do not rely on it for sensitive conversations. OMEMO is off by default and only available for direct chats. Before sending, every peer device must be manually fingerprint-verified. Unknown, changed, or untrusted device keys block encryption/decryption; an OMEMO send never silently falls back to plaintext. Messages received without OMEMO remain visibly unencrypted.

Account and ratchet pickles are encrypted with a random key stored in the operating-system keyring; on Linux this requires an available, unlocked Secret Service (for example GNOME Keyring or KWallet). The SQLite file is stored under the user's private application-data directory. If keyring access fails, OMEMO is unavailable while ordinary TLS-protected XMPP remains usable. File upload is disabled while OMEMO is enabled because XEP-0363 upload contents are not end-to-end encrypted. Group chats/MUC are not supported by this OMEMO prototype.

The audio/video call controls are visual placeholders and disabled. XMPP Jingle, voice messages, audio/video playback, and message history synchronization are not implemented yet. File upload requires an XEP-0363 service address provided by the XMPP server administrator. The demo mode is local-only and does not send anything over the network.

## Development

Format and check with `cargo fmt --check`, `cargo check`, and `cargo test`. Tests cover PubSub wire stanzas, persistence across reloads, and two-device encrypted-message round-trips. The XMPP dependency is the xmpp-rs high-level API with its escape hatch enabled for OMEMO stanzas.
