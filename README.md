✨ **Change Log v1.5.3:**

- **Full SplitHTTP Transport (XHTTP) Fixes:**
  - Corrected double handshake (`0x00 0x00`) in stream‑up, packet‑up, and stream‑one modes – connections no longer drop immediately.
  - Closed quota bypass in packet‑up mode; all upload chunks now pass through the adaptive Quota Gate.
  - Eliminated race condition in packet ordering with a dedicated `seq_lock`, preventing TCP stream corruption.
  - Fixed memory leak / deadlock in `_teardown_xhttp`; terminated sessions are now always released properly.
- **Automatic Domain Detection:**
  - `get_domain` now resolves the real hostname from the HTTP `Host` header, eliminating “localhost” in all generated links (Subscription, User Dashboard, Admin Panel).
  - Injected `server_domain` into every `generate_vless_link` call and link‑building endpoint so that configuration exports always carry the correct domain.
- **XHTTP Path Standardization:**
  - Generated paths now include the transport mode and user UUID (e.g., `/xhttp/stream‑up/<uuid>`) to match the widely‑used standard implemented by other panels and clients (v2rayNG, Nekobox, etc.).
  - `dynamic_xhttp_router` was updated to parse the new path format (`/mode/uuid/sessionId/seq`) transparently, while remaining backward‑compatible with legacy paths.
- **SQLite Integrity:**
  - Resolved all “31 values for 32 columns” and “incorrect number of bindings” errors by ensuring every `INSERT` into the `links` table includes the `used_bytes` column.
- **Security Hardening:**
  - SSRF protection added to both WebSocket and XHTTP tunnels – connections to private, loopback, and link‑local addresses are now blocked.
  - DNS resolution in `resolve_domain_to_ip` is wrapped with a 3‑second timeout to prevent slow‑DNS attacks.
- **Docker & Deployment:**
  - Switched to a multi‑stage `Dockerfile` with a non‑root user (`sulgx`) and `gosu` for safer execution.
  - Added `HEALTHCHECK` instruction to the container image, improving reliability on orchestrated platforms (Render, Railway, etc.).

✨ Change Log v1.5.2:
- **UI Overhaul:** Fundamental redesign of the panel UI and frontend code.
- **Inbound Fallback Redirect:** Set a custom redirect URL (e.g., https://google.com) for non‑matching requests.
- **Stealth Address (Reverse Proxy):** Use a reverse proxy address as camouflage.
- **Subscription Filename:** Rename the subscription file as needed.
- **Admin Panel Prefix:** Define a hidden admin path for the panel.
- **Blocked Domains:** Specify blocked domains (one per line).
- **Clash & Sing‑box Sub Links:** Generate subscription links for Clash and Sing‑box clients.
- **Mobile/Tablet Compatibility:** Enhanced responsiveness for mobile and tablet views.
- **Logging Accuracy:** Improved precision of inbound/outbound logs and user usage data.
- **Anti‑Sleep Reinforcement:** Major reinforcement of the Keep‑Alive system.
- **DOH Link:** Added DNS‑over‑HTTPS link (works on some services).
- **IP Profiles:** Assign specific IP profiles to each inbound.

✨ Change Log v1.5.0 (beta):
- **XHTTP Protocol:** Full SplitHTTP transport with packet‑up, stream‑up, and stream‑one modes.
- **Adaptive Quota Gate:** Batches bandwidth checks based on real‑time speed, reducing database load.
- **Raw Downlink Response:** GET responses without chunked encoding for full Xray‑core compatibility.
- **Dynamic XHTTP Router:** Automatic request dispatch using inbound’s custom path – no extra config.
- **Auto ALPN Injection:** Adds `alpn=http/1.1` automatically for XHTTP links when ALPN is missing.
- **XHTTP Diagnostic Tool:** Standalone script (`xhttp_diag.py`) simulates a client to test latency and throughput.
- **Security Enhancement:** Public IP scanner WebSocket endpoint disabled by default to avoid abuse.
- **Performance Optimizations:** Added `uvloop`, updated Dockerfile and platform settings for smoother deployments.

✨ Change Log v1.1.0:
- **UI & UX:** Glass‑morphism interface polished, Blue Theme bug fixed, mobile responsiveness improved.
- **Performance:** Periodic link‑cache cleaning, scanner tasks correctly cancelled on WebSocket close.
- **Anti‑Sleep:** Redesigned Keep‑Alive engine with two modes (Simple/Advanced) switchable in real time.
- **Inbounds:** Fragment (FRAG) support added for DPI bypass, country flags assignable to each inbound.
- **User Dashboard:** Live usage progress bar with color‑coded thresholds (green→yellow→red).
- **Telegram:** Language toggle (EN/FA) fixed, now saves and restores correctly.
- **Database:** Automatic schema migration adds `flag` and `fragment` columns without manual intervention.
- **Bug Fixes:** Settings status cards sync with actual configs, time‑zone/language selectors harmonised.


<p align="center">
  <sub>Dedicated to the people of my homeland Iran, from <a href="https://github.com/SulgX">SulgX</a></sub>
</p>
