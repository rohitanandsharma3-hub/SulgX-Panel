✨ **Change Log v1.5.5:**

- **Bulk proxy deletion:** Fixed bug preventing selected proxies from being deleted (server‑side correction and response validation).
- **Progress bar and stop button for proxy testing:** Added a progress bar and a Stop button to the Proxy Lines section, with the ability to cancel an ongoing test.
- **Automatic redirect to login page:** When the session expires (401), the user is now automatically sent to the login page.
- **Column count mismatch fix:** Automatic synchronization of column counts and values when inserting the default link (resolves the well‑known “39 values for 40 columns” error).

✨ **Change Log v1.5.4:**

- **Per-Inbound Xray DNS Settings:** Added "Xray DNS Mode", "DoH URL", and "Allowed Domains" fields for each inbound. Choose between DoH (DNS over HTTPS), FakeDNS, or system DNS, with an optional custom DoH URL.
- **Proxy Liner:** This feature lets you easily add a proxy (SOCKS or HTTP) to obtain new IPs, so your outbound traffic uses a different IP than the server. (Note: Do not use the proxy scanner for heavy tests like 500 or 1000 items; doing so may result in your account being suspended.)
- **Domain Whitelist:** Define a list of allowed domains per inbound; only these domains are routed through the proxy, while all other traffic is sent directly (with Fragment/Noise) – ideal for selective proxy usage.
- **Country Bypass:** Three new toggles (Bypass Iran, China, Russia) let you decide whether traffic from those countries should go directly without passing through the proxy. Applied across all subscription formats (Xray JSON, Clash Meta, Sing‑Box).
- **Xray Config JSON Link:** A dedicated “Xray Config” button (⚙️) is now available in the inbound list and on the user dashboard, copying the direct URL of the full Xray JSON config – ready to import into v2rayNG, Nekobox, etc.
- **UDP Unblocked:** UDP traffic is no longer blocked in any default subscription output; instead it is routed through the proxy (with optional UDP noise for DPI bypass), fixing voice calls, QUIC/HTTP3, and online games.
- **Performance & Concurrency:** Heavy database queries for subscription endpoints are now executed outside of locks, eliminating bottlenecks during high traffic.
- **Abuse Prevention:** Scanner and proxy-test operations now use reduced concurrency and built-in delays to avoid triggering abuse detection on hosting platforms (Railway, Render, etc.). This also applies to proxy flag retrieval.
- **DoH Setting Persistence:** The DoH enable/disable toggle now correctly saves to the database and survives page reloads.

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
