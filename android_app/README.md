# ScamShield AI — Native Mobile Architecture (Android & iOS)

To eliminate any manual DNS setup for everyday users, ScamShield AI provides a **1-Tap Mobile Companion App** architecture:

* **Live Installable Mobile App (PWA — iOS & Android):** Served directly at `/app` (`mobile_app/index.html`) with Web App Manifest & Android Share Target support. Users tap **1 button** to toggle protection across WhatsApp, SMS, Google Maps, Search, Safari, and Chrome.
* **Native Android Implementation (`android_app/`):**
  * `LinkInterceptorActivity.kt`: Registers an `ACTION_VIEW` intent handler to intercept tapped links from WhatsApp, SMS, and Google Maps *before* Chrome loads them, checking `POST /api/analyze` in real time.
  * `LocalDnsVpnService` (declared in `AndroidManifest.xml`): Activates a local on-device DNS filter (`VpnService`) with a single toggle—identical to Cloudflare 1.1.1.1 and AdGuard.
* **Native iOS Path:** Uses Apple's `NEDNSProxyProvider` (inside a signed iOS app) OR our 1-Tap Apple `.mobileconfig` DoH profile (`/scamshield.mobileconfig`) pointing straight to `/dns-query`.
