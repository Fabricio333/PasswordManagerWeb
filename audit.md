# Developer Brief — Targeted Security Audit (Password Manager + Nostr)

**Mission:** Verify that (1) master-key entropy is truly CSPRNG-strong, (2) no sensitive data can ever leak (network, storage, logs, clipboard, DOM), and (3) offline brute force is impractical given your KDF parameters. Record all findings in `audit.md` (structure already provided).

## What to prove (pass/fail)

1. **Entropy (master key & salts)**

* Only `crypto.getRandomValues` used; **no** `Math.random` or third-party RNG.
* Seed ≥ **256 bits**, salts ≥ **128 bits**; hard-fail if `crypto` is missing.
* Any user-entropy is *additive only* (never replaces CSPRNG).

2. **KDF & brute-force**

* **Argon2id** (preferred) or **scrypt**; PBKDF2 only if absolutely necessary.
* Target params (desktop 2025): Argon2id **256–512 MiB**, **t=3–6**, **p=1–2**.
  Prove unlock latency on low-end devices \~1–2s; document measured times.
* Rehash-upgrade on successful unlock when device can handle more memory.
* Secrets never live as JS strings; use `Uint8Array` and zeroize.

3. **Leak-proofing**

* **No network by default.** Only explicit user action may talk to allow-listed Nostr relays.
* Strict **CSP**: `default-src 'none'; script-src 'self'; connect-src 'self' https://<relays>; ...`
* IndexedDB only; **no** secrets in local/sessionStorage; **no** analytics; **no** console logs of sensitive data.
* Clipboard use is optional, timed, and auto-cleared.

4. **Nostr backup (nonces only)**

* Nonces are **encrypted** (NIP-04 or client-side AEAD) before publishing.
* Derive a **backup-only key** via **HKDF(masterKey, "nostr-backup", relayURL)**; don’t reuse identity keys.
* No domain/user metadata in backups; if per-site nonces exist, store under **H(domain‖siteID, salt)** (salt never published).
* Use TLS relays; DM (kind 4) only—never kind 1 for backups.

5. **XSS & supply chain**

* No `innerHTML` sinks with untrusted data, no `eval/new Function`, no inline scripts unless hashed.
* No CDN script dependencies; bundle locally; pin versions; verify hashes.

## One-command red-flag sweep (run all, paste hits into `audit.md`)

```bash
# RNG
rg -n "Math\\.random|seedrandom|chance\\(|mersenne|xoroshiro|uuid" --hidden
rg -n "crypto\\.getRandomValues" --hidden

# Exfil & endpoints
rg -n "fetch\\(|XMLHttpRequest|WebSocket|navigator\\.sendBeacon" --hidden
rg -n "http://|https://" --hidden

# Dangerous DOM & eval
rg -n "innerHTML|outerHTML|eval\\(|new Function\\(|setTimeout\\(.*'|setInterval\\(.*'" --hidden

# Storage & logs
rg -n "localStorage|sessionStorage|console\\.log\\(.*password|console\\.log\\(.*secret" --hidden

# Insecure crypto
rg -n "AES-ECB|md5\\(|sha1\\(|RC4" --hidden
```

## Required code patterns (verify in code)

* CSPRNG:

  ```js
  function secureRandomBytes(len=32){const b=new Uint8Array(len);crypto.getRandomValues(b);return b;}
  ```
* Argon2id (WASM) baseline:

  ```js
  const params={m:512*1024,t:4,p:1,hashLen:32,type:'argon2id'};
  const salt=secureRandomBytes(16);
  const pwdBytes=new TextEncoder().encode(userPassphrase);
  const keyBytes=await argon2.hash({pass:pwdBytes,salt,...params}); pwdBytes.fill(0);
  ```
* Non-extractable key:

  ```js
  const key=await crypto.subtle.importKey('raw', keyBytes,{name:'AES-GCM'},false,['encrypt','decrypt']);
  ```
* CSP (tight baseline):

  ```html
  <meta http-equiv="Content-Security-Policy" content="
  default-src 'none'; script-src 'self'; style-src 'self';
  img-src 'self' data:; font-src 'self';
  connect-src 'self' https://<relay1> https://<relay2>;
  base-uri 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests;">
  ```
* HKDF subkey for backup identity:

  ```js
  async function deriveSubkey(master,info){
    const k=await crypto.subtle.importKey('raw',master,{name:'HKDF'},false,['deriveBits']);
    const bits=await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:secureRandomBytes(16),info:new TextEncoder().encode(info)},k,256);
    return new Uint8Array(bits);
  }
  ```

---

Want me to plug in your actual code and fill the findings section line-by-line? Paste (or attach) the relevant files, and I’ll go through them using this checklist and update `audit.md` accordingly.
