# crypto-lab-padding-oracle

**`AES-CBC` · `PKCS#7` · `Chosen-Ciphertext` · `Vaudenay 2002`**

**Live demo:** [https://systemslibrarian.github.io/crypto-lab-padding-oracle/](https://systemslibrarian.github.io/crypto-lab-padding-oracle/)

---

## Overview

`crypto-lab-padding-oracle` is a browser-based, fully interactive demonstration of the **CBC padding oracle attack** — a chosen-ciphertext attack that decrypts any AES-CBC ciphertext without knowing the key, using only a padding validity oracle (one bit of information per query).

This is a deep-dive companion to the padding oracle panel in [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/), providing a complete step-by-step walkthrough of the full Vaudenay 2002 attack:
- Single byte recovery
- Full block recovery
- Full multi-block ciphertext decryption

**All cryptographic operations use the browser's native WebCrypto API.** No pure-JS AES, no simulated oracle responses, no faked math. The oracle performs real AES-CBC decryption and real PKCS#7 padding validation on every query.

---

## Attack Stages

| Panel | Description |
|-------|-------------|
| **1 — CBC & Padding** | CBC decryption flow, PKCS#7 rules, valid vs invalid padding, the oracle concept, real-world oracle examples |
| **2 — Single Byte** | Core attack: probe all 256 values for last byte, recover intermediate via oracle, XOR to plaintext |
| **3 — Full Block** | Extend to all 16 bytes: padding fixup for each position, running query count, intermediate state visualization |
| **4 — Full Decryption** | Multi-block attack with block-by-block progress, speed controls, total oracle query count |
| **5 — Hall of Fame** | Vaudenay 2002, MS10-070, Lucky Thirteen, POODLE, BEAST — with citations and CVEs |
| **6 — Defenses** | Encrypt-then-MAC, constant-time validation, AEAD (AES-GCM live demo with tamper rejection) |

**Attack complexity:** O(256 × block\_size × block\_count) oracle queries worst case; ~128 × block\_size × block\_count expected (uniform distribution over 0x00–0xFF).

---

## Primitives Used

- **AES-128-CBC** — WebCrypto `AES-CBC`, 128-bit key, random IV per session
- **PKCS#7 padding** — Real validation: last `n` bytes must all equal `n`, 1 ≤ n ≤ 16
- **Chosen-ciphertext attack** — Attacker submits crafted (C'[n-1], C[n]) pairs to the oracle
- **XOR byte manipulation** — I[j] = probe ⊕ padByte; P[j] = I[j] ⊕ C[n-1][j]
- **AES-256-GCM** — WebCrypto `AES-GCM` for AEAD defense demonstration

---

## Running Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-padding-oracle.git
cd crypto-lab-padding-oracle
npm install
npm run dev
```

Open [http://localhost:5173/crypto-lab-padding-oracle/](http://localhost:5173/crypto-lab-padding-oracle/)

### Build

```bash
npm run build
```

Output goes to `dist/`. All asset paths are relative; the build is GitHub Pages ready.

### Deploy to GitHub Pages

```bash
npm run deploy
```

Requires `gh-pages` (included as dev dependency) and a configured `origin` remote.

---

## Security Notes

This demo implements a **local oracle** — the oracle function and the AES key live in the same browser context, so no network is involved. In real-world attacks, the oracle is remote:

- **Error-response oracle:** HTTP 500 vs 200, TLS alert codes, distinct error messages
- **Timing oracle:** Lucky Thirteen — measurable latency difference in MAC computation
- **Protocol oracle:** POODLE — SSL 3.0 padding structure exploited over MITM

**The fix is always the same: use AEAD.** AES-GCM checks the authentication tag before any decryption. No oracle is possible because no information is revealed on failure.

This demo is for educational purposes. Understanding the attack is essential for anyone auditing legacy systems that still use CBC mode.

---

## Accessibility

This demo implements **WCAG 2.1 AA** compliance throughout:

- All interactive elements have descriptive `aria-label` or `aria-labelledby` attributes
- Full keyboard navigation — logical tab order, no keyboard traps, arrow key panel switching
- Focus indicators visible in both dark and light modes (minimum 3:1 contrast ratio on focus ring)
- Byte state indicators (unknown / probing / found / recovered) use both color and text labels — never color alone
- Attack step animations respect `prefers-reduced-motion`
- All status updates announced via `aria-live` regions
- Color contrast: minimum 4.5:1 for normal text, 3:1 for large text, in both modes
- Minimum tap target size: 44×44px (WCAG 2.5.5)
- Screen reader navigable throughout

---

## Why This Matters

The padding oracle attack has broken production systems serving billions of users:

- **ASP.NET (2010):** Microsoft patched a padding oracle that let attackers decrypt ViewState and session cookies — exploited in the wild within hours of disclosure (MS10-070).
- **TLS (2013):** Lucky Thirteen showed that even constant-time padding validation leaks timing information sufficient to mount the attack.
- **SSL 3.0 (2014):** POODLE forced a permanent deprecation of SSL 3.0 across all major browsers and servers.

One bit of information — valid or invalid padding — answered up to 256 × 16 × n times — decrypts everything. The lesson is not just historical: CBC is still found in legacy payment systems, medical record software, enterprise VPNs, and embedded devices. Knowing this attack is essential for security audits of any system using CBC mode.

---

## Related Demos

| Demo | Description |
|------|-------------|
| [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) | CBC, CTR, GCM modes — padding oracle panel included |
| [crypto-lab-timing-oracle](https://systemslibrarian.github.io/crypto-lab-timing-oracle/) | Timing oracle attacks — companion to Lucky Thirteen |
| [crypto-lab-shadow-vault](https://systemslibrarian.github.io/crypto-lab-shadow-vault/) | ChaCha20-Poly1305 AEAD in depth |
| [crypto-compare](https://systemslibrarian.github.io/crypto-compare/) | Symmetric cipher comparison tool (Symmetric category) |
| [crypto-lab](https://systemslibrarian.github.io/crypto-lab/) | Full crypto-lab collection landing page |

---

## Citations

- **Vaudenay, S. (2002).** Security Flaws Induced by CBC Padding. *EUROCRYPT 2002.* [PDF](https://www.iacr.org/cryptodb/archive/2002/EUROCRYPT/2850/2850.pdf)
- **Al Fardan, N.J. & Paterson, K.G. (2013).** Lucky Thirteen: Breaking the TLS and DTLS Record Protocols. *IEEE S&P 2013.* [PDF](https://www.isg.rhul.ac.uk/tls/TLStiming.pdf)
- **Möller, B., Duong, T., & Kotowicz, K. (2014).** This POODLE Bites: Exploiting the SSL 3.0 Fallback. *Google Security Research.* [PDF](https://www.openssl.org/~bodo/ssl-poodle.pdf)
- **Duong, T. & Rizzo, J. (2011).** Here Come The ⊕ Ninjas. *Ekoparty 2011.*
- **Microsoft (2010).** MS10-070: Vulnerability in ASP.NET Could Allow Information Disclosure.

---

"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31