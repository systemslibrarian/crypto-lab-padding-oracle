# crypto-lab-padding-oracle

**`AES-CBC` · `PKCS#7` · `Chosen-Ciphertext` · `Vaudenay 2002`**

**Live demo:** [https://systemslibrarian.github.io/crypto-lab-padding-oracle/](https://systemslibrarian.github.io/crypto-lab-padding-oracle/)

---

## What It Is

`crypto-lab-padding-oracle` is a browser-based interactive demonstration of the **CBC padding oracle attack** (Vaudenay 2002) — a chosen-ciphertext attack that decrypts any AES-CBC ciphertext without knowing the key, using only a one-bit padding validity oracle. All cryptographic operations use the browser's native WebCrypto API: real AES-128-CBC encryption with PKCS#7 padding, real AES-256-GCM for the AEAD defense demo, and real padding validation on every oracle query. The security model is symmetric-key cryptography — the attack exploits the combination of CBC mode and observable padding validation errors, not a weakness in AES itself.

---

## When to Use It

- **Teaching the Vaudenay 2002 attack** — the demo walks through single-byte recovery, full-block recovery, and multi-block decryption with live oracle query counts, making the O(256 × 16 × n) complexity tangible.
- **Auditing legacy CBC implementations** — understanding how a padding oracle arises (HTTP error codes, TLS alerts, timing differences) is essential before assessing whether a system is vulnerable.
- **Comparing CBC with AEAD** — Panel 6 demonstrates AES-256-GCM tamper rejection side-by-side with CBC, showing why AEAD eliminates the attack class entirely.
- **Security training and CTF preparation** — the interactive byte-grid visualizer and speed controls make the attack mechanics concrete for hands-on learners.
- **Do not use this as a production encryption library** — the oracle and key live in the same browser context; there is no network oracle, no real confidentiality boundary, and no key management.

---

## Live Demo

**[https://systemslibrarian.github.io/crypto-lab-padding-oracle/](https://systemslibrarian.github.io/crypto-lab-padding-oracle/)**

The demo has six tabbed panels. Panels 2–4 let you encrypt arbitrary plaintext with a random AES-128-CBC key, then run the full padding oracle attack at adjustable speeds (slow/medium/fast) while watching byte-by-byte recovery on an interactive grid. Panel 6 lets you encrypt with AES-256-GCM, tamper with the ciphertext, and see authentication fail with no plaintext revealed.

---

## What Can Go Wrong

- **Distinguishable error responses** — returning HTTP 500 for padding errors versus HTTP 200 for other failures gives an attacker a direct one-bit oracle; this is exactly what broke ASP.NET (MS10-070 / CVE-2010-3332).
- **Timing side-channels in padding validation** — even constant-time padding checks can leak information through MAC computation length differences, as demonstrated by Lucky Thirteen against TLS CBC cipher suites.
- **Ignored padding bytes in SSL 3.0** — SSL 3.0 only validates the last padding byte, allowing POODLE to recover one plaintext byte per ~256 requests without a traditional padding oracle.
- **Predictable IVs in TLS 1.0** — reusing the last ciphertext block as the next record's IV (BEAST) enables a related chosen-plaintext attack against CBC, even without a padding oracle.
- **Using CBC without Encrypt-then-MAC** — MAC-then-encrypt or encrypt-only CBC is fundamentally vulnerable; the only complete fix is authenticated encryption (AES-GCM or ChaCha20-Poly1305).

---

## Real-World Usage

- **TLS 1.0–1.2** — CBC cipher suites were standard in TLS for over a decade; TLS 1.3 (RFC 8446) removed them entirely because of the padding oracle attack class.
- **ASP.NET ViewState** — Microsoft's web framework used AES-CBC to protect ViewState and session cookies, leading to full plaintext recovery via MS10-070 before the patch.
- **IPsec ESP** — the Encapsulating Security Payload protocol supports AES-CBC mode for VPN tunnels; implementations must use Encrypt-then-MAC to avoid padding oracles.
- **OpenSSL / GnuTLS / NSS** — all three major TLS libraries required patches for Lucky Thirteen timing side-channels in their CBC padding validation paths.
- **PKCS#7 / CMS (S/MIME)** — the Cryptographic Message Syntax uses CBC with PKCS#7 padding for email encryption; Efail (2018) demonstrated related plaintext exfiltration against S/MIME implementations.

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