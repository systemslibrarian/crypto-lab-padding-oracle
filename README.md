# crypto-lab-padding-oracle

## What It Is

`crypto-lab-padding-oracle` is a browser-based interactive demonstration of the **CBC padding oracle attack** (Vaudenay 2002) — a chosen-ciphertext attack that recovers CBC ciphertext accepted under the oracle's key without recovering that key, using only observable padding validity. All cryptographic operations use the browser's native WebCrypto API: real AES-128-CBC encryption with PKCS#7 padding, real AES-256-GCM for the AEAD defense demo, and real padding validation on queries that reach CBC decryption; the Encrypt-then-MAC server rejects modified ciphertext before that check. The attack exploits CBC combined with observable padding behavior, not a weakness in AES itself.

## When to Use It

- **Teaching the Vaudenay 2002 attack** — the demo walks through byte-by-byte recovery, full-block recovery, and multi-block decryption with live oracle query counts, making the O(256 × 16 × n) complexity tangible.
- **Auditing legacy CBC implementations** — understanding how a padding oracle arises (HTTP error codes, TLS alerts, timing differences) is essential before assessing whether a system is vulnerable.
- **Comparing CBC defenses** — Panel 6 runs the same attack against leaky CBC, uniform-response CBC, and Encrypt-then-MAC, then demonstrates AES-256-GCM tamper rejection.
- **Security training and CTF preparation** — the interactive byte-grid visualizer and speed controls make the attack mechanics concrete for hands-on learners.
- Do NOT use this as a production encryption library — it is a teaching demo; the oracle and key live in the same browser context; there is no network oracle, no real confidentiality boundary, and no key management.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-padding-oracle](https://systemslibrarian.github.io/crypto-lab-padding-oracle/)**

The demo has six tabbed panels. Panels 2–4 let you encrypt bounded learner-provided plaintext with a random AES-128-CBC key, then run the padding oracle attack at adjustable speeds (slow/medium/fast) while watching byte-by-byte recovery on an interactive grid. The full-ciphertext panel caps input at 128 UTF-8 bytes so a browser exercise cannot turn into an unbounded WebCrypto workload. Panel 6 lets you encrypt with AES-256-GCM, tamper with the ciphertext, and see authenticated decryption reject without returning plaintext.

Four parts of the page are exercises rather than statements:

- **Panel 1 — craft the last padding byte.** Set up a ciphertext whose final block decrypts to a full padding block, choose what its last decrypted byte becomes (the page XORs the difference into `C[n−1][15]`, exactly as the attack does), and commit to *valid* or *invalid* before the real WebCrypto oracle answers. Your running score is kept.
- **Panel 3 — you pick the target block.** The plaintext to recover is typed by the learner, with a live byte count, instead of being fixed in the source.
- **Panel 6 — the same attack against three servers.** The identical `recoverBlock()` runs against a leaky server, a server that performs the same padding check but answers identically whatever it found, and an Encrypt-then-MAC server. The leaky one gives up its plaintext; against the other two the attack genuinely fails — it exhausts all 256 probes for a byte and stops. The table reports oracle queries, how many reached the padding check, and how many died at MAC verification, so "this defense works" is a counter rather than a caption.
- **Panels 3 and 4 — graded recovery.** Both compare the recovered bytes against the plaintext the session actually encrypted and print a byte-for-byte match badge (or a mismatch), rather than echoing the input back.

## Testing

```bash
npm test          # node --test: the attack engine, plus the three server modes
npm run type-check
npm run test:a11y # Playwright: WCAG A/AA scan and the functional exhibit gates
npm run test:workflow
npm run test:mutations
```

`e2e/attack.spec.ts` drives the shipped page: recovered plaintext and the byte-for-byte badges,
the oracle query counters, the AES-GCM rejection (and that the protected message never appears),
the learner padding predictions, and the defense bench — including the two servers the attack must
fail against.

## What Can Go Wrong

- **Distinguishable error responses** — any reliably different response after padding validation can supply the one-bit oracle; this is what broke ASP.NET (MS10-070 / CVE-2010-3332). A particular HTTP status-code pair is not required.
- **Timing side-channels in padding validation** — even constant-time padding checks can leak information through MAC computation length differences, as demonstrated by Lucky Thirteen against TLS CBC cipher suites.
- **Ignored padding bytes in SSL 3.0** — SSL 3.0 only validates the last padding byte, allowing POODLE to recover one plaintext byte per ~256 requests without a traditional padding oracle.
- **Predictable IVs in TLS 1.0** — reusing the last ciphertext block as the next record's IV (BEAST) enables a related chosen-plaintext attack against CBC, even without a padding oracle.
- **Processing unauthenticated CBC** — verify integrity over the IV, ciphertext, and relevant context before attempting padded CBC decryption. Prefer a reviewed AEAD construction such as AES-GCM or ChaCha20-Poly1305 for new designs.

## Real-World Usage

- **TLS 1.0–1.2** — these versions supported CBC suites. The current TLS 1.3 specification, RFC 9846 (2026), obsoletes RFC 8446 and defines no CBC suites.
- **ASP.NET encrypted data** — MS10-070 documented padding-dependent error information that could disclose encrypted data such as ViewState and enable tampering. Microsoft's update added authentication to encrypted ASP.NET data.
- **IPsec ESP** — the Encapsulating Security Payload protocol supports AES-CBC mode for VPN tunnels; implementations must use Encrypt-then-MAC to avoid padding oracles.
- **OpenSSL / GnuTLS / NSS** — all three major TLS libraries required patches for Lucky Thirteen timing side-channels in their CBC padding validation paths.
- **PKCS#7 / CMS (S/MIME)** — the Cryptographic Message Syntax uses CBC with PKCS#7 padding for email encryption; Efail (2018) demonstrated related plaintext exfiltration against S/MIME implementations.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-padding-oracle
cd crypto-lab-padding-oracle
npm ci
npm run dev
```

## Related Demos

- [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — CBC, CTR, and GCM modes with a padding-oracle panel included.
- [crypto-lab-timing-oracle](https://systemslibrarian.github.io/crypto-lab-timing-oracle/) — timing-attack oracles, companion to Lucky Thirteen.
- [crypto-lab-nonce-guard](https://systemslibrarian.github.io/crypto-lab-nonce-guard/) — AES-GCM nonce reuse and the AES-GCM-SIV defense.
- [crypto-lab-shadow-vault](https://systemslibrarian.github.io/crypto-lab-shadow-vault/) — ChaCha20-Poly1305 AEAD in depth.

## Citations

- **Vaudenay, S. (2002).** Security Flaws Induced by CBC Padding — Applications to SSL, IPSEC, WTLS. *EUROCRYPT 2002, LNCS 2332, pp. 534-545.* [PDF](https://www.iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.pdf)
- **Al Fardan, N.J. & Paterson, K.G. (2013).** Lucky Thirteen: Breaking the TLS and DTLS Record Protocols. *IEEE S&P 2013.* [PDF](https://www.isg.rhul.ac.uk/tls/TLStiming.pdf)
- **Möller, B., Duong, T., & Kotowicz, K. (2014).** This POODLE Bites: Exploiting the SSL 3.0 Fallback. *Google Security Research.* [PDF](https://openssl-library.org/files/ssl-poodle.pdf)
- **Duong, T. & Rizzo, J. (2011).** Here Come The ⊕ Ninjas. *Ekoparty 2011.*
- **Microsoft (2010).** [MS10-070: Vulnerability in ASP.NET Could Allow Information Disclosure](https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2010/ms10-070).
- **Microsoft.** [Timing vulnerabilities with CBC-mode symmetric decryption using padding](https://learn.microsoft.com/en-us/dotnet/standard/security/vulnerabilities-cbc-mode).
- **Rescorla, E. (2026).** [TLS 1.3, RFC 9846](https://www.rfc-editor.org/info/rfc9846/) (obsoletes RFC 8446).

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
