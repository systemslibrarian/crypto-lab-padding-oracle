/**
 * ui.ts — Panel controller for all six demo panels.
 *
 * Manages:
 * - Panel navigation (tab-based, keyboard accessible)
 * - Dark/light mode toggle with ARIA state
 * - Each panel's interactive logic
 * - aria-live announcements for screen readers
 */

import {
  createOracleSession,
  queryOracle,
  OracleSession,
  splitBlocks,
  xorBytes,
  toHex,
  toBytes,
  fromBytes,
  stripPKCS7,
  BLOCK_SIZE,
} from './oracle.ts';
import {
  fullCiphertextAttack,
  recoverBlock,
  theoreticalQueryCount,
  AttackEvent,
} from './attack.ts';
import {
  BlockGrid,
  buildCBCDiagram,
  renderCiphertextBlocks,
  renderXOROperation,
} from './visualizer.ts';
import { renderAllExploits } from './exploits.ts';

// ─── Announcement helper ─────────────────────────────────────────────────────

function announce(message: string): void {
  const el = document.getElementById('aria-announcer');
  if (el) {
    el.textContent = '';
    // Force re-announcement even if same text
    requestAnimationFrame(() => { el.textContent = message; });
  }
}

// ─── Dark/light mode ─────────────────────────────────────────────────────────

export function initThemeToggle(): void {
  const btn = document.getElementById('theme-toggle') as HTMLButtonElement | null;
  if (!btn) return;

  // Sync button state with the data-theme already applied by the anti-flash script
  const current = document.documentElement.getAttribute('data-theme') ?? 'dark';
  syncToggleButton(btn, current === 'dark');

  btn.addEventListener('click', () => {
    const nowDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const next = nowDark ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    syncToggleButton(btn, !nowDark);
  });
}

function syncToggleButton(btn: HTMLButtonElement, dark: boolean): void {
  btn.textContent = dark ? '\u{1F319}' : '\u{2600}\u{FE0F}';
  btn.setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');
}

// ─── Panel navigation ─────────────────────────────────────────────────────────

export function initPanelNav(): void {
  const tabs = document.querySelectorAll<HTMLButtonElement>('.panel-tab');
  const panels = document.querySelectorAll<HTMLElement>('.panel');

  function activateTab(index: number): void {
    tabs.forEach((tab, i) => {
      const active = i === index;
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
      tab.setAttribute('tabindex', active ? '0' : '-1');
    });
    panels.forEach((panel, i) => {
      panel.hidden = i !== index;
      if (i === index) panel.setAttribute('tabindex', '-1');
    });
    announce(`Panel ${index + 1}: ${tabs[index]?.textContent?.trim() ?? ''}`);
  }

  tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => activateTab(i));
    tab.addEventListener('keydown', (e) => {
      let next = i;
      if (e.key === 'ArrowRight') next = (i + 1) % tabs.length;
      else if (e.key === 'ArrowLeft') next = (i - 1 + tabs.length) % tabs.length;
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = tabs.length - 1;
      else return;
      e.preventDefault();
      activateTab(next);
      tabs[next]?.focus();
    });
  });

  // Activate first panel on load
  activateTab(0);
}

// ─── Panel 1: CBC Mode and PKCS#7 Refresher ──────────────────────────────────

export function initPanel1(): void {
  // Build CBC diagram
  const diagramEl = document.getElementById('p1-cbc-diagram');
  if (diagramEl) buildCBCDiagram(diagramEl);

  // PKCS#7 padding examples
  const paddingExamplesEl = document.getElementById('p1-padding-examples');
  if (paddingExamplesEl) {
    const examples: { desc: string; bytes: number[] }[] = [
      { desc: '1 byte of padding', bytes: [0x00, 0x01] },
      { desc: '2 bytes of padding', bytes: [0x00, 0x02, 0x02] },
      { desc: '3 bytes of padding', bytes: [0x00, 0x03, 0x03, 0x03] },
      { desc: '4 bytes of padding', bytes: [0x00, 0x04, 0x04, 0x04, 0x04] },
      { desc: '16 bytes (full block) of padding', bytes: new Array(16).fill(0x10) },
    ];

    const list = document.createElement('div');
    list.className = 'padding-examples';
    list.setAttribute('role', 'list');
    list.setAttribute('aria-label', 'PKCS#7 padding examples');

    examples.forEach(ex => {
      const item = document.createElement('div');
      item.setAttribute('role', 'listitem');
      item.className = 'padding-example';

      const label = document.createElement('span');
      label.className = 'padding-example__label';
      label.textContent = ex.desc;

      const bytes = document.createElement('div');
      bytes.className = 'padding-example__bytes';
      bytes.setAttribute('aria-label', `${ex.desc}: ${ex.bytes.map(b => '0x' + b.toString(16).padStart(2, '0')).join(', ')}`);

      ex.bytes.forEach((byte, i) => {
        const span = document.createElement('span');
        span.className = i >= ex.bytes.length - (ex.bytes[ex.bytes.length - 1]) && ex.bytes[ex.bytes.length - 1] > 0
          ? 'hex-byte hex-byte--pad' : 'hex-byte';
        span.textContent = byte.toString(16).padStart(2, '0');
        bytes.appendChild(span);
      });

      item.appendChild(label);
      item.appendChild(bytes);
      list.appendChild(item);
    });

    paddingExamplesEl.appendChild(list);
  }

  // Valid vs invalid padding examples
  const validPaddingEl = document.getElementById('p1-valid-padding');
  const invalidPaddingEl = document.getElementById('p1-invalid-padding');

  if (validPaddingEl) {
    const valid = [
      { bytes: [0x61, 0x62, 0x63, 0x01], label: 'Valid: …abc 01' },
      { bytes: [0x61, 0x62, 0x02, 0x02], label: 'Valid: …ab 02 02' },
      { bytes: [0x61, 0x03, 0x03, 0x03], label: 'Valid: …a 03 03 03' },
    ];
    valid.forEach(ex => {
      const row = document.createElement('div');
      row.className = 'padding-valid-example';
      row.setAttribute('aria-label', ex.label + ' (valid padding)');
      ex.bytes.forEach((b, i) => {
        const span = document.createElement('span');
        const ispad = i >= ex.bytes.length - ex.bytes[ex.bytes.length - 1];
        span.className = ispad ? 'hex-byte hex-byte--pad' : 'hex-byte';
        span.textContent = b.toString(16).padStart(2, '0');
        row.appendChild(span);
      });
      const badge = document.createElement('span');
      badge.className = 'badge badge--valid';
      badge.setAttribute('aria-label', 'Valid padding');
      badge.textContent = 'Valid ✓';
      row.appendChild(badge);
      validPaddingEl.appendChild(row);
    });
  }

  if (invalidPaddingEl) {
    const invalid = [
      { bytes: [0x61, 0x62, 0x63, 0x02], label: 'Invalid: …abc 02 (only 1 pad byte, expected 2)' },
      { bytes: [0x61, 0x02, 0x03, 0x03], label: 'Invalid: …a 02 03 03 (inconsistent)' },
      { bytes: [0x61, 0x62, 0x63, 0x00], label: 'Invalid: …abc 00 (zero padding)' },
    ];
    invalid.forEach(ex => {
      const row = document.createElement('div');
      row.className = 'padding-invalid-example';
      row.setAttribute('aria-label', ex.label + ' (invalid padding)');
      ex.bytes.forEach(b => {
        const span = document.createElement('span');
        span.className = 'hex-byte hex-byte--error';
        span.textContent = b.toString(16).padStart(2, '0');
        row.appendChild(span);
      });
      const badge = document.createElement('span');
      badge.className = 'badge badge--invalid';
      badge.setAttribute('aria-label', 'Invalid padding');
      badge.textContent = 'Invalid ✗';
      row.appendChild(badge);
      invalidPaddingEl.appendChild(row);
    });
  }
}

// ─── Panel 2: Single Byte Recovery ───────────────────────────────────────────

let p2Session: OracleSession | null = null;
let p2Aborted = false;
let p2Controller: AbortController | null = null;

export function initPanel2(): void {
  const encryptBtn = document.getElementById('p2-encrypt-btn') as HTMLButtonElement;
  const runBtn = document.getElementById('p2-run-btn') as HTMLButtonElement;
  const stopBtn = document.getElementById('p2-stop-btn') as HTMLButtonElement;
  const plaintextInput = document.getElementById('p2-plaintext') as HTMLInputElement;
  const speedSelect = document.getElementById('p2-speed') as HTMLSelectElement;
  const statusEl = document.getElementById('p2-status');
  const queryCountEl = document.getElementById('p2-query-count');
  const ivDisplay = document.getElementById('p2-iv-display');
  const cipherDisplay = document.getElementById('p2-cipher-display');
  const byteGridEl = document.getElementById('p2-byte-grid');
  const resultEl = document.getElementById('p2-result');

  if (!encryptBtn || !runBtn) return;

  encryptBtn.addEventListener('click', async () => {
    const text = plaintextInput?.value ?? 'Hello, padding oracle!';
    // Do NOT pre-pad: createOracleSession passes data to WebCrypto encrypt which
    // applies PKCS#7 automatically. Pre-padding would create a spurious extra block.
    const plaintext = toBytes(text);

    try {
      encryptBtn.disabled = true;
      p2Session = await createOracleSession(plaintext);

      if (ivDisplay) {
        ivDisplay.textContent = toHex(p2Session.iv);
        ivDisplay.setAttribute('aria-label', `IV: ${toHex(p2Session.iv)}`);
      }
      if (cipherDisplay) {
        cipherDisplay.textContent = toHex(p2Session.ciphertext);
        cipherDisplay.setAttribute('aria-label', `Ciphertext: ${toHex(p2Session.ciphertext)}`);
      }

      if (statusEl) statusEl.textContent = 'Session ready. Click "Run Attack" to start.';
      announce('Encryption complete. Session ready.');
      runBtn.disabled = false;
    } catch (err) {
      if (statusEl) statusEl.textContent = `Error: ${String(err)}`;
    } finally {
      encryptBtn.disabled = false;
    }
  });

  runBtn.addEventListener('click', async () => {
    if (!p2Session) return;

    const blocks = splitBlocks(p2Session.ciphertext);
    if (blocks.length < 1) return;

    p2Controller = new AbortController();
    p2Aborted = false;
    runBtn.disabled = true;
    stopBtn.disabled = false;

    // Attack the last block (index blocks.length-1), prev = blocks[length-2] or IV
    const targetIdx = blocks.length - 1;
    const prevBlock = targetIdx === 0 ? p2Session.iv : blocks[targetIdx - 1];
    const targetBlock = blocks[targetIdx];

    const grid = byteGridEl ? new BlockGrid(byteGridEl) : null;
    grid?.reset();

    const delay = parseInt(speedSelect?.value ?? '100');

    let lastEvent: AttackEvent | null = null;

    try {
      const { plaintext } = await recoverBlock(
        p2Session,
        prevBlock,
        targetBlock,
        targetIdx,
        blocks.length,
        async (event: AttackEvent) => {
          lastEvent = event;
          grid?.applyEvent(event);
          if (queryCountEl) queryCountEl.textContent = String(event.queryCount);

          if (event.kind === 'byte-found' && statusEl) {
            const inter = event.intermediateValue ?? 0;
            const pt = event.recoveredByte ?? 0;
            statusEl.textContent =
              `Byte ${BLOCK_SIZE - event.byteIndex}: I=0x${inter.toString(16).padStart(2,'0')} → P=0x${pt.toString(16).padStart(2,'0')} (${pt >= 32 && pt < 127 ? String.fromCharCode(pt) : '·'})`;
          }

          if (delay > 0 && (event.kind === 'byte-found' || event.probeValue === 0 || (event.probeValue ?? 0) % 16 === 0)) {
            await sleep(delay);
          }
        },
        p2Controller.signal
      );

      if (resultEl) {
        const strippedPlain = stripPKCS7(plaintext) ?? plaintext;
        const hex = toHex(strippedPlain);
        const text = fromBytes(strippedPlain);
        resultEl.innerHTML = `
          <div class="result-block" role="region" aria-label="Attack result">
            <div class="result-row"><span class="result-label">Recovered plaintext (hex):</span>
              <span class="hex-display" aria-label="Hex: ${escapeHtml(hex)}">${escapeHtml(hex)}</span></div>
            <div class="result-row"><span class="result-label">Recovered plaintext (text):</span>
              <span class="text-display" aria-label="Text: ${escapeHtml(text)}">${escapeHtml(text)}</span></div>
            <div class="result-row"><span class="result-label">Total oracle queries:</span>
              <span class="query-count">${(lastEvent as AttackEvent | null)?.queryCount ?? 0}</span></div>
          </div>
        `;
        announce(`Attack complete. Recovered: ${text}`);
      }

      if (statusEl) statusEl.textContent = 'Attack complete!';
    } catch (err) {
      if (p2Aborted) {
        if (statusEl) statusEl.textContent = 'Attack stopped.';
        announce('Attack stopped.');
      } else {
        if (statusEl) statusEl.textContent = `Error: ${String(err)}`;
      }
    } finally {
      runBtn.disabled = false;
      stopBtn.disabled = true;
    }
  });

  stopBtn?.addEventListener('click', () => {
    p2Aborted = true;
    p2Controller?.abort();
  });
}

// ─── Panel 3: Full Block Recovery ────────────────────────────────────────────

let p3Session: OracleSession | null = null;
let p3Controller: AbortController | null = null;

export function initPanel3(): void {
  const encryptBtn = document.getElementById('p3-encrypt-btn') as HTMLButtonElement;
  const runBtn = document.getElementById('p3-run-btn') as HTMLButtonElement;
  const stopBtn = document.getElementById('p3-stop-btn') as HTMLButtonElement;
  const speedSelect = document.getElementById('p3-speed') as HTMLSelectElement;
  const statusEl = document.getElementById('p3-status');
  const queryCountEl = document.getElementById('p3-query-count');
  const byteGridEl = document.getElementById('p3-byte-grid');
  const intermediateGridEl = document.getElementById('p3-intermediate-grid');
  const xorDisplayEl = document.getElementById('p3-xor-display');
  const resultEl = document.getElementById('p3-result');

  if (!encryptBtn || !runBtn) return;

  // Use a fixed 16-byte plaintext so one ciphertext block is targeted
  const FIXED_PLAINTEXT = 'Attack at dawn!!'; // exactly 16 bytes

  encryptBtn.addEventListener('click', async () => {
    try {
      encryptBtn.disabled = true;
      p3Session = await createOracleSession(toBytes(FIXED_PLAINTEXT));

      if (statusEl) statusEl.textContent = `Plaintext: "${FIXED_PLAINTEXT}" encrypted. Click "Run Full Block" to start.`;
      announce('Encryption complete. Ready to attack.');
      runBtn.disabled = false;
      if (resultEl) resultEl.innerHTML = '';
    } catch (err) {
      if (statusEl) statusEl.textContent = `Error: ${String(err)}`;
    } finally {
      encryptBtn.disabled = false;
    }
  });

  runBtn.addEventListener('click', async () => {
    if (!p3Session) return;

    p3Controller = new AbortController();
    runBtn.disabled = true;
    stopBtn.disabled = false;

    const blocks = splitBlocks(p3Session.ciphertext);
    // Attack block 0 — that is where "Attack at dawn!!" lives.
    // Block-aligned plaintexts cause WebCrypto to append a full extra padding block;
    // targeting the last block would recover 0x10×16 (padding bytes), not plaintext.
    const targetIdx = 0;
    const prevBlock = p3Session.iv; // prev block for block 0 is always the IV
    const targetBlock = blocks[targetIdx];

    const grid = byteGridEl ? new BlockGrid(byteGridEl) : null;
    const interGrid = intermediateGridEl ? new BlockGrid(intermediateGridEl) : null;
    grid?.reset();
    interGrid?.reset();

    p3Session.queryCount = 0;
    const delay = parseInt(speedSelect?.value ?? '100');

    const intermediateArr = new Uint8Array(BLOCK_SIZE);

    try {
      const { plaintext, intermediate } = await recoverBlock(
        p3Session,
        prevBlock,
        targetBlock,
        targetIdx,
        blocks.length,
        async (event: AttackEvent) => {
          grid?.applyEvent(event);

          if (event.kind === 'byte-found') {
            intermediateArr[event.byteIndex] = event.intermediateValue ?? 0;
            interGrid?.applyEvent({
              ...event,
              recoveredByte: event.intermediateValue,
            });

            if (xorDisplayEl) {
              renderXOROperation(
                xorDisplayEl,
                intermediateArr.slice(event.byteIndex),
                prevBlock.slice(event.byteIndex),
                xorBytes(intermediateArr.slice(event.byteIndex), prevBlock.slice(event.byteIndex)),
                'Intermediate I[j..]',
                'Prev Block C[n-1][j..]',
                'Plaintext P[j..]'
              );
            }
          }

          if (queryCountEl) queryCountEl.textContent = String(event.queryCount);

          if (statusEl && event.kind === 'byte-found') {
            const byteNum = BLOCK_SIZE - event.byteIndex;
            statusEl.textContent = `Recovered byte ${byteNum}/16 — queries: ${event.queryCount}`;
          }

          if (delay > 0 && (event.kind === 'byte-found' || (event.probeValue ?? 0) % 32 === 0)) {
            await sleep(delay);
          }
        },
        p3Controller.signal
      );

      // Show result
      const strippedPlain = stripPKCS7(plaintext) ?? plaintext;
      if (resultEl) {
        const theoretic = theoreticalQueryCount(p3Session.ciphertext.length);
        resultEl.innerHTML = `
          <div class="result-block" role="region" aria-label="Full block recovery result">
            <div class="result-row"><span class="result-label">Recovered plaintext:</span>
              <span class="text-display">${escapeHtml(fromBytes(strippedPlain))}</span></div>
            <div class="result-row"><span class="result-label">Oracle queries used:</span>
              <span class="query-count">${p3Session.queryCount}</span></div>
            <div class="result-row"><span class="result-label">Theoretical O(256×16×blocks) worst case:</span>
              <span class="query-count">${theoretic.worstCase.toLocaleString()}</span></div>
            <div class="result-row"><span class="result-label">Expected (~128×16×blocks):</span>
              <span class="query-count">${theoretic.expectedCase.toLocaleString()}</span></div>
            <div class="result-row"><span class="result-label">Intermediate values (hex):</span>
              <span class="hex-display">${toHex(intermediate)}</span></div>
          </div>
        `;
      }
      announce(`Full block recovered: "${fromBytes(strippedPlain)}"`);
      if (statusEl) statusEl.textContent = 'Full block recovered!';
    } catch {
      if (statusEl) statusEl.textContent = 'Attack stopped.';
    } finally {
      runBtn.disabled = false;
      stopBtn.disabled = true;
    }
  });

  stopBtn?.addEventListener('click', () => {
    p3Controller?.abort();
  });
}

// ─── Panel 4: Full Ciphertext Decryption ─────────────────────────────────────

let p4Session: OracleSession | null = null;
let p4Controller: AbortController | null = null;

export function initPanel4(): void {
  const generateBtn = document.getElementById('p4-generate-btn') as HTMLButtonElement;
  const runBtn = document.getElementById('p4-run-btn') as HTMLButtonElement;
  const stopBtn = document.getElementById('p4-stop-btn') as HTMLButtonElement;
  const plaintextInput = document.getElementById('p4-plaintext') as HTMLTextAreaElement;
  const speedSelect = document.getElementById('p4-speed') as HTMLSelectElement;
  const statusEl = document.getElementById('p4-status');
  const queryCountEl = document.getElementById('p4-query-count');
  const blockVizEl = document.getElementById('p4-block-viz');
  const resultEl = document.getElementById('p4-result');
  const progressBar = document.getElementById('p4-progress') as HTMLProgressElement;

  if (!generateBtn || !runBtn) return;

  generateBtn.addEventListener('click', async () => {
    const text = plaintextInput?.value ?? 'The quick brown fox jumps over the lazy dog. Secrets hidden in CBC ciphertext.';
    try {
      generateBtn.disabled = true;
      p4Session = await createOracleSession(toBytes(text));

      const cblocks = splitBlocks(p4Session.ciphertext);
      if (blockVizEl) {
        renderCiphertextBlocks(blockVizEl, p4Session.iv, cblocks);
      }

      if (statusEl) {
        const info = theoreticalQueryCount(p4Session.ciphertext.length);
        statusEl.textContent = `${cblocks.length} block(s) encrypted. Worst-case queries: ${info.worstCase.toLocaleString()}. Click "Run Full Attack".`;
      }
      announce('Ciphertext generated. Ready to attack.');
      runBtn.disabled = false;
      if (resultEl) resultEl.innerHTML = '';
    } catch (err) {
      if (statusEl) statusEl.textContent = `Error: ${String(err)}`;
    } finally {
      generateBtn.disabled = false;
    }
  });

  runBtn.addEventListener('click', async () => {
    if (!p4Session) return;

    p4Controller = new AbortController();
    runBtn.disabled = true;
    stopBtn.disabled = false;

    p4Session.queryCount = 0;
    const delay = parseInt(speedSelect?.value ?? '0');
    const cblocks = splitBlocks(p4Session.ciphertext);
    const totalBlocks = cblocks.length;

    if (progressBar) {
      progressBar.max = totalBlocks;
      progressBar.value = 0;
    }

    const blockEls = blockVizEl
      ? renderCiphertextBlocks(blockVizEl, p4Session.iv, cblocks, 0)
      : [];

    const recoveredParts: string[] = [];

    try {
      const result = await fullCiphertextAttack(
        p4Session,
        async (event: AttackEvent) => {
          if (queryCountEl) queryCountEl.textContent = String(event.queryCount);

          if (event.kind === 'block-complete') {
            if (progressBar) progressBar.value = event.blockIndex + 1;
            if (blockEls[event.blockIndex]) {
              blockEls[event.blockIndex].classList.remove('cipher-block--active');
              blockEls[event.blockIndex].classList.add('cipher-block--done');
            }
            if (blockEls[event.blockIndex + 1]) {
              blockEls[event.blockIndex + 1].classList.add('cipher-block--active');
            }
            if (event.recoveredBlock) {
              // Show raw block bytes — do NOT strip PKCS#7 per-block; padding
              // only appears in the very last block and is stripped by
              // fullCiphertextAttack at the end.
              recoveredParts.push(fromBytes(event.recoveredBlock));
              if (statusEl) {
                statusEl.textContent = `Block ${event.blockIndex + 1}/${totalBlocks} recovered. Queries: ${event.queryCount.toLocaleString()}`;
              }
            }
          }

          if (event.kind === 'attack-complete' && statusEl) {
            statusEl.textContent = `Attack complete! Total queries: ${event.queryCount.toLocaleString()}`;
          }

          if (delay > 0 && event.kind === 'byte-found') {
            await sleep(delay);
          }
        },
        p4Controller.signal
      );

      const recoveredText = fromBytes(result.plaintext);
      if (resultEl) {
        const info = theoreticalQueryCount(p4Session.ciphertext.length);
        resultEl.innerHTML = `
          <div class="result-block" role="region" aria-label="Full decryption result">
            <div class="result-row"><span class="result-label">Recovered plaintext:</span>
              <blockquote class="recovered-text" aria-label="Recovered plaintext: ${escapeHtml(recoveredText)}">${escapeHtml(recoveredText)}</blockquote></div>
            <div class="result-row"><span class="result-label">Total oracle queries:</span>
              <span class="query-count">${result.queryCount.toLocaleString()}</span></div>
            <div class="result-row"><span class="result-label">Theoretical O(256×16×${totalBlocks}) worst case:</span>
              <span class="query-count">${info.worstCase.toLocaleString()}</span></div>
            <div class="result-row"><span class="result-label">Blocks decrypted:</span>
              <span class="query-count">${totalBlocks}</span></div>
          </div>
        `;
      }
      announce(`Full decryption complete. Recovered: ${recoveredText}`);
    } catch {
      if (statusEl) statusEl.textContent = 'Attack stopped.';
    } finally {
      runBtn.disabled = false;
      stopBtn.disabled = true;
    }
  });

  stopBtn?.addEventListener('click', () => {
    p4Controller?.abort();
  });
}

// ─── Panel 5: Real-World Exploits ─────────────────────────────────────────────

export function initPanel5(): void {
  const container = document.getElementById('p5-exploits');
  if (container) renderAllExploits(container);
}

// ─── Panel 6: Defenses and AEAD ───────────────────────────────────────────────

export function initPanel6(): void {
  initAEADDemo();
}

async function initAEADDemo(): Promise<void> {
  const runBtn = document.getElementById('p6-aead-btn') as HTMLButtonElement;
  const tamperBtn = document.getElementById('p6-tamper-btn') as HTMLButtonElement;
  const resultEl = document.getElementById('p6-aead-result');

  if (!runBtn || !resultEl) return;

  let aeadKey: CryptoKey | null = null;
  let aeadCiphertext: Uint8Array | null = null;
  let aeadIV: Uint8Array<ArrayBuffer> | null = null;

  runBtn.addEventListener('click', async () => {
    runBtn.disabled = true;
    try {
      // Generate AES-GCM key
      aeadKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );

      aeadIV = crypto.getRandomValues(new Uint8Array(12) as Uint8Array<ArrayBuffer>);
      const msg = toBytes('Secret message protected by AES-GCM');
      const msgBuf = new Uint8Array(msg) as Uint8Array<ArrayBuffer>;

      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: aeadIV, tagLength: 128 },
        aeadKey,
        msgBuf
      );
      aeadCiphertext = new Uint8Array(encrypted);

      resultEl.innerHTML = `
        <div class="result-block">
          <div class="result-row"><span class="result-label">AES-GCM key (256-bit):</span>
            <span class="badge badge--valid" aria-label="Key generated">Generated (not extractable)</span></div>
          <div class="result-row"><span class="result-label">IV (96-bit):</span>
            <span class="hex-display">${toHex(aeadIV)}</span></div>
          <div class="result-row"><span class="result-label">Ciphertext + auth tag:</span>
            <span class="hex-display">${toHex(aeadCiphertext)}</span></div>
          <div class="result-row"><span class="result-label">Tag length:</span>
            <span>128-bit (embedded in ciphertext)</span></div>
        </div>
        <p class="info-note" role="note">
          No padding needed — GCM is a stream mode. Authentication tag covers entire ciphertext.
          Any modification — even one bit — will cause decryption to reject the message.
        </p>
      `;
      tamperBtn.disabled = false;
      announce('AES-GCM encryption complete. Try tampering with the ciphertext.');
    } catch (err) {
      resultEl.innerHTML = `<p role="alert">Error: ${String(err)}</p>`;
    } finally {
      runBtn.disabled = false;
    }
  });

  tamperBtn?.addEventListener('click', async () => {
    if (!aeadKey || !aeadCiphertext || !aeadIV) return;
    tamperBtn.disabled = true;

    // Flip the first byte of the ciphertext (not the tag)
    const tampered = aeadCiphertext.slice();
    tampered[0] ^= 0xFF;

    try {
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: aeadIV, tagLength: 128 },
        aeadKey,
        tampered
      );
      // Should never reach here
      if (resultEl) {
        resultEl.innerHTML += `<p class="error" role="alert">Unexpected: decryption succeeded! This indicates a bug.</p>`;
      }
    } catch {
      // Expected — tampered ciphertext rejected by authentication tag
      if (resultEl) {
        resultEl.innerHTML += `
          <div class="result-block result-block--error" role="alert" aria-live="assertive">
            <p class="aead-reject">
              <strong>Tampered ciphertext REJECTED by authentication tag.</strong>
            </p>
            <p>
              AES-GCM checks the authentication tag <em>before</em> any decryption.
              If the tag fails, no plaintext is ever produced — there is no oracle.
              No information about the plaintext is revealed. No padding oracle attack is possible.
            </p>
            <p>
              Byte 0 was flipped: <span class="hex-byte">${aeadCiphertext[0].toString(16).padStart(2,'0')}</span>
              → <span class="hex-byte hex-byte--error">${tampered[0].toString(16).padStart(2,'0')}</span>
              — authentication failed immediately.
            </p>
          </div>
        `;
      }
      announce('AES-GCM rejected tampered ciphertext. No oracle possible.');
    } finally {
      tamperBtn.disabled = false;
    }
  });
}

// ─── Panel 1 Oracle query live demo ──────────────────────────────────────────

export async function initP1OracleDemo(): Promise<void> {
  const btn = document.getElementById('p1-oracle-demo-btn') as HTMLButtonElement | null;
  const resultEl = document.getElementById('p1-oracle-demo-result');
  if (!btn || !resultEl) return;

  btn.addEventListener('click', async () => {
    btn.disabled = true;
    resultEl.innerHTML = '<p aria-busy="true">Encrypting…</p>';

    try {
      const session = await createOracleSession(toBytes('Hello Oracle!'));
      const blocks = splitBlocks(session.ciphertext);
      const prevBlock = session.iv;
      const targetBlock = blocks[0];

      // Query with valid prev block — should be valid
      const validResult = await queryOracle(session, prevBlock, targetBlock);

      // Query with a zeroed prev block — very likely invalid
      const invalidPrev = new Uint8Array(BLOCK_SIZE);
      const invalidResult = await queryOracle(session, invalidPrev, targetBlock);

      resultEl.innerHTML = `
        <div class="result-block" role="region" aria-label="Oracle demo results">
          <div class="result-row">
            <span class="result-label">Query 1 (unmodified C[n-1]):</span>
            <span class="badge badge--${validResult.valid ? 'valid' : 'invalid'}" aria-label="${validResult.valid ? 'Valid' : 'Invalid'} padding">
              ${validResult.valid ? 'Valid ✓' : 'Invalid ✗'}
            </span>
          </div>
          <div class="result-row">
            <span class="result-label">Query 2 (zeroed C[n-1]):</span>
            <span class="badge badge--${invalidResult.valid ? 'valid' : 'invalid'}" aria-label="${invalidResult.valid ? 'Valid' : 'Invalid'} padding">
              ${invalidResult.valid ? 'Valid ✓' : 'Invalid ✗'}
            </span>
          </div>
          <p class="info-note" role="note">
            The oracle reveals one bit. That bit, queried ${BLOCK_SIZE * 256} times per block,
            is enough to decrypt everything — without knowing the key.
          </p>
        </div>
      `;
      announce(`Oracle demo: Query 1 ${validResult.valid ? 'valid' : 'invalid'}, Query 2 ${invalidResult.valid ? 'valid' : 'invalid'}`);
    } catch (err) {
      resultEl.innerHTML = `<p role="alert">Error: ${String(err)}</p>`;
    } finally {
      btn.disabled = false;
    }
  });
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
