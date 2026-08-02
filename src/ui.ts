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
  splitBlocks,
  xorBytes,
  toHex,
  toBytes,
  fromBytes,
  stripPKCS7,
  applyPKCS7,
  BLOCK_SIZE,
} from './oracle.ts';
import type { OracleMode, OracleSession } from './oracle.ts';
import {
  fullCiphertextAttack,
  recoverBlock,
  theoreticalQueryCount,
  trialAgainstMode,
} from './attack.ts';
import type { AttackEvent, DefenseTrial } from './attack.ts';
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
  const icon = btn.querySelector<HTMLElement>('.theme-toggle__icon') ?? btn;
  icon.textContent = dark ? '\u{1F319}' : '\u{2600}\u{FE0F}';
  // Stable name ("Dark mode") + aria-pressed carries the on/off state, so screen
  // readers announce a clear "Dark mode, toggle button, pressed/not pressed".
  btn.setAttribute('aria-pressed', dark ? 'true' : 'false');
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
    // Keep the active tab fully visible in the horizontally-scrolling bar (mobile).
    tabs[index]?.scrollIntoView({ block: 'nearest', inline: 'center' });
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
  const commentaryEl = document.getElementById('p2-commentary');
  const commentaryTextEl = document.getElementById('p2-commentary-text');

  function setP2Commentary(html: string): void {
    if (!commentaryEl || !commentaryTextEl) return;
    commentaryEl.classList.add('attack-commentary--active');
    commentaryTextEl.innerHTML = html;
  }

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
      setP2Commentary(
        `Encryption done. The attack targets the <strong>last block</strong> of the ciphertext. ` +
        `It will probe all 256 possible values for the last byte of the previous ciphertext block (C[n−1][15]), ` +
        `submitting each modified pair to the padding oracle. When the oracle says <em>valid 0x01 padding</em>, ` +
        `we can compute the intermediate byte I[15] = probe ⊕ 0x01, and then recover ` +
        `plaintext P[15] = I[15] ⊕ C[n−1][15] — <strong>no key needed</strong>.`
      );
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
    runBtn.disabled = true;
    stopBtn.disabled = false;
    // Reset per-run state so a second run reports its own query count, not a
    // cumulative total, and doesn't show the previous run's result block.
    p2Session.queryCount = 0;
    if (resultEl) resultEl.innerHTML = '';

    // Attack the last block (index blocks.length-1), prev = blocks[length-2] or IV
    const targetIdx = blocks.length - 1;
    const prevBlock = targetIdx === 0 ? p2Session.iv : blocks[targetIdx - 1];
    const targetBlock = blocks[targetIdx];

    const grid = byteGridEl ? new BlockGrid(byteGridEl) : null;
    grid?.reset();

    const delay = parseInt(speedSelect?.value ?? '100');

    let lastEvent: AttackEvent | null = null;

    setP2Commentary(
      `Attack started on block ${targetIdx + 1}. Probing byte position 15 (rightmost) first — ` +
      `trying all 256 values of C[n−1][15] until the oracle returns valid <code>0x01</code> padding.`
    );

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
            const char = pt >= 32 && pt < 127 ? String.fromCharCode(pt) : '·';
            const bytePos = BLOCK_SIZE - 1 - event.byteIndex;
            statusEl.textContent =
              `Byte ${BLOCK_SIZE - event.byteIndex}: I=0x${inter.toString(16).padStart(2,'0')} → P=0x${pt.toString(16).padStart(2,'0')} (${pt >= 32 && pt < 127 ? String.fromCharCode(pt) : '·'})`;
            const cprev = prevBlock[event.byteIndex];
            const padByte = BLOCK_SIZE - event.byteIndex;
            setP2Commentary(
              `<strong>Byte ${BLOCK_SIZE - event.byteIndex} of 16 recovered!</strong> ` +
              `Probe <code>0x${(event.probeValue ?? 0).toString(16).padStart(2,'0')}</code> produced valid ` +
              `<code>0x${padByte.toString(16).padStart(2,'0')}</code> padding. ` +
              `Intermediate: I[${event.byteIndex}] = <code>0x${(event.probeValue ?? 0).toString(16).padStart(2,'0')}</code> ⊕ ` +
              `<code>0x${padByte.toString(16).padStart(2,'0')}</code> = <code>0x${inter.toString(16).padStart(2,'0')}</code>. ` +
              `Plaintext: P[${event.byteIndex}] = I[${event.byteIndex}] ⊕ C[n−1][${event.byteIndex}] = ` +
              `<code>0x${inter.toString(16).padStart(2,'0')}</code> ⊕ <code>0x${cprev.toString(16).padStart(2,'0')}</code> = ` +
              `<code>0x${pt.toString(16).padStart(2,'0')}</code> ` +
              (bytePos > 0
                ? `("<strong>${escapeHtml(char)}</strong>"). Now setting up padding <code>0x${(padByte + 1).toString(16).padStart(2,'0')}</code> to recover byte ${bytePos}.`
                : `("<strong>${escapeHtml(char)}</strong>"). All bytes recovered!`)
            );
          }

          if (delay > 0 && (event.kind === 'byte-found' || event.probeValue === 0 || (event.probeValue ?? 0) % 16 === 0)) {
            await sleep(delay);
          }
        },
        p2Controller.signal
      );

      if (resultEl) {
        // When the input length is an exact multiple of 16, PKCS#7 appends a
        // whole extra block of 0x10 bytes — which becomes the *last* block this
        // panel attacks. The recovery is correct, but stripping padding leaves
        // an empty string, so explain rather than show a blank "success".
        const isFullPaddingBlock =
          plaintext.length === BLOCK_SIZE && plaintext.every(b => b === BLOCK_SIZE);
        const strippedPlain = stripPKCS7(plaintext) ?? plaintext;
        const hex = toHex(isFullPaddingBlock ? plaintext : strippedPlain);
        const text = fromBytes(strippedPlain);
        const paddingNote = isFullPaddingBlock
          ? `<div class="result-row"><span class="result-label">Note:</span>
              <span class="text-display">This last block is a full PKCS#7 padding block (16 × 0x10),
              appended because the message length is a multiple of 16. The attack recovered it correctly —
              the message bytes live in the earlier blocks (try Panel 4 for full multi-block recovery).</span></div>`
          : '';
        resultEl.innerHTML = `
          <div class="result-block" role="region" aria-label="Attack result">
            <div class="result-row"><span class="result-label">Recovered ${isFullPaddingBlock ? 'block' : 'plaintext'} (hex):</span>
              <span class="hex-display" aria-label="Hex: ${escapeHtml(hex)}">${escapeHtml(hex)}</span></div>
            <div class="result-row"><span class="result-label">Recovered plaintext (text):</span>
              <span class="text-display" aria-label="Text: ${escapeHtml(text)}">${escapeHtml(text) || '<em>(empty — this block was pure padding)</em>'}</span></div>
            ${paddingNote}
            <div class="result-row"><span class="result-label">Total oracle queries:</span>
              <span class="query-count">${(lastEvent as AttackEvent | null)?.queryCount ?? 0}</span></div>
          </div>
        `;
        announce(isFullPaddingBlock
          ? 'Attack complete. The last block was a full padding block and was recovered correctly.'
          : `Attack complete. Recovered: ${text}`);
      }

      if (statusEl) statusEl.textContent = 'Attack complete!';
      setP2Commentary(
        `<strong>Attack complete!</strong> The last block was fully decrypted in ` +
        `<strong>${(lastEvent as AttackEvent | null)?.queryCount ?? 0}</strong> oracle queries. ` +
        `Each byte cost at most 256 queries to find (on average ~128). ` +
        `The AES key was never needed — only the oracle's valid/invalid response.`
      );
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') {
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
  const commentaryEl = document.getElementById('p3-commentary');
  const commentaryTextEl = document.getElementById('p3-commentary-text');

  function setP3Commentary(html: string): void {
    if (!commentaryEl || !commentaryTextEl) return;
    commentaryEl.classList.add('attack-commentary--active');
    commentaryTextEl.innerHTML = html;
  }

  const plaintextInput = document.getElementById('p3-plaintext') as HTMLInputElement | null;
  const byteCountEl = document.getElementById('p3-bytecount');

  if (!encryptBtn || !runBtn) return;

  // The learner types the block to be recovered. Block 0 is attacked, so the
  // first 16 bytes of whatever they enter are what comes back.
  function currentPlaintext(): string {
    const value = plaintextInput?.value ?? '';
    return value.length > 0 ? value : 'Attack at dawn!!';
  }

  function updateByteCount(): void {
    if (!byteCountEl) return;
    const len = toBytes(currentPlaintext()).length;
    byteCountEl.textContent = len === BLOCK_SIZE
      ? '16 bytes — exactly one block'
      : `${len} byte${len === 1 ? '' : 's'} — block 0 is the first ${Math.min(len, BLOCK_SIZE)}${len < BLOCK_SIZE ? ' plus PKCS#7 padding' : ''}`;
  }

  plaintextInput?.addEventListener('input', () => {
    updateByteCount();
    // A new target invalidates the session encrypted from the old one.
    p3Session = null;
    runBtn.disabled = true;
    if (statusEl) statusEl.textContent = 'Plaintext changed — click "Encrypt Target Block" again.';
  });
  updateByteCount();

  encryptBtn.addEventListener('click', async () => {
    const targetPlaintext = currentPlaintext();
    try {
      encryptBtn.disabled = true;
      p3Session = await createOracleSession(toBytes(targetPlaintext));

      if (statusEl) statusEl.textContent = `Plaintext: "${targetPlaintext}" encrypted. Click "Run Full Block" to start.`;
      setP3Commentary(
        `The plaintext "<strong>${escapeHtml(targetPlaintext)}</strong>" is now AES-CBC encrypted. ` +
        `The attack will recover all 16 bytes of this block, one at a time from right to left. ` +
        `For each byte position j, the oracle is queried with craft prefix bytes that force ` +
        `the desired PKCS#7 padding byte — revealing the intermediate value I[j] = AES⁻¹(C[n])[j].`
      );
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

            const inter = event.intermediateValue ?? 0;
            const pt = event.recoveredByte ?? 0;
            const char = pt >= 32 && pt < 127 ? String.fromCharCode(pt) : '·';
            const recovered = BLOCK_SIZE - event.byteIndex;
            const padByte = BLOCK_SIZE - event.byteIndex;
            setP3Commentary(
              `<strong>Byte ${recovered}/16 recovered.</strong> ` +
              `Probe <code>0x${(event.probeValue ?? 0).toString(16).padStart(2,'0')}</code> gave valid ` +
              `<code>0x${padByte.toString(16).padStart(2,'0')}</code> padding at position ${event.byteIndex}. ` +
              `Intermediate I[${event.byteIndex}] = <code>0x${inter.toString(16).padStart(2,'0')}</code>. ` +
              `Plaintext P[${event.byteIndex}] = <code>0x${pt.toString(16).padStart(2,'0')}</code> ` +
              `("<strong>${escapeHtml(char)}</strong>"). ` +
              (event.byteIndex > 0
                ? `Next: fix up known bytes for <code>0x${(padByte + 1).toString(16).padStart(2,'0')}</code> padding, then probe position ${event.byteIndex - 1}.`
                : `All 16 bytes recovered — XOR with C[n−1] confirms the full plaintext!`)
            );
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

      // Grade the recovery against block 0 of what was actually encrypted. The
      // attack path never reads session.plaintext, so this is the demo checking
      // itself rather than restating its own input.
      const expectedBlock = applyPKCS7(p3Session.plaintext).slice(0, BLOCK_SIZE);
      const exactBlock =
        plaintext.length === expectedBlock.length &&
        plaintext.every((b, i) => b === expectedBlock[i]);

      if (resultEl) {
        const theoretic = theoreticalQueryCount(p3Session.ciphertext.length);
        resultEl.innerHTML = `
          <div class="result-block" role="region" aria-label="Full block recovery result">
            <div class="result-row"><span class="result-label">Recovered plaintext:</span>
              <span class="text-display">${escapeHtml(fromBytes(strippedPlain))}</span></div>
            <div class="result-row"><span class="result-label">Checked against the encrypted block:</span>
              <span class="badge badge--${exactBlock ? 'valid' : 'invalid'}">${exactBlock ? 'byte-for-byte match' : 'MISMATCH — the attack did not recover this block'}</span></div>
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
      setP3Commentary(
        `<strong>Full block decrypted!</strong> "${escapeHtml(fromBytes(strippedPlain))}" — ` +
        `recovered in <strong>${p3Session.queryCount}</strong> oracle queries. ` +
        `The XOR table above shows how each intermediate byte I[j] XORed with C[n−1][j] ` +
        `yields the plaintext. The AES key was never used or needed.`
      );
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
  const commentaryEl = document.getElementById('p4-commentary');
  const commentaryTextEl = document.getElementById('p4-commentary-text');

  function setP4Commentary(html: string): void {
    if (!commentaryEl || !commentaryTextEl) return;
    commentaryEl.classList.add('attack-commentary--active');
    commentaryTextEl.innerHTML = html;
  }

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
      setP4Commentary(
        `<strong>${cblocks.length} ciphertext block${cblocks.length > 1 ? 's' : ''} ready.</strong> ` +
        `The attack will process each block in turn, recovering 16 plaintext bytes per block. ` +
        `Each byte requires up to 256 oracle queries (expected ~128). ` +
        `The IV is used to recover the first block — just as in a real-world attack where the IV travels with the ciphertext.`
      );
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

      // Byte-for-byte check of the recovered plaintext against the plaintext the
      // session actually encrypted. The attacker path never reads this — it is
      // the demo grading itself, so the "recovered" claim on screen is a result
      // and not an assertion the page could make even if the attack were broken.
      const original = p4Session.plaintext;
      const exact =
        result.plaintext.length === original.length &&
        result.plaintext.every((b, i) => b === original[i]);

      if (resultEl) {
        const info = theoreticalQueryCount(p4Session.ciphertext.length);
        resultEl.innerHTML = `
          <div class="result-block" role="region" aria-label="Full decryption result">
            <div class="result-row"><span class="result-label">Recovered plaintext:</span>
              <blockquote class="recovered-text" aria-label="Recovered plaintext: ${escapeHtml(recoveredText)}">${escapeHtml(recoveredText)}</blockquote></div>
            <div class="result-row"><span class="result-label">Checked against the encrypted plaintext:</span>
              <span class="badge badge--${exact ? 'valid' : 'invalid'}">${exact ? 'byte-for-byte match' : 'MISMATCH — the attack did not fully recover it'}</span></div>
            <div class="result-row"><span class="result-label">Total oracle queries:</span>
              <span class="query-count">${result.queryCount.toLocaleString()}</span></div>
            <div class="result-row"><span class="result-label">Theoretical O(256×16×${totalBlocks}) worst case:</span>
              <span class="query-count">${info.worstCase.toLocaleString()}</span></div>
            <div class="result-row"><span class="result-label">Blocks decrypted:</span>
              <span class="query-count">${totalBlocks}</span></div>
          </div>
        `;
      }
      announce(
        `Full decryption complete. Recovered: ${recoveredText}. ` +
        (exact ? 'Byte-for-byte match with the original plaintext.' : 'It does NOT match the original plaintext.')
      );
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
            The oracle reveals one bit. That bit, queried at most ${BLOCK_SIZE * 256} times per
            block — about ${BLOCK_SIZE * 128} on average, since a 256-value scan finds the right
            probe halfway through — is enough to decrypt everything, without knowing the key.
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

// ─── Panel 1: learner-crafted padding byte ───────────────────────────────────

/**
 * The learner picks what the final decrypted byte becomes, commits to a
 * prediction, and only then does the real oracle answer.
 *
 * The forcing trick is the attack's own: the practice message is exactly one
 * block, so WebCrypto appends a second block that decrypts to 0x10 sixteen
 * times. XOR (0x10 ^ chosen) into C[n−1][15] and the receiver decrypts `chosen`
 * in that position instead. The page knows the plaintext here — a real attacker
 * would not — but the valid/invalid answer comes from WebCrypto, not from us.
 */
export function initP1PaddingCraft(): void {
  const setupBtn = document.getElementById('p1-craft-setup-btn') as HTMLButtonElement | null;
  const byteSelect = document.getElementById('p1-craft-byte') as HTMLSelectElement | null;
  const predictValidBtn = document.getElementById('p1-predict-valid-btn') as HTMLButtonElement | null;
  const predictInvalidBtn = document.getElementById('p1-predict-invalid-btn') as HTMLButtonElement | null;
  const correctEl = document.getElementById('p1-craft-correct');
  const totalEl = document.getElementById('p1-craft-total');
  const resultEl = document.getElementById('p1-craft-result');

  if (!setupBtn || !byteSelect || !predictValidBtn || !predictInvalidBtn || !resultEl) return;

  const PRACTICE_TEXT = 'Padding practice';   // exactly 16 bytes
  const PAD_BYTE = BLOCK_SIZE;                // the appended block is 0x10 x 16

  let session: OracleSession | null = null;
  let prevBlock: Uint8Array | null = null;
  let targetBlock: Uint8Array | null = null;
  let correct = 0;
  let total = 0;

  setupBtn.addEventListener('click', async () => {
    setupBtn.disabled = true;
    try {
      session = await createOracleSession(toBytes(PRACTICE_TEXT));
      const blocks = splitBlocks(session.ciphertext);
      targetBlock = blocks[blocks.length - 1];
      prevBlock = blocks.length > 1 ? blocks[blocks.length - 2] : session.iv;

      resultEl.innerHTML = `
        <div class="result-block" role="region" aria-label="Practice ciphertext ready">
          <div class="result-row"><span class="result-label">Message:</span>
            <span class="text-display">"${escapeHtml(PRACTICE_TEXT)}" (16 bytes, so PKCS#7 appends a whole padding block)</span></div>
          <div class="result-row"><span class="result-label">Last block decrypts to:</span>
            <span class="hex-display">${toHex(new Uint8Array(BLOCK_SIZE).fill(PAD_BYTE))}</span></div>
          <p class="info-note" role="note">
            Pick a value, decide whether the padding will still be valid, and press your prediction.
          </p>
        </div>
      `;
      predictValidBtn.disabled = false;
      predictInvalidBtn.disabled = false;
      announce('Practice ciphertext ready. Choose a byte and predict.');
    } catch (err) {
      resultEl.innerHTML = `<p role="alert">Error: ${String(err)}</p>`;
    } finally {
      setupBtn.disabled = false;
    }
  });

  async function judge(predictedValid: boolean): Promise<void> {
    if (!session || !prevBlock || !targetBlock || !resultEl || !byteSelect) return;

    predictValidBtn!.disabled = true;
    predictInvalidBtn!.disabled = true;

    try {
      const chosen = Number(byteSelect.value) & 0xff;

      // Force the last decrypted byte to `chosen` without touching the key.
      const modified = prevBlock.slice();
      modified[BLOCK_SIZE - 1] ^= PAD_BYTE ^ chosen;

      const answer = await queryOracle(session, modified, targetBlock);
      const wasRight = answer.valid === predictedValid;

      total++;
      if (wasRight) correct++;
      if (correctEl) correctEl.textContent = String(correct);
      if (totalEl) totalEl.textContent = String(total);

      // What the receiver now decrypts: 0x10 fifteen times, then the chosen byte.
      const decrypted = new Uint8Array(BLOCK_SIZE).fill(PAD_BYTE);
      decrypted[BLOCK_SIZE - 1] = chosen;

      const hex = (b: number): string => `0x${b.toString(16).padStart(2, '0')}`;
      const why = chosen === 0x01
        ? `${hex(chosen)} claims one padding byte, and that one byte is itself — valid.`
        : chosen === PAD_BYTE
          ? `${hex(chosen)} claims sixteen padding bytes, and all sixteen really are 0x10 — valid.`
          : chosen === 0
            ? `${hex(chosen)} claims zero padding bytes, which PKCS#7 does not allow.`
            : chosen > BLOCK_SIZE
              ? `${hex(chosen)} claims more than 16 padding bytes, which cannot fit in a block.`
              : `${hex(chosen)} claims ${chosen} padding bytes, so the ${chosen - 1} bytes before it would all have to be ${hex(chosen)} — they are 0x10.`;

      resultEl.innerHTML = `
        <div class="result-block ${wasRight ? '' : 'result-block--error'}" role="region" aria-label="Prediction result">
          <div class="result-row"><span class="result-label">You predicted:</span>
            <span class="badge badge--${predictedValid ? 'valid' : 'invalid'}">${predictedValid ? 'Valid' : 'Invalid'}</span></div>
          <div class="result-row"><span class="result-label">The oracle answered:</span>
            <span class="badge badge--${answer.valid ? 'valid' : 'invalid'}">${answer.valid ? 'Valid ✓' : 'Invalid ✗'}</span></div>
          <div class="result-row"><span class="result-label">Verdict:</span>
            <span class="text-display">${wasRight ? 'Correct.' : 'Not this time.'}</span></div>
          <div class="result-row"><span class="result-label">Block the receiver decrypted:</span>
            <span class="hex-display">${toHex(decrypted)}</span></div>
          <div class="result-row"><span class="result-label">Why:</span>
            <span class="text-display">${escapeHtml(why)}</span></div>
          <div class="result-row"><span class="result-label">Oracle queries so far:</span>
            <span class="query-count">${answer.queryCount}</span></div>
        </div>
      `;
      announce(`Oracle said ${answer.valid ? 'valid' : 'invalid'}. Your prediction was ${wasRight ? 'correct' : 'wrong'}.`);
    } catch (err) {
      resultEl.innerHTML = `<p role="alert">Error: ${String(err)}</p>`;
    } finally {
      predictValidBtn!.disabled = false;
      predictInvalidBtn!.disabled = false;
    }
  }

  predictValidBtn.addEventListener('click', () => { void judge(true); });
  predictInvalidBtn.addEventListener('click', () => { void judge(false); });
}

// ─── Panel 6: the same attack against three servers ──────────────────────────

const MODE_LABELS: Record<OracleMode, string> = {
  leaky: 'Leaky CBC — padding errors are observable',
  silent: 'Silent CBC — same response whatever the padding check said',
  etm: 'Encrypt-then-MAC — MAC verified before decryption',
};

export function initDefenseBench(): void {
  const runBtn = document.getElementById('p6-bench-btn') as HTMLButtonElement | null;
  const input = document.getElementById('p6-bench-plaintext') as HTMLInputElement | null;
  const statusEl = document.getElementById('p6-bench-status');
  const rowsEl = document.getElementById('p6-bench-rows');
  const noteEl = document.getElementById('p6-bench-note');

  if (!runBtn || !rowsEl) return;

  runBtn.addEventListener('click', async () => {
    runBtn.disabled = true;
    const text = input?.value?.length ? input.value : 'Attack at dawn!!';
    rowsEl.innerHTML = '<tr><td colspan="5">Running…</td></tr>';
    if (statusEl) statusEl.textContent = 'Running the same attack against each server…';

    try {
      const modes: OracleMode[] = ['leaky', 'silent', 'etm'];
      const trials: DefenseTrial[] = [];

      for (const mode of modes) {
        // Same plaintext, same attack code — only the server's behaviour differs.
        trials.push(await trialAgainstMode(toBytes(text), mode));
      }

      rowsEl.innerHTML = trials.map((trial) => {
        const outcome = trial.failure === null
          ? `<span class="badge badge--invalid">plaintext recovered</span> "${escapeHtml(fromBytes(trial.recovered ? (stripPKCS7(trial.recovered) ?? trial.recovered) : new Uint8Array()))}"${trial.matchedPlaintext ? ' — byte-for-byte match' : ' — DID NOT match the encrypted block'}`
          : `<span class="badge badge--valid">attack failed</span> ${escapeHtml(trial.failure)} (${trial.bytesRecovered} of 16 bytes)`;
        return `
          <tr>
            <th scope="row">${escapeHtml(MODE_LABELS[trial.mode])}</th>
            <td>${outcome}</td>
            <td class="query-count">${trial.queryCount.toLocaleString()}</td>
            <td class="query-count">${trial.paddingChecks.toLocaleString()}</td>
            <td class="query-count">${trial.macRejections.toLocaleString()}</td>
          </tr>
        `;
      }).join('');

      const leaky = trials[0];
      const silent = trials[1];
      const etm = trials[2];

      if (statusEl) {
        statusEl.textContent = leaky.failure === null && silent.failure !== null && etm.failure !== null
          ? 'Attack succeeded against the leaky server and failed against both defended ones.'
          : 'Unexpected outcome — see the table.';
      }

      if (noteEl) {
        noteEl.innerHTML = `
          <div class="result-block" role="region" aria-label="Defense bench summary">
            <p>
              The leaky server gave up its block in <strong>${leaky.queryCount.toLocaleString()}</strong> queries.
              The silent server ran <strong>${silent.paddingChecks.toLocaleString()}</strong> padding checks and still
              starved the attack — it withheld the answer, not the computation, and one bit that never changes is
              no bit at all. It is modelled here as one constant response to every submission, which is what an
              attacker sees from a server that reveals nothing about how a message was processed.
              Encrypt-then-MAC reached the padding check <strong>${etm.paddingChecks.toLocaleString()}</strong>
              times: every one of its <strong>${etm.macRejections.toLocaleString()}</strong> queries died at MAC
              verification, before AES-CBC decryption was attempted.
            </p>
            <p class="info-note" role="note">
              Silent-mode's protection is the fragile one. A real deployment leaks the same bit through response
              timing, log volume, or downstream behaviour — which is exactly how Lucky Thirteen beat "constant"
              error handling. Only authentication removes the oracle rather than hiding it.
            </p>
          </div>
        `;
      }
    } catch (err) {
      if (statusEl) statusEl.textContent = `Error: ${String(err)}`;
    } finally {
      runBtn.disabled = false;
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
