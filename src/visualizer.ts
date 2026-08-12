/**
 * visualizer.ts — Byte grid animation and oracle query counter.
 *
 * Renders a 16-column byte grid showing attack state per byte position.
 * Each cell can be in one of several states:
 *   - unknown:  not yet attacked
 *   - probing:  currently being probed (flashing)
 *   - found:    intermediate value recovered
 *   - complete: plaintext byte recovered
 *
 * Respects prefers-reduced-motion: when enabled, animations are skipped.
 * All color states have text equivalents (aria labels + data attributes).
 */

import { BLOCK_SIZE } from './oracle.ts';
import type { AttackEvent } from './attack.ts';

export type ByteState = 'unknown' | 'probing' | 'found' | 'complete';

export interface ByteCellData {
  state: ByteState;
  value: number | null;        // byte value (0–255) or null if unknown
  intermediateValue: number | null;
  label: string;               // text label for screen readers
}

// Single shared reduced-motion tracker — one listener for the whole module
// (each BlockGrid used to add its own listener that was never removed).
let prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
window.matchMedia('(prefers-reduced-motion: reduce)')
  .addEventListener('change', (e) => { prefersReducedMotion = e.matches; });

/** A rendered block grid (one row of 16 cells) */
export class BlockGrid {
  private cells: ByteCellData[] = [];
  private container: HTMLElement;
  private queryCountEl: HTMLElement | null = null;
  // Persistent cell elements so updates touch only the changed cell instead of
  // rebuilding all 16 cells' innerHTML on every one of ~thousands of probes.
  private cellEls: HTMLElement[] = [];
  private valueEls: HTMLElement[] = [];
  private stateEls: HTMLElement[] = [];

  constructor(container: HTMLElement, queryCountEl?: HTMLElement) {
    this.container = container;
    this.queryCountEl = queryCountEl ?? null;
    this.initCells();
    this.buildDom();
  }

  private initCells(): void {
    this.cells = Array.from({ length: BLOCK_SIZE }, (_, i) => ({
      state: 'unknown',
      value: null,
      intermediateValue: null,
      label: `Byte ${i + 1} of ${BLOCK_SIZE}: unknown`,
    }));
  }

  /** Build the cell DOM once; subsequent updates mutate cells in place. */
  private buildDom(): void {
    this.container.innerHTML = '';
    // Keep the container a labeled, focusable scroll region (role="group" +
    // tabindex from the markup); the inner row carries role="list". Leaving an
    // aria-label on a roleless generic div is an aria-prohibited-attr failure.
    this.container.setAttribute('role', 'group');

    const row = document.createElement('div');
    row.className = 'byte-grid-row';
    // Read-only set of bytes — a list conveys "16 items" without implying the
    // arrow-key-navigable interaction that role="grid" promises.
    row.setAttribute('role', 'list');
    row.setAttribute('aria-label', 'Block bytes, position 1 to 16');

    this.cellEls = [];
    this.valueEls = [];
    this.stateEls = [];

    this.cells.forEach((cell, i) => {
      const cellEl = document.createElement('div');
      cellEl.setAttribute('role', 'listitem');
      cellEl.className = `byte-cell byte-cell--${cell.state}`;
      cellEl.setAttribute('aria-label', cell.label);
      cellEl.setAttribute('data-state', cell.state);
      cellEl.setAttribute('data-index', String(i));

      const valueEl = document.createElement('span');
      valueEl.className = 'byte-cell__value';
      valueEl.setAttribute('aria-hidden', 'true');
      valueEl.textContent = '??';

      const stateLabel = document.createElement('span');
      stateLabel.className = 'byte-cell__state-label sr-only';
      stateLabel.textContent = stateText(cell.state);

      cellEl.appendChild(valueEl);
      cellEl.appendChild(stateLabel);
      row.appendChild(cellEl);

      this.cellEls[i] = cellEl;
      this.valueEls[i] = valueEl;
      this.stateEls[i] = stateLabel;
    });

    this.container.appendChild(row);
  }

  /** Sync a single cell's DOM to its current data. */
  private updateCell(i: number): void {
    const cell = this.cells[i];
    const cellEl = this.cellEls[i];
    if (!cellEl) return;
    cellEl.className = `byte-cell byte-cell--${cell.state}`;
    if (!prefersReducedMotion && cell.state === 'probing') {
      cellEl.classList.add('byte-cell--animate');
    }
    cellEl.setAttribute('aria-label', cell.label);
    cellEl.setAttribute('data-state', cell.state);
    this.valueEls[i].textContent = cell.value !== null
      ? cell.value.toString(16).padStart(2, '0')
      : '??';
    this.stateEls[i].textContent = stateText(cell.state);
  }

  reset(): void {
    this.initCells();
    for (let i = 0; i < BLOCK_SIZE; i++) this.updateCell(i);
  }

  /**
   * Update a cell based on an attack event. Touches only the affected cell(s).
   */
  applyEvent(event: AttackEvent): void {
    const idx = event.byteIndex;

    switch (event.kind) {
      case 'byte-probe':
        if (idx < 0 || idx >= BLOCK_SIZE) break;
        this.cells[idx] = {
          state: 'probing',
          value: event.probeValue ?? null,
          intermediateValue: null,
          label: `Byte ${idx + 1}: probing — trying 0x${(event.probeValue ?? 0).toString(16).padStart(2, '0')}`,
        };
        this.updateCell(idx);
        break;

      case 'byte-found':
        if (idx < 0 || idx >= BLOCK_SIZE) break;
        this.cells[idx] = {
          state: 'found',
          value: event.recoveredByte ?? null,
          intermediateValue: event.intermediateValue ?? null,
          label: `Byte ${idx + 1}: intermediate 0x${(event.intermediateValue ?? 0).toString(16).padStart(2, '0')} found`,
        };
        this.updateCell(idx);
        break;

      case 'block-complete':
        if (event.recoveredBlock) {
          for (let i = 0; i < BLOCK_SIZE; i++) {
            this.cells[i] = {
              state: 'complete',
              value: event.recoveredBlock[i],
              intermediateValue: this.cells[i].intermediateValue,
              label: `Byte ${i + 1}: plaintext 0x${event.recoveredBlock[i].toString(16).padStart(2, '0')}`,
            };
            this.updateCell(i);
          }
        }
        break;

      case 'attack-complete':
        break;
    }

    if (this.queryCountEl) {
      this.queryCountEl.textContent = event.queryCount.toString();
    }
  }
}

function stateText(state: ByteState): string {
  switch (state) {
    case 'unknown': return 'unknown';
    case 'probing': return 'probing';
    case 'found': return 'intermediate found';
    case 'complete': return 'recovered';
  }
}

/**
 * Render a multi-block ciphertext visualization.
 * Returns an array of block containers for per-block updates.
 */
export function renderCiphertextBlocks(
  container: HTMLElement,
  iv: Uint8Array,
  ciphertextBlocks: Uint8Array[],
  activeBlock?: number
): HTMLElement[] {
  container.innerHTML = '';
  container.setAttribute('role', 'group');
  container.setAttribute('aria-label', 'Ciphertext block visualization');

  const blockEls: HTMLElement[] = [];

  // IV block
  const ivEl = createBlockEl(iv, 'IV', -1, false);
  container.appendChild(ivEl);

  // Ciphertext blocks
  ciphertextBlocks.forEach((block, i) => {
    const blockEl = createBlockEl(block, `C[${i}]`, i, i === activeBlock);
    container.appendChild(blockEl);
    blockEls.push(blockEl);
  });

  return blockEls;
}

function createBlockEl(
  data: Uint8Array,
  label: string,
  _index: number,
  active: boolean
): HTMLElement {
  const wrapper = document.createElement('div');
  wrapper.className = `cipher-block ${active ? 'cipher-block--active' : ''}`;
  // role="img": both children are already `aria-hidden`, so this box's entire
  // accessible content IS its label — and a name on a role-less <div> is
  // prohibited by ARIA and silently discarded, which is what was happening.
  wrapper.setAttribute('role', 'img');
  wrapper.setAttribute('aria-label', `${label}: ${Array.from(data).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);

  const titleEl = document.createElement('div');
  titleEl.className = 'cipher-block__title';
  titleEl.setAttribute('aria-hidden', 'true');
  titleEl.textContent = label;

  const hexEl = document.createElement('div');
  hexEl.className = 'cipher-block__hex';
  // No aria-label: the element is `aria-hidden`, so the name was dead weight —
  // and it was prohibited here anyway (role-less <div>).
  hexEl.setAttribute('aria-hidden', 'true');

  Array.from(data).forEach((byte, i) => {
    const span = document.createElement('span');
    span.className = 'hex-byte';
    span.textContent = byte.toString(16).padStart(2, '0');
    span.setAttribute('data-byte-index', String(i));
    hexEl.appendChild(span);
  });

  wrapper.appendChild(titleEl);
  wrapper.appendChild(hexEl);
  return wrapper;
}

/**
 * Animated CBC decryption diagram builder.
 * Creates a step-by-step visual of C[i] → AES_D → XOR with C[i-1] → P[i].
 */
export function buildCBCDiagram(container: HTMLElement): void {
  container.innerHTML = `
    <div class="cbc-diagram" role="img" aria-label="CBC decryption flow: ciphertext block C[i] passes through AES inverse cipher to produce an intermediate value, which is XORed with the previous ciphertext block C[i minus 1] to yield plaintext block P[i]. The plaintext's final bytes are then checked for valid PKCS#7 padding — that check is the oracle.">
      <div class="cbc-diagram__row">
        <div class="cbc-block cbc-block--cipher">
          <span class="cbc-block__label" aria-hidden="true">C[i−1]</span>
          <div class="cbc-block__bytes" aria-hidden="true">
            <span class="hex-byte">c0</span><span class="hex-byte">c1</span>
            <span class="hex-byte">c2</span><span class="hex-byte">…</span>
          </div>
        </div>
        <div class="cbc-arrow" aria-hidden="true">→</div>
        <div class="cbc-block cbc-block--cipher">
          <span class="cbc-block__label" aria-hidden="true">C[i]</span>
          <div class="cbc-block__bytes" aria-hidden="true">
            <span class="hex-byte">d0</span><span class="hex-byte">d1</span>
            <span class="hex-byte">d2</span><span class="hex-byte">…</span>
          </div>
        </div>
      </div>
      <div class="cbc-diagram__row cbc-diagram__row--ops">
        <div class="cbc-op"></div>
        <div class="cbc-arrow cbc-arrow--down" aria-hidden="true">↓</div>
        <div class="cbc-op cbc-block--aes">
          <span>AES⁻¹</span>
        </div>
      </div>
      <div class="cbc-diagram__row cbc-diagram__row--xor">
        <div class="cbc-xor">
          <span aria-hidden="true">⊕</span>
        </div>
      </div>
      <div class="cbc-diagram__row">
        <div class="cbc-block cbc-block--plain">
          <span class="cbc-block__label" aria-hidden="true">P[i] + padding</span>
          <div class="cbc-block__bytes" aria-hidden="true">
            <span class="hex-byte">p0</span><span class="hex-byte">p1</span>
            <span class="hex-byte">p2</span><span class="hex-byte">…</span>
            <span class="hex-byte hex-byte--pad">03</span>
            <span class="hex-byte hex-byte--pad">03</span>
            <span class="hex-byte hex-byte--pad">03</span>
          </div>
        </div>
        <div class="cbc-padding-check">
          <span class="cbc-padding-check__label">Padding Oracle</span>
          <span class="cbc-padding-check__result" id="padding-check-result">Valid ✓</span>
        </div>
      </div>
    </div>
  `;
}

/**
 * Animate XOR operation between two byte arrays (for padding fix-up visualization).
 */
export function renderXOROperation(
  container: HTMLElement,
  a: Uint8Array,
  b: Uint8Array,
  result: Uint8Array,
  labelA: string,
  labelB: string,
  labelResult: string
): void {
  container.innerHTML = '';
  container.setAttribute('role', 'group');
  container.setAttribute('aria-label', `XOR: ${labelA} XOR ${labelB} = ${labelResult}`);

  const makeRow = (data: Uint8Array, label: string) => {
    const row = document.createElement('div');
    row.className = 'xor-row';
    const lbl = document.createElement('span');
    lbl.className = 'xor-row__label';
    lbl.textContent = label;
    row.appendChild(lbl);
    Array.from(data).forEach(byte => {
      const span = document.createElement('span');
      span.className = 'hex-byte';
      span.textContent = byte.toString(16).padStart(2, '0');
      row.appendChild(span);
    });
    return row;
  };

  container.appendChild(makeRow(a, labelA));

  const opRow = document.createElement('div');
  opRow.className = 'xor-row xor-row--op';
  opRow.setAttribute('aria-hidden', 'true');
  opRow.innerHTML = '<span class="xor-row__label">XOR</span>' +
    Array(b.length).fill('<span class="xor-op">⊕</span>').join('');
  container.appendChild(opRow);

  container.appendChild(makeRow(b, labelB));

  const divider = document.createElement('div');
  divider.className = 'xor-divider';
  divider.setAttribute('aria-hidden', 'true');
  container.appendChild(divider);

  container.appendChild(makeRow(result, labelResult));
}
