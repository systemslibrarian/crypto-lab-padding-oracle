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
import { AttackEvent } from './attack.ts';

export type ByteState = 'unknown' | 'probing' | 'found' | 'complete';

export interface ByteCellData {
  state: ByteState;
  value: number | null;        // byte value (0–255) or null if unknown
  intermediateValue: number | null;
  label: string;               // text label for screen readers
}

/** A rendered block grid (one row of 16 cells) */
export class BlockGrid {
  private cells: ByteCellData[] = [];
  private container: HTMLElement;
  private queryCountEl: HTMLElement | null = null;
  private reducedMotion: boolean;

  constructor(container: HTMLElement, queryCountEl?: HTMLElement) {
    this.container = container;
    this.queryCountEl = queryCountEl ?? null;
    this.reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // Re-check if media query changes
    window.matchMedia('(prefers-reduced-motion: reduce)').addEventListener('change', (e) => {
      this.reducedMotion = e.matches;
    });

    this.initCells();
    this.render();
  }

  private initCells(): void {
    this.cells = Array.from({ length: BLOCK_SIZE }, (_, i) => ({
      state: 'unknown',
      value: null,
      intermediateValue: null,
      label: `Byte ${i + 1} of ${BLOCK_SIZE}: unknown`,
    }));
  }

  reset(): void {
    this.initCells();
    this.render();
  }

  /**
   * Update a cell based on an attack event.
   */
  applyEvent(event: AttackEvent): void {
    const idx = event.byteIndex;
    if (idx < 0 || idx >= BLOCK_SIZE) return;

    switch (event.kind) {
      case 'byte-probe':
        this.cells[idx] = {
          state: 'probing',
          value: event.probeValue ?? null,
          intermediateValue: null,
          label: `Byte ${idx + 1}: probing — trying 0x${(event.probeValue ?? 0).toString(16).padStart(2, '0')}`,
        };
        break;

      case 'byte-found':
        this.cells[idx] = {
          state: 'found',
          value: event.recoveredByte ?? null,
          intermediateValue: event.intermediateValue ?? null,
          label: `Byte ${idx + 1}: intermediate 0x${(event.intermediateValue ?? 0).toString(16).padStart(2, '0')} found`,
        };
        break;

      case 'block-complete':
        // Mark all cells complete if we have the block
        if (event.recoveredBlock) {
          for (let i = 0; i < BLOCK_SIZE; i++) {
            this.cells[i] = {
              state: 'complete',
              value: event.recoveredBlock[i],
              intermediateValue: this.cells[i].intermediateValue,
              label: `Byte ${i + 1}: plaintext 0x${event.recoveredBlock[i].toString(16).padStart(2, '0')}`,
            };
          }
        }
        break;

      case 'attack-complete':
        break;
    }

    this.render();

    if (this.queryCountEl) {
      this.queryCountEl.textContent = event.queryCount.toString();
    }
  }

  private render(): void {
    this.container.innerHTML = '';
    this.container.setAttribute('role', 'grid');
    this.container.setAttribute('aria-label', 'Block byte state grid');

    const row = document.createElement('div');
    row.setAttribute('role', 'row');
    row.className = 'byte-grid-row';

    this.cells.forEach((cell, i) => {
      const cellEl = document.createElement('div');
      cellEl.setAttribute('role', 'gridcell');
      cellEl.className = `byte-cell byte-cell--${cell.state}`;
      cellEl.setAttribute('aria-label', cell.label);
      cellEl.setAttribute('data-state', cell.state);
      cellEl.setAttribute('data-index', String(i));

      if (!this.reducedMotion && cell.state === 'probing') {
        cellEl.classList.add('byte-cell--animate');
      }

      const valueEl = document.createElement('span');
      valueEl.className = 'byte-cell__value';
      valueEl.setAttribute('aria-hidden', 'true');
      valueEl.textContent = cell.value !== null
        ? cell.value.toString(16).padStart(2, '0')
        : '??';

      const stateLabel = document.createElement('span');
      stateLabel.className = 'byte-cell__state-label sr-only';
      stateLabel.textContent = stateText(cell.state);

      cellEl.appendChild(valueEl);
      cellEl.appendChild(stateLabel);
      row.appendChild(cellEl);
    });

    this.container.appendChild(row);
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
 * Render a static hex row for displaying ciphertext blocks.
 */
export function renderHexRow(
  container: HTMLElement,
  data: Uint8Array,
  label: string,
  highlightIndex?: number
): void {
  container.innerHTML = '';
  container.setAttribute('aria-label', label);
  container.setAttribute('role', 'group');

  const bytes = Array.from(data);
  bytes.forEach((byte, i) => {
    const span = document.createElement('span');
    span.className = 'hex-byte';
    if (i === highlightIndex) {
      span.classList.add('hex-byte--highlight');
      span.setAttribute('aria-current', 'true');
    }
    span.textContent = byte.toString(16).padStart(2, '0');
    span.setAttribute('aria-label', `byte ${i + 1}: 0x${byte.toString(16).padStart(2, '0')}`);
    container.appendChild(span);
  });
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
  wrapper.setAttribute('aria-label', `${label}: ${Array.from(data).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);

  const titleEl = document.createElement('div');
  titleEl.className = 'cipher-block__title';
  titleEl.setAttribute('aria-hidden', 'true');
  titleEl.textContent = label;

  const hexEl = document.createElement('div');
  hexEl.className = 'cipher-block__hex';
  hexEl.setAttribute('aria-hidden', 'true');
  hexEl.setAttribute('aria-label', `${label} hex bytes`);

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
    <div class="cbc-diagram" role="img" aria-label="CBC decryption block diagram">
      <div class="cbc-diagram__row">
        <div class="cbc-block cbc-block--cipher" aria-label="Ciphertext block C[i-1]">
          <span class="cbc-block__label" aria-hidden="true">C[i−1]</span>
          <div class="cbc-block__bytes" aria-hidden="true">
            <span class="hex-byte">c0</span><span class="hex-byte">c1</span>
            <span class="hex-byte">c2</span><span class="hex-byte">…</span>
          </div>
        </div>
        <div class="cbc-arrow" aria-hidden="true">→</div>
        <div class="cbc-block cbc-block--cipher" aria-label="Ciphertext block C[i]">
          <span class="cbc-block__label" aria-hidden="true">C[i]</span>
          <div class="cbc-block__bytes" aria-hidden="true">
            <span class="hex-byte">d0</span><span class="hex-byte">d1</span>
            <span class="hex-byte">d2</span><span class="hex-byte">…</span>
          </div>
        </div>
      </div>
      <div class="cbc-diagram__row cbc-diagram__row--ops">
        <div class="cbc-op" aria-label="Previous ciphertext block used as XOR input"></div>
        <div class="cbc-arrow cbc-arrow--down" aria-hidden="true">↓</div>
        <div class="cbc-op cbc-block--aes" aria-label="AES block cipher decryption">
          <span>AES⁻¹</span>
        </div>
      </div>
      <div class="cbc-diagram__row cbc-diagram__row--xor">
        <div class="cbc-xor" aria-label="XOR operation combining decrypted block with previous ciphertext">
          <span aria-hidden="true">⊕</span>
        </div>
      </div>
      <div class="cbc-diagram__row">
        <div class="cbc-block cbc-block--plain" aria-label="Plaintext block P[i] with PKCS#7 padding check">
          <span class="cbc-block__label" aria-hidden="true">P[i] + padding</span>
          <div class="cbc-block__bytes" aria-hidden="true">
            <span class="hex-byte">p0</span><span class="hex-byte">p1</span>
            <span class="hex-byte">p2</span><span class="hex-byte">…</span>
            <span class="hex-byte hex-byte--pad">03</span>
            <span class="hex-byte hex-byte--pad">03</span>
            <span class="hex-byte hex-byte--pad">03</span>
          </div>
        </div>
        <div class="cbc-padding-check" aria-label="Padding oracle returns valid or invalid">
          <span class="cbc-padding-check__label">Padding Oracle</span>
          <span class="cbc-padding-check__result" id="padding-check-result">Valid ✓</span>
        </div>
      </div>
    </div>
  `;
}

/**
 * Create an oracle query counter display.
 */
export function createQueryCounter(container: HTMLElement): HTMLElement {
  container.innerHTML = `
    <div class="query-counter" role="status" aria-live="polite" aria-label="Oracle query counter">
      <span class="query-counter__label">Oracle Queries:</span>
      <span class="query-counter__value" id="query-count-value">0</span>
    </div>
  `;
  return container.querySelector('#query-count-value') as HTMLElement;
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
