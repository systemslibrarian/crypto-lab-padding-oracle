/**
 * main.ts — Entry point for crypto-lab-padding-oracle.
 *
 * Initializes all panels and global UI controls.
 */

import {
  initThemeToggle,
  initPanelNav,
  initPanel1,
  initPanel2,
  initPanel3,
  initPanel4,
  initPanel5,
  initPanel6,
  initP1OracleDemo,
  initP1PaddingCraft,
  initDefenseBench,
} from './ui.ts';

/**
 * The live demos rely on the Web Crypto API (crypto.subtle), which browsers only
 * expose in a secure context (https:// or http://localhost). When it's missing
 * (e.g. opened via file://), surface a clear banner instead of letting the
 * encrypt buttons throw opaque TypeErrors. The explanatory content still works.
 */
function warnIfCryptoUnavailable(): void {
  if (window.isSecureContext && globalThis.crypto?.subtle) return;
  const main = document.getElementById('main-content');
  if (!main) return;
  const banner = document.createElement('div');
  banner.className = 'info-box info-box--warning';
  banner.setAttribute('role', 'alert');
  banner.innerHTML =
    '<strong>Live demos need the Web Crypto API.</strong> ' +
    'Browsers only expose it in a secure context, so open this page over ' +
    '<code>https://</code> or <code>http://localhost</code> (not <code>file://</code>) ' +
    'to run the interactive encryption demos. All explanatory content below still works.';
  main.prepend(banner);
}

document.addEventListener('DOMContentLoaded', () => {
  warnIfCryptoUnavailable();
  initThemeToggle();
  initPanelNav();
  initPanel1();
  initPanel2();
  initPanel3();
  initPanel4();
  initPanel5();
  initPanel6();
  initP1OracleDemo();
  initP1PaddingCraft();
  initDefenseBench();
});
