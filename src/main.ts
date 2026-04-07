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
} from './ui.ts';

document.addEventListener('DOMContentLoaded', () => {
  initThemeToggle();
  initPanelNav();
  initPanel1();
  initPanel2();
  initPanel3();
  initPanel4();
  initPanel5();
  initPanel6();
  initP1OracleDemo();
});
