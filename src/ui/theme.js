/**
 * LinkLens Theme Manager
 * Permanent dark cyberpunk terminal theme.
 */

export function initTheme() {
  document.documentElement.setAttribute('data-theme', 'dark');
}

export function getTheme() {
  return 'dark';
}
