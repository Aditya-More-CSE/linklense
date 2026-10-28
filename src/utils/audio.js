/**
 * Audio feedback utilities (disabled/no-op for clean, quiet terminal operation)
 */

export function playClickSound() {}
export function playBlipSound() {}
export function playCompleteSound() {}
export function toggleSound() { return false; }
export function isSoundEnabled() { return false; }
