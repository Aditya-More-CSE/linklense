/**
 * LinkLens — Main Application Controller
 * Minimal, intuitive, and accessible cyber link scanner.
 */

import { initTheme } from './ui/theme.js';
import { renderEmptyState, renderReport } from './ui/renderReport.js';
import { startScanPipeline, cancelActiveScan } from './ui/scanAnimation.js';
import { parseUrl, MAX_URL_LENGTH } from './analyzer/parseUrl.js';
import { SAMPLE_URLS } from './data/sampleUrls.js';
import { showToast } from './ui/notifications.js';

document.addEventListener('DOMContentLoaded', () => {
  // 1. Initialize permanent dark theme
  initTheme();

  // 2. Select DOM Elements
  const form = document.getElementById('url-analyzer-form');
  const urlInput = document.getElementById('url-input');
  const inputWrapper = document.getElementById('url-input-wrapper');
  const clearInputBtn = document.getElementById('btn-clear-input');
  const charCounter = document.getElementById('char-counter');
  const feedbackMsg = document.getElementById('input-feedback');
  const analyzeBtn = document.getElementById('btn-analyze-submit');
  const analyzeText = document.getElementById('btn-analyze-text');
  const panelContainer = document.getElementById('analysis-panel-container');
  const exampleChipsContainer = document.getElementById('example-chips-container');
  const moreExamplesContainer = document.getElementById('more-example-chips-container');

  // Modal Elements
  const aboutBtn = document.getElementById('nav-about-btn');
  const aboutModal = document.getElementById('about-modal');
  const modalCloseBtn = document.getElementById('modal-close-btn');

  let isAnalyzing = false;

  // 3. Initial Standby Render
  renderEmptyState(panelContainer);

  // 4. Populate Example URL Buttons (3 prominent initially, remainder in disclosure)
  const primaryExamples = SAMPLE_URLS.slice(0, 3);
  const remainingExamples = SAMPLE_URLS.slice(3);

  function renderChipHtml(sample, idx) {
    return `
      <button type="button" class="preset-chip-btn" data-sample-id="${sample.id}" title="${sample.description}">
        <span class="chip-tag">0${idx + 1}</span>
        <span class="chip-label">${sample.label}</span>
      </button>
    `;
  }

  if (exampleChipsContainer) {
    exampleChipsContainer.innerHTML = primaryExamples.map((s, idx) => renderChipHtml(s, idx)).join('');
  }

  if (moreExamplesContainer) {
    moreExamplesContainer.innerHTML = remainingExamples.map((s, idx) => renderChipHtml(s, idx + 3)).join('');
  }

  function handleExampleClick(e) {
    const chip = e.target.closest('.preset-chip-btn');
    if (!chip) return;
    const sampleId = chip.getAttribute('data-sample-id');
    const sample = SAMPLE_URLS.find(s => s.id === sampleId);
    if (sample && urlInput) {
      urlInput.value = sample.url;
      handleInputChange();
      clearError();
      urlInput.focus();
      showToast(`Loaded example: ${sample.label}`, 'info', 1600);
    }
  }

  if (exampleChipsContainer) {
    exampleChipsContainer.addEventListener('click', handleExampleClick);
  }
  if (moreExamplesContainer) {
    moreExamplesContainer.addEventListener('click', handleExampleClick);
  }

  // 5. Input Monitoring & Character Counting
  function handleInputChange() {
    const val = urlInput.value;
    const len = val.length;

    if (charCounter) {
      charCounter.textContent = `${len} / ${MAX_URL_LENGTH} chars`;
      charCounter.style.color = len > MAX_URL_LENGTH ? 'var(--threat-critical)' : 'var(--text-muted)';
    }

    if (clearInputBtn) {
      clearInputBtn.style.display = len > 0 ? 'inline-flex' : 'none';
    }

    if (len === 0) {
      clearError();
    }
  }

  urlInput.addEventListener('input', handleInputChange);
  urlInput.addEventListener('change', handleInputChange);

  if (clearInputBtn) {
    clearInputBtn.addEventListener('click', () => {
      urlInput.value = '';
      handleInputChange();
      clearError();
      urlInput.focus();
    });
  }

  function showError(msg) {
    if (feedbackMsg) {
      feedbackMsg.textContent = `[Error]: ${msg}`;
      feedbackMsg.style.display = 'block';
    }
    if (inputWrapper) {
      inputWrapper.classList.add('has-error');
    }
  }

  function clearError() {
    if (feedbackMsg) {
      feedbackMsg.textContent = '';
      feedbackMsg.style.display = 'none';
    }
    if (inputWrapper) {
      inputWrapper.classList.remove('has-error');
    }
  }

  function setAnalyzingState(busy) {
    isAnalyzing = busy;
    if (analyzeBtn) {
      analyzeBtn.disabled = busy;
    }
    if (analyzeText) {
      analyzeText.textContent = busy ? 'ANALYZING...' : 'ANALYZE';
    }
  }

  // 6. Form Submission & Scan Trigger
  form.addEventListener('submit', (e) => {
    e.preventDefault();

    if (isAnalyzing) return;

    const rawVal = urlInput.value.trim();

    if (!rawVal) {
      showError('Please paste a link to check.');
      urlInput.focus();
      return;
    }

    const testParse = parseUrl(rawVal);
    if (!testParse.isValid) {
      showError(testParse.error || 'Please enter a valid HTTP or HTTPS link.');
      urlInput.focus();
      return;
    }

    clearError();
    setAnalyzingState(true);
    cancelActiveScan();

    startScanPipeline(
      rawVal,
      panelContainer,
      (report) => {
        setAnalyzingState(false);
        renderReport(panelContainer, report);
      },
      (errorMsg) => {
        setAnalyzingState(false);
        showError(errorMsg);
        renderEmptyState(panelContainer);
      }
    );
  });

  // 7. About & Methodology Modal Handlers
  function openModal() {
    if (aboutModal) {
      aboutModal.classList.add('open');
      modalCloseBtn && modalCloseBtn.focus();
      document.body.style.overflow = 'hidden';
    }
  }

  function closeModal() {
    if (aboutModal) {
      aboutModal.classList.remove('open');
      document.body.style.overflow = '';
      aboutBtn && aboutBtn.focus();
    }
  }

  if (aboutBtn) {
    aboutBtn.addEventListener('click', openModal);
  }

  if (modalCloseBtn) {
    modalCloseBtn.addEventListener('click', closeModal);
  }

  if (aboutModal) {
    aboutModal.addEventListener('click', (e) => {
      if (e.target === aboutModal) closeModal();
    });

    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && aboutModal.classList.contains('open')) {
        closeModal();
      }
    });
  }
});
