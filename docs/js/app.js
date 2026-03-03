// Main application logic for IRAI Cybersecurity AI Assistant

import { getApiKey, setApiKey, clearApiKey, callOpenAI } from './api.js';
import { listTemplates, getTemplateForMode } from './templates.js';
import { parseYAML, extractSigmaComponents, sigmaToXQL, sigmaToAQL } from './sigma.js';
import { validateXQL, validateAQL, validateRuleOutput } from './validation.js';
import { buildEnrichmentContext, searchMitreTechniques, lookupCVE } from './feeds.js';

// DOM elements
let elements = {};

/**
 * Initialize the application
 */
export function init() {
  cacheElements();
  setupEventListeners();
  loadSettings();
  populateTemplates();
  updateUIState();
}

function cacheElements() {
  elements = {
    apiKeyInput: document.getElementById('api-key-input'),
    saveKeyBtn: document.getElementById('save-key-btn'),
    clearKeyBtn: document.getElementById('clear-key-btn'),
    keyStatus: document.getElementById('key-status'),
    modeSelect: document.getElementById('mode-select'),
    formatSelect: document.getElementById('format-select'),
    structuredToggle: document.getElementById('structured-toggle'),
    queryInput: document.getElementById('query-input'),
    submitBtn: document.getElementById('submit-btn'),
    outputArea: document.getElementById('output-area'),
    outputContent: document.getElementById('output-content'),
    validationArea: document.getElementById('validation-area'),
    validationContent: document.getElementById('validation-content'),
    copyBtn: document.getElementById('copy-btn'),
    exportBtn: document.getElementById('export-btn'),
    copyJsonBtn: document.getElementById('copy-json-btn'),
    templateSelect: document.getElementById('template-select'),
    loadTemplateBtn: document.getElementById('load-template-btn'),
    sigmaInput: document.getElementById('sigma-input'),
    convertSigmaBtn: document.getElementById('convert-sigma-btn'),
    sigmaOutput: document.getElementById('sigma-output'),
    enrichToggle: document.getElementById('enrich-toggle'),
    feedStatus: document.getElementById('feed-status'),
    mitreSearchInput: document.getElementById('mitre-search-input'),
    mitreSearchBtn: document.getElementById('mitre-search-btn'),
    mitreResults: document.getElementById('mitre-results'),
    cveInput: document.getElementById('cve-input'),
    cveLookupBtn: document.getElementById('cve-lookup-btn'),
    cveResults: document.getElementById('cve-results'),
    loadingIndicator: document.getElementById('loading-indicator'),
    settingsToggle: document.getElementById('settings-toggle'),
    settingsPanel: document.getElementById('settings-panel'),
    tabBtns: document.querySelectorAll('.tab-btn'),
    tabPanels: document.querySelectorAll('.tab-panel')
  };
}

function setupEventListeners() {
  elements.saveKeyBtn.addEventListener('click', saveApiKey);
  elements.clearKeyBtn.addEventListener('click', clearKey);
  elements.submitBtn.addEventListener('click', handleSubmit);
  elements.copyBtn.addEventListener('click', copyOutput);
  elements.exportBtn.addEventListener('click', exportOutput);
  elements.copyJsonBtn.addEventListener('click', copyJsonOutput);
  elements.loadTemplateBtn.addEventListener('click', loadTemplate);
  elements.convertSigmaBtn.addEventListener('click', convertSigma);
  elements.settingsToggle.addEventListener('click', toggleSettings);
  elements.mitreSearchBtn.addEventListener('click', handleMitreSearch);
  elements.cveLookupBtn.addEventListener('click', handleCveLookup);

  elements.queryInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      handleSubmit();
    }
  });

  elements.tabBtns.forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });
}

function switchTab(tabName) {
  elements.tabBtns.forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabName);
  });
  elements.tabPanels.forEach(panel => {
    panel.classList.toggle('active', panel.dataset.tab === tabName);
  });
}

function loadSettings() {
  const key = getApiKey();
  if (key) {
    elements.apiKeyInput.value = '••••••••••••••••';
    elements.keyStatus.textContent = '✅ API key saved';
    elements.keyStatus.className = 'status-ok';
  } else {
    elements.keyStatus.textContent = '⚠️ No API key set';
    elements.keyStatus.className = 'status-warn';
  }
}

function updateUIState() {
  const hasKey = !!getApiKey();
  elements.submitBtn.disabled = !hasKey;
}

function saveApiKey() {
  const key = elements.apiKeyInput.value.trim();
  if (!key || key.includes('••')) {
    alert('Please enter a valid API key');
    return;
  }
  setApiKey(key);
  elements.apiKeyInput.value = '••••••••••••••••';
  elements.keyStatus.textContent = '✅ API key saved';
  elements.keyStatus.className = 'status-ok';
  updateUIState();
}

function clearKey() {
  clearApiKey();
  elements.apiKeyInput.value = '';
  elements.keyStatus.textContent = '⚠️ No API key set';
  elements.keyStatus.className = 'status-warn';
  updateUIState();
}

function toggleSettings() {
  elements.settingsPanel.classList.toggle('collapsed');
  elements.settingsToggle.textContent = elements.settingsPanel.classList.contains('collapsed') ? '⚙️ Settings ▶' : '⚙️ Settings ▼';
}

function populateTemplates() {
  const templates = listTemplates();
  elements.templateSelect.innerHTML = '<option value="">-- Select Template --</option>';
  templates.forEach(t => {
    const opt = document.createElement('option');
    opt.value = t.key;
    opt.textContent = `${t.name} (${t.mitre.technique})`;
    elements.templateSelect.appendChild(opt);
  });
}

function loadTemplate() {
  const key = elements.templateSelect.value;
  if (!key) return;

  const mode = elements.modeSelect.value;
  const templateData = getTemplateForMode(key, mode);
  if (!templateData) return;

  const output = JSON.stringify(templateData, null, 2);
  displayOutput(output, true);

  // Validate the template
  if (mode === 'cortex' && templateData.xql_query) {
    const result = validateXQL(templateData.xql_query);
    displayValidation(result);
  } else if (mode === 'qradar' && templateData.aql_query) {
    const result = validateAQL(templateData.aql_query);
    displayValidation(result);
  }
}

async function handleSubmit() {
  const query = elements.queryInput.value.trim();
  if (!query) {
    alert('Please enter a detection query or description');
    return;
  }

  const mode = elements.modeSelect.value;
  const outputFormat = elements.formatSelect.value;
  const structured = elements.structuredToggle.checked;
  const enrich = elements.enrichToggle.checked;

  showLoading(true);
  clearOutput();

  try {
    let enrichmentContext = '';
    if (enrich) {
      elements.feedStatus.textContent = '🔄 Fetching threat intelligence...';
      enrichmentContext = await buildEnrichmentContext(query);
      elements.feedStatus.textContent = enrichmentContext ? '✅ Enrichment applied' : 'ℹ️ No enrichment data found';
    }

    const result = await callOpenAI({
      userMessage: query,
      mode,
      outputFormat,
      structured,
      enrichmentContext
    });

    displayOutput(result.content, structured);

    // Run validation
    if (structured) {
      try {
        const parsed = JSON.parse(result.content);
        const valResult = validateRuleOutput(parsed, mode);
        displayValidation(valResult);
      } catch {
        displayValidation({ valid: false, errors: ['Response is not valid JSON'], warnings: [] });
      }
    } else {
      // Try to validate any embedded queries
      if (mode === 'cortex') {
        const xqlMatch = result.content.match(/dataset\s*=[\s\S]*?(?=\n\n|```|$)/);
        if (xqlMatch) {
          const valResult = validateXQL(xqlMatch[0]);
          displayValidation(valResult);
        }
      } else if (mode === 'qradar') {
        const aqlMatch = result.content.match(/SELECT[\s\S]*?(?=\n\n|```|$)/i);
        if (aqlMatch) {
          const valResult = validateAQL(aqlMatch[0]);
          displayValidation(valResult);
        }
      }
    }

  } catch (err) {
    displayOutput(`Error: ${err.message}`, false);
  } finally {
    showLoading(false);
  }
}

function convertSigma() {
  const yamlInput = elements.sigmaInput.value.trim();
  if (!yamlInput) {
    alert('Please enter a Sigma rule in YAML format');
    return;
  }

  try {
    const parsed = parseYAML(yamlInput);
    const components = extractSigmaComponents(parsed);
    const mode = elements.modeSelect.value;

    let converted;
    let validation;
    if (mode === 'cortex') {
      converted = sigmaToXQL(parsed);
      validation = validateXQL(converted);
    } else {
      converted = sigmaToAQL(parsed);
      validation = validateAQL(converted);
    }

    const output = {
      sigma_title: components.title,
      sigma_level: components.level,
      logsource: components.logsource,
      converted_query: converted,
      target_platform: mode === 'cortex' ? 'Cortex XDR (XQL)' : 'QRadar (AQL)',
      tags: components.tags
    };

    elements.sigmaOutput.textContent = JSON.stringify(output, null, 2);
    displayValidation(validation);
  } catch (err) {
    elements.sigmaOutput.textContent = `Error parsing Sigma rule: ${err.message}`;
  }
}

async function handleMitreSearch() {
  const query = elements.mitreSearchInput.value.trim();
  if (!query) return;

  elements.mitreResults.classList.remove('hidden');
  elements.mitreResults.textContent = 'Searching...';
  try {
    const results = await searchMitreTechniques(query);
    if (results.length === 0) {
      elements.mitreResults.textContent = 'No techniques found.';
    } else {
      elements.mitreResults.textContent = JSON.stringify(results, null, 2);
    }
  } catch (err) {
    elements.mitreResults.textContent = `Error: ${err.message}`;
  }
}

async function handleCveLookup() {
  const cveId = elements.cveInput.value.trim();
  if (!cveId) return;

  elements.cveResults.classList.remove('hidden');
  elements.cveResults.textContent = 'Looking up CVE...';
  try {
    const result = await lookupCVE(cveId);
    if (result) {
      elements.cveResults.textContent = JSON.stringify(result, null, 2);
    } else {
      elements.cveResults.textContent = 'CVE not found.';
    }
  } catch (err) {
    elements.cveResults.textContent = `Error: ${err.message}`;
  }
}

function displayOutput(content, isJson) {
  elements.outputArea.classList.remove('hidden');
  if (isJson) {
    try {
      const parsed = JSON.parse(content);
      elements.outputContent.textContent = JSON.stringify(parsed, null, 2);
    } catch {
      elements.outputContent.textContent = content;
    }
  } else {
    elements.outputContent.textContent = content;
  }
}

function displayValidation(result) {
  elements.validationArea.classList.remove('hidden');
  let html = '';
  if (result.valid && result.warnings.length === 0) {
    html = '<span class="val-pass">✅ Validation passed</span>';
  } else {
    if (result.errors.length > 0) {
      html += result.errors.map(e => `<div class="val-error">❌ ${escapeHtml(e)}</div>`).join('');
    }
    if (result.warnings.length > 0) {
      html += result.warnings.map(w => `<div class="val-warn">⚠️ ${escapeHtml(w)}</div>`).join('');
    }
    if (result.valid) {
      html += '<div class="val-pass">✅ Structure valid (with warnings)</div>';
    }
  }
  elements.validationContent.innerHTML = html;
}

function clearOutput() {
  elements.outputContent.textContent = '';
  elements.validationContent.innerHTML = '';
  elements.outputArea.classList.add('hidden');
  elements.validationArea.classList.add('hidden');
  elements.feedStatus.textContent = '';
}

function showLoading(show) {
  elements.loadingIndicator.classList.toggle('hidden', !show);
  elements.submitBtn.disabled = show;
}

function copyOutput() {
  const text = elements.outputContent.textContent;
  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied to clipboard');
  });
}

function copyJsonOutput() {
  const text = elements.outputContent.textContent;
  try {
    const parsed = JSON.parse(text);
    navigator.clipboard.writeText(JSON.stringify(parsed, null, 2)).then(() => {
      showToast('JSON copied to clipboard');
    });
  } catch {
    navigator.clipboard.writeText(text).then(() => {
      showToast('Copied to clipboard');
    });
  }
}

function exportOutput() {
  const text = elements.outputContent.textContent;
  const mode = elements.modeSelect.value;
  const format = elements.formatSelect.value;
  let filename = `irai_${mode}_${format}_${Date.now()}`;

  let content = text;
  try {
    JSON.parse(text);
    filename += '.json';
  } catch {
    filename += '.txt';
  }

  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast('File exported');
}

function showToast(message) {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2000);
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', init);
