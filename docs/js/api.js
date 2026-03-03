// OpenAI API integration with rate limiting
// All API calls are client-side, key stored in localStorage

import { CORTEX_FIELDS, CORTEX_DATASETS, QRADAR_FIELDS } from './fields.js';

const RATE_LIMIT_WINDOW_MS = 60000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 10;
let requestTimestamps = [];

/**
 * Get API key from localStorage
 * @returns {string|null}
 */
export function getApiKey() {
  return localStorage.getItem('irai_openai_api_key');
}

/**
 * Set API key in localStorage
 * @param {string} key
 */
export function setApiKey(key) {
  localStorage.setItem('irai_openai_api_key', key);
}

/**
 * Clear API key from localStorage
 */
export function clearApiKey() {
  localStorage.removeItem('irai_openai_api_key');
}

/**
 * Client-side rate limiting check
 * @returns {boolean} true if request is allowed
 */
function checkRateLimit() {
  const now = Date.now();
  requestTimestamps = requestTimestamps.filter(ts => now - ts < RATE_LIMIT_WINDOW_MS);
  if (requestTimestamps.length >= RATE_LIMIT_MAX_REQUESTS) {
    return false;
  }
  requestTimestamps.push(now);
  return true;
}

/**
 * Build the system prompt for structured detection mode
 * @param {string} mode - 'cortex' or 'qradar'
 * @param {string} outputFormat - 'rule', 'query', or 'playbook'
 * @param {boolean} structured - Whether to force structured JSON output
 * @param {string} enrichmentContext - Additional context from feeds
 * @returns {string}
 */
function buildSystemPrompt(mode, outputFormat, structured, enrichmentContext) {
  let prompt = `You are an expert cybersecurity detection engineer specializing in SIEM and XDR platforms. You produce production-ready, accurate detection content.\n\n`;

  if (mode === 'cortex') {
    prompt += `MODE: Cortex XDR\n`;
    prompt += `VALID DATASETS: ${CORTEX_DATASETS.join(', ')}\n`;
    prompt += `VALID FIELDS (use ONLY these): ${CORTEX_FIELDS.join(', ')}\n\n`;
    prompt += `RULES:\n`;
    prompt += `- Use valid XQL syntax\n`;
    prompt += `- Reference only valid datasets listed above\n`;
    prompt += `- Use only the valid field names listed above\n`;
    prompt += `- Include MITRE ATT&CK mapping when applicable\n`;

    if (outputFormat === 'rule') {
      prompt += `- Generate a BIOC rule with: name, severity, description, mitre_tactic, mitre_technique, rule_type, xql_query\n`;
    } else if (outputFormat === 'query') {
      prompt += `- Generate a standalone XQL query\n`;
    } else if (outputFormat === 'playbook') {
      prompt += `- Generate a detection playbook with: detection query, triage steps, response actions, containment steps\n`;
    }
  } else if (mode === 'qradar') {
    prompt += `MODE: QRadar SIEM\n`;
    prompt += `VALID FIELDS (use ONLY these): ${QRADAR_FIELDS.join(', ')}\n\n`;
    prompt += `RULES:\n`;
    prompt += `- Use valid AQL syntax\n`;
    prompt += `- AQL queries MUST start with SELECT and contain FROM events\n`;
    prompt += `- Use only the valid field names listed above\n`;
    prompt += `- Include MITRE ATT&CK mapping when applicable\n`;

    if (outputFormat === 'rule') {
      prompt += `- Generate a CRE rule with: name, severity, conditions, building_block, aql_query\n`;
    } else if (outputFormat === 'query') {
      prompt += `- Generate a standalone AQL query\n`;
    } else if (outputFormat === 'playbook') {
      prompt += `- Generate a detection playbook with: detection query, triage steps, response actions, containment steps\n`;
    }
  }

  if (structured) {
    prompt += `\nOUTPUT FORMAT: Respond ONLY with valid JSON. No markdown, no explanations outside the JSON.\n`;
    if (mode === 'cortex') {
      if (outputFormat === 'rule') {
        prompt += `JSON schema: {"rule_name":"","description":"","severity":"","mitre_tactic":"","mitre_technique":"","xql_query":"","bioc_rule":{"name":"","severity":"","description":"","mitre_tactic":"","mitre_technique":"","rule_type":"","condition":""}}\n`;
      } else if (outputFormat === 'query') {
        prompt += `JSON schema: {"query":"","description":"","mitre_mapping":{"tactic":"","technique":""}}\n`;
      } else {
        prompt += `JSON schema: {"playbook_name":"","description":"","detection_query":"","triage_steps":[],"response_actions":[],"containment_steps":[],"mitre_mapping":{"tactic":"","technique":""}}\n`;
      }
    } else {
      if (outputFormat === 'rule') {
        prompt += `JSON schema: {"rule_name":"","description":"","severity":"","mitre_tactic":"","mitre_technique":"","aql_query":"","cre_rule":{"name":"","severity":"","conditions":[],"building_block":""}}\n`;
      } else if (outputFormat === 'query') {
        prompt += `JSON schema: {"query":"","description":"","mitre_mapping":{"tactic":"","technique":""}}\n`;
      } else {
        prompt += `JSON schema: {"playbook_name":"","description":"","detection_query":"","triage_steps":[],"response_actions":[],"containment_steps":[],"mitre_mapping":{"tactic":"","technique":""}}\n`;
      }
    }
  }

  if (enrichmentContext) {
    prompt += `\n[Threat Intelligence Context]\n${enrichmentContext}\n`;
  }

  return prompt;
}

/**
 * Call OpenAI API
 * @param {object} params
 * @param {string} params.userMessage - User's query
 * @param {string} params.mode - 'cortex' or 'qradar'
 * @param {string} params.outputFormat - 'rule', 'query', or 'playbook'
 * @param {boolean} params.structured - Force JSON output
 * @param {string} params.enrichmentContext - Additional context
 * @returns {Promise<{content: string, usage: object}>}
 */
export async function callOpenAI({ userMessage, mode, outputFormat, structured, enrichmentContext }) {
  const apiKey = getApiKey();
  if (!apiKey) {
    throw new Error('API key not set. Please enter your OpenAI API key in Settings.');
  }

  if (!checkRateLimit()) {
    throw new Error('Rate limit exceeded. Please wait a moment before trying again (max 10 requests/minute).');
  }

  const systemPrompt = buildSystemPrompt(mode, outputFormat, structured, enrichmentContext || '');

  const fullMessage = systemPrompt + '\n\nUser request: ' + userMessage;

  const resp = await fetch('/api/chat', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      message: fullMessage
    })
  });

  if (!resp.ok) {
    const errData = await resp.json().catch(() => ({}));
    throw new Error(errData.error?.message || errData.error || `API error: ${resp.status}`);
  }

  const data = await resp.json();
  return {
    content: data.choices?.[0]?.message?.content || '',
    usage: data.usage || {}
  };
}
