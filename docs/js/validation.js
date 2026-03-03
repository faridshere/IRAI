// Validation layer for detection rules
// Ensures no hallucinated fields and valid syntax structure

import { CORTEX_FIELDS, CORTEX_DATASETS, QRADAR_FIELDS } from './fields.js';

const XQL_RESERVED_KEYWORDS = ['dataset', 'config', 'preset', 'and', 'or', 'not', 'as', 'by', 'to', 'from', 'limit', 'fields', 'filter', 'alter', 'comp', 'dedup', 'sort', 'bin', 'timeframe', 'stage'];

/**
 * Validate Cortex XDR XQL query
 * @param {string} xql - XQL query string
 * @returns {{valid: boolean, errors: string[], warnings: string[]}}
 */
export function validateXQL(xql) {
  const errors = [];
  const warnings = [];

  if (!xql || typeof xql !== 'string' || xql.trim().length === 0) {
    return { valid: false, errors: ['Empty XQL query'], warnings: [] };
  }

  const normalized = xql.toLowerCase();

  // Check dataset usage
  const datasetMatch = normalized.match(/dataset\s*=\s*(\w+)/g);
  if (datasetMatch) {
    datasetMatch.forEach(m => {
      const ds = m.replace(/dataset\s*=\s*/, '').trim();
      if (!CORTEX_DATASETS.some(d => d.toLowerCase() === ds)) {
        errors.push(`Unknown dataset: "${ds}". Valid datasets: ${CORTEX_DATASETS.join(', ')}`);
      }
    });
  }

  // Extract field references and validate
  const fieldPattern = /\b([a-z_][a-z0-9_]*)\s*(?:=|!=|contains|!contains|in\b|not\s+in\b|~=)/gi;
  let match;
  while ((match = fieldPattern.exec(xql)) !== null) {
    const field = match[1];
    if (XQL_RESERVED_KEYWORDS.includes(field.toLowerCase())) continue;
    if (!CORTEX_FIELDS.some(f => f.toLowerCase() === field.toLowerCase())) {
      warnings.push(`Possibly invalid Cortex XDR field: "${field}"`);
    }
  }

  // Basic structure checks
  if (!normalized.includes('dataset') && !normalized.includes('preset')) {
    warnings.push('XQL query should reference a dataset or preset');
  }

  return { valid: errors.length === 0, errors, warnings };
}

/**
 * Validate QRadar AQL query
 * @param {string} aql - AQL query string
 * @returns {{valid: boolean, errors: string[], warnings: string[]}}
 */
export function validateAQL(aql) {
  const errors = [];
  const warnings = [];

  if (!aql || typeof aql !== 'string' || aql.trim().length === 0) {
    return { valid: false, errors: ['Empty AQL query'], warnings: [] };
  }

  const normalized = aql.toLowerCase();

  // Must start with SELECT
  if (!normalized.trimStart().startsWith('select')) {
    errors.push('AQL query must start with SELECT');
  }

  // Must contain FROM
  if (!/\bfrom\b/i.test(normalized)) {
    errors.push('AQL query must contain a FROM clause');
  }

  // Extract field references in SELECT
  const selectMatch = aql.match(/select\s+([\s\S]*?)\s+from/i);
  if (selectMatch) {
    const selectFields = selectMatch[1].split(',').map(f => f.trim().replace(/\s+as\s+\w+/i, '').trim());
    selectFields.forEach(field => {
      if (field === '*') return;
      // Handle function calls like COUNT(*), DATEFORMAT(...)
      const funcMatch = field.match(/^[A-Z_]+\(.*\)$/i);
      if (funcMatch) return;
      const baseName = field.replace(/["']/g, '');
      if (!QRADAR_FIELDS.some(f => f.toLowerCase() === baseName.toLowerCase())) {
        warnings.push(`Possibly invalid QRadar field: "${baseName}"`);
      }
    });
  }

  return { valid: errors.length === 0, errors, warnings };
}

/**
 * Validate a structured JSON detection rule output
 * @param {object} ruleObj - Parsed JSON rule object
 * @param {string} mode - 'cortex' or 'qradar'
 * @returns {{valid: boolean, errors: string[], warnings: string[]}}
 */
export function validateRuleOutput(ruleObj, mode) {
  const errors = [];
  const warnings = [];

  if (!ruleObj || typeof ruleObj !== 'object') {
    return { valid: false, errors: ['Invalid rule object'], warnings: [] };
  }

  if (mode === 'cortex') {
    if (ruleObj.xql_query) {
      const xqlResult = validateXQL(ruleObj.xql_query);
      errors.push(...xqlResult.errors);
      warnings.push(...xqlResult.warnings);
    }
    if (ruleObj.bioc_rule && typeof ruleObj.bioc_rule === 'object') {
      if (!ruleObj.bioc_rule.name) warnings.push('BIOC rule should have a name');
      if (!ruleObj.bioc_rule.severity) warnings.push('BIOC rule should have a severity');
    }
  } else if (mode === 'qradar') {
    if (ruleObj.aql_query) {
      const aqlResult = validateAQL(ruleObj.aql_query);
      errors.push(...aqlResult.errors);
      warnings.push(...aqlResult.warnings);
    }
    if (ruleObj.cre_rule && typeof ruleObj.cre_rule === 'object') {
      if (!ruleObj.cre_rule.name) warnings.push('CRE rule should have a name');
      if (!ruleObj.cre_rule.conditions) warnings.push('CRE rule should define conditions');
    }
  }

  return { valid: errors.length === 0, errors, warnings };
}
