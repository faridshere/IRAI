// Open-source security feed integration
// Fetches data from public APIs for threat intelligence enrichment

const MITRE_ATTACK_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';
const CVE_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const SIGMA_HQ_API = 'https://api.github.com/repos/SigmaHQ/sigma/contents/rules';
const ELASTIC_RULES_API = 'https://api.github.com/repos/elastic/detection-rules/contents/rules';

let mitreCache = null;

/**
 * Fetch MITRE ATT&CK data (cached)
 * @returns {Promise<object>}
 */
export async function fetchMitreAttack() {
  if (mitreCache) return mitreCache;
  try {
    const resp = await fetch(MITRE_ATTACK_URL);
    if (!resp.ok) throw new Error(`MITRE fetch failed: ${resp.status}`);
    mitreCache = await resp.json();
    return mitreCache;
  } catch (err) {
    console.warn('MITRE ATT&CK fetch failed:', err.message);
    return null;
  }
}

/**
 * Search MITRE ATT&CK techniques by keyword
 * @param {string} keyword
 * @returns {Promise<Array>}
 */
export async function searchMitreTechniques(keyword) {
  const data = await fetchMitreAttack();
  if (!data || !data.objects) return [];

  const kw = keyword.toLowerCase();
  return data.objects
    .filter(obj =>
      obj.type === 'attack-pattern' &&
      !obj.revoked &&
      ((obj.name && obj.name.toLowerCase().includes(kw)) ||
       (obj.description && obj.description.toLowerCase().includes(kw)) ||
       (obj.external_references && obj.external_references.some(r =>
         r.external_id && r.external_id.toLowerCase().includes(kw)
       )))
    )
    .slice(0, 10)
    .map(obj => ({
      id: obj.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id || '',
      name: obj.name,
      description: (obj.description || '').substring(0, 200),
      tactics: (obj.kill_chain_phases || []).map(p => p.phase_name),
      url: obj.external_references?.find(r => r.source_name === 'mitre-attack')?.url || ''
    }));
}

/**
 * Lookup CVE details from NVD
 * @param {string} cveId - e.g., CVE-2021-44228
 * @returns {Promise<object|null>}
 */
export async function lookupCVE(cveId) {
  try {
    const resp = await fetch(`${CVE_API_URL}?cveId=${encodeURIComponent(cveId)}`);
    if (!resp.ok) throw new Error(`CVE fetch failed: ${resp.status}`);
    const data = await resp.json();
    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
      const cve = data.vulnerabilities[0].cve;
      return {
        id: cve.id,
        description: cve.descriptions?.find(d => d.lang === 'en')?.value || '',
        severity: cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || 'UNKNOWN',
        score: cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || null,
        references: (cve.references || []).slice(0, 5).map(r => r.url)
      };
    }
    return null;
  } catch (err) {
    console.warn('CVE lookup failed:', err.message);
    return null;
  }
}

/**
 * List Sigma HQ rule categories
 * @returns {Promise<Array>}
 */
export async function listSigmaCategories() {
  try {
    const resp = await fetch(SIGMA_HQ_API);
    if (!resp.ok) throw new Error(`Sigma HQ fetch failed: ${resp.status}`);
    const data = await resp.json();
    return data
      .filter(item => item.type === 'dir')
      .map(item => ({ name: item.name, path: item.path, url: item.html_url }));
  } catch (err) {
    console.warn('Sigma HQ fetch failed:', err.message);
    return [];
  }
}

/**
 * List Elastic detection rule categories
 * @returns {Promise<Array>}
 */
export async function listElasticRuleCategories() {
  try {
    const resp = await fetch(ELASTIC_RULES_API);
    if (!resp.ok) throw new Error(`Elastic rules fetch failed: ${resp.status}`);
    const data = await resp.json();
    return data
      .filter(item => item.type === 'dir')
      .map(item => ({ name: item.name, path: item.path, url: item.html_url }));
  } catch (err) {
    console.warn('Elastic rules fetch failed:', err.message);
    return [];
  }
}

/**
 * Build enrichment context string for AI prompt
 * @param {string} query - User query
 * @returns {Promise<string>}
 */
export async function buildEnrichmentContext(query) {
  let context = '';

  // Check for CVE references
  const cveMatch = query.match(/CVE-\d{4}-\d{4,}/i);
  if (cveMatch) {
    const cveData = await lookupCVE(cveMatch[0]);
    if (cveData) {
      context += `\n[CVE Intelligence] ${cveData.id}: ${cveData.description} (Severity: ${cveData.severity}, Score: ${cveData.score})\n`;
    }
  }

  // Check for MITRE technique references
  const mitreMatch = query.match(/T\d{4}(?:\.\d{3})?/i);
  if (mitreMatch) {
    const techniques = await searchMitreTechniques(mitreMatch[0]);
    if (techniques.length > 0) {
      context += `\n[MITRE ATT&CK] ${techniques[0].id}: ${techniques[0].name} - Tactics: ${techniques[0].tactics.join(', ')}\n`;
    }
  }

  return context;
}
