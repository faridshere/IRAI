// Sigma YAML parser and conversion engine
// Converts Sigma rules to Cortex XQL and QRadar AQL

/**
 * Minimal YAML parser for Sigma rules
 * Handles the subset of YAML used in Sigma detection rules
 * @param {string} yaml - YAML string
 * @returns {object}
 */
export function parseYAML(yaml) {
  const result = {};
  const lines = yaml.split('\n');
  const stack = [{ indent: -1, obj: result }];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trimEnd();
    if (trimmed === '' || trimmed.startsWith('#')) continue;

    const indent = line.search(/\S/);
    const content = trimmed.trim();

    // Pop stack to correct level
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }
    const parent = stack[stack.length - 1].obj;

    // Handle list items
    if (content.startsWith('- ')) {
      const val = content.substring(2).trim();
      if (Array.isArray(parent)) {
        // Check if it's a key-value inside a list item
        const kvMatch = val.match(/^([^:]+):\s*(.*)$/);
        if (kvMatch && !val.includes('|')) {
          const listItem = {};
          listItem[kvMatch[1].trim()] = parseValue(kvMatch[2].trim());
          parent.push(listItem);
          stack.push({ indent: indent + 2, obj: listItem });
        } else {
          parent.push(parseValue(val));
        }
      } else {
        // First list item under a key - shouldn't happen if we handle key: correctly
        // but handle gracefully
        const arr = [parseValue(val)];
        const parentKeys = Object.keys(parent);
        if (parentKeys.length > 0) {
          const lastKey = parentKeys[parentKeys.length - 1];
          if (parent[lastKey] === null || parent[lastKey] === '') {
            parent[lastKey] = arr;
            stack.push({ indent, obj: arr });
          }
        }
      }
      continue;
    }

    // Handle key: value
    const kvMatch = content.match(/^([^:]+):\s*(.*)$/);
    if (kvMatch) {
      const key = kvMatch[1].trim();
      const val = kvMatch[2].trim();

      if (val === '' || val === '|' || val === '>') {
        // Could be a nested object, list, or multiline string
        // Peek ahead to determine type
        const nextLine = i + 1 < lines.length ? lines[i + 1] : '';
        const nextTrimmed = nextLine.trim();
        if (nextTrimmed.startsWith('- ')) {
          parent[key] = [];
          stack.push({ indent, obj: parent[key] });
        } else if (val === '|' || val === '>') {
          // Multiline string
          let multiline = '';
          const baseIndent = i + 1 < lines.length ? lines[i + 1].search(/\S/) : indent + 2;
          while (i + 1 < lines.length) {
            const nl = lines[i + 1];
            if (nl.trim() === '' || nl.search(/\S/) >= baseIndent) {
              multiline += (multiline ? '\n' : '') + nl.trim();
              i++;
            } else {
              break;
            }
          }
          parent[key] = multiline;
        } else {
          parent[key] = {};
          stack.push({ indent, obj: parent[key] });
        }
      } else {
        parent[key] = parseValue(val);
      }
    }
  }

  return result;
}

function parseValue(val) {
  if (val === 'true') return true;
  if (val === 'false') return false;
  if (val === 'null' || val === '~') return null;
  if (/^\d+$/.test(val)) return parseInt(val, 10);
  // Strip quotes
  if ((val.startsWith("'") && val.endsWith("'")) || (val.startsWith('"') && val.endsWith('"'))) {
    return val.slice(1, -1);
  }
  return val;
}

/**
 * Extract Sigma rule components
 * @param {object} sigma - Parsed Sigma rule object
 * @returns {{logsource: object, detection: object, condition: string, title: string, level: string, tags: string[]}}
 */
export function extractSigmaComponents(sigma) {
  return {
    title: sigma.title || 'Untitled Sigma Rule',
    description: sigma.description || '',
    level: sigma.level || 'medium',
    logsource: sigma.logsource || {},
    detection: sigma.detection || {},
    condition: sigma.detection?.condition || '',
    tags: sigma.tags || []
  };
}

/**
 * Map Sigma logsource to Cortex XDR dataset
 */
function mapLogsourceToCortexDataset(logsource) {
  const category = (logsource.category || '').toLowerCase();
  const product = (logsource.product || '').toLowerCase();

  if (category === 'process_creation' || category === 'process_access') return 'xdr_data';
  if (category === 'file_event' || category === 'file_creation') return 'xdr_data';
  if (category === 'registry_event' || category === 'registry_set') return 'xdr_data';
  if (category === 'network_connection' || category === 'firewall') return 'xdr_data';
  if (category === 'dns_query') return 'xdr_data';
  if (product === 'windows') return 'xdr_data';
  if (product === 'linux') return 'xdr_data';
  return 'xdr_data';
}

/**
 * Map Sigma field names to Cortex XDR field names
 */
function mapFieldToCortex(field) {
  const mapping = {
    'Image': 'action_process_image_path',
    'OriginalFileName': 'action_process_image_name',
    'CommandLine': 'action_process_image_command_line',
    'ParentImage': 'actor_process_image_path',
    'ParentCommandLine': 'actor_process_command_line',
    'User': 'actor_primary_normalized_user',
    'TargetFilename': 'action_file_path',
    'TargetFileName': 'action_file_path',
    'SourceIp': 'action_local_ip',
    'DestinationIp': 'action_remote_ip',
    'DestinationPort': 'action_remote_port',
    'SourcePort': 'action_local_port',
    'DestinationHostname': 'action_external_hostname',
    'QueryName': 'dns_query_name',
    'Hashes': 'action_file_sha256',
    'md5': 'action_file_md5',
    'sha256': 'action_file_sha256',
    'ProcessId': 'action_process_os_pid',
    'TargetObject': 'action_registry_key_name',
    'Details': 'action_registry_data',
    'ComputerName': 'agent_hostname',
    'EventType': 'event_type'
  };
  return mapping[field] || field;
}

/**
 * Map Sigma field names to QRadar field names
 */
function mapFieldToQRadar(field) {
  const mapping = {
    'Image': 'ProcessName',
    'OriginalFileName': 'ProcessName',
    'CommandLine': 'Command',
    'ParentImage': 'ProcessName',
    'ParentCommandLine': 'Command',
    'User': 'username',
    'TargetFilename': 'FileName',
    'TargetFileName': 'FileName',
    'SourceIp': 'sourceip',
    'DestinationIp': 'destinationip',
    'DestinationPort': 'destinationport',
    'SourcePort': 'sourceport',
    'DestinationHostname': 'Hostname',
    'QueryName': 'URL',
    'ProcessId': 'ProcessId',
    'TargetObject': 'RegistryKey',
    'Details': 'RegistryValueName',
    'ComputerName': 'Hostname',
    'EventType': 'categoryname',
    'EventID': 'EventID'
  };
  return mapping[field] || field;
}

/**
 * Build filter conditions from Sigma detection selection
 */
function buildConditions(selection, fieldMapper) {
  const conditions = [];

  if (typeof selection !== 'object' || selection === null) return conditions;

  for (const [key, value] of Object.entries(selection)) {
    if (key === 'condition') continue;
    const mappedField = fieldMapper(key);

    if (Array.isArray(value)) {
      const escaped = value.map(v => typeof v === 'string' ? `"${v}"` : v);
      conditions.push(`${mappedField} IN (${escaped.join(', ')})`);
    } else if (typeof value === 'string') {
      if (value.includes('*')) {
        const clean = value.replace(/\*/g, '');
        conditions.push(`${mappedField} contains "${clean}"`);
      } else {
        conditions.push(`${mappedField} = "${value}"`);
      }
    } else if (typeof value === 'number') {
      conditions.push(`${mappedField} = ${value}`);
    } else if (typeof value === 'object' && value !== null) {
      // Nested modifier like |endswith, |contains, etc.
      for (const [mod, modVal] of Object.entries(value)) {
        const modField = key.includes('|') ? fieldMapper(key.split('|')[0]) : mappedField;
        if (Array.isArray(modVal)) {
          const subConds = modVal.map(v => `${modField} contains "${v}"`);
          conditions.push(`(${subConds.join(' OR ')})`);
        } else {
          conditions.push(`${modField} contains "${modVal}"`);
        }
      }
    }
  }

  return conditions;
}

/**
 * Convert Sigma to Cortex XQL
 * @param {object} sigma - Parsed Sigma object
 * @returns {string}
 */
export function sigmaToXQL(sigma) {
  const components = extractSigmaComponents(sigma);
  const dataset = mapLogsourceToCortexDataset(components.logsource);

  let filters = [];
  const detection = components.detection;

  for (const [key, value] of Object.entries(detection)) {
    if (key === 'condition' || key === 'timeframe') continue;
    const conds = buildConditions(value, mapFieldToCortex);
    if (conds.length > 0) {
      filters.push(...conds);
    }
  }

  let xql = `// Sigma Rule: ${components.title}\n`;
  xql += `// Level: ${components.level}\n`;
  xql += `dataset = ${dataset}\n`;
  if (filters.length > 0) {
    xql += `| filter ${filters.join('\n    and ')}`;
  }

  return xql;
}

/**
 * Convert Sigma to QRadar AQL
 * @param {object} sigma - Parsed Sigma object
 * @returns {string}
 */
export function sigmaToAQL(sigma) {
  const components = extractSigmaComponents(sigma);

  let conditions = [];
  const detection = components.detection;
  const selectFields = new Set(['sourceip', 'destinationip', 'username', 'starttime']);

  for (const [key, value] of Object.entries(detection)) {
    if (key === 'condition' || key === 'timeframe') continue;
    const conds = buildConditions(value, mapFieldToQRadar);
    if (conds.length > 0) {
      conditions.push(...conds);
      // Add referenced fields to SELECT
      conds.forEach(c => {
        const fieldMatch = c.match(/^(\w+)\s/);
        if (fieldMatch) selectFields.add(fieldMatch[1]);
      });
    }
  }

  let aql = `-- Sigma Rule: ${components.title}\n`;
  aql += `-- Level: ${components.level}\n`;
  aql += `SELECT ${[...selectFields].join(', ')}\n`;
  aql += `FROM events\n`;
  if (conditions.length > 0) {
    // Convert XQL-style operators to AQL
    const aqlConditions = conditions.map(c =>
      c.replace(/\bcontains\b/g, 'ILIKE').replace(/"/g, "'").replace(/ILIKE '([^']+)'/g, "ILIKE '%$1%'")
    );
    aql += `WHERE ${aqlConditions.join('\n  AND ')}`;
  }
  aql += `\nLAST 24 HOURS`;

  return aql;
}
