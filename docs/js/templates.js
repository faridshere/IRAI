// Detection rule templates for common threat scenarios
// Uses correct field names for Cortex XDR and QRadar

export const TEMPLATES = {
  ddos_detection: {
    name: "DDoS Detection",
    description: "Detect Distributed Denial of Service attack patterns",
    mitre: { tactic: "Impact", technique: "T1498", name: "Network Denial of Service" },
    cortex: {
      xql_query: `dataset = xdr_data
| filter event_type = ENUM.NETWORK and action_remote_ip != null
| comp count(action_remote_ip) as connection_count by agent_hostname, action_local_port
| filter connection_count > 1000
| sort desc connection_count
| limit 50`,
      bioc_rule: {
        name: "Potential DDoS - High Volume Inbound Connections",
        severity: "HIGH",
        description: "Detects unusually high connection volume to a single port, indicative of DDoS.",
        mitre_tactic: "Impact",
        mitre_technique: "T1498",
        rule_type: "Network",
        condition: "connection_count > 1000 per host per minute"
      }
    },
    qradar: {
      aql_query: `SELECT sourceip, destinationip, destinationport, COUNT(*) as conn_count
FROM events
WHERE categoryname = 'Firewall Session Opened'
GROUP BY sourceip, destinationip, destinationport
HAVING conn_count > 1000
ORDER BY conn_count DESC
LAST 15 MINUTES`,
      cre_rule: {
        name: "DDoS - High Volume Connections Detected",
        severity: "High",
        conditions: [
          { field: "eventcount", operator: ">", value: "1000" },
          { field: "categoryname", operator: "=", value: "Firewall Session Opened" },
          { timeframe: "15 minutes", groupBy: ["sourceip", "destinationip"] }
        ],
        building_block: "BB: High Connection Rate per Source IP"
      }
    }
  },

  smb_brute_force: {
    name: "SMB Brute Force",
    description: "Detect SMB authentication brute force attempts",
    mitre: { tactic: "Credential Access", technique: "T1110.001", name: "Brute Force: Password Guessing" },
    cortex: {
      xql_query: `dataset = xdr_data
| filter event_type = ENUM.NETWORK and action_remote_port = 445
| comp count(action_remote_ip) as attempt_count by actor_primary_normalized_user, agent_hostname
| filter attempt_count > 20
| sort desc attempt_count`,
      bioc_rule: {
        name: "SMB Brute Force - Multiple Failed Auth on Port 445",
        severity: "HIGH",
        description: "Detects multiple SMB connection attempts from a single source, indicating brute force.",
        mitre_tactic: "Credential Access",
        mitre_technique: "T1110.001",
        rule_type: "Network",
        condition: "More than 20 SMB connection attempts from same source within 5 minutes"
      }
    },
    qradar: {
      aql_query: `SELECT sourceip, destinationip, username, COUNT(*) as attempts
FROM events
WHERE destinationport = 445 AND EventID IN (4625, 529, 530)
GROUP BY sourceip, destinationip, username
HAVING attempts > 20
LAST 10 MINUTES`,
      cre_rule: {
        name: "SMB Brute Force Detected",
        severity: "High",
        conditions: [
          { field: "destinationport", operator: "=", value: "445" },
          { field: "EventID", operator: "IN", value: "4625, 529, 530" },
          { field: "eventcount", operator: ">", value: "20" },
          { timeframe: "10 minutes", groupBy: ["sourceip", "username"] }
        ],
        building_block: "BB: Multiple Failed SMB Authentication"
      }
    }
  },

  suspicious_process: {
    name: "Suspicious Process Execution",
    description: "Detect suspicious process execution patterns (LOLBins, encoded commands)",
    mitre: { tactic: "Execution", technique: "T1059", name: "Command and Scripting Interpreter" },
    cortex: {
      xql_query: `dataset = xdr_data
| filter event_type = ENUM.PROCESS and (
    action_process_image_name in ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","regsvr32.exe","rundll32.exe","certutil.exe","bitsadmin.exe") 
    or action_process_image_command_line contains "-enc" 
    or action_process_image_command_line contains "downloadstring"
    or action_process_image_command_line contains "invoke-expression"
  )
| fields agent_hostname, actor_process_image_name, action_process_image_name, action_process_image_command_line, actor_primary_normalized_user, _time
| sort desc _time`,
      bioc_rule: {
        name: "Suspicious LOLBin / Encoded Command Execution",
        severity: "MEDIUM",
        description: "Detects execution of living-off-the-land binaries or encoded PowerShell commands.",
        mitre_tactic: "Execution",
        mitre_technique: "T1059",
        rule_type: "Process",
        condition: "Process image name matches known LOLBins OR command line contains encoded/download patterns"
      }
    },
    qradar: {
      aql_query: `SELECT sourceip, username, ProcessName, Command, Hostname, starttime
FROM events
WHERE ProcessName IN ('powershell.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe','regsvr32.exe','rundll32.exe','certutil.exe','bitsadmin.exe')
  OR Command ILIKE '%encodedcommand%' OR Command ILIKE '%downloadstring%'
ORDER BY starttime DESC
LAST 1 HOURS`,
      cre_rule: {
        name: "Suspicious Process Execution Detected",
        severity: "Medium",
        conditions: [
          { field: "ProcessName", operator: "IN", value: "powershell.exe, cmd.exe, wscript.exe, mshta.exe, regsvr32.exe, rundll32.exe, certutil.exe" },
          { field: "Command", operator: "ILIKE", value: "%encodedcommand%" }
        ],
        building_block: "BB: LOLBin Execution Detection"
      }
    }
  },

  persistence_services: {
    name: "Persistence via Services",
    description: "Detect adversary persistence through Windows service creation/modification",
    mitre: { tactic: "Persistence", technique: "T1543.003", name: "Create or Modify System Process: Windows Service" },
    cortex: {
      xql_query: `dataset = xdr_data
| filter event_type = ENUM.PROCESS and (
    action_process_image_name = "sc.exe" and action_process_image_command_line contains "create"
  ) or (
    action_registry_key_name contains "\\\\Services\\\\"
    and action_registry_value_name = "ImagePath"
  )
| fields agent_hostname, actor_process_image_name, action_process_image_name, action_process_image_command_line, action_registry_key_name, action_registry_data, _time
| sort desc _time`,
      bioc_rule: {
        name: "Persistence - New Service Created via sc.exe or Registry",
        severity: "HIGH",
        description: "Detects service creation via sc.exe or direct registry modification to Services key.",
        mitre_tactic: "Persistence",
        mitre_technique: "T1543.003",
        rule_type: "Process / Registry",
        condition: "sc.exe create OR Services registry key modification"
      }
    },
    qradar: {
      aql_query: `SELECT sourceip, username, ProcessName, Command, ServiceName, RegistryKey, Hostname, starttime
FROM events
WHERE (ProcessName = 'sc.exe' AND Command ILIKE '%create%')
   OR (EventID = 7045)
   OR (RegistryKey ILIKE '%\\Services\\%' AND EventID IN (4657, 13))
ORDER BY starttime DESC
LAST 24 HOURS`,
      cre_rule: {
        name: "Persistence via Service Creation Detected",
        severity: "High",
        conditions: [
          { field: "ProcessName", operator: "=", value: "sc.exe" },
          { field: "Command", operator: "ILIKE", value: "%create%" },
          { field: "EventID", operator: "IN", value: "7045, 4657, 13" }
        ],
        building_block: "BB: Service Creation or Modification"
      }
    }
  },

  rdp_brute_force: {
    name: "RDP Brute Force",
    description: "Detect RDP brute force authentication attempts",
    mitre: { tactic: "Credential Access", technique: "T1110.001", name: "Brute Force: Password Guessing" },
    cortex: {
      xql_query: `dataset = xdr_data
| filter event_type = ENUM.NETWORK and action_remote_port = 3389
| comp count(action_remote_ip) as attempt_count by action_remote_ip, agent_hostname
| filter attempt_count > 15
| sort desc attempt_count`,
      bioc_rule: {
        name: "RDP Brute Force - Multiple Connection Attempts on Port 3389",
        severity: "HIGH",
        description: "Detects multiple RDP connection attempts from a single source IP.",
        mitre_tactic: "Credential Access",
        mitre_technique: "T1110.001",
        rule_type: "Network",
        condition: "More than 15 RDP connection attempts from same source within 10 minutes"
      }
    },
    qradar: {
      aql_query: `SELECT sourceip, destinationip, username, COUNT(*) as attempts
FROM events
WHERE destinationport = 3389 AND EventID IN (4625, 529)
GROUP BY sourceip, destinationip, username
HAVING attempts > 15
LAST 10 MINUTES`,
      cre_rule: {
        name: "RDP Brute Force Detected",
        severity: "High",
        conditions: [
          { field: "destinationport", operator: "=", value: "3389" },
          { field: "EventID", operator: "IN", value: "4625, 529" },
          { field: "eventcount", operator: ">", value: "15" },
          { timeframe: "10 minutes", groupBy: ["sourceip", "destinationip"] }
        ],
        building_block: "BB: Multiple Failed RDP Authentication"
      }
    }
  }
};

/**
 * Get a template by key
 * @param {string} key - Template key
 * @returns {object|null}
 */
export function getTemplate(key) {
  return TEMPLATES[key] || null;
}

/**
 * Get all template names
 * @returns {Array<{key: string, name: string, description: string}>}
 */
export function listTemplates() {
  return Object.entries(TEMPLATES).map(([key, val]) => ({
    key,
    name: val.name,
    description: val.description,
    mitre: val.mitre
  }));
}

/**
 * Get template output for a specific mode
 * @param {string} key - Template key
 * @param {string} mode - 'cortex' or 'qradar'
 * @returns {object|null}
 */
export function getTemplateForMode(key, mode) {
  const template = TEMPLATES[key];
  if (!template) return null;
  return {
    name: template.name,
    description: template.description,
    mitre: template.mitre,
    ...template[mode]
  };
}
