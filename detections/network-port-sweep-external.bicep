param workspace string

resource workspace_Microsoft_SecurityInsights_246d9df3_2a61_440c_b771_c1b82281497d 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-12-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/246d9df3-2a61-440c-b771-c1b82281497d'
  kind: 'Scheduled'
  properties: {
    displayName: 'Network Port Sweep from External Network (ASIM Network Session schema)'
    description: 'This detection rule detects scenarios when a particular port is being scanned by multiple external sources. The rule utilize [ASIM](https://aka.ms/AboutASIM) normalization, and is applied to any source which supports the ASIM Network Session schema.'
    severity: 'High'
    enabled: true
    query: 'let lookback = 1h;\nlet threshold = 20;\n_Im_NetworkSession(starttime=ago(lookback),endtime=now())\n| where NetworkDirection == "Inbound"\n| summarize make_set(DstIpAddr,100) by SrcIpAddr, DstPortNumber\n| where array_length(set_DstIpAddr) > threshold\n'
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    startTimeUtc: null
    tactics: [
      'Reconnaissance'
      'Discovery'
    ]
    techniques: [
      'T1590'
      'T1046'
    ]
    subTechniques: []
    alertRuleTemplateName: 'cd8faa84-4464-4b4e-96dc-b22f50c27541'
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: false
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'SingleAlert'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Network Port Sweep detected on {{DstPortNumber}}'
      alertDescriptionFormat: 'Network Port Sweep was detection by multiple IPs'
    }
    customDetails: {
      AllDstIpAddr: 'set_DstIpAddr'
    }
    entityMappings: null
    sentinelEntitiesMappings: null
    templateVersion: '1.0.5'
  }
}
