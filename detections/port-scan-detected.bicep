param workspace string

resource workspace_Microsoft_SecurityInsights_8a895a9b_7a5b_4181_ae02_cce1f6302531 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-12-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/8a895a9b-7a5b-4181-ae02-cce1f6302531'
  kind: 'Scheduled'
  properties: {
    displayName: 'Port scan detected  (ASIM Network Session schema)'
    description: '#INC_CORR#This rule identifies a possible port scan, in which a single source tries to access a large number of different ports is a short time frame. This may indicate that a [port scanner](https://en.wikipedia.org/wiki/Port_scanner) is trying to identify open ports in order to penetrate a system.\nThis analytic rule uses [ASIM](https://aka.ms/AboutASIM) and supports any built-in or custom source that supports the ASIM NetworkSession schema'
    severity: 'Medium'
    enabled: true
    query: 'let PortScanThreshold = 50;\n_Im_NetworkSession\n| where ipv4_is_private(SrcIpAddr) == False\n| where SrcIpAddr !in ("127.0.0.1", "::1")\n| summarize AttemptedPortsCount=dcount(DstPortNumber), AttemptedPorts=make_set(DstPortNumber, 100), ReportedBy=make_set(strcat(EventVendor, "/", EventProduct), 20) by SrcIpAddr, bin(TimeGenerated, 5m)\n| where AttemptedPortsCount > PortScanThreshold\n'
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    startTimeUtc: null
    tactics: [
      'Discovery'
    ]
    techniques: [
      'T1046'
    ]
    subTechniques: []
    alertRuleTemplateName: '1da9853f-3dea-4ea9-b7e5-26730da3d537'
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: true
        lookbackDuration: 'P1D'
        matchingMethod: 'Selected'
        groupByEntities: [
          'IP'
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'SingleAlert'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Potential port scan from {{SrcIpAddr}}'
      alertDescriptionFormat: 'A port scan has been performed from address {{SrcIpAddr}} over {{AttemptedPortsCount}} ports within 5 minutes. This may indicate that a [port scanner](https://en.wikipedia.org/wiki/Port_scanner) is trying to identify open ports in order to penetrate a system.'
    }
    customDetails: {
      AttemptedPortsCount: 'AttemptedPortsCount'
    }
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'SrcIpAddr'
          }
        ]
      }
    ]
    sentinelEntitiesMappings: null
    templateVersion: '1.0.6'
  }
}
