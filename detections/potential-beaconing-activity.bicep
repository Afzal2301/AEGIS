param workspace string

resource workspace_Microsoft_SecurityInsights_7704282b_1064_4dfc_b2ff_5cd4294d443c 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-12-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/7704282b-1064-4dfc-b2ff-5cd4294d443c'
  kind: 'Scheduled'
  properties: {
    displayName: 'Potential beaconing activity (ASIM Network Session schema)'
    description: 'This rule identifies beaconing patterns from Network traffic logs based on recurrent frequency patterns. \nSuch potential outbound beaconing patterns to untrusted public networks should be investigated for any malware callbacks or data exfiltration attempts as discussed in this [Blog](https://medium.com/@HuntOperator/detect-beaconing-with-flare-elastic-stack-and-intrusion-detection-systems-110dc74e0c56).\nThis analytic rule uses [ASIM](https://aka.ms/AboutASIM) and supports any built-in or custom source that supports the ASIM NetworkSession schema\''
    severity: 'Low'
    enabled: true
    query: 'let querystarttime = 2d;\nlet queryendtime = 1d;\nlet TimeDeltaThreshold = 10;\nlet TotalEventsThreshold = 15;\nlet PercentBeaconThreshold = 80;\nlet LocalNetworks=dynamic(["169.254.0.0/16","127.0.0.0/8"]);\n_Im_NetworkSession(starttime=ago(querystarttime), endtime=ago(queryendtime))\n| where not(ipv4_is_private(DstIpAddr))\n| where not (ipv4_is_in_any_range(DstIpAddr, LocalNetworks))\n| project \n    TimeGenerated\n    , SrcIpAddr\n    , SrcPortNumber\n    , DstIpAddr\n    , DstPortNumber\n    , DstBytes\n    , SrcBytes\n| sort by \n    SrcIpAddr asc\n    , TimeGenerated asc\n    , DstIpAddr asc\n    , DstPortNumber asc\n| serialize\n| extend \n    nextTimeGenerated = next(TimeGenerated, 1)\n    , nextSrcIpAddr = next(SrcIpAddr, 1)\n| extend \n    TimeDeltainSeconds = datetime_diff(\'second\', nextTimeGenerated, TimeGenerated)\n| where SrcIpAddr == nextSrcIpAddr\n//Whitelisting criteria/ threshold criteria\n| where TimeDeltainSeconds > TimeDeltaThreshold \n| project\n    TimeGenerated\n    , TimeDeltainSeconds\n    , SrcIpAddr\n    , SrcPortNumber\n    , DstIpAddr\n    , DstPortNumber\n    , DstBytes\n    , SrcBytes\n| summarize\n    count()\n    , sum(DstBytes)\n    , sum(SrcBytes)\n    , make_list(TimeDeltainSeconds) \n    by TimeDeltainSeconds\n        , bin(TimeGenerated, 1h)\n        , SrcIpAddr\n        , DstIpAddr\n        , DstPortNumber\n| summarize\n    (MostFrequentTimeDeltaCount, MostFrequentTimeDeltainSeconds) = arg_max(count_, TimeDeltainSeconds)\n    , TotalEvents=sum(count_)\n    , TotalSrcBytes = sum(sum_SrcBytes)\n    , TotalDstBytes = sum(sum_DstBytes)\n    by bin(TimeGenerated, 1h)\n        , SrcIpAddr\n        , DstIpAddr\n        , DstPortNumber\n| where TotalEvents > TotalEventsThreshold \n| extend BeaconPercent = MostFrequentTimeDeltaCount/toreal(TotalEvents) * 100\n| where BeaconPercent > PercentBeaconThreshold\n'
    queryFrequency: 'P1D'
    queryPeriod: 'P2D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    startTimeUtc: null
    tactics: [
      'CommandAndControl'
    ]
    techniques: [
      'T1071'
      'T1571'
    ]
    subTechniques: []
    alertRuleTemplateName: 'fcb9d75c-c3c1-4910-8697-f136bfef2363'
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
      alertDisplayNameFormat: 'Potential beaconing from {{SrcIpAddr}} to {{DstIpAddr}}'
      alertDescriptionFormat: 'Potential beaconing pattern from a client at address {{SrcIpAddr}} to a server at address {{DstIpAddr}} over port {{DstPortNumber}} identified. Such potential outbound beaconing pattern to untrusted public networks should be investigated for any malware callbacks or data exfiltration attempts as discussed in this [Blog](http://www.austintaylor.io/detect/beaconing/intrusion/detection/system/command/control/flare/elastic/stack/2017/06/10/detect-beaconing-with-flare-elasticsearch-and-intrusion-detection-systems/). The recurring frequency, reported as FrequencyTime in the custom details, and the total transferred volume reported as TotalDstBytes in the custom details, can help to determine the significance of this incident.'
    }
    customDetails: {
      FrequencyTime: 'MostFrequentTimeDeltaCount'
      FrequencyCount: 'TotalSrcBytes'
      DstPortNumber: 'DstPortNumber'
      TotalDstBytes: 'TotalDstBytes'
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
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'DstIpAddr'
          }
        ]
      }
    ]
    sentinelEntitiesMappings: null
    templateVersion: '1.1.6'
  }
}
