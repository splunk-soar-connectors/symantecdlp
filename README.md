[comment]: # "Auto-generated SOAR connector documentation"
# Symantec Data Loss Prevention

Publisher: Splunk  
Connector Version: 2.2.1  
Product Vendor: Symantec  
Product Name: Symantec DLP  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.3.0  

This app supports incident update and incident ingestion from Symantec Data Loss Prevention installation

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2018-2024 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## On Poll

### Ingestion

#### Schedule | Interval Polling

-   During scheduled | interval polling, the app will start from the number of days specified in
    **first_scheduled_ingestion_span** and will ingest up to the number of incidents specified in
    the **max_containers** (Default value 10) in configuration parameter per cycle. Then it
    remembers the last ingested 'incident_id' and stores it in the state file against the key
    'last_incident_ingested'. For the next scheduled | interval cycles, ingestion will start from
    the last_incident_ingested in the state file and will ingest up to the number of incidents
    specified in the **max_containers** .
-   The number of incidents ingested will depend on the specified **max_containers** and
    **poll_now_ingestion_span** , whichever limit is hit first.

#### Manual Polling

-   During a **POLL NOW** , incidents will be ingested starting with the oldest first. The number of
    incidents ingested will depend on the specified **max_containers** and
    **poll_now_ingestion_span** , whichever limit is hit first.

**Custom Severity Config Parameter**

-   It is an optional parameter. Here the user needs to provide a JSON string in the following
    format  
    {'symantecdlp_severity': 'phantom_severity'}  
    This parameter can be used to map the Symantec DLP incident severity to any of the custom
    phantom severity.
-   To configure a custom severity in the Phantom, go to Administrator → Event Settings → Severity.
    Click on 'add item' and give an appropriate name for the severity and click on 'Done' button.
-   By default, the severity is mapped in the following way:
    -   For the incident having 'high' severity, the container's severity will be 'high'.
    -   For the incident having 'medium' severity, the container's severity will be 'medium'.
    -   For the incident having 'low' severity, the container's severity will be 'low'.
    -   For the incident having severity other than 'high', 'low' or 'medium' the container's
        severity will be 'medium'.

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Mattermost server. Below are the
default ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |


### Configuration variables
This table lists the configuration variables required to operate Symantec Data Loss Prevention. These variables are specified when configuring a Symantec DLP asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | Device URL, e.g. https://mysymcdlp.contoso.com
**verify_server_cert** |  optional  | boolean | Verify server certificate
**username** |  required  | string | Username
**password** |  required  | password | Password
**report_id** |  required  | numeric | Report ID to ingest data from
**extract_components** |  optional  | boolean | Extract additional components
**poll_now_ingestion_span** |  optional  | numeric | Poll last n days for 'Poll Now' (Default: 15)
**first_scheduled_ingestion_span** |  optional  | numeric | Poll last n days for first scheduled polling (Default: 10)
**max_containers** |  optional  | numeric | Maximum number of containers to ingest during scheduled polling (Default: 10)
**timezone** |  required  | timezone | Device timezone
**custom_severity** |  optional  | string | JSON dictionary represented as a serialized JSON string (More details in the documentation)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[update incident](#action-update-incident) - Update a DLP incident  
[list incidents](#action-list-incidents) - List DLP incidents  
[get incident](#action-get-incident) - Get DLP incident  
[on poll](#action-on-poll) - Action handler for the ingest functionality  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'update incident'
Update a DLP incident

Type: **generic**  
Read only: **False**

For custom attributes defined in the administration console of DLP, use the custom_fields parameter. The parameter must be a JSON string with the key being the name of the attribute and the value being the value of the attribute.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_id** |  required  | ID of incident to update | numeric |  `dlp incident id` 
**status** |  optional  | New status of incident | string | 
**severity** |  optional  | New severity of incident | string | 
**remediation_status** |  optional  | New remediation status of incident | string | 
**remediation_location** |  optional  | Represents the remediation location of the incident | string | 
**note** |  optional  | Represents the note of the incident | string | 
**custom_fields** |  optional  | JSON string representing custom fields to update (defined in administration console) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.custom_fields | string |  |   {'custom_attribute': 'test_value'} 
action_result.parameter.incident_id | numeric |  `dlp incident id`  |   49487 
action_result.parameter.note | string |  |   This is test note 
action_result.parameter.remediation_location | string |  |   test location 
action_result.parameter.remediation_status | string |  |   BLOCKED 
action_result.parameter.severity | string |  |   MEDIUM 
action_result.parameter.status | string |  |   In Progress 
action_result.data.\*.batchId | string |  |   304ee0ec-cd7c-4c92-ab28-8a561d9c4d7b 
action_result.data.\*.statusCode | string |  |   SUCCESS 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully updated incident 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list incidents'
List DLP incidents

Type: **investigate**  
Read only: **True**

<b>creation_time</b> parameter is used to fetch the incidents that were created after the creation time.<br>The timestamp should be entered in <b>YYYY-MM-DD</b> or a valid &quotISO 8601 timestamp&quot format.<br>Some examples of valid time formats are:<ul><li>2018-09-24</li><li>2018-09-23T14:40:44Z</li><li>2018-09-23T14:40:44+05:30</li><li>2020-08-30T01:45:36.123Z</li><li>2021-12-13T21:20:37.593194+05:30</li></ul><br><b>report_id</b> specifies the ID of the saved report to execute on the Enforce Server from which we want to fetch incident.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report_id** |  required  | ID of the saved report to fetch incident from | numeric |  `dlp report id` 
**creation_time** |  required  | Fetch the incidents that were created after the creation time | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.creation_time | string |  |  
action_result.parameter.report_id | numeric |  `dlp report id`  |  
action_result.data.\*.incident_id | numeric |  `dlp incident id`  |  
action_result.summary | string |  |  
action_result.summary.total_incidents | numeric |  |   18 
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get incident'
Get DLP incident

Type: **investigate**  
Read only: **True**

User needs to provide value for either <b>incident_id</b> or <b>incident_long_id</b> to get the incident details. It is recommended to use <b>incident_long_id</b> parameter to fetch incident details.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_id** |  optional  | ID of incident to update | numeric |  `dlp incident id` 
**incident_long_id** |  optional  | Long ID of incident to update | numeric |  `dlp incident id` 
**include_violations** |  optional  | Whether the Web Service should return policy violation data with the basic incident details | boolean | 
**include_history** |  optional  | Whether the Web Service should return incident history information | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.incident_id | numeric |  `dlp incident id`  |  
action_result.parameter.incident_long_id | numeric |  `dlp incident id`  |  
action_result.parameter.include_history | boolean |  |   True  False 
action_result.parameter.include_violations | boolean |  |   True  False 
action_result.data.\*.incident.applicationName | string |  |   Microsoft Host Process For Windows Services 
action_result.data.\*.incident.applicationPath | string |  |   \\Device\\HarddiskVolume2\\Windows\\System32\\svchost.exe 
action_result.data.\*.incident.blockedStatus | string |  |  
action_result.data.\*.incident.customAttributeGroup.\*.customAttribute.\*.name | string |  |   Group Attribute 1 
action_result.data.\*.incident.customAttributeGroup.\*.customAttribute.\*.value | string |  |  
action_result.data.\*.incident.customAttributeGroup.\*.name | string |  |   Test Group 1 
action_result.data.\*.incident.dataOwner | string |  |  
action_result.data.\*.incident.detectionDate | string |  |  
action_result.data.\*.incident.detectionServer | string |  |   DLP SingleTierServer 
action_result.data.\*.incident.eventDate | string |  |   2021-12-27T04:31:26-0800 
action_result.data.\*.incident.incidentCreationDate | string |  |  
action_result.data.\*.incident.incidentHistory.\*.actionType._value_1 | string |  |   Status Changed 
action_result.data.\*.incident.incidentHistory.\*.actionType.actionTypeId | numeric |  |   2 
action_result.data.\*.incident.incidentHistory.\*.date | string |  |   2021-12-27T04:32:46-0800 
action_result.data.\*.incident.incidentHistory.\*.detail | string |  |   New 
action_result.data.\*.incident.incidentHistory.\*.user | string |  |   Test 
action_result.data.\*.incident.incidentId | numeric |  `dlp incident id`  |   2882 
action_result.data.\*.incident.incidentLongId | numeric |  `dlp incident id`  |   2882 
action_result.data.\*.incident.isHTTPS | boolean |  |   False 
action_result.data.\*.incident.machineIP | string |  |   10.1.17.191 
action_result.data.\*.incident.machineName | string |  |   DLP158A1 
action_result.data.\*.incident.matchCount | numeric |  |   1 
action_result.data.\*.incident.messageBody | string |  |  
action_result.data.\*.incident.messageBodyContent | string |  |  
action_result.data.\*.incident.messageHeader.componentId | numeric |  |   2921 
action_result.data.\*.incident.messageHeader.componentLongId | numeric |  |   2921 
action_result.data.\*.incident.messageHeader.componentType._value_1 | string |  |   Header 
action_result.data.\*.incident.messageHeader.componentType.typeId | numeric |  |   1 
action_result.data.\*.incident.messageHeader.documentFormat | string |  |   unicode 
action_result.data.\*.incident.messageHeader.name | string |  |   Header 
action_result.data.\*.incident.messageHeader.policyRuleViolation.\*.policyRule.ruleId | numeric |  |   102 
action_result.data.\*.incident.messageHeader.policyRuleViolation.\*.policyRule.ruleName | string |  |   Matching Keyword ABGD 
action_result.data.\*.incident.messageHeader.policyRuleViolation.\*.violation.\*.documentViolation | string |  |  
action_result.data.\*.incident.messageHeader.policyRuleViolation.\*.violation.\*.fileSizeViolation | string |  |  
action_result.data.\*.incident.messageHeader.policyRuleViolation.\*.violation.\*.imageViolation | string |  |  
action_result.data.\*.incident.messageHeader.policyRuleViolation.\*.violation.\*.violationText | string |  |   delta 
action_result.data.\*.incident.messageHeader.ruleViolationCount | numeric |  |   1 
action_result.data.\*.incident.messageSource._value_1 | string |  |   Endpoint 
action_result.data.\*.incident.messageSource.sourceType | string |  |   ENDPOINT 
action_result.data.\*.incident.messageType._value_1 | string |  |   Endpoint HTTP 
action_result.data.\*.incident.messageType.typeId | numeric |  |   27 
action_result.data.\*.incident.originator.IPAddress | string |  |   10.1.17.191 
action_result.data.\*.incident.originator.originatorId | numeric |  |   2721 
action_result.data.\*.incident.originator.originatorIdLong | numeric |  |   2721 
action_result.data.\*.incident.originator.port | numeric |  |   0 
action_result.data.\*.incident.originator.senderIdentifier | string |  |   10.1.17.191 
action_result.data.\*.incident.otherViolatedPolicy.\*.label | string |  |  
action_result.data.\*.incident.otherViolatedPolicy.\*.name | string |  |   test_policy-2 
action_result.data.\*.incident.otherViolatedPolicy.\*.policyId | numeric |  |   41 
action_result.data.\*.incident.otherViolatedPolicy.\*.version | numeric |  |   4 
action_result.data.\*.incident.policy.label | string |  |  
action_result.data.\*.incident.policy.name | string |  |   Custom_Network_Endpoint_Policy 
action_result.data.\*.incident.policy.policyId | numeric |  |   81 
action_result.data.\*.incident.policy.version | numeric |  |   5 
action_result.data.\*.incident.recipient.\*.IPAddress | string |  |   34.104.35.123 
action_result.data.\*.incident.recipient.\*.port | numeric |  |   80 
action_result.data.\*.incident.recipient.\*.recipientId | numeric |  |   2701 
action_result.data.\*.incident.recipient.\*.recipientIdLong | numeric |  |   2701 
action_result.data.\*.incident.recipient.\*.recipientIdentifier | string |  |   http://example.com/example/delta-update/example.crxd 
action_result.data.\*.incident.ruleViolationCount | numeric |  |  
action_result.data.\*.incident.severity | string |  |  
action_result.data.\*.incident.status | string |  |  
action_result.data.\*.incident.superseded | string |  |   No 
action_result.data.\*.incident.uniqueMessageId | string |  `unique message id`  |  
action_result.data.\*.incident.userJustification | string |  |  
action_result.data.\*.incident.userName | string |  |   NT AUTHORITY\\system 
action_result.data.\*.incident.violatedPolicyRule.\*.ruleId | numeric |  |   102 
action_result.data.\*.incident.violatedPolicyRule.\*.ruleName | string |  |   Matching Keyword ABGD 
action_result.data.\*.incidentId | numeric |  `dlp incident id`  |   2882 
action_result.data.\*.incidentLongId | numeric |  `dlp incident id`  |  
action_result.data.\*.incidentType | string |  |  
action_result.data.\*.statusCode | string |  |   SUCCESS 
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'on poll'
Action handler for the ingest functionality

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** |  optional  | Parameter ignored in this app | numeric | 
**end_time** |  optional  | Parameter ignored in this app | numeric | 
**container_id** |  optional  | Parameter ignored in this app | string | 
**container_count** |  optional  | Maximum number of emails to ingest | numeric | 
**artifact_count** |  optional  | Parameter ignored in this app | numeric | 

#### Action Output
No Output