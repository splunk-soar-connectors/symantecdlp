[comment]: # "Auto-generated SOAR connector documentation"
# Symantec Data Loss Prevention

Publisher: Splunk  
Connector Version: 2\.1\.7  
Product Vendor: Symantec  
Product Name: Symantec DLP  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.0\.0  

This app supports incident update and incident ingestion from Symantec Data Loss Prevention installation

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2018-2022 Splunk Inc."
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

#### Schedule \| Interval Polling

-   During scheduled \| interval polling, the app will start from the number of days specified in
    **first_scheduled_ingestion_span** and will ingest up to the number of incidents specified in
    the **max_containers** (Default value 10) in configuration parameter per cycle. Then it
    remembers the last ingested 'incident_id' and stores it in the state file against the key
    'last_incident_ingested'. For the next scheduled \| interval cycles, ingestion will start from
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


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Symantec DLP asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | Device URL, e\.g\. https\://mysymcdlp\.contoso\.com
**verify\_server\_cert** |  optional  | boolean | Verify server certificate
**username** |  required  | string | Username
**password** |  required  | password | Password
**report\_id** |  required  | numeric | Report ID to ingest data from
**extract\_components** |  optional  | boolean | Extract additional components
**poll\_now\_ingestion\_span** |  optional  | numeric | Poll last n days for 'Poll Now' \(Default\: 15\)
**first\_scheduled\_ingestion\_span** |  optional  | numeric | Poll last n days for first scheduled polling \(Default\: 10\)
**max\_containers** |  optional  | numeric | Maximum number of containers to ingest during scheduled polling \(Default\: 10\)
**timezone** |  required  | timezone | Device timezone
**custom\_severity** |  optional  | string | JSON dictionary represented as a serialized JSON string \(More details in the documentation\)

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

For custom attributes defined in the administration console of DLP, use the custom\_fields parameter\. The parameter must be a JSON string with the key being the name of the attribute and the value being the value of the attribute\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident\_id** |  required  | ID of incident to update | numeric |  `dlp incident id` 
**status** |  optional  | New status of incident | string | 
**severity** |  optional  | New severity of incident | string | 
**remediation\_status** |  optional  | New remediation status of incident | string | 
**remediation\_location** |  optional  | Represents the remediation location of the incident | string | 
**note** |  optional  | Represents the note of the incident | string | 
**custom\_fields** |  optional  | JSON string representing custom fields to update \(defined in administration console\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.custom\_fields | string | 
action\_result\.parameter\.incident\_id | numeric |  `dlp incident id` 
action\_result\.parameter\.note | string | 
action\_result\.parameter\.remediation\_location | string | 
action\_result\.parameter\.remediation\_status | string | 
action\_result\.parameter\.severity | string | 
action\_result\.parameter\.status | string | 
action\_result\.data\.\*\.batchId | string | 
action\_result\.data\.\*\.statusCode | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list incidents'
List DLP incidents

Type: **investigate**  
Read only: **True**

<b>creation\_time</b> parameter is used to fetch the incidents that were created after the creation time\.<br>The timestamp should be entered in <b>YYYY\-MM\-DD</b> or a valid &quotISO 8601 timestamp&quot format\.<br>Some examples of valid time formats are\:<ul><li>2018\-09\-24</li><li>2018\-09\-23T14\:40\:44Z</li><li>2018\-09\-23T14\:40\:44\+05\:30</li><li>2020\-08\-30T01\:45\:36\.123Z</li><li>2021\-12\-13T21\:20\:37\.593194\+05\:30</li></ul><br><b>report\_id</b> specifies the ID of the saved report to execute on the Enforce Server from which we want to fetch incident\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report\_id** |  required  | ID of the saved report to fetch incident from | numeric |  `dlp report id` 
**creation\_time** |  required  | Fetch the incidents that were created after the creation time | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.creation\_time | string | 
action\_result\.parameter\.report\_id | numeric |  `dlp report id` 
action\_result\.data\.\*\.incident\_id | numeric |  `dlp incident id` 
action\_result\.summary | string | 
action\_result\.summary\.total\_incidents | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get incident'
Get DLP incident

Type: **investigate**  
Read only: **True**

User needs to provide value for either <b>incident\_id</b> or <b>incident\_long\_id</b> to get the incident details\. It is recommended to use <b>incident\_long\_id</b> parameter to fetch incident details\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident\_id** |  optional  | ID of incident to update | numeric |  `dlp incident id` 
**incident\_long\_id** |  optional  | Long ID of incident to update | numeric |  `dlp incident id` 
**include\_violations** |  optional  | Whether the Web Service should return policy violation data with the basic incident details | boolean | 
**include\_history** |  optional  | Whether the Web Service should return incident history information | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.incident\_id | numeric |  `dlp incident id` 
action\_result\.parameter\.incident\_long\_id | numeric |  `dlp incident id` 
action\_result\.parameter\.include\_history | boolean | 
action\_result\.parameter\.include\_violations | boolean | 
action\_result\.data\.\*\.incident\.applicationName | string | 
action\_result\.data\.\*\.incident\.applicationPath | string | 
action\_result\.data\.\*\.incident\.blockedStatus | string | 
action\_result\.data\.\*\.incident\.customAttributeGroup\.\*\.customAttribute\.\*\.name | string | 
action\_result\.data\.\*\.incident\.customAttributeGroup\.\*\.customAttribute\.\*\.value | string | 
action\_result\.data\.\*\.incident\.customAttributeGroup\.\*\.name | string | 
action\_result\.data\.\*\.incident\.dataOwner | string | 
action\_result\.data\.\*\.incident\.detectionDate | string | 
action\_result\.data\.\*\.incident\.detectionServer | string | 
action\_result\.data\.\*\.incident\.eventDate | string | 
action\_result\.data\.\*\.incident\.incidentCreationDate | string | 
action\_result\.data\.\*\.incident\.incidentHistory\.\*\.actionType\.\_value\_1 | string | 
action\_result\.data\.\*\.incident\.incidentHistory\.\*\.actionType\.actionTypeId | numeric | 
action\_result\.data\.\*\.incident\.incidentHistory\.\*\.date | string | 
action\_result\.data\.\*\.incident\.incidentHistory\.\*\.detail | string | 
action\_result\.data\.\*\.incident\.incidentHistory\.\*\.user | string | 
action\_result\.data\.\*\.incident\.incidentId | numeric |  `dlp incident id` 
action\_result\.data\.\*\.incident\.incidentLongId | numeric |  `dlp incident id` 
action\_result\.data\.\*\.incident\.isHTTPS | boolean | 
action\_result\.data\.\*\.incident\.machineIP | string | 
action\_result\.data\.\*\.incident\.machineName | string | 
action\_result\.data\.\*\.incident\.matchCount | numeric | 
action\_result\.data\.\*\.incident\.messageBody | string | 
action\_result\.data\.\*\.incident\.messageBodyContent | string | 
action\_result\.data\.\*\.incident\.messageHeader\.componentId | numeric | 
action\_result\.data\.\*\.incident\.messageHeader\.componentLongId | numeric | 
action\_result\.data\.\*\.incident\.messageHeader\.componentType\.\_value\_1 | string | 
action\_result\.data\.\*\.incident\.messageHeader\.componentType\.typeId | numeric | 
action\_result\.data\.\*\.incident\.messageHeader\.documentFormat | string | 
action\_result\.data\.\*\.incident\.messageHeader\.name | string | 
action\_result\.data\.\*\.incident\.messageHeader\.policyRuleViolation\.\*\.policyRule\.ruleId | numeric | 
action\_result\.data\.\*\.incident\.messageHeader\.policyRuleViolation\.\*\.policyRule\.ruleName | string | 
action\_result\.data\.\*\.incident\.messageHeader\.policyRuleViolation\.\*\.violation\.\*\.documentViolation | string | 
action\_result\.data\.\*\.incident\.messageHeader\.policyRuleViolation\.\*\.violation\.\*\.fileSizeViolation | string | 
action\_result\.data\.\*\.incident\.messageHeader\.policyRuleViolation\.\*\.violation\.\*\.imageViolation | string | 
action\_result\.data\.\*\.incident\.messageHeader\.policyRuleViolation\.\*\.violation\.\*\.violationText | string | 
action\_result\.data\.\*\.incident\.messageHeader\.ruleViolationCount | numeric | 
action\_result\.data\.\*\.incident\.messageSource\.\_value\_1 | string | 
action\_result\.data\.\*\.incident\.messageSource\.sourceType | string | 
action\_result\.data\.\*\.incident\.messageType\.\_value\_1 | string | 
action\_result\.data\.\*\.incident\.messageType\.typeId | numeric | 
action\_result\.data\.\*\.incident\.originator\.IPAddress | string | 
action\_result\.data\.\*\.incident\.originator\.originatorId | numeric | 
action\_result\.data\.\*\.incident\.originator\.originatorIdLong | numeric | 
action\_result\.data\.\*\.incident\.originator\.port | numeric | 
action\_result\.data\.\*\.incident\.originator\.senderIdentifier | string | 
action\_result\.data\.\*\.incident\.otherViolatedPolicy\.\*\.label | string | 
action\_result\.data\.\*\.incident\.otherViolatedPolicy\.\*\.name | string | 
action\_result\.data\.\*\.incident\.otherViolatedPolicy\.\*\.policyId | numeric | 
action\_result\.data\.\*\.incident\.otherViolatedPolicy\.\*\.version | numeric | 
action\_result\.data\.\*\.incident\.policy\.label | string | 
action\_result\.data\.\*\.incident\.policy\.name | string | 
action\_result\.data\.\*\.incident\.policy\.policyId | numeric | 
action\_result\.data\.\*\.incident\.policy\.version | numeric | 
action\_result\.data\.\*\.incident\.recipient\.\*\.IPAddress | string | 
action\_result\.data\.\*\.incident\.recipient\.\*\.port | numeric | 
action\_result\.data\.\*\.incident\.recipient\.\*\.recipientId | numeric | 
action\_result\.data\.\*\.incident\.recipient\.\*\.recipientIdLong | numeric | 
action\_result\.data\.\*\.incident\.recipient\.\*\.recipientIdentifier | string | 
action\_result\.data\.\*\.incident\.ruleViolationCount | numeric | 
action\_result\.data\.\*\.incident\.severity | string | 
action\_result\.data\.\*\.incident\.status | string | 
action\_result\.data\.\*\.incident\.superseded | string | 
action\_result\.data\.\*\.incident\.uniqueMessageId | string |  `unique message id` 
action\_result\.data\.\*\.incident\.userJustification | string | 
action\_result\.data\.\*\.incident\.userName | string | 
action\_result\.data\.\*\.incident\.violatedPolicyRule\.\*\.ruleId | numeric | 
action\_result\.data\.\*\.incident\.violatedPolicyRule\.\*\.ruleName | string | 
action\_result\.data\.\*\.incidentId | numeric |  `dlp incident id` 
action\_result\.data\.\*\.incidentLongId | numeric |  `dlp incident id` 
action\_result\.data\.\*\.incidentType | string | 
action\_result\.data\.\*\.statusCode | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'on poll'
Action handler for the ingest functionality

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start\_time** |  optional  | Parameter ignored in this app | numeric | 
**end\_time** |  optional  | Parameter ignored in this app | numeric | 
**container\_id** |  optional  | Parameter ignored in this app | string | 
**container\_count** |  optional  | Maximum number of emails to ingest | numeric | 
**artifact\_count** |  optional  | Parameter ignored in this app | numeric | 

#### Action Output
No Output