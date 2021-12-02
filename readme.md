[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2018-2021 Splunk Inc."
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
