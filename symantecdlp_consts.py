# File: symantecdlp_consts.py
#
# Copyright (c) 2018-2023 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
DLP_JSON_VERIFY_SERVER_CERT = "verify_server_cert"
DLP_JSON_URL = "url"
DLP_JSON_TIMEZONE = "timezone"
DLP_JSON_USERNAME = "username"
DLP_JSON_PASSWORD = "password"  # pragma: allowlist secret
DLP_JSON_REPORT_ID = "report_id"
DLP_JSON_POLL_NOW_DAYS = "poll_now_ingestion_span"
DLP_JSON_SCHEDULED_POLL_DAYS = "first_scheduled_ingestion_span"
DLP_JSON_EXTRACT_COMPONENTS = "extract_components"
DLP_JSON_LAST_DATE_TIME = "last_date_time"
DLP_JSON_LAST_INCIDENT_ID = "last_incident_ingested"
DLP_JSON_INCIDENT_ID = "incident_id"
DLP_JSON_INCIDENT_LONG_ID = "incident_long_id"
DLP_JSON_SEVERITY = "severity"
DLP_JSON_STATUS = "status"
DLP_JSON_NOTE = "note"
DLP_JSON_CUSTOM_FIELDS = "custom_fields"
DLP_JSON_REMEDIATION_STATUS = "remediation_status"
DLP_JSON_REMEDIATION_LOCATION = "remediation_location"
DLP_JSON_CREATION_TIME = "creation_time"
DLP_JSON_MAX_RESULTS = "max_results"
DLP_JSON_TOTAL_INCIDENTS = "total_incidents"
DLP_JSON_INCLUDE_HISTORY = "include_history"
DLP_JSON_INCLUDE_VIOLATIONS = "include_violations"
DLP_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S%z"
DLP_TIMESTAMP_VALIDATION_FAILED_MSG = 'Incorrect timestamp format, please enter in YYYY-MM-DD or valid ' \
                                             'ISO 8601 timestamp format.'
DLP_VALID_TIME = 'Time validation successful'

DLP_VALIDATE_INTEGER_MESSAGE = "Please provide a valid integer value in the {key} parameter"
DLP_ERR_MESSAGE = "Unknown error occurred. Please check the asset configuration and|or action parameters."
DLP_ERR_CODE_MESSAGE = "Error code unavailable"
DLP_UNKNOWN_SEVERITY = 'Unknown severity found. Severity {key} is not defined in custom severity. Hence, we are setting it as medium.'

DLP_SEVERITY_DICT = {
    'low': 'low',
    'medium': 'medium',
    'high': 'high'
}
