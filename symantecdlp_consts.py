# File: symantecdlp_consts.py
# Copyright (c) 2018-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

DLP_JSON_VERIFY_SERVER_CERT = "verify_server_cert"
DLP_JSON_URL = "url"
DLP_JSON_TIMEZONE = "timezone"
DLP_JSON_USERNAME = "username"
DLP_JSON_PASSWORD = "password"
DLP_JSON_REPORT_ID = "report_id"
DLP_JSON_POLL_NOW_DAYS = "poll_now_ingestion_span"
DLP_JSON_SCHEDULED_POLL_DAYS = "first_scheduled_ingestion_span"
DLP_JSON_EXTRACT_COMPONENTS = "extract_components"
DLP_JSON_LAST_DATE_TIME = "last_date_time"
DLP_JSON_LAST_INCIDENT_ID = "last_incident_ingested"
DLP_JSON_INCIDENT_ID = "incident_id"
DLP_JSON_SEVERITY = "severity"
DLP_JSON_STATUS = "status"
DLP_JSON_NOTE = "note"
DLP_JSON_CUSTOM_FIELDS = "custom_fields"
DLP_JSON_REMEDIATION_STATUS = "remediation_status"
DLP_JSON_REMEDIATION_LOCATION = "remediation_location"

DLP_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S%z"

DLP_VALIDATE_INTEGER_MESSAGE = "Please provide a valid integer value in the {key} parameter"
DLP_ERR_MESSAGE = "Unknown error occurred. Please check the asset configuration and|or action parameters."
DLP_ERR_CODE_MESSAGE = "Error code unavailable"
DLP_UNKNOWN_SEVERITY = 'Unknown severity found. Severity {key} is not defined in custom severity. Hence, we are setting it as medium.'

DLP_SEVERITY_DICT = {
    'low': 'low',
    'medium': 'medium',
    'high': 'high'
}
