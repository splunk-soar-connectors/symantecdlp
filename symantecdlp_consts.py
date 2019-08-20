# --
# File: symantecdlp_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --

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

DLP_ERR_JSON_PARSE = "Unable to parse reply, raw string reply: '{raw_text}'"
DLP_REST_CALL_FAIL = "Call to Symantec DLP failed, with error code: {0}, message: {1}"
DLP_ERR_SERVER_CONNECTION = "Connection failed"

DLP_DEFAULT_ARTIFACT_COUNT = 100
DLP_DEFAULT_CONTAINER_COUNT = 100
DLP_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S%z"
