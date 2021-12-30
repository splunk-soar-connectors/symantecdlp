# File: parse_incidents.py
#
# Copyright (c) 2018-2021 Splunk Inc.
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
import os
import tempfile

from phantom.app import CONTAINS_VALIDATORS

from symantecdlp_consts import *

container_common = {
    "description": "Container added by Phantom",
}

artifact_common = {
    "label": "incident",
    "type": "network",
    "run_automation": False,
    "description": "Artifact added by Phantom DLP App"
}


def determine_contains(value):
    contains = []
    for c, f in list(CONTAINS_VALIDATORS.items()):
        if f(value):
            contains.append(c)
    return contains


def parse_originator_recipient(incident, artifacts):

    originators = incident.get('originator')
    if originators:

        if not isinstance(originators, list):
            originators = [originators]

        for originator in originators:

            cef = {}
            cef_types = {}
            artifact = {}
            artifact['cef'] = cef
            artifact['cef_types'] = cef_types

            sender_id = originator.get('senderIdentifier', 'Unknown')
            artifact['name'] = "Sender: {0}".format(sender_id)

            cef['sourceAddress'] = originator.get('IPAddress')
            cef['sourcePort'] = originator.get('port')
            cef['senderIdentifier'] = sender_id
            cef_types['senderIdentifier'] = determine_contains(sender_id)

            artifact.update(artifact_common)
            artifacts.append(artifact)

    recipients = incident.get('recipient')
    if recipients:

        if not isinstance(recipients, list):
            recipients = [recipients]

        for recipient in recipients:

            cef = {}
            cef_types = {}
            artifact = {}
            artifact['cef'] = cef
            artifact['cef_types'] = cef_types

            recipient_id = recipient.get('recipientIdentifier', 'Unknown')
            artifact['name'] = "Recipeint: {0}".format(recipient_id)

            cef['destinationAddress'] = recipient.get('IPAddress')
            cef['destinationPort'] = recipient.get('port')
            cef['recipientIdentifier'] = recipient_id
            cef_types['recipientIdentifier'] = determine_contains(recipient_id)

            artifact.update(artifact_common)
            artifacts.append(artifact)

    return True


# ------------------
# NETWORK INCIDENTS
# -------------------
def parse_network_email_incident(incident, container, artifact):

    artifact['name'] = "Email Info"

    subject = incident.get('subject')
    if subject:
        container['name'] = "Email: {0}".format(subject)
        artifact['cef']['emailSubject'] = subject
    else:
        container['name'] = "Email at {0}".format(incident['incidentCreationDate'])

    return True


def parse_network_ftp_incident(incident, container, artifact):

    artifact['name'] = "File Transfer Info"
    container['name'] = "File Transfer at {0}".format(incident['incidentCreationDate'])

    return True


def parse_network_http_incident(incident, container, artifact):

    artifact['name'] = "HTTP Request Info"
    container['name'] = "HTTP Request at {0}".format(incident['incidentCreationDate'])

    https = incident.get('HTTPS')
    if https:
        artifact['cef']['isHttps'] = https

    return True


def parse_network_im_incident(incident, container, artifact):

    artifact['name'] = "Instant Message Info"
    container['name'] = "Instant Message at {0}".format(incident['incidentCreationDate'])

    return True


def parse_network_nntp_incident(incident, container, artifact):

    artifact['name'] = "NNTP Info"

    subject = incident.get('subject')
    if subject:
        container['name'] = "NNTP Article: {0}".format(subject)
        artifact['cef']['nntpSubject'] = subject
    else:
        container['name'] = "NNTP Article at {0}".format(incident['incidentCreationDate'])

    return True


def parse_network_rest_incident(incident, container, artifact):

    artifact['name'] = "REST Info"
    container['name'] = "REST Request at {0}".format(incident['incidentCreationDate'])

    if 'httpUrl' in incident:
        artifact['cef_types']['httpUrl'] = ['url']

    return True


def parse_network_universal_incident(incident, container, artifact):

    artifact['name'] = "Network Info"
    container['name'] = "Network incident at {0}".format(incident['incidentCreationDate'])

    return True


def parse_network_incident(incident_type, incident, container, artifacts):

    parse_originator_recipient(incident, artifacts)

    artifact = {}
    artifacts.append(artifact)
    artifact.update(artifact_common)
    cef = {}
    cef_types = {}
    artifact['cef'] = cef
    artifact['cef_types'] = cef_types

    for k, v in list(incident.items()):
        if k in ['policy', 'components', 'originator', 'recipient']:
            continue
        cef[k] = v
        if isinstance(v, (str, bytes)):
            cef_types = determine_contains(v)

    parser_dict = {
            'NetworkEmailIncidentDetail': parse_network_email_incident,
            'NetworkFTPIncidentDetail': parse_network_ftp_incident,
            'NetworkHTTPIncidentDetail': parse_network_http_incident,
            'NetworkIMIncidentDetail': parse_network_im_incident,
            'NetworkNNTPIncidentDetail': parse_network_nntp_incident,
            'NetworkRESTIncidentDetail': parse_network_rest_incident,
            'NetworkUniversalIncidentDetail': parse_network_universal_incident
        }

    if incident_type not in parser_dict:
        artifact['name'] = "Network Incident Info"
        container['name'] = "Network Incident at {0}".format(incident['incidentCreationDate'])
        return True

    parser = parser_dict[incident_type]
    parser(incident, container, artifact)

    return True


# ------------------
# ENDPOINT INCIDENTS
# ------------------
def parse_endpoint_clipboard_incident(incident, container, artifact):

    artifact['name'] = "Clipboard Activity Info"
    container['name'] = "Clipboard Activity at {0}".format(incident['incidentCreationDate'])

    return True


def parse_endpoint_email_incident(incident, container, artifact):

    artifact['name'] = "Email Info"

    subject = incident.get('subject')
    if subject:
        container['name'] = "Email: {0}".format(subject)
        artifact['cef']['emailSubject'] = subject
    else:
        container['name'] = "Email at {0}".format(incident['incidentCreationDate'])

    return True


def parse_endpoint_ftp_incident(incident, container, artifact):

    artifact['name'] = "File Transfer Info"
    container['name'] = "File Transfer at {0}".format(incident['incidentCreationDate'])

    return True


def parse_endpoint_http_incident(incident, container, artifact):

    artifact['name'] = "HTTP Request Info"
    container['name'] = "HTTP Request at {0}".format(incident['incidentCreationDate'])

    https = incident.get('HTTPS')
    if https:
        artifact['cef']['isHttps'] = https

    return True


def parse_endpoint_im_incident(incident, container, artifact):

    artifact['name'] = "Instant Message Info"
    container['name'] = "Instant Message at {0}".format(incident['incidentCreationDate'])

    return True


def parse_endpoint_local_file_system_incident(incident, container, artifact):

    artifact['name'] = "File System Activity Info"
    container['name'] = "File System Activity at {0}".format(incident['incidentCreationDate'])

    artifact['cef_types']['sourceFileName'] = ['file name']
    artifact['cef_types']['sourceFilePath'] = ['file path']

    return True


def parse_endpoint_nntp_incident(incident, container, artifact):

    artifact['name'] = "NNTP Info"

    subject = incident.get('subject')
    if subject:
        container['name'] = "NNTP Article: {0}".format(subject)
        artifact['cef']['nntpSubject'] = subject
    else:
        container['name'] = "NNTP Article at {0}".format(incident['incidentCreationDate'])

    return True


def parse_endpoint_print_fax_incident(incident, container, artifact):

    artifact['name'] = "Print/Fax Info"
    container['name'] = "Print/Fax at {0}".format(incident['incidentCreationDate'])

    return True


def parse_endpoint_removable_storage_incident(incident, container, artifact):

    artifact['name'] = "Removable Storage Activity Info"
    container['name'] = "Removable Storage Activity at {0}".format(incident['incidentCreationDate'])

    artifact['cef_types']['sourceFileName'] = ['file name']
    artifact['cef_types']['sourceFilePath'] = ['file path']

    return True


def parse_endpoint_incident(incident_type, incident, container, artifacts):

    if 'originator' in incident or 'recipient' in incident:
        parse_originator_recipient(incident, artifacts)

    artifact = {}
    artifacts.append(artifact)
    artifact.update(artifact_common)
    cef = {}
    cef_types = {'userName': ['user name']}
    artifact['cef'] = cef
    artifact['cef_types'] = cef_types

    for k, v in list(incident.items()):
        if k in ['policy', 'components', 'originator', 'recipient']:
            continue
        if k.startswith('machine'):
            cef[k.replace('machine', 'device')] = v
        cef[k] = v
        if isinstance(v, (str, bytes)):
            cef_types = determine_contains(v)

    parser_dict = {
            'EndpointClipboardIncidentDetail': parse_endpoint_clipboard_incident,
            'EndpointEmailIncidentDetail': parse_endpoint_email_incident,
            'EndpointFTPIncidentDetail': parse_endpoint_ftp_incident,
            'EndpointHTTPIncidentDetail': parse_endpoint_http_incident,
            'EndpointIMIncidentDetail': parse_endpoint_im_incident,
            'EndpointLocalFileSystemIncidentDetail': parse_endpoint_local_file_system_incident,
            'EndpointNNTPIncidentDetail': parse_endpoint_nntp_incident,
            'EndpointPrintFaxIncidentDetail': parse_endpoint_print_fax_incident,
            'EndpointRemovableStorageIncidentDetail': parse_endpoint_removable_storage_incident
        }

    if incident_type not in parser_dict:
        artifact['name'] = "Network Incident Info"
        container['name'] = "Network Incident at {0}".format(incident['incidentCreationDate'])
        return True

    parser = parser_dict[incident_type]
    parser(incident, container, artifact)

    return True


# ------------------
# DISCOVER INCIDENTS
# ------------------
def parse_discover_box_crawler_incident(incident, container, artifact):

    artifact['name'] = "Box Crawler Info"
    container['name'] = "Box Crawler at {0}".format(incident['incidentCreationDate'])

    return True


def parse_discover_documentum_scanner_incident(incident, container, artifact):

    artifact['name'] = "Documentum Scanner Info"
    container['name'] = "Documentum Scanner at {0}".format(incident['incidentCreationDate'])

    return True


def parse_discover_dropbox_crawler_incident(incident, container, artifact):

    artifact['name'] = "Dropbox Crawler Info"
    container['name'] = "Dropbox Crawler at {0}".format(incident['incidentCreationDate'])

    return True


def parse_discover_endpoint_file_system_incident(incident, container, artifact):

    artifact['name'] = "Endpoint File System Activity Info"
    container['name'] = "Endpoint File System Activity at {0}".format(incident['incidentCreationDate'])

    return True


def parse_discover_exchange_crawler_incident(incident, container, artifact):

    artifact['name'] = "Exchange Crawler Info"

    subject = incident.get('subject')
    if subject:
        container['name'] = "Exchange Crawler: {0}".format(subject)
        artifact['cef']['nntpSubject'] = subject
    else:
        container['name'] = "Exchange Crawler at {0}".format(incident['incidentCreationDate'])

    return True


def parse_discover_exchange_scanner_incident(incident, container, artifact):

    artifact['name'] = "Exchange Scanner Info"
    container['name'] = "Exchange Scanner at {0}".format(incident['incidentCreationDate'])

    return True


def parse_discover_file_system_incident(incident, container, artifact):

    artifact['name'] = "File System Activity Info"
    container['name'] = "File System Activity at {0}".format(incident['incidentCreationDate'])

    return True


def parse_discover_file_system_scanner_incident(incident, container, artifact):

    artifact['name'] = "File System Scanner Info"
    container['name'] = "File System Scanner at {0}".format(incident['incidentCreationDate'])

    return True


def parse_discover_generic_scanner_incident(incident, container, artifact):

    artifact['name'] = "Scanner Info"
    container['name'] = "Scanner at {0}".format(incident['incidentCreationDate'])

    return True


def parse_discover_livelink_scanner_incident(incident, container, artifact):

    artifact['name'] = "Livelink Scanner Info"
    container['name'] = "Livelink Scanner at {0}".format(incident['incidentCreationDate'])

    return True


def parse_discover_lotus_notes_incident(incident, container, artifact):

    artifact['name'] = "Lotus Notes Activity Info"
    container['name'] = "Lotus Notes Activity at {0}".format(incident['incidentCreationDate'])

    return True


def parse_discover_one_drive_crawler_incident(incident, container, artifact):

    artifact['name'] = "OneDrive Crawler Info"
    container['name'] = "OneDrive Crawler at {0}".format(incident['incidentCreationDate'])

    return True


def parse_discover_sql_database_incident(incident, container, artifact):

    artifact['name'] = "SQL Database Activity Info"
    container['name'] = "SQL Database Activity at {0}".format(incident['incidentCreationDate'])

    return True


def parse_discover_share_point_crawler_incident(incident, container, artifact):

    artifact['name'] = "SharePoint Crawler Info"
    container['name'] = "SharePoint Crawler at {0}".format(incident['incidentCreationDate'])

    return True


def parse_discover_share_point_scanner_incident(incident, container, artifact):

    artifact['name'] = "SharePoint Scanner Info"
    container['name'] = "SharePoint Scanner at {0}".format(incident['incidentCreationDate'])

    return True


def parse_discover_web_server_scanner_incident(incident, container, artifact):

    artifact['name'] = "Web Server Scanner Info"
    container['name'] = "Web Server Scanner at {0}".format(incident['incidentCreationDate'])

    return True


def parse_discover_web_service_incident(incident, container, artifact):

    artifact['name'] = "Web Service Info"
    container['name'] = "Web Service at {0}".format(incident['incidentCreationDate'])

    return True


def parse_discover_incident(incident_type, incident, container, artifacts):

    artifact = {}
    artifacts.append(artifact)
    artifact.update(artifact_common)
    cef = {}
    cef_types = {'userName': ['user name']}
    artifact['cef'] = cef
    artifact['cef_types'] = cef_types

    for k, v in list(incident.items()):
        if k in ['policy', 'components', 'originator', 'recipient']:
            continue
        if k.startswith('machine'):
            cef[k.replace('machine', 'device')] = v
        cef[k] = v
        if isinstance(v, (str, bytes)):
            cef_types = determine_contains(v)

    parser_dict = {
            'DiscoverBoxCrawlerIncidentDetail': parse_discover_box_crawler_incident,
            'DiscoverDocumentumScannerIncidentDetail': parse_discover_documentum_scanner_incident,
            'DiscoverDropboxCrawlerIncidentDetail': parse_discover_dropbox_crawler_incident,
            'DiscoverEndpointFileSystemIncidentDetail': parse_discover_endpoint_file_system_incident,
            'DiscoverExchangeCrawlerIncidentDetail': parse_discover_exchange_crawler_incident,
            'DiscoverExchangeScannerIncidentDetail': parse_discover_exchange_scanner_incident,
            'DiscoverFileSystemIncidentDetail': parse_discover_file_system_incident,
            'DiscoverFileSystemScannerIncidentDetail': parse_discover_file_system_scanner_incident,
            'DiscoverGenericScannerIncidentDetail': parse_discover_generic_scanner_incident,
            'DiscoverLivelinkScannerIncidentDetail': parse_discover_livelink_scanner_incident,
            'DiscoverLotusNotesIncidentDetail': parse_discover_lotus_notes_incident,
            'DiscoverOneDriveCrawlerIncidentDetail': parse_discover_one_drive_crawler_incident,
            'DiscoverSQLDatabaseIncidentDetail': parse_discover_sql_database_incident,
            'DiscoverSharePointCrawlerIncidentDetail': parse_discover_share_point_crawler_incident,
            'DiscoverSharepointScannerIncidentDetail': parse_discover_share_point_scanner_incident,
            'DiscoverWebServerScannerIncidentDetail': parse_discover_web_server_scanner_incident,
            'DiscoverWebServiceIncidentDetail': parse_discover_web_service_incident
        }

    if incident_type == 'DiscoverExchangeCrawlerIncidentDetail':
        parse_originator_recipient(incident, artifacts)

    if incident_type not in parser_dict:
        artifact['name'] = "Discover Incident Info"
        container['name'] = "Discover Incident at {0}".format(incident['incidentCreationDate'])
        return True

    parser = parser_dict[incident_type]
    parser(incident, container, artifact)

    return True


# ----------------
# MOBILE INCIDENTS
# ----------------
def parse_mobile_incident(incident_type, incident, container, artifacts):

    parse_originator_recipient(incident, artifacts)

    artifact = {}
    artifacts.append(artifact)
    artifact.update(artifact_common)
    cef = {}
    cef_types = {}
    artifact['cef'] = cef
    artifact['cef_types'] = cef_types

    for k, v in list(incident.items()):
        if k in ['policy', 'components', 'originator', 'recipient']:
            continue
        if k.startswith('machine'):
            cef[k.replace('machine', 'device')] = v
        cef[k] = v
        if isinstance(v, (str, bytes)):
            cef_types = determine_contains(v)

    if incident_type == 'MobileFTPIncidentDetail':

        artifact['name'] = "File Tansfer Info"
        container['name'] = "File Tansfer at {0}".format(incident['incidentCreationDate'])

    elif incident_type == 'MobileHTTPIncidentDetail':

        artifact['name'] = "HTTP Request Info"
        container['name'] = "HTTP Request at {0}".format(incident['incidentCreationDate'])

        https = incident.get('HTTPS')
        if https:
            artifact['cef']['isHttps'] = https

    elif incident_type == 'MobileRESTIncidentDetail':

        artifact['name'] = "REST Request Info"
        container['name'] = "REST Request at {0}".format(incident['incidentCreationDate'])

        if 'httpUrl' in incident:
            artifact['cef_types']['httpUrl'] = ['url']

    return True


# ------------------
# REST INCIDENTS
# ------------------
def parse_rest_incident(incident_type, incident, container, artifacts):

    parse_originator_recipient(incident, artifacts)

    artifact = {}
    artifacts.append(artifact)
    artifact.update(artifact_common)
    cef = {}
    cef_types = {'userName': ['user name']}
    artifact['cef'] = cef
    artifact['cef_types'] = cef_types

    for k, v in list(incident.items()):
        if k in ['policy', 'components', 'originator', 'recipient']:
            continue
        if k.startswith('machine'):
            cef[k.replace('machine', 'device')] = v
        cef[k] = v
        if isinstance(v, (str, bytes)):
            cef_types = determine_contains(v)

    if incident_type == 'RestDARIncidentDetail':

        artifact['name'] = "Data at Rest Info"
        container['name'] = "Data at Rest at {0}".format(incident['incidentCreationDate'])

    elif incident_type == 'RestDIMIncidentDetail':

        artifact['name'] = "Data in Motion Info"
        container['name'] = "Data in Motion at {0}".format(incident['incidentCreationDate'])

    return True


def parse_incident(incident_type, incident, container, artifacts):
    if incident_type.startswith('Network'):
        return parse_network_incident(incident_type, incident, container, artifacts)
    elif incident_type.startswith('Endpoint'):
        return parse_endpoint_incident(incident_type, incident, container, artifacts)
    elif incident_type.startswith('Discover'):
        return parse_discover_incident(incident_type, incident, container, artifacts)
    elif incident_type.startswith('Mobile'):
        return parse_mobile_incident(incident_type, incident, container, artifacts)
    elif incident_type.startswith('Rest'):
        return parse_rest_incident(incident_type, incident, container, artifacts)
    return False


def parse_incidents(incidents, base_connector):

    if not isinstance(incidents, list):
        raise "incidents parameter is not a list"

    results = []

    for i, curr_incident in enumerate(incidents):

        base_connector.send_progress("Processing Incident # {0}".format(i + 1))

        incident_id = curr_incident['incidentId']

        container = {}
        artifacts = []

        # First work on the keys that all data types (SHOULD) have
        container['source_data_identifier'] = incident_id
        container['data'] = curr_incident

        incident_type = curr_incident.get('incidentType')

        # create the default name, the helper parser for the message type might
        # override the name
        container_name = "{0} ID: {1}".format(incident_type, incident_id)
        container['name'] = container_name
        container.update(container_common)

        if 'severity' in curr_incident.get('incident', []):
            container['severity'] = curr_incident.get('incident', {}).get('severity', 'medium').lower()
            if container['severity'] in base_connector._severity.keys():
                container['severity'] = base_connector._severity[container['severity']]
            else:
                base_connector.debug_print(DLP_UNKNOWN_SEVERITY.format(key=container['severity']))
                container['severity'] = 'medium'

        cef = {}
        if 'policy' in curr_incident:
            cef['policyInfo'] = curr_incident['policy']

        if cef:
            artifact = {}
            artifact['name'] = 'Policy Info'
            artifact['cef'] = cef
            artifact.update(artifact_common)
            artifacts.append(artifact)

        ret_val = parse_incident(incident_type, curr_incident['incident'], container, artifacts)  # noqa

        files = []

        # work on the files if present
        components = curr_incident.get('components', [])

        if not isinstance(components, list):
            components = [components]

        for component in components:

            content = component.get('content')
            if not content:
                continue

            file_desc, file_path = tempfile.mkstemp(suffix='.comp', prefix='app_dlp', dir='/vault/tmp/')

            file_name = component.get('name')
            if not file_name:
                file_name = os.path.split(file_path)[1]

            try:
                with open(file_path, 'w') as file_handle:
                    file_handle.write(content)
            except Exception as e:
                base_connector.debug_print("Unable to save file content", e)
                continue

            os.chmod(file_path, 0o660)

            file_info = {'file_path': file_path, 'file_name': file_name}

            files.append(file_info)

        container['artifacts'] = artifacts
        results.append({'container': container, 'files': files})

    return results
