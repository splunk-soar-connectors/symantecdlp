# --
# File: parse_incidents.py
#
# Copyright (c) Phantom Cyber Corporation, 2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --


import tempfile
import os
import base64

container_common = {
    "description": "Container added by Phantom",
}

artifact_common = {
    "label": "incident",
    "type": "network",
    "run_automation": False,  # Set this to false here, the app will set it to true for the correct (last) artifact
    "description": "Artifact added by Phantom DLP App"
}


def parse_network_email_incident(incident, container, artifacts, base_connector):

    subject = incident.get('ns5_subject')
    cef = {}
    cef_types = {}

    if (subject):
        container['name'] = "Email: {0}".format(subject)
        cef['emailSubject'] = subject

    originator = incident.get('ns5_originator')
    if (originator):
        cef['fromEmail'] = originator.get('ns2_senderIdentifier')
        cef['sourceAddress'] = originator.get('ns2_IPAddress')
        cef['sourcePort'] = originator.get('ns2_port')
        cef_types.update({'fromEmail': ['email']})

    recipient = incident.get('ns5_recipient')
    if (recipient):
        cef['toEmail'] = recipient.get('ns2_recipientIdentifier')
        cef['destinationAddress'] = recipient.get('ns2_IPAddress')
        cef['destinationPort'] = recipient.get('ns2_port')
        cef_types.update({'toEmail': ['email']})

    if (not cef):
        return True

    artifact = {}
    artifact['name'] = "Email Info"
    artifact['cef'] = cef
    artifact['cef_types'] = cef_types
    artifact.update(artifact_common)
    artifacts.append(artifact)

    return True


parser_functions = {
        'NetworkEmailIncidentDetail': parse_network_email_incident}


def parse_incidents(incidents, base_connector):

    if (type(incidents) != list):
        raise "incidents parameter is not a list"

    results = []

    for i, curr_incident in enumerate(incidents):

        base_connector.send_progress("Processing Incident # {0}".format(i + 1))

        incident_id = curr_incident['ns5_incidentId']

        container = {}
        artifacts = []

        # First work on the keys that all data types (SHOULD) have
        container['source_data_identifier'] = incident_id
        container['data'] = curr_incident

        incident_type = curr_incident.get('@xsi_type')

        # create the default name, the helper parser for the message type might
        # override the name
        container_name = "{0} ID: {1}".format(incident_type, incident_id)
        container['name'] = container_name
        container.update(container_common)

        if ('ns5_severity' in curr_incident):
            container['severity'] = curr_incident.get('ns5_severity', 'medium')

        cef = {}
        if ('ns5_policy') in curr_incident:
            cef['policyInfo'] = curr_incident['ns5_policy']

        if (cef):
            artifact = {}
            artifact['name'] = 'Policy Info'
            artifact['cef'] = cef
            artifact.update(artifact_common)
            artifacts.append(artifact)

        parse_function = parser_functions.get(incident_type)

        if (parse_function is not None):
            parse_function(curr_incident, container, artifacts, base_connector)

        files = []

        # work on the files if present
        components = curr_incident.get('components', {}).get('ns5_Component', [])

        if (type(components) != list):
            components = [components]

        for component in components:

            content = component.get('ns5_content')
            if (not content):
                continue

            file_desc, file_path = tempfile.mkstemp(suffix='.comp', prefix='app_dlp', dir='/vault/tmp/')

            file_name = component.get('ns5_name')
            if (not file_name):
                file_name = os.path.split(file_path)[1]

            try:
                file_contents = base64.b64decode(content)
            except Exception as e:
                base_connector.debug_print("Unable to decode file content", e)
                continue

            try:
                with open(file_path, 'wb') as file_handle:
                    file_handle.write(file_contents)
            except Exception as e:
                base_connector.debug_print("Unable to save file content", e)
                continue

            os.chmod(file_path, 0660)

            file_info = {'file_path': file_path, 'file_name': file_name}

            files.append(file_info)

        results.append({'container': container, 'artifacts': artifacts, 'files': files})

    return results
