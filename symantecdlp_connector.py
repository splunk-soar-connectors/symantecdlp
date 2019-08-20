# --
# File: symantecdlp_connector.py
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

# Phantom imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# THIS Connector imports
from symantecdlp_consts import *

import os
import re
import ssl
import json
import magic
import base64
import hashlib
import requests
import parse_incidents as pi
import uuid

from datetime import datetime
from datetime import timedelta
from pytz import timezone, utc
from suds.client import Client
from urllib2 import HTTPSHandler
from suds.sudsobject import asdict
from suds.transport.https import HttpAuthenticated


class RetVal(tuple):
    def __new__(cls, status, data=None):
        return tuple.__new__(RetVal, (status, data))


class NoVerifyTransport(HttpAuthenticated):
    def u2handlers(self):
        handlers = HttpAuthenticated.u2handlers(self)
        context = ssl._create_unverified_context()
        handlers.append(HTTPSHandler(context=context))
        return handlers


FILE_EXTENSIONS = {
  '.vmsn': ['os memory dump', 'vm snapshot file'],
  '.vmss': ['os memory dump', 'vm suspend file'],
  '.js': ['javascript'],
  '.doc': ['doc'],
  '.docx': ['doc'],
  '.xls': ['xls'],
  '.xlsx': ['xls'],
}


MAGIC_FORMATS = [
  (re.compile('^PE.* Windows'), ['pe file', 'hash']),
  (re.compile('^MS-DOS executable'), ['pe file', 'hash']),
  (re.compile('^PDF '), ['pdf']),
  (re.compile('^MDMP crash'), ['process dump']),
  (re.compile('^Macromedia Flash'), ['flash']),
]


class SymantecDLPConnector(BaseConnector):

    ACTION_ID_TEST_CONNECTIVITY = "test_connectivity"
    ACTION_ID_UPDATE_INCIDENT = "update_incident"
    ACTION_ID_ON_POLL = "on_poll"

    def __init__(self):

        # Call the BaseConnectors init first
        super(SymantecDLPConnector, self).__init__()

        self._base_url = None
        self._session = None
        self._client = None
        self._state = {}

    def initialize(self):

        config = self.get_config()
        self._state = self.load_state()
        self._session = requests.Session()
        self._verify = config[DLP_JSON_VERIFY_SERVER_CERT]
        self._auth = base64.b64encode('{0}:{1}'.format(config[DLP_JSON_USERNAME], config[DLP_JSON_PASSWORD]))
        self._base_url = "{0}/ProtectManager/services/v2011/incidents?wsdl".format(config[DLP_JSON_URL].strip('/'))

        self._proxy = {}
        env_vars = config.get('_reserved_environment_variables', {})
        if 'HTTP_PROXY' in env_vars:
            self._proxy['http'] = env_vars['HTTP_PROXY']['value']
        if 'HTTPS_PROXY' in env_vars:
            self._proxy['https'] = env_vars['HTTPS_PROXY']['value']

        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _create_client(self, action_result):

        try:

            if self._verify:
                self._client = Client(self._base_url)
            else:
                self._client = Client(self._base_url, transport=NoVerifyTransport())

            options = {'headers': {'Authorization': 'Basic {0}'.format(self._auth)}}

            if self._proxy:
                options['proxy'] = self._proxy

            self._client.set_options(**options)

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, 'Could not connect to the DLP API endpoint', e)

        return phantom.APP_SUCCESS

    def _make_soap_call(self, action_result, method, soap_args=()):

        if not hasattr(self._client.service, method):
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Could not find given method {0}'.format(method)), None)

        soap_call = getattr(self._client.service, method)

        try:
            response = soap_call(*soap_args)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'SOAP call to DLP failed', e), None)

        return True, response

    def _suds_to_dict(self, sud_obj):

        if hasattr(sud_obj, '__keylist__'):

            sud_dict = asdict(sud_obj)
            new_dict = {}

            for key in sud_dict:
                new_dict[key] = self._suds_to_dict(sud_dict[key])

            return new_dict

        elif isinstance(sud_obj, list):
            new_list = []
            for elm in sud_obj:
                new_list.append(self._suds_to_dict(elm))
            return new_list

        elif isinstance(sud_obj, datetime):
            # Sometimes an event's DateInserted field can be '0001-01-01 00:00:00', which causes a ValueError in strftime()
            try:
                return sud_obj.strftime(DLP_TIME_FORMAT)
            except ValueError:
                return None

        # Checking for NaN
        elif sud_obj != sud_obj:
            return None

        return sud_obj

    def _cleanse_key_names(self, input_dict):

        if not input_dict:
            return input_dict

        for k, v in input_dict.items():

            new_k = k

            if k.startswith('_'):
                new_k = k.strip('_')
                input_dict[new_k] = v
                del input_dict[k]

            if type(v) == dict:
                input_dict[new_k] = self._cleanse_key_names(v)

            elif type(v) == list:
                new_v = []
                for curr_v in v:
                    new_v.append(self._cleanse_key_names(curr_v))
                input_dict[new_k] = new_v

        return input_dict

    def _test_connectivity(self, param):
        """ Function that handles the test connectivity action, it is much simpler than other action handlers.
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._create_client(action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        config = self.get_config()

        self.save_progress("Querying incident IDs to test connectivity")
        ret_val, response = self._make_soap_call(action_result, 'incidentList', (config[DLP_JSON_REPORT_ID], '0001-01-01T00:00:00'))

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, "Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Successful")

        return action_result.set_status(phantom.APP_SUCCESS, "Test Connectivity Successful")

    def _handle_update_incident(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # create SUDS client
        ret_val = self._create_client(action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        # required field, even though it is not used by DLP
        batch_id = uuid.uuid4()
        incident_id = param[DLP_JSON_INCIDENT_ID]
        status = param.get(DLP_JSON_STATUS)
        severity = param.get(DLP_JSON_SEVERITY)
        note = param.get(DLP_JSON_NOTE)
        now_date = str(datetime.now())
        custom_fields = param.get(DLP_JSON_CUSTOM_FIELDS)
        remediation_status = param.get(DLP_JSON_REMEDIATION_STATUS)
        remediation_location = param.get(DLP_JSON_REMEDIATION_LOCATION)

        update_request = {
            'batchId': batch_id,
            'incidentId': incident_id,
            'incidentAttributes': {
            }
        }

        if status:
            update_request['incidentAttributes']['status'] = status

        if severity:
            update_request['incidentAttributes']['severity'] = severity

        if note:
            update_request['incidentAttributes']['note'] = {
                'note': note,
                'dateAndTime': now_date
            }

        if remediation_status:
            update_request['incidentAttributes']['remediationStatus'] = remediation_status

        if remediation_location:
            update_request['incidentAttributes']['remediationLocation'] = remediation_location

        if custom_fields:
            # should be JSON string
            # {'name': value}
            try:
                custom_fields = json.loads(custom_fields)
            except ValueError as ve:
                return action_result.set_status(phantom.APP_ERROR, "custom_fields must be a JSON string.\r\nError: {}".format(ve)) 
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "custom_fields must be a JSON string.\r\nError: {}".format(ve)) 

            custom_fields = [
                {'name': key, 'value': value} 
                for key, value in custom_fields.iteritems()
            ]

            update_request['incidentAttributes']['customAttributes'] = custom_fields

        try:
            response = self._client.service.updateIncidents(update_request)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, 'SOAP call to DLP failed', e)

        if not response:
            return action_result.set_status(phantom.APP_ERROR, "Response was empty")

        action_result.update_data(self._suds_to_dict(response))
        
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated incident")

    def _get_incident_ids(self, action_result, report_id, date_string):

        ret_val, response = self._make_soap_call(action_result, 'incidentList', (report_id, date_string))

        if phantom.is_fail(ret_val):
            return RetVal(ret_val, None)

        resp_dict = self._suds_to_dict(response)

        return RetVal(phantom.APP_SUCCESS, resp_dict.get('incidentLongId'))

    def _get_incident_details(self, action_result, incident_id, extract_files):

        ret_val, response = self._make_soap_call(action_result, 'incidentDetail', (incident_id, True))

        if phantom.is_fail(ret_val):
            return RetVal(ret_val)

        if not response:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Incident response returned was empty or None"))

        resp_dict = self._suds_to_dict(response)

        try:
            incident_details = resp_dict[0]
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Could not get incident details: {0}".format(e)))

        if not incident_details:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Incident details returned were empty or None"))

        incident_type = response[0].incident.__class__.__name__
        incident_details['incidentType'] = incident_type

        if not extract_files:
            return RetVal(phantom.APP_SUCCESS, incident_details)

        ret_val, response = self._make_soap_call(action_result, 'incidentBinaries', (incident_id, False, True))

        if phantom.is_fail(ret_val):
            return RetVal(action_result.get_status())

        if not response:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Got empty or None incident response for files"))

        resp_dict = self._suds_to_dict(response)

        if 'Component' in resp_dict:
            incident_details['components'] = resp_dict['Component']

        return RetVal(phantom.APP_SUCCESS, incident_details)

    def _get_file_contains(self, file_path):

        contains = []
        ext = os.path.splitext(file_path)[1]
        contains.extend(FILE_EXTENSIONS.get(ext, []))
        magic_str = magic.from_file(file_path)
        for regex, cur_contains in MAGIC_FORMATS:
            if regex.match(magic_str):
                contains.extend(cur_contains)

        return contains

    def _handle_file(self, curr_file, vault_ids, container_id, artifact_id, is_last):

        file_name = curr_file.get('file_name')

        local_file_path = curr_file['file_path']

        contains = self._get_file_contains(local_file_path)

        # lets move the data into the vault
        vault_attach_dict = {}

        if not file_name:
            file_name = os.path.basename(local_file_path)

        self.debug_print("Vault file name: {0}".format(file_name))

        vault_attach_dict[phantom.APP_JSON_ACTION_NAME] = self.get_action_name()
        vault_attach_dict[phantom.APP_JSON_APP_RUN_ID] = self.get_app_run_id()

        vault_ret = {}

        try:
            vault_ret = Vault.add_attachment(local_file_path, container_id, file_name, vault_attach_dict)
        except Exception as e:
            self.debug_print(phantom.APP_ERR_FILE_ADD_TO_VAULT.format(e))
            return phantom.APP_ERROR, phantom.APP_ERROR

        # self.debug_print("vault_ret_dict", vault_ret_dict)

        if not vault_ret.get('succeeded'):
            self.debug_print("Failed to add file to Vault: {0}".format(json.dumps(vault_ret)))
            return phantom.APP_ERROR, phantom.APP_ERROR

        # add the vault id artifact to the container
        cef_artifact = {}
        if file_name:
            cef_artifact.update({'fileName': file_name})
        if phantom.APP_JSON_HASH in vault_ret:
            cef_artifact.update({'vaultId': vault_ret[phantom.APP_JSON_HASH]})

        if not cef_artifact:
            return phantom.APP_SUCCESS, phantom.APP_ERROR

        artifact = {}
        artifact.update(pi.artifact_common)
        artifact['container_id'] = container_id
        artifact['name'] = 'Vault Artifact'
        artifact['cef'] = cef_artifact
        if contains:
            artifact['cef_types'] = {'vaultId': contains}
        self._set_sdi(artifact_id, artifact)
        if is_last:
            artifact['run_automation'] = True

        ret_val, status_string, artifact_id = self.save_artifact(artifact)
        self.debug_print("save_artifact returns, value: {0}, reason: {1}, id: {2}".format(ret_val, status_string, artifact_id))

        return phantom.APP_SUCCESS, ret_val

    def _set_sdi(self, default_id, input_dict):

        if 'source_data_identifier' in input_dict:
            del input_dict['source_data_identifier']

        input_dict['source_data_identifier'] = self._create_dict_hash(input_dict)

        return phantom.APP_SUCCESS

    def _create_dict_hash(self, input_dict):

        input_dict_str = None

        if not input_dict:
            return None

        try:
            input_dict_str = json.dumps(input_dict, sort_keys=True)
        except Exception as e:
            self.debug_print('Handled exception in _create_dict_hash', e)
            return None

        return hashlib.md5(input_dict_str).hexdigest()

    def _parse_results(self, action_result, param, results):

        container_count = DLP_DEFAULT_CONTAINER_COUNT

        if param:
            container_count = param.get(phantom.APP_JSON_CONTAINER_COUNT, DLP_DEFAULT_CONTAINER_COUNT)

        results = results[:container_count]

        for i, result in enumerate(results):

            container = result.get('container')
            files = result.get('files', [])

            if not container:
                self.save_progress("no container")
                continue

            artifacts = container.get('artifacts', [])
            len_artifacts = len(artifacts)

            for j, artifact in enumerate(artifacts):

                if not artifact:
                    continue

                self._set_sdi(j, artifact)

                # if it is the last artifact of the last container
                if not files and (j + 1) == len_artifacts:
                    # mark it such that active playbooks get executed
                    artifact['run_automation'] = True

            container['artifacts'] = artifacts

            self.send_progress("Saving Container # {0}".format(i + 1))

            try:
                ret_val, message, container_id = self.save_container(container)
            except Exception as e:
                self.debug_print("Handled Exception while saving container", e)
                continue

            self.debug_print("save_container returns, value: {0}, reason: {1}, id: {2}".format(ret_val, message, container_id))

            if phantom.is_fail(ret_val):
                message = "Failed to add Container for id: {0}, error msg: {1}".format(container['source_data_identifier'], message)
                self.debug_print(message)
                continue

            if not container_id:
                message = "save_container did not return a container_id"
                self.debug_print(message)
                continue

            vault_ids = list()
            len_files = len(files)
            count = len_artifacts

            for curr_file in files:
                count += 1
                ret_val, added_to_vault = self._handle_file(curr_file, vault_ids, container_id, count, count == len_artifacts + len_files)

        return self.set_status(phantom.APP_SUCCESS)

    def _get_time_string(self):

        # function to separate on poll and poll now
        config = self.get_config()
        last_time = self._state.get(DLP_JSON_LAST_DATE_TIME)

        if self.is_poll_now():
            dt_diff = datetime.utcnow() - timedelta(days=int(config[DLP_JSON_POLL_NOW_DAYS]))
        elif self._state.get('first_run', True):
            self._state['first_run'] = False
            dt_diff = datetime.utcnow() - timedelta(days=int(config[DLP_JSON_SCHEDULED_POLL_DAYS]))
        elif last_time:
            return last_time
        else:
            dt_diff = datetime.utcnow() - timedelta(days=int(config[DLP_JSON_SCHEDULED_POLL_DAYS]))

        # get the device timezone
        device_tz_sting = config[DLP_JSON_TIMEZONE]
        to_tz = timezone(device_tz_sting)

        # convert datetime to device timezone
        dt_diff = dt_diff.replace(tzinfo=utc)
        to_dt = to_tz.normalize(dt_diff.astimezone(to_tz))

        time_str = to_dt.strftime(DLP_TIME_FORMAT)

        # DLP is weird and wants a colon in the timezone value
        return time_str[:-2] + ':' + time_str[-2:]

    def _on_poll(self, param):

        action_result = self.add_action_result(ActionResult(param))

        ret_val = self._create_client(action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        config = self.get_config()

        # Get the maximum number of incidents that we can pull, same as container count
        if self.is_poll_now():
            max_containers = int(param[phantom.APP_JSON_CONTAINER_COUNT])
        else:
            max_containers = int(config['max_containers'])

        time_string = self._get_time_string()

        self.save_progress("Getting incident IDs generated since {0}".format(time_string))

        config = self.get_config()

        incident_ids = []

        # get the number of incidents
        ret_val, incident_ids = self._get_incident_ids(action_result, config[DLP_JSON_REPORT_ID], time_string)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not incident_ids:
            self.save_progress("Did not get any new Incidents")
            return action_result.set_status(phantom.APP_SUCCESS, "Did not get any new Incidents")

        incident_len = len(incident_ids)

        self.save_progress("Got {0} incidents".format(incident_len))

        incident_count = 0
        queried_incident_details = []
        last_inc_id = self._state.get(DLP_JSON_LAST_INCIDENT_ID, -1)

        for curr_incident_id in incident_ids:

            ret_val, incident_detail = self._get_incident_details(action_result, curr_incident_id, config[DLP_JSON_EXTRACT_COMPONENTS])

            if phantom.is_fail(ret_val):
                return ret_val

            self._cleanse_key_names(incident_detail)

            if not self.is_poll_now() and int(incident_detail['incident']['incidentId']) <= last_inc_id:
                continue

            incident_count += 1
            queried_incident_details.append(incident_detail)

            if incident_count == max_containers:
                break

        if not self.is_poll_now():
            self._state[DLP_JSON_LAST_DATE_TIME] = incident_detail['incident']['incidentCreationDate']
            self._state[DLP_JSON_LAST_INCIDENT_ID] = int(incident_detail['incident']['incidentId'])

        try:
            results = pi.parse_incidents(queried_incident_details, self)
        except Exception as e:
            self.debug_print("The incidents parser script threw an exception", e)
            return action_result.set_status(phantom.APP_ERROR, "The incident parser script ran into an error, please see the logs for the complete stack trace")

        no_of_containers = len(results)

        self.save_progress("Parsed incidents into {0} containers".format(no_of_containers))

        self._parse_results(action_result, param, results)

        # blank line to update the last status message
        self.send_progress('')

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        action = self.get_action_identifier()
        ret_val = phantom.APP_SUCCESS

        if action == self.ACTION_ID_TEST_CONNECTIVITY:
            ret_val = self._test_connectivity(param)
        elif action == self.ACTION_ID_UPDATE_INCIDENT:
            ret_val = self._handle_update_incident(param)
        elif action == self.ACTION_ID_ON_POLL:
            ret_val = self._on_poll(param)

        return ret_val


if __name__ == '__main__':

    import sys
    # import pudb
    import argparse

    # pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print "Accessing the Login page"
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print "Logging into Platform to get the session id"
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print "Unable to get session id from the platfrom. Error: " + str(e)
            exit(1)

    if len(sys.argv) < 2:
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print json.dumps(in_json, indent=4)

        connector = SymantecDLPConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print json.dumps(json.loads(ret_val), indent=4)

    exit(0)
