# --
# File: symantecdlp_connector.py
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

# Phantom imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# THIS Connector imports
from symantecdlp_consts import *
import dlp_soap

import requests
import json
import xmltodict
import re
from bs4 import BeautifulSoup
from datetime import datetime
from datetime import timedelta
import parse_incidents as pi
import hashlib
import os
import magic
import inspect

requests.packages.urllib3.disable_warnings()


class RetVal(tuple):
    def __new__(cls, status, data):
        return tuple.__new__(RetVal, (status, data))


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

    ACTION_ID_TEST_ASSET_CONNECTIVITY = "test_connectivity"
    ACTION_ID_ON_POLL = "on_poll"

    def __init__(self):

        # Call the BaseConnectors init first
        super(SymantecDLPConnector, self).__init__()

        self._base_url = None

        self._state = {}

        self._session = None

    def initialize(self):
        '''
        Initializes the authentication tuple that the REST call needs

        :return:
        '''
        config = self.get_config()

        self._auth = (config[DLP_JSON_USERNAME], config[DLP_JSON_PASSWORD])

        base_url = config[DLP_JSON_URL].strip('/')
        self._base_url = "{0}/ProtectManager/services/v2011".format(base_url)

        self._session = requests.Session()

        self._load_state()

        return phantom.APP_SUCCESS

    def _load_state(self):

        # get the directory of the class
        dirpath = os.path.dirname(inspect.getfile(self.__class__))
        asset_id = self.get_asset_id()
        self._state_file_path = "{0}/{1}_serialized_data.json".format(dirpath, asset_id)
        try:
            with open(self._state_file_path, 'r') as f:
                in_json = f.read()
                self._state = json.loads(in_json)
        except Exception as e:
            self.debug_print("In _load_state: Exception: {0}".format(str(e)))
            pass
        self.debug_print("Loaded state: ", self._state)
        return phantom.APP_SUCCESS

    def _save_state(self):

        self.debug_print("Saving state: ", self._state)
        if (not self._state_file_path):
            self.debug_print("_state_file_path is None in _save_state")
            return phantom.APP_SUCCESS
        try:
            with open(self._state_file_path, 'w+') as f:
                f.write(json.dumps(self._state))
        except Exception as e:
            self.debug_print("Exception in _save_state", e)
            pass
        return phantom.APP_SUCCESS

    def finalize(self):
        self._save_state()
        return phantom.APP_SUCCESS

    def _cleanse_key_names(self, input_dict):

        if (not input_dict):
            return input_dict

        for k, v in input_dict.items():
            if (k.find(':') != -1):
                new_key = k.replace(':', '_')
                input_dict[new_key] = v
                del input_dict[k]
            if (type(v) == dict):
                input_dict[new_key] = self._cleanse_key_names(v)
            if (type(v) == list):

                new_v = []

                for curr_v in v:
                    new_v.append(self._cleanse_key_names(curr_v))

                input_dict[new_key] = new_v

        return input_dict

    def _clean_xml(self, input_xml):

        # MS is known to send invalid xml chars, that it's own msxml library deems as invalid,
        # SYMC might be using MS libs, not taking any chances here
        # https://support.microsoft.com/en-us/kb/315580
        replace_regex = r"&#x([0-8]|[b-cB-C]|[e-fE-F]|1[0-9]|1[a-fA-F]);"
        clean_xml, number_of_substitutes = re.subn(replace_regex, '', input_xml)

        self.debug_print("Cleaned xml with {0} substitutions".format(number_of_substitutes))

        return clean_xml

    def _get_http_error_details(self, r):

        if ('text/xml' in r.headers.get('Content-Type', '')):

            # Try a xmltodict parse
            try:
                resp_json = xmltodict.parse(self._clean_xml(r.text))

                # convert from OrderedDict to plain dict
                resp_json = json.loads(json.dumps(resp_json))
            except Exception as e:
                self.debug_print("Handled Exp", e)
                return "Unable to parse error details"

            try:
                return resp_json['S:Envelope']['S:Body']['S:Fault']['faultstring'].replace('{', '"').replace('}', '"')
            except:
                pass
        elif('text/html' in r.headers.get('Content-Type', '')):

            # Try BeautifulSoup
            try:
                soup = BeautifulSoup(r.text, 'html.parser')
                return soup.text
            except:
                pass

        return ""

    def _get_response_result(self, action_result, resp_json, func_call, result_name=None):

        if (not func_call):
            return resp_json

        response_key = 'ns5:{0}Response'.format(func_call)
        # get the response that is part of the body
        try:
            response = resp_json['S:Envelope']['S:Body'][response_key]
        except:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Response dictionary does not contain the '{0}' key".format(response_key)), resp_json)

        # Now check if the result_key is present
        if (result_name is None):
            # it's not, meaning the response is what the caller is interested in
            return RetVal(phantom.APP_SUCCESS, response)

        result_key = 'ns5:{0}'.format(result_name)

        # now get the result, the key name could be one of the two possibiliteis
        response_result = response.get(result_key)

        if (not response_result):
            return RetVal(action_result.set_status(phantom.APP_SUCCESS, "Response dictionary does not contain the result key"), None)

        return RetVal(phantom.APP_SUCCESS, response_result)

    def _make_rest_call(self, endpoint, result, data={}, func_call=None, result_key=None):
        """ Will query the endpoint, parses the response and returns status and data,
        BEWARE data can be None"""

        # Get the config
        config = self.get_config()

        resp_json = None

        data = dlp_soap.add_to_envelope(data)

        data = dlp_soap.get_string(data)

        self.debug_print(data)

        url = "{0}{1}".format(self._base_url, endpoint)

        # Make the call
        try:
            r = self._session.post(url, data=data, auth=self._auth, verify=config[DLP_JSON_VERIFY_SERVER_CERT])
        except Exception as e:
            return RetVal(result.set_status(phantom.APP_ERROR, DLP_ERR_SERVER_CONNECTION, e), resp_json)

        if (hasattr(result, 'add_debug_data')):
            result.add_debug_data({'r_text': r.text if r else 'r is None'})

        if (not (200 <= r.status_code <= 399)):
            # error
            detail = self._get_http_error_details(r)
            return RetVal(result.set_status(phantom.APP_ERROR,
                "Call failed with HTTP Code: {0}. Reason: {1}. Details: {2}".format(r.status_code, r.reason, detail)), None)

        # Try a xmltodict parse
        try:
            resp_json = xmltodict.parse(self._clean_xml(r.text))

            # convert from OrderedDict to plain dict
            resp_json = json.loads(json.dumps(resp_json))
        except Exception as e:
            # r.text is guaranteed to be NON None, it will be empty, but not None
            msg_string = DLP_ERR_JSON_PARSE.format(raw_text=r.text)
            return RetVal(result.set_status(phantom.APP_ERROR, msg_string, e), resp_json)

        # Now try getting the response message

        ret_val, resp_message = self._get_response_result(result, resp_json, func_call, result_key)

        if (phantom.is_fail(ret_val)):
            msg_string = DLP_ERR_JSON_PARSE.format(raw_text=r.text)
            return RetVal(result.set_status(phantom.APP_ERROR, msg_string), resp_json)

        return RetVal(phantom.APP_SUCCESS, resp_message)

    def _test_connectivity(self, param):
        """ Function that handles the test connectivity action, it is much simpler than other action handlers.
        """

        action_result = ActionResult(param)

        config = self.get_config()

        input_xml = dlp_soap.xml_get_incident_list(config[DLP_JSON_REPORT_ID], '0001-01-01T00:00:00')

        self.save_progress("Querying incident ids to test connectivity")
        ret_val, resp_json = self._make_rest_call('/incidents?wsdl', action_result, input_xml,
                func_call='incidentList', result_key='incidentLongId')

        if (phantom.is_fail(ret_val)):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, "Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Successful")

        return self.set_status(phantom.APP_SUCCESS, "Test Connectivity Successful")

    def _get_incident_ids(self, action_result, report_id, date_string):

        input_xml = dlp_soap.xml_get_incident_list(report_id, date_string)

        ret_val, incident_ids = self._make_rest_call('/incidents?wsdl', action_result, input_xml,
                func_call='incidentList', result_key='incidentLongId')

        if (phantom.is_fail(ret_val)):
            return RetVal(action_result.get_status(), None)

        return RetVal(phantom.APP_SUCCESS, incident_ids)

    def _get_incident_details(self, action_result, incident_id, extract_files):

        input_xml = dlp_soap.xml_get_incident_details(incident_id)

        ret_val, response = self._make_rest_call('/incidents?wsdl', action_result, input_xml, func_call='incidentDetail', result_key='response')

        if (phantom.is_fail(ret_val)):
            return RetVal(action_result.get_status(), None)

        if (not response):
            return action_result.set_status(phantom.APP_ERROR, "Got empty or None incident response")

        status_code = response.get('ns5:statusCode')

        if (status_code is not None) and (status_code.lower() != 'success'):
            return RetVal(action_result.set_status(phantom.APP_ERROR, status_code), None)

        incident_details = response.get('ns5:incident')

        if (not incident_details):
            return action_result.set_status(phantom.APP_ERROR, "Incident details returned were empty or None")

        if (not extract_files):
            return RetVal(phantom.APP_SUCCESS, incident_details)

        # Try to extract all files
        input_xml = dlp_soap.xml_get_incident_binaries(incident_id)

        ret_val, response = self._make_rest_call('/incidents?wsdl', action_result, input_xml, func_call='incidentBinaries', result_key=None)

        if (phantom.is_fail(ret_val)):
            return RetVal(action_result.get_status(), None)

        if (not response):
            return action_result.set_status(phantom.APP_ERROR, "Got empty or None incident response for files")

        status_code = response.get('ns5:statusCode')

        if (status_code is not None) and (status_code.lower() != 'success'):
            return RetVal(action_result.set_status(phantom.APP_ERROR, status_code), None)

        ns5_component = response.get('ns5_Component')
        if (type(ns5_component) != list):
            response['ns5_Component'] = ns5_component

        incident_details['components'] = response

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

    def _handle_file(self, curr_file, vault_ids, container_id, artifact_id):

        file_name = curr_file.get('file_name')

        local_file_path = curr_file['file_path']

        contains = self._get_file_contains(local_file_path)

        # lets move the data into the vault
        vault_attach_dict = {}

        if (not file_name):
            file_name = os.path.basename(local_file_path)

        self.debug_print("Vault file name: {0}".format(file_name))

        vault_attach_dict[phantom.APP_JSON_ACTION_NAME] = self.get_action_name()
        vault_attach_dict[phantom.APP_JSON_APP_RUN_ID] = self.get_app_run_id()

        vault_ret = {}

        try:
            vault_ret = Vault.add_attachment(local_file_path, container_id, file_name, vault_attach_dict)
        except Exception as e:
            self.debug_print(phantom.APP_ERR_FILE_ADD_TO_VAULT.format(e))
            return (phantom.APP_ERROR, phantom.APP_ERROR)

        # self.debug_print("vault_ret_dict", vault_ret_dict)

        if (not vault_ret.get('succeeded')):
            self.debug_print("Failed to add file to Vault: {0}".format(json.dumps(vault_ret)))
            return (phantom.APP_ERROR, phantom.APP_ERROR)

        # add the vault id artifact to the container
        cef_artifact = {}
        if (file_name):
            cef_artifact.update({'fileName': file_name})
        if (phantom.APP_JSON_HASH in vault_ret):
            cef_artifact.update({'vaultId': vault_ret[phantom.APP_JSON_HASH]})

        if (not cef_artifact):
            return (phantom.APP_SUCCESS, phantom.APP_ERROR)

        artifact = {}
        artifact.update(pi.artifact_common)
        artifact['container_id'] = container_id
        artifact['name'] = 'Vault Artifact'
        artifact['cef'] = cef_artifact
        if (contains):
            artifact['cef_types'] = {'vaultId': contains}
        self._set_sdi(artifact_id, artifact)

        ret_val, status_string, artifact_id = self.save_artifact(artifact)
        self.debug_print("save_artifact returns, value: {0}, reason: {1}, id: {2}".format(ret_val, status_string, artifact_id))

        return (phantom.APP_SUCCESS, ret_val)

    def _set_sdi(self, default_id, input_dict):

        if ('source_data_identifier' in input_dict):
            del input_dict['source_data_identifier']

        input_dict['source_data_identifier'] = self._create_dict_hash(input_dict)

        return phantom.APP_SUCCESS

    def _create_dict_hash(self, input_dict):

        input_dict_str = None

        if (not input_dict):
            return None

        try:
            input_dict_str = json.dumps(input_dict, sort_keys=True)
        except Exception as e:
            self.debug_print('Handled exception in _create_dict_hash', e)
            return None

        return hashlib.md5(input_dict_str).hexdigest()

    def _parse_results(self, action_result, param, results):

        container_count = DLP_DEFAULT_CONTAINER_COUNT

        if (param):
            container_count = param.get(phantom.APP_JSON_CONTAINER_COUNT, DLP_DEFAULT_CONTAINER_COUNT)

        results = results[:container_count]

        for i, result in enumerate(results):

            container = result.get('container')

            if (not container):
                continue

            self.send_progress("Saving Container # {0}".format(i + 1))

            try:
                (ret_val, message, container_id) = self.save_container(container)
            except Exception as e:
                self.debug_print("Handled Exception while saving container", e)
                continue

            self.debug_print("save_container returns, value: {0}, reason: {1}, id: {2}".format(ret_val, message, container_id))

            if (phantom.is_fail(ret_val)):
                message = "Failed to add Container for id: {0}, error msg: {1}".format(container['source_data_identifier'], message)
                self.debug_print(message)
                continue

            if (not container_id):
                message = "save_container did not return a container_id"
                self.debug_print(message)
                continue

            files = result.get('files')

            vault_ids = list()

            vault_artifacts_added = 0

            for curr_file in files:
                ret_val, added_to_vault = self._handle_file(curr_file, vault_ids, container_id, vault_artifacts_added)

                if (added_to_vault):
                    vault_artifacts_added += 1

            artifacts = result.get('artifacts')
            if (not artifacts):
                continue

            len_artifacts = len(artifacts)

            for j, artifact in enumerate(artifacts):

                if (not artifact):
                    continue

                # add the container id to the artifact
                artifact['container_id'] = container_id
                self._set_sdi((j + vault_artifacts_added), artifact)

                # if it is the last artifact of the last container
                if ((j + 1) == len_artifacts):
                    # mark it such that active playbooks get executed
                    artifact['run_automation'] = True

                ret_val, status_string, artifact_id = self.save_artifact(artifact)
                self.debug_print("save_artifact returns, value: {0}, reason: {1}, id: {2}".format(ret_val, status_string, artifact_id))

        return self.set_status(phantom.APP_SUCCESS)

    def _get_time_string(self):

        # function to separate on poll and poll now
        config = self.get_config()
        last_time = self._state.get(DLP_JSON_LAST_DATE_TIME)

        if self.is_poll_now():
            dt_diff = datetime.utcnow() - timedelta(days=int(config[DLP_JSON_POLL_NOW_DAYS]))
            time_string = dt_diff.strftime("%Y-%m-%dT%H:%M:%S.000")
            return time_string
        elif (self._state.get('first_run', True)):
            self._state['first_run'] = False
            dt_diff = datetime.utcnow() - timedelta(days=int(config[DLP_JSON_SCHEDULED_POLL_DAYS]))
            time_string = dt_diff.strftime("%Y-%m-%dT%H:%M:%S.000")
            return time_string
        elif (last_time):
            return last_time

        # treat it as the same days past as first run
        dt_diff = datetime.utcnow() - timedelta(days=int(config[DLP_JSON_SCHEDULED_POLL_DAYS]))
        time_string = dt_diff.strftime("%Y-%m-%dT%H:%M:%S.000")
        return time_string

    def _on_poll(self, param):

        # Get the maximum number of emails that we can pull, same as container count
        try:
            max_containers = int(param[phantom.APP_JSON_CONTAINER_COUNT])
        except:
            return self.set_status(phantom.APP_ERROR, "Invalid Container count")

        config = self.get_config()

        time_string = self._get_time_string()

        self.save_progress("Getting incident IDs generated since {0}".format(time_string))

        action_result = self.add_action_result(ActionResult(param))

        config = self.get_config()

        incident_ids = []

        # get the number of incidents
        ret_val, incident_ids = self._get_incident_ids(action_result, config[DLP_JSON_REPORT_ID], time_string)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if (not incident_ids):
            self.save_progress("Did not get any new Incidents")
            return action_result.set_status(phantom.APP_SUCCESS, "Did not get any new Incidents")

        incident_len = len(incident_ids)

        self.save_progress("Got {0} incidents".format(incident_len))

        if (max_containers < incident_len):
            self.save_progress("Will trim ingested incidents to {0}".format(max_containers))
            incident_ids.sort(key=int)
            incident_ids = incident_ids[-(max_containers)]

        queried_incident_details = []

        for curr_incident_id in incident_ids:

            action_result = ActionResult()
            ret_val, incident_detail = self._get_incident_details(action_result, curr_incident_id, config[DLP_JSON_EXTRACT_COMPONENTS])

            if (phantom.is_fail(ret_val)):
                continue

            self._cleanse_key_names(incident_detail)
            incident_detail['@xsi_type'] = incident_detail['@xsi_type'].lstrip('ns5:')
            queried_incident_details.append(incident_detail)

            if (not self.is_poll_now()):
                self._state[DLP_JSON_LAST_DATE_TIME] = incident_detail['ns5_incidentCreationDate']

        try:
            results = pi.parse_incidents(queried_incident_details, self)
        except Exception as e:
            self.debug_print("The incidents parser script threw an exception", e)
            return action_result.set_status(phantom.APP_ERROR, "The incident parser script ran into an error, please see the logs for the complete stack trace")

        no_of_containers = len(results)

        self.save_progress("Parsed incidents into {0} containers".format(no_of_containers))

        self._parse_results(action_result, param, results)

        # black line to update the last status message
        self.send_progress('')

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        action = self.get_action_identifier()
        ret_val = phantom.APP_SUCCESS

        if (action == self.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)
        elif (action == self.ACTION_ID_ON_POLL):
            ret_val = self._on_poll(param)

        return ret_val


if __name__ == '__main__':
    # Imports
    import sys
    import pudb

    # Breakpoint at runtime
    pudb.set_trace()

    # The first param is the input json file
    with open(sys.argv[1]) as f:
        # Load the input json file
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        # Create the connector class object
        connector = SymantecDLPConnector()

        # Se the member vars
        connector.print_progress_message = True

        # Call BaseConnector::_handle_action(...) to kickoff action handling.
        ret_val = connector._handle_action(json.dumps(in_json), None)

        # Dump the return value
        print ret_val

    exit(0)
