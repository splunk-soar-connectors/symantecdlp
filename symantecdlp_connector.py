# File: symantecdlp_connector.py
#
# Copyright (c) 2018-2022 Splunk Inc.
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
#
#
# Phantom imports
import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timedelta

import magic
import phantom.app as phantom
import phantom.rules as phantom_rules
import requests
from bs4 import UnicodeDammit
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from pytz import timezone, utc
from requests.auth import AuthBase, HTTPBasicAuth
from zeep import Client, Settings, helpers
from zeep.transports import Transport

import parse_incidents as pi
# THIS Connector imports
from symantecdlp_consts import *


class RetVal(tuple):
    def __new__(cls, status, data=None):
        return tuple.__new__(RetVal, (status, data))


class SymantecAuth(AuthBase):
    def __init__(self, username, password, host):
        self.basic = HTTPBasicAuth(username, password)
        self.host = host

    def __call__(self, r):
        if r.url.startswith(self.host):
            return self.basic(r)
        else:
            return r


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
    ACTION_ID_LIST_INCIDENTS = "list_incidents"
    ACTION_ID_GET_INCIDENT = "get_incident"
    ACTION_ID_ON_POLL = "on_poll"

    def __init__(self):

        # Call the BaseConnectors init first
        super(SymantecDLPConnector, self).__init__()

        self._base_url = None
        self._session = None
        self._client = None
        self._report_id = None
        self._poll_now_days = None
        self._schedule_poll_days = None
        self._max_containers = None
        self._custom_severity = None
        self._severity = None
        self._state = {}

    def initialize(self):

        config = self.get_config()
        self._state = self.load_state()
        self._verify = config[DLP_JSON_VERIFY_SERVER_CERT]

        self._severity = DLP_SEVERITY_DICT
        self._report_id = self._validate_integers(self, config[DLP_JSON_REPORT_ID], DLP_JSON_REPORT_ID, True)
        if self._report_id is None:
            return self.get_status()

        self._poll_now_days = self._validate_integers(self, config.get(DLP_JSON_POLL_NOW_DAYS, 15), DLP_JSON_POLL_NOW_DAYS)
        if self._poll_now_days is None:
            return self.get_status()

        self._schedule_poll_days = self._validate_integers(self, config.get(DLP_JSON_SCHEDULED_POLL_DAYS, 10), DLP_JSON_SCHEDULED_POLL_DAYS)
        if self._schedule_poll_days is None:
            return self.get_status()

        self._max_containers = self._validate_integers(self, config.get('max_containers', 10), 'max_containers')
        if self._max_containers is None:
            return self.get_status()

        self._base_url = "{0}/ProtectManager/services/v2011/incidents?wsdl".format(config[DLP_JSON_URL].strip('/'))
        self._proxy = {}
        env_vars = config.get('_reserved_environment_variables', {})
        if 'HTTP_PROXY' in env_vars:
            self._proxy['http'] = env_vars['HTTP_PROXY']['value']
        if 'HTTPS_PROXY' in env_vars:
            self._proxy['https'] = env_vars['HTTPS_PROXY']['value']

        self._session = requests.Session()
        self._session.auth = SymantecAuth(config[DLP_JSON_USERNAME],
                                    config[DLP_JSON_PASSWORD],
                                    config[DLP_JSON_URL].strip('/'))

        if self._proxy:
            self._session.proxies.update(self._proxy)

        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _create_client(self, action_result):

        try:
            if not self._verify:
                self._session.verify = False
                os.environ.pop('REQUESTS_CA_BUNDLE', None)
                os.environ.pop('CURL_CA_BUNDLE', None)

            transport = Transport(session=self._session)
            settings = Settings(strict=False)

            self._client = Client(wsdl=self._base_url, transport=transport, settings=settings)
            return phantom.APP_SUCCESS

        except Exception as e:
            return action_result.set_status(
                phantom.APP_ERROR,
                'Could not connect to the DLP API endpoint : {}' .format(self._get_error_message_from_exception(e))
            )

    def _validate_integers(self, action_result, parameter, key, allow_zero=False):
        """ This method is to check if the provided input parameter value
        is a non-zero positive integer and returns the integer value of the parameter itself.
        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :return: integer value of the parameter or None in case of failure
        """

        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    action_result.set_status(phantom.APP_ERROR, DLP_VALIDATE_INTEGER_MESSAGE.format(key=key))
                    return None
                parameter = int(parameter)

            except Exception as e:
                self.debug_print('Exception occurred in _validate_integers: {}'.format(self._get_error_message_from_exception(e)))
                action_result.set_status(phantom.APP_ERROR, DLP_VALIDATE_INTEGER_MESSAGE.format(key=key))
                return None

            if parameter < 0:
                action_result.set_status(phantom.APP_ERROR, "Please provide a valid non-negative integer value in the {} parameter".format(key))
                return None
            if not allow_zero and parameter == 0:
                action_result.set_status(phantom.APP_ERROR, "Please provide non-zero positive integer in {} parameter".format(key))
                return None

        return parameter

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_msg = DLP_ERR_MESSAGE
        error_code = DLP_ERR_CODE_MESSAGE
        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = DLP_ERR_CODE_MESSAGE
                    error_msg = e.args[0]
        except:
            pass

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _cleanse_key_names(self, input_dict):

        if not input_dict:
            return input_dict

        for k in list(input_dict.keys()):

            new_k = k
            v = input_dict[k]

            if k.startswith('_'):
                new_k = k.strip('_')
                input_dict[new_k] = v
                input_dict.pop(k)

            if isinstance(v, dict):
                input_dict[new_k] = self._cleanse_key_names(v)

            elif isinstance(v, list):
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
            return action_result.get_status()

        self.save_progress("Querying incident IDs to test connectivity")
        try:
            _ = self._client.service.incidentList(self._report_id, '0001-01-01T00:00:00')
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            self.debug_print('Error occurred in test connectivity: {}'.format(error_message))
            return action_result.set_status(phantom.APP_ERROR, "Test Connectivity Failed: {}".format(error_message))

        self.save_progress("Test Connectivity Successful")

        return action_result.set_status(phantom.APP_SUCCESS, "Test Connectivity Successful")

    def _handle_update_incident(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # create zeep client
        ret_val = self._create_client(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # required field, even though it is not used by DLP
        batch_id = uuid.uuid4()
        incident_id = self._validate_integers(action_result, param[DLP_JSON_INCIDENT_ID], DLP_JSON_INCIDENT_ID)

        if incident_id is None:
            return action_result.get_status()

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
            except Exception as e:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "custom_fields must be a JSON string.\r\nError: {}".format(self._get_error_message_from_exception(e))
                )

            custom_fields = [
                {'name': key, 'value': value} for key, value in list(custom_fields.items())
            ]

            update_request['incidentAttributes']['customAttribute'] = custom_fields

        if len(update_request['incidentAttributes']) == 0:
            return action_result.set_status(
                phantom.APP_ERROR,
                'Unable to update the incident. Please provide value in at least one parameter to update the incident.'
            )

        try:
            response = self._client.service.updateIncidents(update_request)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, 'SOAP call to DLP failed : {}'.format(self._get_error_message_from_exception(e)))

        if not response:
            return action_result.set_status(phantom.APP_ERROR, "Response was empty")

        dict_response = self._zeep_to_dict(response)

        if dict_response[0]['statusCode'] != 'SUCCESS':
            return action_result.set_status(
                phantom.APP_ERROR,
                'Unable to update the incident. Please check the value provided to update the incident.'
            )

        action_result.update_data(dict_response)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated incident")

    def _handle_list_incidents(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # create zeep client
        ret_val = self._create_client(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        report_id = self._validate_integers(action_result, param[DLP_JSON_REPORT_ID], DLP_JSON_REPORT_ID)

        if report_id is None:
            return action_result.get_status()

        creation_time_after = param[DLP_JSON_CREATION_TIME]

        date_status = self._validate_date(creation_time_after)
        if not date_status:
            return action_result.set_status(phantom.APP_ERROR, DLP_TIMESTAMP_VALIDATION_FAILED_MSG)

        try:
            response = self._client.service.incidentList(report_id, creation_time_after)
        except Exception as e:
            message = 'SOAP call to DLP failed. {}'.format(self._get_error_message_from_exception(e))
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Occurred: {}".format(message)))

        resp_dict = self._zeep_to_dict(response)
        incident_ids = resp_dict.get('incidentLongId')

        for incident_id in incident_ids:
            data = action_result.add_data({})
            data[DLP_JSON_INCIDENT_ID] = incident_id

        summary = action_result.update_summary({})
        summary[DLP_JSON_TOTAL_INCIDENTS] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _validate_date(self, date_timestamp):
        """ This function is used to validate date timestamp as per YYYY-MM-DD format or valid ISO 8601 format.

        :param date_timestamp: Value of the date timestamp
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        regex = r'^(-?(?:[1-9][0-9]*)?[0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])T(2[0-3]|[01][0-9]):' \
                r'([0-5][0-9]):([0-5][0-9])(\.[0-9]+)?(Z|[+-](?:2[0-3]|[01][0-9]):[0-5][0-9])?$'

        match_iso8601 = re.compile(regex).match
        try:
            if match_iso8601(date_timestamp) is not None:
                return phantom.APP_SUCCESS
            elif datetime.strptime(date_timestamp, '%Y-%m-%d'):
                return phantom.APP_SUCCESS
        except Exception:
            return phantom.APP_ERROR

        return phantom.APP_ERROR

    def _handle_get_incident(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # create zeep client
        ret_val = self._create_client(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        config = self.get_config()
        if param.get(DLP_JSON_INCIDENT_LONG_ID) is None and param.get(DLP_JSON_INCIDENT_ID) is None:
            return action_result.set_status(
                phantom.APP_ERROR,
                'Please provide a value for at least one of the parameters incident_long_id or incident_id.'
            )

        incident_long_id = self._validate_integers(action_result, param.get(DLP_JSON_INCIDENT_LONG_ID), DLP_JSON_INCIDENT_LONG_ID)

        if param.get(DLP_JSON_INCIDENT_LONG_ID) is not None and incident_long_id is None:
            return action_result.get_status()

        incident_id = self._validate_integers(action_result, param.get(DLP_JSON_INCIDENT_ID), DLP_JSON_INCIDENT_ID)

        if param.get(DLP_JSON_INCIDENT_ID) is not None and incident_id is None:
            return action_result.get_status()

        if incident_long_id is not None and incident_id is not None:
            return action_result.set_status(
                phantom.APP_ERROR,
                'Please specify only one of the following parameters: incident_long_id or incident_id.'
            )

        include_violations = param.get(DLP_JSON_INCLUDE_VIOLATIONS)
        include_history = param.get(DLP_JSON_INCLUDE_HISTORY)
        ret_val, incident_detail = self._get_incident_details(
            action_result, incident_id, incident_long_id, config[DLP_JSON_EXTRACT_COMPONENTS], include_violations, include_history
        )

        if phantom.is_fail(ret_val):
            return action_result.set_status(
                phantom.APP_ERROR,
                'Unable to fatch the incident. Please check the value provided to fatch the incident.'
            )
        else:
            message = "The incident has been retrieved successfully"

        action_result.add_data(incident_detail)

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _get_incident_ids(self, action_result, report_id, date_string):

        try:
            response = self._client.service.incidentList(report_id, date_string)
        except Exception as e:
            message = 'SOAP call to DLP failed. {}'.format(self._get_error_message_from_exception(e))
            return RetVal(action_result.set_status(phantom.APP_ERROR, "On poll Failed: {}".format(message)))

        resp_dict = self._zeep_to_dict(response)

        return RetVal(phantom.APP_SUCCESS, resp_dict.get('incidentLongId'))

    def _sanitize_dict(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime(DLP_TIME_FORMAT)
        elif isinstance(obj, str):
            return obj.replace('\u0000', '')
        elif isinstance(obj, list):
            return [self._sanitize_dict(item) for item in obj]
        elif isinstance(obj, dict):
            return {k: self._sanitize_dict(v) for k, v in obj.items()}
        elif isinstance(obj, bytes):
            return UnicodeDammit(obj).unicode_markup
        return obj

    def _zeep_to_dict(self, resp):
        response = helpers.serialize_object(resp, dict)
        response = self._sanitize_dict(response)
        return response

    def _get_incident_details(self, action_result, incident_id, incident_long_id, extract_files, includeViolations, includeHistory):

        binary_incident_id = incident_id
        kwargs = dict()
        if incident_long_id is not None:
            kwargs['incidentLongId'] = incident_long_id
            binary_incident_id = incident_long_id
        else:
            kwargs['incidentId'] = incident_id
        try:
            response = self._client.service.incidentDetail(includeViolations=includeViolations, includeHistory=includeHistory, **kwargs)
        except Exception as e:
            message = 'SOAP call to DLP failed. {}'.format(self._get_error_message_from_exception(e))
            return RetVal(action_result.set_status(phantom.APP_ERROR, message))

        if not response:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Incident response returned was empty or None"))

        resp_dict = self._zeep_to_dict(response)

        try:
            incident_details = resp_dict[0]
        except Exception as e:
            return RetVal(action_result.set_status(
                phantom.APP_ERROR,
                "Could not get incident details: {0}".format(self._get_error_message_from_exception(e)))
            )

        if not incident_details:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Incident details returned were empty or None"))

        incident_type = response[0].incident.__class__.__name__
        incident_details['incidentType'] = incident_type

        if not extract_files:
            return RetVal(phantom.APP_SUCCESS, incident_details)

        try:
            response = self._client.service.incidentBinaries(binary_incident_id, False, True)
        except Exception as e:
            message = 'SOAP call to DLP failed. {}'.format(self._get_error_message_from_exception(e))
            return RetVal(action_result.set_status(phantom.APP_ERROR, message))

        if not response:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Got empty or None incident response for files"))

        resp_dict = self._zeep_to_dict(response)

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

    def _handle_file(self, curr_file, vault_ids, container_id, container_severity, artifact_id, is_last):

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

        try:
            success, message, vault_id = phantom_rules.vault_add(
                file_location=local_file_path, container=container_id, file_name=file_name, metadata=vault_attach_dict
            )
        except Exception as e:
            self.debug_print(phantom.APP_ERR_FILE_ADD_TO_VAULT.format(self._get_error_message_from_exception(e)))
            return phantom.APP_ERROR, phantom.APP_ERROR

        if not success:
            self.debug_print("Failed to add file to Vault: {0}".format(message))
            return phantom.APP_ERROR, phantom.APP_ERROR

        # add the vault id artifact to the container
        cef_artifact = {}
        if file_name:
            cef_artifact.update({'fileName': file_name})
        if vault_id:
            cef_artifact.update({'vaultId': vault_id})

        if not cef_artifact:
            return phantom.APP_SUCCESS, phantom.APP_ERROR

        artifact = {}
        artifact.update(pi.artifact_common)
        artifact['container_id'] = container_id
        artifact['severity'] = container_severity
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

    def _get_fips_enabled(self):
        try:
            from phantom_common.install_info import is_fips_enabled
        except ImportError:
            return False

        fips_enabled = is_fips_enabled()
        if fips_enabled:
            self.debug_print('FIPS is enabled')
        else:
            self.debug_print('FIPS is not enabled')
        return fips_enabled

    def _create_dict_hash(self, input_dict):

        input_dict_str = None

        if not input_dict:
            return None

        try:
            input_dict_str = json.dumps(input_dict, sort_keys=True)
        except Exception as e:
            self.debug_print('Handled exception in _create_dict_hash', e)
            return None

        if isinstance(input_dict_str, str):
            input_dict_str = input_dict_str.encode('utf-8')

        fips_enabled = self._get_fips_enabled()
        # if fips is not enabled, we should continue with our existing md5 usage for generating hashes
        # to not impact existing customers
        if not fips_enabled:
            dict_hash = hashlib.md5(input_dict_str)
        else:
            dict_hash = hashlib.sha256(input_dict_str)
        return dict_hash.hexdigest()

    def _parse_results(self, action_result, param, results):

        container_count = self._max_containers

        if param:
            container_count = param.get(phantom.APP_JSON_CONTAINER_COUNT, self._max_containers)

        results = results[:container_count]

        for i, result in enumerate(results):

            container = result.get('container')
            files = result.get('files', [])

            if not container:
                self.save_progress("no container")
                continue

            artifacts = container.pop('artifacts', [])
            len_artifacts = len(artifacts)

            for j, artifact in enumerate(artifacts):

                if not artifact:
                    continue

                self._set_sdi(j, artifact)

                # if it is the last artifact of the last container
                if not files and (j + 1) == len_artifacts:
                    # mark it such that active playbooks get executed
                    artifact['run_automation'] = True

            self.send_progress("Saving Container # {0}".format(i + 1))

            try:
                container = self._sanitize_dict(container)
                ret_val, message, container_id = self.save_container(container)

                if phantom.is_fail(ret_val):
                    message = "Failed to add Container for id: {0}, error msg: {1}".format(container['source_data_identifier'], message)
                    self.debug_print(message)
                    continue

                if not container_id:
                    message = "save_container did not return a container_id"
                    self.debug_print(message)
                    continue

                for artifact in artifacts:
                    artifact['container_id'] = container_id
                    artifact['severity'] = container.get('severity', 'medium')
                if artifacts:
                    ret_val, artifact_message, ids = self.save_artifacts(artifacts)

                    if phantom.is_fail(ret_val):
                        message = "Failed to add Artifact for container_id: {0}, error msg: {1}".format(container_id, artifact_message)
                        self.debug_print(message)
                        continue

            except Exception as e:
                self.debug_print("Handled Exception while saving container: {}".format(self._get_error_message_from_exception(e)))
                continue

            self.debug_print("save_container returns, value: {0}, reason: {1}, id: {2}".format(ret_val, message, container_id))

            vault_ids = list()
            len_files = len(files)
            count = len_artifacts
            container_severity = container.get('severity', 'medium')
            for curr_file in files:
                count += 1
                ret_val, added_to_vault = self._handle_file(
                    curr_file, vault_ids, container_id, container_severity, count, count == len_artifacts + len_files
                )

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_time_string(self):

        # function to separate on poll and poll now
        config = self.get_config()
        last_time = self._state.get(DLP_JSON_LAST_DATE_TIME)

        if self.is_poll_now():
            dt_diff = datetime.utcnow() - timedelta(days=self._poll_now_days)
        elif self._state.get('first_run', True):
            self._state['first_run'] = False
            dt_diff = datetime.utcnow() - timedelta(days=self._schedule_poll_days)
        elif last_time:
            return '{0}:{1}'.format(last_time[:-2], last_time[-2:])
        else:
            dt_diff = datetime.utcnow() - timedelta(days=self._schedule_poll_days)

        # get the device timezone
        device_tz_sting = config[DLP_JSON_TIMEZONE]
        to_tz = timezone(device_tz_sting)

        # convert datetime to device timezone
        dt_diff = dt_diff.replace(tzinfo=utc)
        to_dt = to_tz.normalize(dt_diff.astimezone(to_tz))

        time_str = to_dt.strftime(DLP_TIME_FORMAT)

        # DLP is weird and wants a colon in the timezone value
        return '{0}:{1}'.format(time_str[:-2], time_str[-2:])

    def _on_poll(self, param):

        action_result = self.add_action_result(ActionResult(param))

        ret_val = self._create_client(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        config = self.get_config()

        if config.get('custom_severity'):
            try:
                self._custom_severity = json.loads(config.get('custom_severity'))
                self._custom_severity = {
                    dlp_severity.lower(): phantom_severity for dlp_severity, phantom_severity in self._custom_severity.items()
                }
            except Exception as e:
                error_message = self._get_error_message_from_exception(e)
                self.debug_print('Error occurred while loading the json: {}'.format(error_message))
                return action_result.set_status(phantom.APP_ERROR, "Please provide a valid JSON in custom severity parameter")

            self._severity.update(self._custom_severity)
        # Get the maximum number of incidents that we can pull, same as container count
        if self.is_poll_now():
            max_containers = self._validate_integers(action_result, param[phantom.APP_JSON_CONTAINER_COUNT], phantom.APP_JSON_CONTAINER_COUNT)
            if max_containers is None:
                return action_result.get_status()
        else:
            max_containers = self._max_containers

        time_string = self._get_time_string()

        self.save_progress("Getting incident IDs generated since {0}".format(time_string))

        config = self.get_config()

        incident_ids = []

        # get the number of incidents
        ret_val, incident_ids = self._get_incident_ids(action_result, self._report_id, time_string)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not incident_ids:
            self.save_progress("Did not get any new Incidents")
            return action_result.set_status(phantom.APP_SUCCESS, "Did not get any new Incidents")

        incident_len = len(incident_ids)

        self.save_progress("Got {0} incidents".format(incident_len))

        incident_count = 0
        queried_incident_details = []
        incident_ids.sort()
        last_inc_id = self._state.get(DLP_JSON_LAST_INCIDENT_ID, -1)

        for curr_incident_id in incident_ids:

            ret_val, incident_detail = self._get_incident_details(
                action_result, curr_incident_id, curr_incident_id, config[DLP_JSON_EXTRACT_COMPONENTS], True, True
            )

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
            self.debug_print("The incidents parser script threw an exception : {}".format(self._get_error_message_from_exception(e)))
            return action_result.set_status(
                phantom.APP_ERROR,
                "The incident parser script ran into an error, please see the logs for the complete stack trace"
            )

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
        elif action == self.ACTION_ID_LIST_INCIDENTS:
            ret_val = self._handle_list_incidents(param)
        elif action == self.ACTION_ID_GET_INCIDENT:
            ret_val = self._handle_get_incident(param)
        elif action == self.ACTION_ID_ON_POLL:
            ret_val = self._on_poll(param)

        return ret_val


if __name__ == '__main__':

    # import pudb
    import argparse
    import sys

    # pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print("Accessing the Login page")
            login_url = "{}login".format(BaseConnector._get_phantom_base_url())
            r = requests.get(login_url, verify=verify, timeout=60)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={}'.format(csrftoken)
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=60)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: {}".format(str(e)))
            sys.exit(1)

    if len(sys.argv) < 2:
        print("No test json specified as input")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SymantecDLPConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
