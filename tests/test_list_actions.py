# File: test_list_actions.py
#
# Copyright (c) 2026 Splunk Inc.
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

"""Run with the SOAR Python environment: python -m unittest discover -s tests."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

import phantom.app as phantom
import requests

from symantecdlp_connector import SymantecAuth, SymantecDLPConnector


class ListAPIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.respond()

    def do_PUT(self):
        self.respond()

    def respond(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.calls.append((self.command, self.path, self.headers, body))
        self.send_response(self.server.status)
        self.send_header("Content-Type", "application/json")
        if 300 <= self.server.status < 400:
            self.send_header("Location", "/should-not-follow")
        self.end_headers()
        self.wfile.write(self.server.body)

    def log_message(self, *args):
        pass


class ListActionsTest(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ListAPIHandler)
        self.server.calls = []
        self.server.status = 200
        self.definition = {
            "id": 508,
            "name": "Example",
            "ruleType": 4,
            "userPatterns": ["a@example.com", "b@example.com"],
            "ipAddresses": ["192.0.2.1"],
        }
        self.server.body = json.dumps(self.definition).encode()
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.connector = SymantecDLPConnector()
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.connector.get_config = Mock(return_value={"url": self.url + "/"})
        self.connector._verify = True
        self.connector._session = requests.Session()
        self.connector._session.trust_env = False
        self.connector._session.auth = SymantecAuth("test", "fixture-only", self.url)
        self.addCleanup(self.connector._session.close)
        self.connector._create_client = Mock(side_effect=AssertionError("List actions must not require SOAP"))

    def run_action(self, identifier="get_list", **parameters):
        self.connector.get_action_identifier = Mock(return_value=identifier)
        status = self.connector.handle_action(parameters)
        return status, self.connector.get_action_results()[-1]

    def test_get_list_uses_authenticated_fixed_rest_endpoint(self):
        status, result = self.run_action(list_id=508)
        self.assertEqual(status, phantom.APP_SUCCESS, result.get_message())
        method, path, headers, body = self.server.calls[-1]
        self.assertEqual((method, path), ("GET", "/ProtectManager/webservices/v2/senderRecipientPattern/508"))
        self.assertEqual(headers["Authorization"], "Basic dGVzdDpmaXh0dXJlLW9ubHk=")
        self.assertEqual(headers["Accept"], "application/json")
        self.assertEqual(body, b"")
        self.assertEqual(result.get_data(), [self.definition])
        self.assertEqual(result.get_summary(), {"list_id": 508, "list_name": "Example", "total_entries": 3})

    def test_update_sends_json_definition(self):
        status, result = self.run_action("update_list", list_id="508", new_value=json.dumps(self.definition))
        self.assertEqual(status, phantom.APP_SUCCESS, result.get_message())
        method, path, headers, body = self.server.calls[-1]
        self.assertEqual((method, path), ("PUT", "/ProtectManager/webservices/v2/senderRecipientPattern/508"))
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(json.loads(body), self.definition)
        self.assertEqual(result.get_summary(), {"list_id": 508, "update_status": "success"})

    def test_update_accepts_empty_204_response(self):
        self.server.status, self.server.body = 204, b""
        status, result = self.run_action("update_list", list_id=508, new_value=json.dumps(self.definition))
        self.assertEqual(status, phantom.APP_SUCCESS, result.get_message())
        self.assertEqual(result.get_data(), [])

    def test_invalid_ids_never_make_requests(self):
        for action in ("get_list", "update_list"):
            for list_id in (None, True, False, -1, 0, 1.5, "abc", "508/other"):
                with self.subTest(action=action, list_id=list_id):
                    status, result = self.run_action(action, list_id=list_id, new_value=json.dumps(self.definition))
                    self.assertEqual(status, phantom.APP_ERROR)
                    self.assertIn("list_id", result.get_message())
        self.assertEqual(self.server.calls, [])

    def test_update_requires_nonempty_json_object(self):
        for payload in (None, "", "invalid", "null", "[]", "1", '"text"', "true", "{}"):
            with self.subTest(payload=payload):
                status, result = self.run_action("update_list", list_id=508, new_value=payload)
                self.assertEqual(status, phantom.APP_ERROR)
                self.assertIn("new_value", result.get_message())
        self.assertEqual(self.server.calls, [])

    def test_http_errors_and_redirects_are_failures(self):
        for action in ("get_list", "update_list"):
            for code in (302, 307, 401, 403, 404, 500):
                with self.subTest(action=action, code=code):
                    before = len(self.server.calls)
                    self.server.status = code
                    self.server.body = b'{"message": "fixture failure"}'
                    status, result = self.run_action(action, list_id=508, new_value=json.dumps(self.definition))
                    self.assertEqual(status, phantom.APP_ERROR)
                    self.assertIn(str(code), result.get_message())
                    self.assertIn("fixture failure", result.get_message())
                    self.assertEqual(len(self.server.calls), before + 1)
                    self.assertFalse(result.get_summary().get("update_status"))

    def test_nonjson_error_response(self):
        self.server.status, self.server.body = 503, b"service unavailable"
        status, result = self.run_action(list_id=508)
        self.assertEqual(status, phantom.APP_ERROR)
        self.assertIn("service unavailable", result.get_message())

    def test_invalid_success_responses_are_failures(self):
        for action in ("get_list", "update_list"):
            for body in (b"not JSON", b"[]", b"null"):
                with self.subTest(action=action, body=body):
                    self.server.body = body
                    status, result = self.run_action(action, list_id=508, new_value=json.dumps(self.definition))
                    self.assertEqual(status, phantom.APP_ERROR, result.get_message())
        self.server.body = b""
        status, _ = self.run_action(list_id=508)
        self.assertEqual(status, phantom.APP_ERROR)

    def test_empty_patterns_count_as_zero(self):
        self.server.body = b'{"id": 508, "userPatterns": null, "ipAddresses": []}'
        status, result = self.run_action(list_id=508)
        self.assertEqual(status, phantom.APP_SUCCESS, result.get_message())
        self.assertEqual(result.get_summary()["total_entries"], 0)

    def test_request_settings_and_connection_failures(self):
        for error in (requests.Timeout("fixture timeout"), requests.ConnectionError("fixture connection failure")):
            with self.subTest(error=error), patch.object(self.connector._session, "request", side_effect=error) as request:
                status, result = self.run_action(list_id=508)
                self.assertEqual(status, phantom.APP_ERROR)
                self.assertIn("Error connecting", result.get_message())
                self.assertEqual(request.call_args.kwargs["timeout"], 60)
                self.assertTrue(request.call_args.kwargs["verify"])
                self.assertFalse(request.call_args.kwargs["allow_redirects"])


if __name__ == "__main__":
    unittest.main()
