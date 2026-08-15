from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    import requests  # noqa: F401
except ModuleNotFoundError:
    class _RequestException(Exception):
        pass

    sys.modules["requests"] = SimpleNamespace(
        RequestException=_RequestException,
        Session=lambda: (_ for _ in ()).throw(RuntimeError("tests must inject a fake HTTP session")),
    )

from lib.zabbix_client import ZabbixClient, ZabbixPackError, dispatch


class FakeResponse:
    def __init__(self, body, status=200, redirect=False):
        self._body = json.dumps(body).encode() if not isinstance(body, bytes) else body
        self.status_code = status
        self.is_redirect = redirect
        self.closed = False

    def iter_content(self, chunk_size=65536):
        for offset in range(0, len(self._body), chunk_size):
            yield self._body[offset : offset + chunk_size]

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, responder):
        self.responder = responder
        self.calls = []
        self.trust_env = True
        self.closed = False

    def post(self, url, **kwargs):
        payload = json.loads(kwargs["data"])
        self.calls.append((url, kwargs, payload))
        return self.responder(payload, kwargs)

    def close(self):
        self.closed = True


TOKEN_PROFILE = {
    "api_url": "https://zabbix.invalid/zabbix/api_jsonrpc.php",
    "auth": {"type": "api_token", "token": "synthetic-secret-token"},
    "verify_tls": True,
}


def success(result):
    return lambda payload, kwargs: FakeResponse({"jsonrpc": "2.0", "id": payload["id"], "result": result})


class ClientTests(unittest.TestCase):
    def test_profile_requires_verified_https_and_exact_auth_shape(self):
        invalid = [
            {**TOKEN_PROFILE, "api_url": "http://zabbix.invalid/api_jsonrpc.php"},
            {**TOKEN_PROFILE, "verify_tls": False},
            {**TOKEN_PROFILE, "api_url": "https://u:p@zabbix.invalid/api_jsonrpc.php"},
            {**TOKEN_PROFILE, "api_url": "https://zabbix.invalid/api_jsonrpc.php?x=1"},
            {**TOKEN_PROFILE, "auth": {"type": "api_token", "token": "x", "extra": "x"}},
        ]
        for profile in invalid:
            with self.subTest(profile=profile), self.assertRaises(ZabbixPackError):
                ZabbixClient(profile)

    def test_api_token_is_header_only_and_request_id_is_checked(self):
        session = FakeSession(success([{"hostid": "1"}]))
        with ZabbixClient(TOKEN_PROFILE, session=session) as client:
            result = client.call("host.get", {"output": ["hostid"]})
            self.assertEqual(result, [{"hostid": "1"}])
            _, kwargs, payload = session.calls[0]
            self.assertEqual(kwargs["headers"]["Authorization"], "Bearer synthetic-secret-token")
            self.assertNotIn("auth", payload)
            self.assertNotIn("synthetic-secret-token", kwargs["data"])
            self.assertFalse(kwargs["allow_redirects"])
            self.assertTrue(kwargs["stream"])
            self.assertEqual(kwargs["timeout"], (10, 30))
            self.assertFalse(session.trust_env)
        self.assertTrue(session.closed)

    def test_password_login_uses_current_username_and_bearer_token(self):
        def responder(payload, kwargs):
            if payload["method"] == "user.login":
                self.assertEqual(payload["params"], {"username": "automation", "password": "synthetic-password"})
                self.assertNotIn("Authorization", kwargs["headers"])
                result = "synthetic-session-token"
            else:
                self.assertEqual(kwargs["headers"]["Authorization"], "Bearer synthetic-session-token")
                result = []
            return FakeResponse({"jsonrpc": "2.0", "id": payload["id"], "result": result})

        profile = {
            "api_url": "https://zabbix.invalid/api_jsonrpc.php",
            "auth": {"type": "password", "username": "automation", "password": "synthetic-password"},
        }
        session = FakeSession(responder)
        with ZabbixClient(profile, session=session) as client:
            client.call("host.get")
            client.call("host.get")
        self.assertEqual([call[2]["method"] for call in session.calls], ["user.login", "host.get", "host.get"])

    def test_api_error_redacts_credentials_and_omits_data(self):
        def responder(payload, kwargs):
            return FakeResponse({
                "jsonrpc": "2.0",
                "id": payload["id"],
                "error": {"code": -32602, "message": "bad synthetic-secret-token", "data": "private-response-data"},
            })

        with (
            ZabbixClient(TOKEN_PROFILE, session=FakeSession(responder)) as client,
            self.assertRaisesRegex(ZabbixPackError, r"-32602: bad \[REDACTED\]") as caught,
        ):
            client.call("host.get")
        self.assertNotIn("private-response-data", str(caught.exception))
        self.assertNotIn("synthetic-secret-token", str(caught.exception))

    def test_redirect_and_mismatched_id_are_rejected(self):
        redirect = FakeSession(lambda payload, kwargs: FakeResponse({}, redirect=True))
        with ZabbixClient(TOKEN_PROFILE, session=redirect) as client, self.assertRaisesRegex(ZabbixPackError, "redirects"):
            client.call("host.get")
        mismatch = FakeSession(lambda payload, kwargs: FakeResponse({"jsonrpc": "2.0", "id": "wrong", "result": []}))
        with ZabbixClient(TOKEN_PROFILE, session=mismatch) as client, self.assertRaisesRegex(ZabbixPackError, "envelope"):
            client.call("host.get")

    def test_custom_ca_file_is_private_and_removed(self):
        profile = {**TOKEN_PROFILE, "ca_bundle_pem": "synthetic-ca"}
        session = FakeSession(success("7.4.2"))
        client = ZabbixClient(profile, session=session)
        ca_path = Path(str(client.verify))
        self.assertTrue(ca_path.exists())
        self.assertEqual(ca_path.stat().st_mode & 0o777, 0o600)
        client.call("apiinfo.version", authenticated=False)
        client.close()
        self.assertFalse(ca_path.exists())


class DispatcherTests(unittest.TestCase):
    def client(self, responder):
        return ZabbixClient(TOKEN_PROFILE, session=FakeSession(responder))

    def test_list_limit_fetches_one_extra_and_reports_truncation(self):
        def responder(payload, kwargs):
            self.assertEqual(payload["method"], "host.get")
            self.assertEqual(payload["params"]["limit"], 3)
            return FakeResponse({"jsonrpc": "2.0", "id": payload["id"], "result": [{"hostid": "1"}, {"hostid": "2"}, {"hostid": "3"}]})

        with self.client(responder) as client:
            data, meta = dispatch(client, "host_list", {"limit": 2})
        self.assertEqual([item["hostid"] for item in data], ["1", "2"])
        self.assertEqual(meta, {"count": 2, "limit": 2, "truncated": True})

    def test_template_operations_are_additive_and_nonclearing(self):
        methods = []

        def responder(payload, kwargs):
            methods.append((payload["method"], payload["params"]))
            return FakeResponse({"jsonrpc": "2.0", "id": payload["id"], "result": {"hostids": ["9"]}})

        with self.client(responder) as client:
            dispatch(client, "template_link", {"host_id": "9", "template_ids": ["2", "3"], "confirmation": "LINK TEMPLATES 2,3 TO HOST 9"})
            dispatch(client, "template_unlink", {"host_id": "9", "template_ids": ["2"], "confirmation": "UNLINK TEMPLATES 2 FROM HOST 9"})
        self.assertEqual(methods[0][0], "host.massadd")
        self.assertEqual(methods[1], ("host.massremove", {"hostids": ["9"], "templateids": ["2"]}))
        self.assertNotIn("templateids_clear", methods[1][1])

    def test_destructive_and_script_confirmations_block_before_request(self):
        session = FakeSession(success({}))
        with ZabbixClient(TOKEN_PROFILE, session=session) as client:
            cases = [
                ("host_delete", {"host_id": "7", "confirmation": "yes"}),
                ("maintenance_delete", {"maintenance_id": "8", "confirmation": "DELETE 8"}),
                ("script_execute", {"script_id": "2", "host_id": "7", "confirmation": "run"}),
                ("event_acknowledge", {"event_id": "3", "close": True, "confirmation": "close"}),
                ("monitoring_set", {"host_id": "7", "enabled": False, "confirmation": "disable"}),
            ]
            for operation, params in cases:
                with self.subTest(operation=operation), self.assertRaises(ZabbixPackError):
                    dispatch(client, operation, params)
        self.assertEqual(session.calls, [])

    def test_acknowledge_action_bits_and_no_retry(self):
        session = FakeSession(success({"eventids": ["12"]}))
        with ZabbixClient(TOKEN_PROFILE, session=session) as client:
            _, meta = dispatch(client, "event_acknowledge", {
                "event_id": "12", "message": "handled", "close": True, "confirmation": "CLOSE EVENT 12"
            })
        self.assertEqual(session.calls[0][2]["params"]["action"], 7)
        self.assertEqual(meta, {"mutating": True, "retried": False})
        self.assertEqual(len(session.calls), 1)

    def test_reversed_time_ranges_are_rejected_before_request(self):
        session = FakeSession(success([]))
        with ZabbixClient(TOKEN_PROFILE, session=session) as client, self.assertRaisesRegex(ZabbixPackError, "time_from"):
            dispatch(client, "history_get", {"item_ids": ["1"], "time_from": 20, "time_till": 10})
        self.assertEqual(session.calls, [])

    def test_history_uses_signed_32_bit_timestamp_contract(self):
        session = FakeSession(success([]))
        with ZabbixClient(TOKEN_PROFILE, session=session) as client, self.assertRaisesRegex(ZabbixPackError, "2147483647"):
            dispatch(client, "history_get", {"item_ids": ["1"], "time_till": 2147483648})
        self.assertEqual(session.calls, [])

    def test_proxy_assignment_requires_matching_monitor_mode(self):
        session = FakeSession(success({}))
        with ZabbixClient(TOKEN_PROFILE, session=session) as client:
            with self.assertRaisesRegex(ZabbixPackError, "monitored_by"):
                dispatch(client, "host_update", {"host_id": "7", "proxy_id": "2"})
            with self.assertRaisesRegex(ZabbixPackError, "proxy_group_id"):
                dispatch(client, "host_update", {"host_id": "7", "monitored_by": 2, "proxy_id": "2"})
        self.assertEqual(session.calls, [])

    def test_host_interfaces_reject_snmp_details_in_action_parameters(self):
        session = FakeSession(success({}))
        with ZabbixClient(TOKEN_PROFILE, session=session) as client, self.assertRaisesRegex(ZabbixPackError, "exactly"):
            dispatch(client, "host_create", {
                "host": "node", "group_ids": ["1"],
                "interfaces": [{"type": 2, "main": 1, "useip": 1, "ip": "192.0.2.1", "dns": "", "port": "161", "details": {"community": "secret"}}],
            })
        self.assertEqual(session.calls, [])

    def test_monitoring_disable_preflights_exact_host_then_updates(self):
        def responder(payload, kwargs):
            result = [{"hostid": "7", "host": "node", "status": "0"}] if payload["method"] == "host.get" else {"hostids": ["7"]}
            return FakeResponse({"jsonrpc": "2.0", "id": payload["id"], "result": result})

        session = FakeSession(responder)
        with ZabbixClient(TOKEN_PROFILE, session=session) as client:
            data, _ = dispatch(client, "monitoring_set", {"host_id": "7", "enabled": False, "confirmation": "DISABLE MONITORING 7"})
        self.assertEqual([call[2]["method"] for call in session.calls], ["host.get", "host.update"])
        self.assertEqual(session.calls[1][2]["params"], {"hostid": "7", "status": 1})
        self.assertFalse(data["enabled"])


class SensorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("problem_poll", ROOT / "sensors" / "problem_poll.py")
        cls.sensor = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(cls.sensor)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "var" / "lib" / "attune" / "zabbix"
        self.root.mkdir(parents=True)

    def tearDown(self):
        self.temporary.cleanup()

    def bare_poller(self, path, emit, events):
        poller = self.sensor.ProblemPoller.__new__(self.sensor.ProblemPoller)
        poller.path = path
        poller.batch = 100
        poller.lookback = 300
        poller.host_ids = None
        poller._stop = SimpleNamespace(is_set=lambda: False)
        poller.emit = emit

        class Client:
            def __init__(self):
                self.calls = []

            def call(self, method, query):
                self.calls.append((method, query))
                return events

        return poller, Client()

    def test_checkpoint_advances_only_after_each_successful_emit(self):
        events = [
            {"eventid": "11", "objectid": "101", "clock": "1000", "name": "first", "severity": "3", "acknowledged": "0", "hosts": [], "tags": []},
            {"eventid": "12", "objectid": "102", "clock": "1001", "name": "second", "severity": "4", "acknowledged": "1", "hosts": [], "tags": []},
        ]
        emitted = []

        def emit(payload):
            emitted.append(payload["event_id"])
            if payload["event_id"] == "12":
                raise RuntimeError("synthetic emission failure")

        path = self.root / "events.json"
        with patch.object(self.sensor, "CHECKPOINT_ROOT", self.root):
            poller, client = self.bare_poller(path, emit, events)
            with self.assertRaises(RuntimeError):
                poller.poll_once(client, now=2000)
            self.assertEqual(self.sensor.read_checkpoint(path), 11)
        self.assertEqual(emitted, ["11", "12"])

    def test_checkpoint_deduplicates_and_uses_next_event_id(self):
        path = self.root / "events.json"
        with patch.object(self.sensor, "CHECKPOINT_ROOT", self.root):
            self.sensor.write_checkpoint(path, 20)
            events = [
                {"eventid": "20", "objectid": "1", "clock": "100", "name": "old", "severity": "1", "acknowledged": "0", "hosts": [], "tags": []},
                {"eventid": "21", "objectid": "2", "clock": "101", "name": "new", "severity": "2", "acknowledged": "0", "hosts": [], "tags": []},
            ]
            emitted = []
            poller, client = self.bare_poller(path, lambda payload: emitted.append(payload["event_id"]), events)
            self.assertEqual(poller.poll_once(client), 1)
            self.assertEqual(client.calls[0][1]["eventid_from"], "21")
            self.assertEqual(self.sensor.read_checkpoint(path), 21)
        self.assertEqual(emitted, ["21"])

    def test_checkpoint_path_is_confined(self):
        with patch.object(self.sensor, "CHECKPOINT_ROOT", self.root):
            self.assertEqual(self.sensor.checkpoint_path(str(self.root / "ok.json")), self.root / "ok.json")
            with self.assertRaises(ZabbixPackError):
                self.sensor.checkpoint_path(str(Path(self.temporary.name) / "outside.json"))

    def test_full_page_without_id_progress_fails_instead_of_spinning(self):
        path = self.root / "events.json"
        with patch.object(self.sensor, "CHECKPOINT_ROOT", self.root):
            self.sensor.write_checkpoint(path, 20)
            events = [{"eventid": "20", "objectid": "1", "clock": "100", "name": "old", "severity": "1", "acknowledged": "0", "hosts": [], "tags": []}]
            poller, client = self.bare_poller(path, lambda payload: None, events)
            poller.batch = 1
            with self.assertRaisesRegex(ZabbixPackError, "no checkpoint progress"):
                poller.poll_once(client)


class MetadataTests(unittest.TestCase):
    def test_curated_action_contracts_and_source_metadata(self):
        action_files = sorted((ROOT / "actions").glob("*.yaml"))
        self.assertEqual(len(action_files), 30)
        for path in action_files:
            text = path.read_text(encoding="utf-8")
            self.assertIn("parameter_delivery: stdin", text, path.name)
            self.assertIn("parameter_format: json", text, path.name)
            self.assertIn("output_format: json", text, path.name)
            self.assertIn("default: zabbix.credentials", text, path.name)
            self.assertNotIn("api_token:", text, path.name)
            self.assertNotIn("password:", text, path.name)
        pack = (ROOT / "pack.yaml").read_text(encoding="utf-8")
        self.assertIn("1b3ebdca44dab27c1a58ed11819a63d5b329d3f8", pack)
        self.assertIn('source_version: "2.0.0"', pack)
        self.assertIn('api_baseline: "Zabbix 7.4.13"', pack)
        self.assertIn("3c95000629791258a59622e3e4e995df45c44453", pack)
        self.assertTrue((ROOT / "LICENSE").exists())
        self.assertTrue((ROOT / "NOTICE").exists())

    def test_no_unsafe_generic_dispatch_or_live_test_dependencies(self):
        source = (ROOT / "lib" / "zabbix_client.py").read_text(encoding="utf-8")
        self.assertNotIn("verify=False", source)
        self.assertNotIn("zabbix_utils", source)
        self.assertNotIn("pytest", (ROOT / "requirements.txt").read_text(encoding="utf-8"))
        self.assertFalse((ROOT / "actions" / "call_api.yaml").exists())


if __name__ == "__main__":
    unittest.main()
