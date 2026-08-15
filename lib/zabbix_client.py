"""Direct, bounded Zabbix JSON-RPC client and curated action dispatcher."""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests

DEFAULT_CREDENTIAL_KEY = "zabbix.credentials"
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_REQUEST_BYTES = 2 * 1024 * 1024
_ID = re.compile(r"^[1-9][0-9]*$")
_MUTATIONS = {
    "host_create", "host_update", "host_delete", "monitoring_set",
    "host_group_create", "host_group_update", "host_group_delete",
    "template_link", "template_unlink", "maintenance_create",
    "maintenance_update", "maintenance_delete", "event_acknowledge",
    "script_execute",
}


class ZabbixPackError(Exception):
    """An action-safe error that never intentionally contains credentials or bodies."""


def fetch_key(key_ref: str) -> dict[str, Any]:
    if not isinstance(key_ref, str) or not key_ref.strip():
        raise ZabbixPackError("credential_key must be a non-empty string")
    try:
        import attune
        from attune.api_client.api.secrets import get_key

        response = get_key.sync_detailed(client=attune.context.client, key_ref=key_ref)
    except Exception as exc:  # noqa: BLE001
        raise ZabbixPackError(f"could not read Zabbix credential Key ({type(exc).__name__})") from None
    if response.status_code != 200 or response.parsed is None:
        if response.status_code == 404:
            raise ZabbixPackError("Zabbix credential Key was not found")
        raise ZabbixPackError(f"could not read Zabbix credential Key (HTTP {response.status_code})")
    value = response.parsed.data.value
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            raise ZabbixPackError("Zabbix credential Key must contain a JSON object") from None
    if not isinstance(value, dict):
        raise ZabbixPackError("Zabbix credential Key must contain an object")
    return value


def read_credential_file(path_value: Any) -> dict[str, Any]:
    if not isinstance(path_value, str) or not os.path.isabs(path_value):
        raise ZabbixPackError("credential_file must be an absolute path")
    resolved = Path(path_value).resolve()
    secrets_root = Path("/run/secrets").resolve()
    if secrets_root not in resolved.parents:
        raise ZabbixPackError("credential_file must be below /run/secrets")
    try:
        stat = resolved.stat()
        if not resolved.is_file() or stat.st_size > 65536:
            raise ZabbixPackError("credential_file must be a regular JSON file no larger than 64 KiB")
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except ZabbixPackError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ZabbixPackError("credential_file must contain a readable JSON object") from None
    if not isinstance(value, dict):
        raise ZabbixPackError("credential_file must contain a JSON object")
    return value


def _nonempty(value: Any, name: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ZabbixPackError(f"{name} must be a non-empty string no longer than {maximum} characters")
    if any(ord(character) < 32 for character in value):
        raise ZabbixPackError(f"{name} contains a control character")
    return value


def _integer(params: Mapping[str, Any], name: str, default: int | None, minimum: int, maximum: int) -> int | None:
    value = params.get(name, default)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ZabbixPackError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def _boolean(params: Mapping[str, Any], name: str, default: bool = False) -> bool:
    value = params.get(name, default)
    if not isinstance(value, bool):
        raise ZabbixPackError(f"{name} must be a boolean")
    return value


def _id(value: Any, name: str) -> str:
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ZabbixPackError(f"{name} must be a positive numeric Zabbix ID")
    return value


def _ids(value: Any, name: str, *, required: bool = False, maximum: int = 1000) -> list[str] | None:
    if value is None:
        if required:
            raise ZabbixPackError(f"{name} is required")
        return None
    if not isinstance(value, list) or not value or len(value) > maximum:
        raise ZabbixPackError(f"{name} must be a non-empty array with at most {maximum} IDs")
    result = [_id(item, name) for item in value]
    if len(set(result)) != len(result):
        raise ZabbixPackError(f"{name} must not contain duplicate IDs")
    return result


def _time_range(params: Mapping[str, Any], maximum: int = 4102444800) -> dict[str, int]:
    start = _integer(params, "time_from", None, 0, maximum)
    end = _integer(params, "time_till", None, 0, maximum)
    if start is not None and end is not None and start > end:
        raise ZabbixPackError("time_from must not be later than time_till")
    output: dict[str, int] = {}
    if start is not None:
        output["time_from"] = start
    if end is not None:
        output["time_till"] = end
    return output


def _search(params: Mapping[str, Any], field: str) -> dict[str, Any]:
    value = params.get("search")
    if value is None:
        return {}
    return {"search": {field: _nonempty(value, "search", 255)}, "searchWildcardsEnabled": True}


class ZabbixClient:
    """Strict JSON-RPC 2.0 client with no automatic retries or redirects."""

    def __init__(self, profile: Mapping[str, Any], timeout_seconds: int = 30, session: Any = None):
        if not isinstance(profile, Mapping):
            raise ZabbixPackError("credential profile must be an object")
        unknown = set(profile) - {"api_url", "auth", "verify_tls", "ca_bundle_pem"}
        if unknown:
            raise ZabbixPackError("credential profile contains unsupported fields")
        api_url = _nonempty(profile.get("api_url"), "credential api_url", 2048)
        parsed = urlsplit(api_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ZabbixPackError("credential api_url must be an HTTPS URL without embedded credentials")
        if parsed.query or parsed.fragment or not parsed.path.endswith("/api_jsonrpc.php"):
            raise ZabbixPackError("credential api_url must end in /api_jsonrpc.php without query or fragment")
        try:
            _ = parsed.port
        except ValueError:
            raise ZabbixPackError("credential api_url has an invalid port") from None
        verify_tls = profile.get("verify_tls", True)
        if verify_tls is not True:
            raise ZabbixPackError("credential verify_tls must be true for authenticated Zabbix access")
        auth = profile.get("auth")
        if not isinstance(auth, Mapping):
            raise ZabbixPackError("credential auth must be an object")
        auth_type = auth.get("type")
        if auth_type == "api_token":
            if set(auth) != {"type", "token"}:
                raise ZabbixPackError("api_token auth must contain only type and token")
            self._api_token = _nonempty(auth.get("token"), "credential auth token", 65536)
            self._username = self._password = None
        elif auth_type == "password":
            if set(auth) != {"type", "username", "password"}:
                raise ZabbixPackError("password auth must contain only type, username, and password")
            self._username = _nonempty(auth.get("username"), "credential auth username", 255)
            self._password = _nonempty(auth.get("password"), "credential auth password", 255)
            self._api_token = None
        else:
            raise ZabbixPackError("credential auth type must be api_token or password")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 120:
            raise ZabbixPackError("timeout_seconds must be an integer from 1 to 120")
        self.api_url = api_url
        self.timeout = (min(10, timeout_seconds), timeout_seconds)
        self.session = session or requests.Session()
        self.session.trust_env = False
        self._session_token: str | None = None
        self._counter = 0
        self._lock = threading.Lock()
        self._prefix = uuid.uuid4().hex
        self.last_request_id: str | None = None
        self._ca_path: str | None = None
        ca_pem = profile.get("ca_bundle_pem")
        if ca_pem is not None:
            ca_pem = _nonempty(ca_pem, "credential ca_bundle_pem", 1024 * 1024)
            with tempfile.NamedTemporaryFile(mode="w", prefix="attune-zabbix-ca-", suffix=".pem", delete=False) as handle:
                os.chmod(handle.name, 0o600)
                handle.write(ca_pem)
                self._ca_path = handle.name
        self.verify: bool | str = self._ca_path or True

    def close(self) -> None:
        try:
            self.session.close()
        finally:
            if self._ca_path:
                try:
                    os.unlink(self._ca_path)
                except FileNotFoundError:
                    pass
                self._ca_path = None

    def __enter__(self):
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _request_id(self) -> str:
        with self._lock:
            self._counter += 1
            return f"{self._prefix}-{self._counter}"

    def _redact(self, value: str) -> str:
        for secret in (self._api_token, self._session_token, self._password):
            if secret:
                value = value.replace(secret, "[REDACTED]")
        return value[:512]

    def _auth_value(self) -> str:
        if self._api_token:
            return self._api_token
        if self._session_token:
            return self._session_token
        result, _ = self._rpc(
            "user.login",
            {"username": self._username, "password": self._password},
            authenticated=False,
        )
        if not isinstance(result, str) or not result:
            raise ZabbixPackError("Zabbix user.login returned an invalid authentication token")
        self._session_token = result
        return result

    def _rpc(self, method: str, params: Any, *, authenticated: bool) -> tuple[Any, str]:
        request_id = self._request_id()
        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": request_id}
        headers = {"Content-Type": "application/json-rpc", "Accept": "application/json"}
        if authenticated:
            headers["Authorization"] = f"Bearer {self._auth_value()}"
        try:
            request_body = json.dumps(payload, separators=(",", ":"))
        except (TypeError, ValueError):
            raise ZabbixPackError("Zabbix request parameters are not JSON serializable") from None
        if len(request_body.encode("utf-8")) > MAX_REQUEST_BYTES:
            raise ZabbixPackError("Zabbix request exceeded 2 MiB")
        try:
            response = self.session.post(
                self.api_url,
                data=request_body,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify,
                allow_redirects=False,
                stream=True,
            )
        except requests.RequestException as exc:
            raise ZabbixPackError(f"Zabbix request failed ({type(exc).__name__})") from None
        try:
            if response.is_redirect:
                raise ZabbixPackError("Zabbix API redirects are not allowed")
            if response.status_code != 200:
                raise ZabbixPackError(f"Zabbix request failed (HTTP {response.status_code})")
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_content(chunk_size=65536):
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise ZabbixPackError("Zabbix response exceeded 16 MiB")
                chunks.append(chunk)
            try:
                body = json.loads(b"".join(chunks))
            except (UnicodeError, json.JSONDecodeError):
                raise ZabbixPackError("Zabbix returned an invalid JSON response") from None
        finally:
            response.close()
        if not isinstance(body, dict) or body.get("jsonrpc") != "2.0" or body.get("id") != request_id:
            raise ZabbixPackError("Zabbix returned an invalid JSON-RPC envelope")
        if "error" in body:
            error = body["error"]
            code = error.get("code") if isinstance(error, dict) else "unknown"
            message = error.get("message", "API error") if isinstance(error, dict) else "API error"
            safe_message = self._redact(str(message))
            raise ZabbixPackError(f"Zabbix API error {code}: {safe_message} (request {request_id})")
        if "result" not in body:
            raise ZabbixPackError("Zabbix response did not contain a result")
        self.last_request_id = request_id
        return body["result"], request_id

    def call(self, method: str, params: Any = None, *, authenticated: bool = True) -> Any:
        result, _ = self._rpc(method, {} if params is None else params, authenticated=authenticated)
        return result


def _limited(client: ZabbixClient, method: str, query: dict[str, Any], params: Mapping[str, Any]) -> tuple[list[Any], dict[str, Any]]:
    limit = _integer(params, "limit", 100, 1, 1000)
    assert limit is not None
    query["limit"] = limit + 1
    data = client.call(method, query)
    if not isinstance(data, list):
        raise ZabbixPackError(f"{method} returned an invalid result")
    truncated = len(data) > limit
    data = data[:limit]
    return data, {"count": len(data), "limit": limit, "truncated": truncated}


def _mutation(client: ZabbixClient, method: str, rpc_params: Any) -> tuple[Any, dict[str, Any]]:
    return client.call(method, rpc_params), {"mutating": True, "retried": False}


def _confirmation(actual: Any, expected: str) -> None:
    if actual != expected:
        raise ZabbixPackError(f"confirmation must exactly equal {expected!r}")


def dispatch(client: ZabbixClient, operation: str, params: Mapping[str, Any]) -> tuple[Any, dict[str, Any]]:
    if operation == "api_version":
        return client.call("apiinfo.version", authenticated=False), {"authenticated": False}

    if operation in {"host_list", "host_get"}:
        query: dict[str, Any] = {
            "output": ["hostid", "host", "name", "status", "description", "monitored_by", "proxyid", "proxy_groupid"],
            "selectGroups": ["groupid", "name"],
            "selectParentTemplates": ["templateid", "host", "name"],
            "selectInterfaces": ["interfaceid", "type", "main", "useip", "ip", "dns", "port", "available", "error"],
            "sortfield": "hostid",
        }
        if operation == "host_get":
            query["hostids"] = [_id(params.get("host_id"), "host_id")]
        else:
            query.update(_search(params, "host"))
            group_ids = _ids(params.get("group_ids"), "group_ids")
            if group_ids:
                query["groupids"] = group_ids
        return _limited(client, "host.get", query, params)

    if operation == "host_create":
        body: dict[str, Any] = {
            "host": _nonempty(params.get("host"), "host", 128),
            "groups": [{"groupid": item} for item in (_ids(params.get("group_ids"), "group_ids", required=True) or [])],
        }
        for source, target, maximum in (("visible_name", "name", 128), ("description", "description", 2048)):
            if params.get(source) is not None:
                body[target] = _nonempty(params[source], source, maximum)
        interfaces = params.get("interfaces")
        if interfaces is not None:
            if not isinstance(interfaces, list) or not interfaces or len(interfaces) > 16:
                raise ZabbixPackError("interfaces must be a non-empty array with at most 16 objects")
            required = {"type", "main", "useip", "ip", "dns", "port"}
            for interface in interfaces:
                if not isinstance(interface, dict) or set(interface) != required:
                    raise ZabbixPackError("each interface must contain exactly type, main, useip, ip, dns, and port")
                for field in ("type", "main", "useip"):
                    if isinstance(interface[field], bool) or not isinstance(interface[field], int):
                        raise ZabbixPackError(f"interface {field} must be an integer")
                if interface["type"] not in {1, 3, 4} or interface["main"] not in {0, 1} or interface["useip"] not in {0, 1}:
                    raise ZabbixPackError("interface type, main, or useip is out of range")
                for field, maximum in (("ip", 64), ("dns", 255), ("port", 64)):
                    if not isinstance(interface[field], str) or len(interface[field]) > maximum:
                        raise ZabbixPackError(f"interface {field} must be a string no longer than {maximum} characters")
                selected = interface["ip"] if interface["useip"] == 1 else interface["dns"]
                if not selected:
                    raise ZabbixPackError("interface selected address must not be empty")
            body["interfaces"] = interfaces
        return _mutation(client, "host.create", body)

    if operation == "host_update":
        body = {"hostid": _id(params.get("host_id"), "host_id")}
        fields = {
            "host": ("host", 128), "visible_name": ("name", 128), "description": ("description", 2048),
            "proxy_id": ("proxyid", None), "proxy_group_id": ("proxy_groupid", None),
        }
        for source, (target, maximum) in fields.items():
            if params.get(source) is not None:
                body[target] = _id(params[source], source) if maximum is None else _nonempty(params[source], source, maximum)
        monitored_by = _integer(params, "monitored_by", None, 0, 2)
        inventory_mode = _integer(params, "inventory_mode", None, -1, 1)
        has_proxy = "proxyid" in body
        has_proxy_group = "proxy_groupid" in body
        if has_proxy and has_proxy_group:
            raise ZabbixPackError("host_update cannot set both proxy_id and proxy_group_id")
        if (has_proxy or has_proxy_group) and monitored_by is None:
            raise ZabbixPackError("monitored_by is required when changing proxy assignment")
        if monitored_by == 1 and not has_proxy:
            raise ZabbixPackError("proxy_id is required when monitored_by is 1")
        if monitored_by == 2 and not has_proxy_group:
            raise ZabbixPackError("proxy_group_id is required when monitored_by is 2")
        if monitored_by == 0 and (has_proxy or has_proxy_group):
            raise ZabbixPackError("proxy assignment is not allowed when monitored_by is 0")
        if monitored_by is not None:
            body["monitored_by"] = monitored_by
        if inventory_mode is not None:
            body["inventory_mode"] = inventory_mode
        if len(body) == 1:
            raise ZabbixPackError("host_update requires at least one field to change")
        return _mutation(client, "host.update", body)

    if operation == "host_delete":
        host_id = _id(params.get("host_id"), "host_id")
        _confirmation(params.get("confirmation"), f"DELETE HOST {host_id}")
        return _mutation(client, "host.delete", [host_id])

    if operation == "monitoring_set":
        host_id = _id(params.get("host_id"), "host_id")
        enabled = _boolean(params, "enabled")
        if not enabled:
            _confirmation(params.get("confirmation"), f"DISABLE MONITORING {host_id}")
        current = client.call("host.get", {"output": ["hostid", "host", "name", "status"], "hostids": [host_id]})
        if not isinstance(current, list) or len(current) != 1:
            raise ZabbixPackError("host_id did not resolve to exactly one visible host")
        result = client.call("host.update", {"hostid": host_id, "status": 0 if enabled else 1})
        return {"before": current[0], "result": result, "enabled": enabled}, {"mutating": True, "retried": False}

    group_methods = {
        "host_group_list": "hostgroup.get", "host_group_create": "hostgroup.create",
        "host_group_update": "hostgroup.update", "host_group_delete": "hostgroup.delete",
    }
    if operation == "host_group_list":
        return _limited(client, group_methods[operation], {"output": ["groupid", "name", "flags"], "sortfield": "groupid", **_search(params, "name")}, params)
    if operation == "host_group_create":
        return _mutation(client, group_methods[operation], {"name": _nonempty(params.get("name"), "name", 255)})
    if operation == "host_group_update":
        return _mutation(client, group_methods[operation], {"groupid": _id(params.get("group_id"), "group_id"), "name": _nonempty(params.get("name"), "name", 255)})
    if operation == "host_group_delete":
        group_id = _id(params.get("group_id"), "group_id")
        _confirmation(params.get("confirmation"), f"DELETE HOST GROUP {group_id}")
        return _mutation(client, group_methods[operation], [group_id])

    if operation == "template_list":
        query = {"output": ["templateid", "host", "name", "description", "vendor_name", "vendor_version"], "sortfield": "templateid", **_search(params, "host")}
        return _limited(client, "template.get", query, params)
    if operation in {"template_link", "template_unlink"}:
        host_id = _id(params.get("host_id"), "host_id")
        template_ids = _ids(params.get("template_ids"), "template_ids", required=True, maximum=100) or []
        joined = ",".join(template_ids)
        verb = "LINK" if operation == "template_link" else "UNLINK"
        preposition = "TO" if operation == "template_link" else "FROM"
        _confirmation(params.get("confirmation"), f"{verb} TEMPLATES {joined} {preposition} HOST {host_id}")
        if operation == "template_link":
            return _mutation(client, "host.massadd", {"hosts": [{"hostid": host_id}], "templates": [{"templateid": item} for item in template_ids]})
        return _mutation(client, "host.massremove", {"hostids": [host_id], "templateids": template_ids})

    if operation == "proxy_list":
        return _limited(client, "proxy.get", {"output": "extend", "sortfield": "proxyid"}, params)
    if operation == "proxy_group_list":
        return _limited(client, "proxygroup.get", {"output": "extend", "sortfield": "proxy_groupid"}, params)

    if operation == "item_list":
        query = {"output": ["itemid", "hostid", "name", "key_", "type", "value_type", "status", "state", "lastvalue", "lastclock", "error"], "sortfield": "itemid", **_search(params, "name")}
        host_ids = _ids(params.get("host_ids"), "host_ids")
        if host_ids:
            query["hostids"] = host_ids
        return _limited(client, "item.get", query, params)
    if operation == "trigger_list":
        query = {"output": ["triggerid", "description", "expression", "priority", "status", "value", "lastchange", "error"], "selectHosts": ["hostid", "host", "name"], "selectTags": "extend", "sortfield": "triggerid", **_search(params, "description")}
        host_ids = _ids(params.get("host_ids"), "host_ids")
        if host_ids:
            query["hostids"] = host_ids
        if params.get("only_true") is not None:
            query["only_true"] = _boolean(params, "only_true")
        return _limited(client, "trigger.get", query, params)

    if operation == "maintenance_list":
        query = {"output": "extend", "selectHosts": ["hostid", "host", "name"], "selectHostGroups": ["groupid", "name"], "selectTimeperiods": "extend", "sortfield": "maintenanceid", **_search(params, "name")}
        return _limited(client, "maintenance.get", query, params)
    if operation in {"maintenance_create", "maintenance_update"}:
        body = {
            "name": _nonempty(params.get("name"), "name", 128),
            "active_since": _integer(params, "active_since", None, 0, 4102444800),
            "active_till": _integer(params, "active_till", None, 0, 4102444800),
            "timeperiods": params.get("timeperiods"),
        }
        if body["active_since"] is None or body["active_till"] is None or body["active_since"] >= body["active_till"]:
            raise ZabbixPackError("active_since must be earlier than active_till")
        if not isinstance(body["timeperiods"], list) or not body["timeperiods"] or len(body["timeperiods"]) > 100:
            raise ZabbixPackError("timeperiods must be a non-empty array with at most 100 entries")
        allowed_timeperiod_fields = {"period", "timeperiod_type", "start_date", "start_time", "every", "day", "dayofweek", "month"}
        for timeperiod in body["timeperiods"]:
            if not isinstance(timeperiod, dict) or not set(timeperiod) <= allowed_timeperiod_fields:
                raise ZabbixPackError("each timeperiod must contain only current Zabbix time period fields")
            period_type = timeperiod.get("timeperiod_type", 0)
            if isinstance(period_type, bool) or not isinstance(period_type, int) or period_type not in {0, 2, 3, 4}:
                raise ZabbixPackError("timeperiod_type must be 0, 2, 3, or 4")
            period = timeperiod.get("period", 3600)
            if isinstance(period, bool) or not isinstance(period, int) or not 300 <= period <= 86399940:
                raise ZabbixPackError("timeperiod period must be from 300 to 86399940 seconds")
        host_ids = _ids(params.get("host_ids"), "host_ids")
        group_ids = _ids(params.get("group_ids"), "group_ids")
        if not host_ids and not group_ids:
            raise ZabbixPackError("at least one host_id or group_id is required")
        if host_ids:
            body["hosts"] = [{"hostid": item} for item in host_ids]
        if group_ids:
            body["groups"] = [{"groupid": item} for item in group_ids]
        body["maintenance_type"] = _integer(params, "maintenance_type", 0, 0, 1)
        if params.get("description") is not None:
            body["description"] = _nonempty(params["description"], "description", 2048)
        if operation == "maintenance_update":
            body["maintenanceid"] = _id(params.get("maintenance_id"), "maintenance_id")
        return _mutation(client, "maintenance.create" if operation.endswith("create") else "maintenance.update", body)
    if operation == "maintenance_delete":
        maintenance_id = _id(params.get("maintenance_id"), "maintenance_id")
        _confirmation(params.get("confirmation"), f"DELETE MAINTENANCE {maintenance_id}")
        return _mutation(client, "maintenance.delete", [maintenance_id])

    if operation == "problem_list":
        query = {"output": "extend", "selectAcknowledges": "extend", "selectTags": "extend", "selectSuppressionData": "extend", "sortfield": ["eventid"], "sortorder": "DESC", **_time_range(params)}
        host_ids = _ids(params.get("host_ids"), "host_ids")
        if host_ids:
            query["hostids"] = host_ids
        if params.get("recent") is not None:
            query["recent"] = _boolean(params, "recent")
        severities = params.get("severities")
        if severities is not None:
            if not isinstance(severities, list) or not severities or any(isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= 5 for v in severities):
                raise ZabbixPackError("severities must be a non-empty array containing values from 0 to 5")
            query["severities"] = severities
        return _limited(client, "problem.get", query, params)
    if operation == "event_list":
        query = {"output": "extend", "source": 0, "object": 0, "selectHosts": ["hostid", "host", "name"], "selectAcknowledges": "extend", "selectTags": "extend", "sortfield": ["eventid"], "sortorder": "DESC", **_time_range(params)}
        host_ids = _ids(params.get("host_ids"), "host_ids")
        if host_ids:
            query["hostids"] = host_ids
        eventid_from = params.get("event_id_from")
        if eventid_from is not None:
            query["eventid_from"] = _id(eventid_from, "event_id_from")
        return _limited(client, "event.get", query, params)
    if operation == "event_acknowledge":
        event_id = _id(params.get("event_id"), "event_id")
        close = _boolean(params, "close", False)
        message = params.get("message")
        if close:
            _confirmation(params.get("confirmation"), f"CLOSE EVENT {event_id}")
        action = 2
        body: dict[str, Any] = {"eventids": [event_id]}
        if message is not None:
            body["message"] = _nonempty(message, "message", 2048)
            action |= 4
        if close:
            action |= 1
        body["action"] = action
        return _mutation(client, "event.acknowledge", body)

    if operation == "alert_list":
        query = {"output": ["alertid", "actionid", "eventid", "userid", "mediatypeid", "clock", "sendto", "subject", "message", "status", "retries", "error"], "sortfield": "alertid", "sortorder": "DESC", **_time_range(params)}
        event_ids = _ids(params.get("event_ids"), "event_ids")
        if event_ids:
            query["eventids"] = event_ids
        return _limited(client, "alert.get", query, params)
    if operation == "history_get":
        query = {"output": "extend", "history": _integer(params, "history_type", 0, 0, 5), "itemids": _ids(params.get("item_ids"), "item_ids", required=True), "sortfield": "clock", "sortorder": params.get("sort_order", "DESC"), **_time_range(params, 2147483647)}
        if query["sortorder"] not in {"ASC", "DESC"}:
            raise ZabbixPackError("sort_order must be ASC or DESC")
        return _limited(client, "history.get", query, params)

    if operation == "user_list":
        query = {"output": ["userid", "username", "name", "surname", "url", "autologin", "autologout", "lang", "refresh", "theme", "rows_per_page", "roleid"], "selectUsrgrps": ["usrgrpid", "name"], "selectMedias": ["mediaid", "mediatypeid", "sendto", "active", "severity", "period"], "sortfield": "userid", **_search(params, "username")}
        return _limited(client, "user.get", query, params)
    if operation == "media_type_list":
        query = {"output": ["mediatypeid", "name", "type", "status", "description", "maxattempts"], "sortfield": "mediatypeid", **_search(params, "name")}
        return _limited(client, "mediatype.get", query, params)

    if operation == "script_execute":
        script_id = _id(params.get("script_id"), "script_id")
        host_id = _id(params.get("host_id"), "host_id")
        _confirmation(params.get("confirmation"), f"EXECUTE SCRIPT {script_id} ON HOST {host_id}")
        return _mutation(client, "script.execute", {"scriptid": script_id, "hostid": host_id})

    raise ZabbixPackError(f"unsupported curated operation: {operation}")


def execute_action(operation: str, params: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(params, Mapping):
        raise ZabbixPackError("action parameters must be a JSON object")
    timeout = _integer(params, "timeout_seconds", 30, 1, 120)
    assert timeout is not None
    profile = fetch_key(str(params.get("credential_key", DEFAULT_CREDENTIAL_KEY)))
    with ZabbixClient(profile, timeout) as client:
        data, meta = dispatch(client, operation, params)
        return {
            "operation": operation,
            "request_id": client.last_request_id,
            "data": data,
            "meta": {"mutating": operation in _MUTATIONS, **meta},
        }
