#!/usr/bin/env python3
"""Managed at-least-once poller for Zabbix trigger problem events."""

from __future__ import annotations

import fcntl
import json
import os
import stat
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

_PACK_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACK_ROOT not in sys.path:
    sys.path.insert(0, _PACK_ROOT)

from lib.zabbix_client import (
    ZabbixClient,
    ZabbixPackError,
    _id,
    _ids,
    _integer,
    read_credential_file,
)

CHECKPOINT_ROOT = Path("/var/lib/attune/zabbix")


def checkpoint_path(value: Any) -> Path:
    if not isinstance(value, str) or not os.path.isabs(value) or not value.endswith(".json"):
        raise ZabbixPackError("checkpoint_file must be an absolute .json path")
    path = Path(value)
    resolved_parent = path.parent.resolve()
    root = CHECKPOINT_ROOT.resolve()
    if resolved_parent != root and root not in resolved_parent.parents:
        raise ZabbixPackError("checkpoint_file must be below /var/lib/attune/zabbix")
    if path.exists() and path.is_symlink():
        raise ZabbixPackError("checkpoint_file must not be a symbolic link")
    return path


def read_checkpoint(path: Path) -> int | None:
    try:
        if not path.exists():
            return None
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or details.st_size > 4096:
                raise ZabbixPackError("checkpoint_file must be a small regular file")
            raw = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
        if len(raw) > 4096:
            raise ZabbixPackError("checkpoint_file must be a small regular file")
        value = json.loads(raw)
    except ZabbixPackError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ZabbixPackError("checkpoint_file is unreadable or invalid") from None
    if not isinstance(value, dict) or value.get("version") != 1:
        raise ZabbixPackError("checkpoint_file has an unsupported format")
    return int(_id(value.get("last_eventid"), "checkpoint last_eventid"))


def write_checkpoint(path: Path, event_id: int) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        payload = json.dumps({"version": 1, "last_eventid": str(event_id)}, separators=(",", ":")).encode()
        os.write(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def event_payload(event: Mapping[str, Any]) -> dict[str, Any]:
    event_id = _id(event.get("eventid"), "event eventid")
    clock = event.get("clock")
    object_id = _id(event.get("objectid"), "event objectid")
    try:
        occurred_at = int(clock)
        severity = int(event.get("severity", 0))
    except (TypeError, ValueError):
        raise ZabbixPackError("event contained invalid clock or severity") from None
    if occurred_at < 0 or not 0 <= severity <= 5:
        raise ZabbixPackError("event contained out-of-range clock or severity")
    name = event.get("name", "")
    if not isinstance(name, str):
        raise ZabbixPackError("event contained an invalid name")
    acknowledged = str(event.get("acknowledged", "0")) == "1"
    hosts = event.get("hosts", [])
    tags = event.get("tags", [])
    if not isinstance(hosts, list) or not isinstance(tags, list):
        raise ZabbixPackError("event contained invalid host or tag data")
    return {
        "event_id": event_id,
        "occurred_at": occurred_at,
        "trigger_id": object_id,
        "name": name,
        "severity": severity,
        "acknowledged": acknowledged,
        "hosts": hosts,
        "tags": tags,
        "event": dict(event),
    }


class ProblemPoller:
    def __init__(self, rule: Any, logger: Any, emit: Callable[[dict[str, Any]], Any]):
        self.rule = rule
        self.rule_id = int(getattr(rule, "rule_id", 0) or 0)
        self.logger = logger
        self.emit = emit
        self.config = dict(rule.trigger_params or {})
        self.interval = _integer(self.config, "poll_interval_seconds", 30, 5, 300) or 30
        self.lookback = _integer(self.config, "initial_lookback_seconds", 300, 0, 86400)
        self.batch = _integer(self.config, "batch_size", 100, 1, 1000) or 100
        self.host_ids = _ids(self.config.get("host_ids"), "host_ids")
        self.path = checkpoint_path(self.config.get("checkpoint_file"))
        self.credentials = read_credential_file(self.config.get("credential_file"))
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"zabbix-problems-{self.rule_id}", daemon=True)
        self._lock_file: Any = None

    def start(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        descriptor = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise ZabbixPackError("checkpoint lock must be a regular file")
        os.fchmod(descriptor, 0o600)
        self._lock_file = os.fdopen(descriptor, "a+", encoding="utf-8")
        try:
            fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._lock_file.close()
            self._lock_file = None
            raise ZabbixPackError("checkpoint_file is already used by another active poller") from None
        self._thread.start()

    def stop(self) -> bool:
        self._stop.set()
        self._thread.join(timeout=10)
        stopped = not self._thread.is_alive()
        if stopped and self._lock_file is not None:
            fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
            self._lock_file.close()
            self._lock_file = None
        return stopped

    def poll_once(self, client: ZabbixClient, now: int | None = None) -> int:
        checkpoint = read_checkpoint(self.path)
        emitted = 0
        while not self._stop.is_set():
            checkpoint_before_batch = checkpoint
            query: dict[str, Any] = {
                "output": ["eventid", "source", "object", "objectid", "clock", "ns", "value", "name", "severity", "acknowledged", "r_eventid", "cause_eventid"],
                "source": 0,
                "object": 0,
                "value": 1,
                "selectHosts": ["hostid", "host", "name"],
                "selectTags": "extend",
                "selectSuppressionData": "extend",
                "sortfield": ["eventid"],
                "sortorder": "ASC",
                "limit": self.batch,
            }
            if self.host_ids:
                query["hostids"] = self.host_ids
            if checkpoint is not None:
                query["eventid_from"] = str(checkpoint + 1)
            else:
                current = int(time.time()) if now is None else now
                query["time_from"] = max(0, current - int(self.lookback or 0))
            events = client.call("event.get", query)
            if not isinstance(events, list):
                raise ZabbixPackError("event.get returned an invalid result")
            ordered = sorted(events, key=lambda item: int(_id(item.get("eventid") if isinstance(item, dict) else None, "event eventid")))
            for event in ordered:
                payload = event_payload(event)
                numeric_id = int(payload["event_id"])
                if checkpoint is not None and numeric_id <= checkpoint:
                    continue
                self.emit(payload)
                write_checkpoint(self.path, numeric_id)
                checkpoint = numeric_id
                emitted += 1
            if len(events) == self.batch and checkpoint == checkpoint_before_batch:
                raise ZabbixPackError("event.get pagination made no checkpoint progress")
            if len(events) < self.batch or not events:
                break
        return emitted

    def _run(self) -> None:
        failures = 0
        while not self._stop.is_set():
            try:
                with ZabbixClient(self.credentials, 30) as client:
                    emitted = self.poll_once(client)
                failures = 0
                if emitted:
                    self.logger.info("rule %s emitted %s Zabbix problem events", self.rule_id, emitted)
                self._stop.wait(self.interval)
            except Exception as exc:  # noqa: BLE001
                failures += 1
                delay = min(60, 2 ** min(failures - 1, 6))
                self.logger.warning("rule %s Zabbix poll failed: %s", self.rule_id, type(exc).__name__)
                self._stop.wait(delay)


def _production_sensor() -> type:
    import attune

    class ZabbixProblemSensor(attune.Sensor):
        def __init__(self) -> None:
            super().__init__()
            self._workers: dict[int, ProblemPoller] = {}
            self._lock = threading.Lock()

        @staticmethod
        def _rule_id(rule: Any) -> int:
            return int(getattr(rule, "rule_id", 0) or 0)

        def _stop_worker(self, rule_id: int) -> bool:
            with self._lock:
                worker = self._workers.get(rule_id)
            if worker is None:
                return True
            stopped = worker.stop()
            if stopped:
                with self._lock:
                    if self._workers.get(rule_id) is worker:
                        self._workers.pop(rule_id, None)
            return stopped

        def _start_worker(self, rule: Any) -> None:
            rule_id = self._rule_id(rule)
            if not self._stop_worker(rule_id):
                raise RuntimeError("existing Zabbix poller is still stopping")

            def emit(payload: dict[str, Any]) -> Any:
                return self.emit(payload, rule=rule, target_rule=True)

            worker = ProblemPoller(rule, self.logger, emit)
            worker.start()
            with self._lock:
                self._workers[rule_id] = worker

        def on_rule_created(self, rule: Any) -> None:
            self._start_worker(rule)

        def on_rule_enabled(self, rule: Any) -> None:
            self._start_worker(rule)

        def on_rule_updated(self, rule: Any, old_params: dict[str, Any]) -> None:
            self._start_worker(rule)

        def on_rule_disabled(self, rule: Any) -> None:
            self._stop_worker(self._rule_id(rule))

        def on_rule_deleted(self, rule: Any) -> None:
            self._stop_worker(self._rule_id(rule))

        def run(self) -> None:
            while not self.is_shutting_down:
                time.sleep(1)

        def cleanup(self) -> None:
            with self._lock:
                rule_ids = list(self._workers)
            for rule_id in rule_ids:
                self._stop_worker(rule_id)

    return ZabbixProblemSensor


def main() -> None:
    import attune

    attune.run_sensor(_production_sensor())


if __name__ == "__main__":
    main()
