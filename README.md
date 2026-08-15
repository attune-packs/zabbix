# Zabbix Attune Pack

This pack translates the Apache-2.0 StackStorm Exchange Zabbix pack at exact
revision `1b3ebdca44dab27c1a58ed11819a63d5b329d3f8` (`v2.0.0`) into a curated
Attune integration. It replaces 139 broad wrappers with 30 explicit actions, a
single direct JSON-RPC client, and one managed polling sensor. See
[SOURCE.md](SOURCE.md) for the verified source and current API baseline.

The implementation targets current stable Zabbix 7.4.13 at release commit
`3c95000629791258a59622e3e4e995df45c44453`, verified with the 7.4 JSON-RPC
documentation on 2026-08-15. The upstream pack's Zabbix 6.0.46 target is
preserved as source metadata but is not claimed as this pack's runtime baseline.

## Requirements

- Python 3.10 or newer on Attune action and sensor workers.
- Zabbix 7.4 with HTTPS enabled for the frontend API endpoint.
- A least-privilege Zabbix API token, or a current username/password account.
- An encrypted, pack-owned Attune Key for actions, normally
  `zabbix.credentials`.
- For the sensor only, a protected JSON file mounted below `/run/secrets` and
  persistent writable storage below `/var/lib/attune/zabbix`.

## Credential Profiles

Every action accepts a `credential_key` reference and resolves the encrypted
Key at execution time. Credentials are never accepted as action parameters.
API token profile:

```json
{
  "api_url": "https://zabbix.example.com/zabbix/api_jsonrpc.php",
  "auth": {
    "type": "api_token",
    "token": "REDACTED"
  },
  "verify_tls": true
}
```

Current username/password profile:

```json
{
  "api_url": "https://zabbix.example.com/api_jsonrpc.php",
  "auth": {
    "type": "password",
    "username": "attune-automation",
    "password": "REDACTED"
  },
  "verify_tls": true,
  "ca_bundle_pem": "-----BEGIN CERTIFICATE-----\nREDACTED PRIVATE CA\n-----END CERTIFICATE-----"
}
```

`api_url` must use HTTPS, contain no URL credentials/query/fragment, and end in
`/api_jsonrpc.php`. TLS verification cannot be disabled for authenticated
access. `ca_bundle_pem` replaces the worker trust bundle for the execution; it
is written to a mode-0600 temporary file and removed on normal completion. A
hard kill can bypass cleanup, so worker temporary storage must remain private.

API tokens and login session tokens are sent only in the current
`Authorization: Bearer` header. Login credentials appear only in the
`user.login` request. Redirects, environment proxy inheritance, response bodies
over 16 MiB, malformed or mismatched JSON-RPC IDs, and plaintext endpoints are
rejected. Timeouts are bounded to 1 through 120 seconds. No JSON-RPC call is
automatically retried, particularly no mutation.

Errors expose normalized HTTP status, exception type, or JSON-RPC code/message.
They never include response bodies or JSON-RPC error `data`; known credential
values are redacted from the bounded message. Unknown exceptions are opaque at
the action boundary.

## Actions

| Area | Actions |
|---|---|
| Connectivity | `zabbix.api_version` |
| Hosts | `host_list`, `host_get`, `host_create`, `host_update`, `host_delete`, `monitoring_set` |
| Host groups | `host_group_list`, `host_group_create`, `host_group_update`, `host_group_delete` |
| Templates | `template_list`, `template_link`, `template_unlink` |
| Distributed monitoring | `proxy_list`, `proxy_group_list` |
| Discovery | `item_list`, `trigger_list` |
| Maintenance | `maintenance_list`, `maintenance_create`, `maintenance_update`, `maintenance_delete` |
| Problems and events | `problem_list`, `event_list`, `event_acknowledge` |
| Data and alerts | `alert_list`, `history_get` |
| Users and media | `user_list`, `media_type_list` |
| Controlled execution | `script_execute` |

All contracts are flat JSON objects delivered on stdin. Complex Zabbix
collections such as interfaces and maintenance time periods remain explicit
arrays of objects rather than opaque JSON strings. Each action returns:

```json
{
  "operation": "host_list",
  "request_id": "0f...-1",
  "data": [],
  "meta": {
    "mutating": false,
    "count": 0,
    "limit": 100,
    "truncated": false
  }
}
```

Read actions request `limit + 1`, return at most `limit` records, and report
`truncated`. Zabbix get methods do not provide a universal stable offset cursor;
the pack does not pretend that they do. `event_list` exposes `event_id_from` for
ID-based continuation. Time parameters are UTC Unix epoch seconds and reject
reversed ranges. General event/alert ranges are bounded through 2100;
`history_get` is bounded through signed-32-bit epoch `2147483647` to match its
7.4.13 API validator. History also requires one explicit value type because
Zabbix stores history types separately.

## Mutation Safety

- `host_update` cannot replace groups, templates, interfaces, or monitoring
  status. Those high-blast-radius concerns have dedicated actions or are
  deliberately omitted.
- `host_create` accepts only agent, IPMI, or JMX interface fields. SNMP
  `details` are deliberately rejected because community and authentication
  material must not travel in ordinary action parameters.
- `template_link` calls additive `host.massadd`. `template_unlink` calls
  `host.massremove` with `templateids`, never the clear variant, so inherited
  entities are not deleted.
- Template link and unlink are capped at 100 IDs and require host-and-ID-bound
  confirmations.
- Monitoring changes preflight the immutable host ID. Disabling requires
  `DISABLE MONITORING <host_id>` exactly.
- Deletions require `DELETE HOST <id>`, `DELETE HOST GROUP <id>`, or
  `DELETE MAINTENANCE <id>` exactly.
- Event close uses current `event.acknowledge` action bits and requires
  `CLOSE EVENT <event_id>`. Zabbix will reject close when the trigger does not
  allow manual close or the event/account is ineligible.
- Remote execution only invokes a preconfigured Zabbix script on one host. It
  accepts no command text, event target, or ad hoc parameters and requires
  `EXECUTE SCRIPT <script_id> ON HOST <host_id>` exactly.
- Mutations are never retried. A timeout can leave outcome unknown; reconcile
  with a read action before deciding whether to run another mutation.

## Problem Event Sensor

`zabbix.problem_poll` maps safely to Attune's managed sensor runtime and emits
`zabbix.problem_event`. It polls current trigger problem events (`source=0`,
`object=0`, `value=1`) in ascending numeric event ID order. Each rule must use a
unique checkpoint path:

```json
{
  "credential_file": "/run/secrets/zabbix/sensor.json",
  "checkpoint_file": "/var/lib/attune/zabbix/production-problems.json",
  "poll_interval_seconds": 30,
  "initial_lookback_seconds": 300,
  "batch_size": 100,
  "host_ids": ["10084"]
}
```

The credential file contains the same JSON profile as an action Key. Managed
sensors use a separately mounted file because action-time Key access must not be
assumed for a long-lived sensor token. The path is confined to `/run/secrets`,
must be a regular JSON file, and is limited to 64 KiB. Rotation takes effect
when the rule is restarted or updated. Do not put the credential file in the
pack or checkpoint volume.

Checkpoint files are confined below `/var/lib/attune/zabbix`, versioned JSON,
mode 0600, atomically replaced, and fsynced with their directory. A nonblocking
lock prevents two active pollers from sharing one checkpoint. Mount this path
on persistent storage and back it up consistently; deleting or rolling it back
replays events according to `initial_lookback_seconds` or the older checkpoint.

Delivery is **at least once**. The sensor writes the checkpoint only after
`emit` succeeds, preventing acknowledged checkpoint progress from dropping an
event. A crash after Attune accepts an event but before the checkpoint fsync can
produce a duplicate. Deduplicate downstream by `event_id`. Ordering is ascending
within one rule and checkpoint, but no ordering is promised across rules,
sensor workers, or retries. If event volume exceeds polling capacity, the
sensor drains consecutive ID batches before sleeping. A persistent API or emit
failure blocks checkpoint advancement and retries with bounded backoff.

This sensor is preferred over an inbound webhook because it needs no exposed
listener or shared webhook secret and can provide durable source-side progress.
No webhook component is included.

## Deliberate Omissions

The pack omits arbitrary method dispatch, mass host mutation, interface
replacement, template clear, user/media writes, credential/token management,
configuration import, script CRUD, and broad discovery-rule CRUD. These are
either lower-value, easy to misuse, or have a blast radius that deserves a
separate reviewed workflow.

## Validation

All tests are deterministic and mock Zabbix, Attune Key access, and sensor
emission. No live Zabbix endpoint or undeclared test package is used.

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q actions lib sensors tests
attune --output json pack check /home/david/Codebase/attune-packs/zabbix
attune pack test "/home/david/Codebase/attune-packs/zabbix" --detailed
```

Live validation remains deployment-specific: API roles, manual-close settings,
script permissions, proxy mode, template content, TLS PKI, event retention, and
sensor persistent-volume ownership cannot be proven by mocked tests.

## License

The verified upstream Apache License 2.0 text is included in [LICENSE](LICENSE).
Attribution and modification details are in [NOTICE](NOTICE).
