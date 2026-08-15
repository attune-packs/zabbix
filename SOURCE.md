# Verified Source And API Baseline

## Upstream Pack

- Repository: `https://github.com/StackStorm-Exchange/stackstorm-zabbix`
- Default branch: `master`
- Revision: `1b3ebdca44dab27c1a58ed11819a63d5b329d3f8`
- Exact tag/version: `v2.0.0` / `2.0.0`
- Author and commit time: Carlos (`nzlosh`), `2026-06-12T07:11:52+02:00`
- Commit subject: `Merge pull request #63 from namachieli/master`
- Upstream declared target: Zabbix `6.0.46`, StackStorm `3.9`, 139 actions
- License: Apache License 2.0 (`Apache-2.0`)
- Upstream NOTICE: none at the verified revision
- Verification date: `2026-08-15`

The tag, branch head, commit object, `pack.yaml`, `CHANGELOG.md`, and `LICENSE`
were checked at the revision above. The upstream is a design and attribution
source; this repository is a curated rewrite and does not copy its 139 wrapper
definitions or its `zabbix-utils` client abstraction.

## Zabbix API

- Current stable documentation channel on verification date: Zabbix `7.4`
- Current stable release: Zabbix `7.4.13`, released `2026-07-29`
- Release commit: `3c95000629791258a59622e3e4e995df45c44453`
- Annotated tag object: `c3081970df553f080409386405b3a760e270e8ff`
- Zabbix source license: `AGPL-3.0-only` (reference inspection only;
  no Zabbix server source is copied into this pack)
- Baseline: `https://www.zabbix.com/documentation/current/en/manual/api`
- JSON-RPC version: `2.0`
- Endpoint: deployment-specific HTTPS URL ending in `/api_jsonrpc.php`
- Authentication: `Authorization: Bearer` with an API token or the token
  returned by current `user.login` using `username` and `password`
- Current methods used: `apiinfo.version`, `user.login`, `host.get`,
  `host.create`, `host.update`, `host.delete`, `host.massadd`,
  `host.massremove`, `hostgroup.get/create/update/delete`, `template.get`,
  `proxy.get`, `proxygroup.get`, `item.get`, `trigger.get`,
  `maintenance.get/create/update/delete`, `problem.get`, `event.get`,
  `event.acknowledge`, `alert.get`, `history.get`, `user.get`,
  `mediatype.get`, and `script.execute`

The release tag and `ZABBIX_API_VERSION` in `ui/include/defines.inc.php` were
verified against the Zabbix source repository. This pack intentionally targets
the verified current 7.4.13 contracts. The
upstream pack's Zabbix 6.0 target is source metadata, not a compatibility claim
for this implementation. Run `zabbix.api_version` before deployment and review
the action against the exact server minor release, roles, and feature settings.
