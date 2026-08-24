# Palo Alto Networks Connector — Connector Discovery

**Дата discovery:** 2026-08-24. SIEM/SOAR-серия — "максимальный функционал,
полный максимум" заявлен для всей серии заранее (тот же прецедент, что
Zscaler/CircleCI/MuleSoft), повторный вопрос не требуется.

## 1. Разграничение с Cortex XDR Connector — не дублировать EDR

Cortex XDR Connector в этом портфеле уже покрывает EDR/XDR-поверхность
Palo Alto Networks (Incidents/Alerts/Endpoints/IOCs). "Palo Alto Networks
Connector" здесь — это **сетевая security-поверхность**: PAN-OS firewall
(NGFW) + Panorama (централизованное управление парком firewall). Та же
логика разделения, что у Microsoft Defender for Endpoint Connector (EDR) vs
Microsoft Sentinel Connector (SIEM) в этом портфеле — разные продукты одного
вендора для разных задач.

## 2. Две поверхности, тот же паттерн, что Fortinet Connector

- **PAN-OS XML/REST API** (`https://{firewall}/api/` или `/restapi/v10.x/`)
  — device-level, прямое управление ОДНИМ firewall: Security Rules, Address/
  Service Objects, Zones, commit. Авторизация: API key, получаемый через
  `GET /api/?type=keygen&user=X&password=Y` один раз, затем передаётся как
  `key` query param в каждом запросе.
- **Panorama XML/REST API** — централизованное управление парком PAN-OS
  устройств через Device Groups + Templates + shared/vsys политики,
  push конфигурации на управляемые firewalls. Тот же API формат, что PAN-OS
  (Panorama — надстройка над тем же XML API), но отдельный host и отдельные
  Device Group scoping параметры.

## 3. WHY XML API (type=config), а не только REST API v10+

PAN-OS REST API (v10.0+) покрывает не 100% операций (например, commit и
некоторые Panorama push-операции доступны только через классический XML
API). Коннектор использует XML API как основной транспорт (`type=config`,
`type=op`, `type=commit`) для универсальности — тот же выбор, что делают
большинство сторонних интеграций (Ansible pan-os-python модуль, Terraform
provider) вместо REST-only подхода.

## 4. WHY api_key, а не username/password в каждом запросе

PAN-OS/Panorama API key — долгоживущий токен, генерируемый один раз через
keygen-запрос, что избегает передачи пароля в каждом вызове (та же практика,
что рекомендует официальная документация Palo Alto). Коннектор просит
пользователя выполнить keygen один раз вручную (или делает это сам при
первом connect с username/password, сохраняя только полученный ключ).

## 5. WHY commit — явное действие с предупреждением о времени выполнения

Изменения конфигурации PAN-OS (add rule, address object) не применяются к
трафику до `commit` — придаточный, потенциально долгий (десятки секунд)
процесс, который может провалиться при синтаксической ошибке в конфиге.
Инструмент `commit_config` явно асинхронный (job id + опрос статуса), не
притворяется мгновенным.

## 6. Security Rule reordering — тот же риск, что Fortinet firewall policy

PAN-OS обрабатывает security rules по порядку (first-match), поэтому
reorder — операция с реальным risk of blast radius (правило "deny all"
выше правила "allow specific" мгновенно ломает нужный трафик). Тот же
паттерн предупреждения, что `reorder_firewall_policy` у Fortinet Connector.

## 7. Scope (Ярус 1+2+3, максимум по заявленному объёму)

**Ярус 1 (PAN-OS device):** connect/disconnect, list/get/create/update/
delete Security Rules, reorder, list/create/update/delete Address Objects +
Address Groups, list/create/update/delete Service Objects, list Zones,
list Interfaces, get System Info, commit config, get job status.

**Ярус 2 (Panorama):** connect/disconnect, list Device Groups, list Managed
Firewalls (with connection status), list/create Panorama-scoped Security
Rules (pre/post rulebase), push config to Device Group (commit-all), list
Templates.

**Ярус 3 (Value-add):** `audit_paloalto_estate` (aggregated health: total
rules across connected devices, disabled/shadowed-looking rules by simple
heuristic, disconnected managed firewalls in Panorama, pending uncommitted
changes), `bulk_security_rule_action` (enable/disable several rules across
one device in one call).
