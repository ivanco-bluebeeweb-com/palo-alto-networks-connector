# Palo Alto Networks Connector — Preparation (Фаза 2.5, до кода)

**Дата:** 2026-08-24. Основано на `CONNECTOR_DISCOVERY.md`. SIEM/SOAR-серия —
"максимальный функционал, полный максимум" заявлен заранее, повторный вопрос
не требуется.

## 1. WHY BYOK

PAN-OS firewall и Panorama живут в собственной сети клиента (on-prem или
private cloud appliance) — Imperal не брокерит доступ централизованно, тот
же принцип, что Fortinet Connector/Cisco Secure Access Connector.

## 2. WHY два раздельных connect_* инструмента (PAN-OS + Panorama), не один

Firewall и Panorama — разные устройства с разными IP/hostname и, как
правило, разными учётными данными (Panorama управляет множеством
firewalls). Пользователь может иметь только firewall (малый офис), только
Panorama (крупная организация без прямого доступа к железу), или оба. Тот
же паттерн раздельных `connect_*`, что Fortinet Connector (FortiGate/
FortiManager/FortiSASE) и Cisco Secure Access Connector (Umbrella/Meraki).

## 3. WHY API key получается один раз через keygen, а не вводится вручную заранее

PAN-OS API key технически можно сгенерировать в GUI (Device > Setup >
Management > API Key), но `type=keygen` endpoint позволяет коннектору
получить его программно из username+password при первом подключении —
убирает шаг "иди в GUI, найди этот раздел, скопируй ключ" и сразу
подтверждает, что креды рабочие. Коннектор хранит полученный API key,
НЕ пароль — тот же принцип, что OAuth2 token exchange где сохраняется
результат обмена, а не исходный секрет.

## 4. WHY XML API (`type=config`/`type=op`/`type=commit`), а не только REST v10+

REST API v10+ не покрывает commit и часть Panorama push-операций — те
доступны только через классический XML API. Коннектор строит единый
XML-based клиент (`pan_client.py`) поверх которого READ-операции проекции
уже структурируются в удобные Pydantic-модели, а не выставляет сырой XML
пользователю.

## 5. WHY commit требует явного подтверждения и предупреждения о времени выполнения

`commit_config` — потенциально долгая (минуты) и потенциально прерывающая
операция (плохое правило может заблокировать легитимный трафик сразу после
применения). Описание инструмента явно предупреждает об этом и требует
explicit confirmation — тот же класс риска, что isolate_endpoint/
block_ip_on_firewall в остальном портфеле.

## 6. WHY security rule reorder — отдельный инструмент, не часть update

PAN-OS порядок security rules определяет приоритет match — перемещение
правила меняет реальное поведение трафика немедленно после commit. Явно
отдельный `reorder_security_rule` (before/after target rule) делает
намерение перемещения видимым в истории вызовов, а не скрытым внутри
generic update.

## 7. Scope (Ярус 1+2+3, максимум по заявленному объёму)

**Ярус 1 (must-have):** connect_panos, connect_panorama, disconnect,
list_connections; list_security_rules, get_security_rule,
create_security_rule, update_security_rule, delete_security_rule,
reorder_security_rule; list_address_objects, create/update/delete
address object; list_service_objects, create/update/delete service
object; commit_config.

**Ярус 2:** list_zones; list_interfaces; get_system_info (firewall
version/serial/uptime); list_threat_logs / list_traffic_logs (security
event visibility — SOC triage surface); list_panorama_device_groups,
list_panorama_managed_devices, push_panorama_config.

**Ярус 3 (value-add):** audit_panos_estate (aggregated health: rule count,
disabled rules, uncommitted changes across connected firewalls/Panorama);
bulk_security_rule_action (enable/disable several rules at once, same
`bulk_*` convention as Fortinet's `bulk_firewall_policy_action`).

## 8. UI shape (высокий уровень, детали в UI_COMPONENT_PLAN.md)

Sidebar: no cards, two independent connect sections (PAN-OS / Panorama),
nav to Security Rules / Address & Service Objects / Panorama overview /
Health audit, single "App settings" button at the bottom — same shape as
Fortinet Connector's panels.py.
