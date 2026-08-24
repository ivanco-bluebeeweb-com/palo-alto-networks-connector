# Palo Alto Networks Connector — UI component plan

Источники: `Docs/session-notes/UI_COMPONENT_VOCABULARY.md`, `UI_INTERFACE_STANDARD.md`,
`concepts/panels.md`. Основано на функционале `palo-alto-networks-connector`
(см. `PREPARATION.md`).

**ВАЖНО (усвоено на Zscaler/Cisco Secure Access/Fortinet Connector —
реальные ошибки DUI-валидатора, не повторять):** `ui.Stack` НЕ принимает
`width=`. `ui.Stats` принимает `children=[ui.Stat(...)]`, НЕ `stats=[...]`/
`items=[dict]`. `ui.Alert` принимает `type=`, НЕ `variant=`. `ui.Badge`
принимает `label=`/`color=`, НЕ `text=`/`variant=`. `ui.Input`/`ui.Password`/
`ui.Select` НЕ принимают `label=` — использовать соседний
`ui.Text(..., variant="caption")` внутри `ui.Stack(direction="v", gap=1)`.
Модалка помощи регистрируется как `@ext.panel(..., slot="center",
center_overlay=True)` и открывается через `ui.Call("__panel__<name>")`, НЕ
через несуществующий `@ext.modal`.

## 0. Разница с реализацией сейчас

Реализация начинается с нуля вместе с этим документом — план строится ПЕРЕД
`panels.py`, по правилу APP_PREPARATION_STANDARD.md §9. Начальный `panels.py`
реализует ровно §1 ниже.

## 1. Компоненты

| Экран | Примитивы | Почему именно эти |
|---|---|---|
| Sidebar (left) | `ui.Stack`(direction="v") + `ui.Text`(host summary) + `ui.Divider` + navigation `ui.ListItem`(Security Rules / Objects / Panorama / Health) + `ui.Button`("App settings") | Без карточек, как Fortinet/Cisco Secure Access Connector. |
| Connect: PAN-OS section | `ui.Stack`(direction="v", gap=1, children=[`ui.Text`("Host", variant="caption"), `ui.Input`(param_name="host", placeholder="https://fw01.company.com")]) + аналогично Input для username + Password для password + submit `ui.Button` | Каждый инпут с явным лейблом-соседом, контекстный placeholder. |
| Connect: Panorama section | `ui.Stack`(...) с host/username/password | Вторая независимая секция, форма растянута на всю ширину сайдбара. |
| Empty (нет ни одного подключения) | `ui.Empty`(message="Подключите PAN-OS firewall или Panorama", icon="Shield") | Явное объяснение вместо пустого экрана. |
| Center: base overview | `ui.Stack`(direction="v") + `ui.Stats`(children=[ui.Stat(...)]) — счётчик rules/objects/managed devices | Стандартный обзорный экран, как у остальных SASE-коннекторов. |
| Center: Security Rules overlay | `ui.Table` или `ui.Stack` со списком правил + `ui.Badge`(label=status, color=...) | Таблица с бейджем статуса вместо текстового поля. |
| Help modal (Connect) | `@ext.panel("pan_connect_help", slot="center", center_overlay=True)` с инструкцией по keygen | Инструкция ТОЛЬКО здесь, не дублируется в сайдбаре. |
| App settings (center overlay) | `ui.Stack` со списком подключений + `ui.Button`("Disconnect", variant="danger") на каждое | Disconnect только здесь, никогда рядом с формой подключения. |

## 2. Действия commit / reorder — предупреждения

`commit_config` и `reorder_security_rule` показывают `ui.Alert(type="warning", ...)`
перед выполнением: commit может занять минуты и не имеет отмены; reorder
меняет порядок реально только после следующего commit.
