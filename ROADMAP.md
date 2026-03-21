# Causal Memory Layer — Roadmap

Этот roadmap описывает эволюцию CML как слоя реальности,
от семантики → к операционной системе → к инфраструктуре → к железу.

Мы движемся не по скорости, а по устойчивости смысла.


---

## v0.1 — Foundation (✅ завершено)

**Цель:**
Зафиксировать Causal Memory Layer как онтологический слой, а не модуль или фичу.

**Состояние:**

- Определён scope и non-goals
- Чётко отделены:
  - CML (что существует как память)
  - vCML (как это живёт в системе)
  - транспорт / исполнение (out of scope)

**Зафиксирован инвариант:**

> A system may be functionally correct while being causally invalid.

**Результат:**
CML существует как цитируемый фундамент.


---

## v0.2 — vCML Skeleton (✅ завершено)

**Цель:**
Показать, как CML может жить в реальной системе, не теряя чистоты.

**Deliverables:**

- `vcml/README.md`
- `vcml/FORMAT.md`
- `vcml/linux-ebpf/README.md`
- пустые reference-структуры (`bpf/`, `user/`)

**Важно:**
Нет кода исполнения. Только форма и смысл.


---

## v0.3 — First Boundary (exec) (✅ завершено)

**Цель:**
Оживить vCML на одной границе смысла.

**Фокус:**
exec / запуск процесса

**Deliverables:**

- `vcml/linux-ebpf/exec_monitor.py` — рабочий eBPF-монитор
- causal record stream (JSONL)
- demo: запуск с/без `parent_cause`


---

## v0.4 — Causal Tags in Action (CTAG) (✅ завершено)

**Цель:**
Доказать, что каузальные теги — не теория.

**Deliverables:**

- `vcml/CTAG.md` — спецификация 16-бит CTAG
- `cml/ctag.py` — полная реализация DOM/CLASS/GEN/LHINT/SEAL
- `cml/` — Python SDK (record, chain, audit, report)
- `cli/main.py` — CLI (`cml audit`, `cml chain`, `cml ctag`, `cml decode`, `cml report`)
- `api/server.py` — FastAPI REST API
- `tests/` — 49 тестов, все проходят
- `pyproject.toml` — pip-installable пакет (`pip install causal-memory-layer`)


---

## v0.5 — Multi-Boundary Memory (✅ завершено)

**Цель:**
Показать, что CML — память системы, а не процессов.

**Добавлено:**

- `vcml/linux-ebpf/file_monitor.py` — мониторинг open/read
- `vcml/linux-ebpf/net_monitor.py` — мониторинг connect/send
- `vcml/linux-ebpf/combined_monitor.py` — единый монитор всех трёх границ

**Цепочка:**
exec → secret access (open/read) → network egress (connect/send)

**Обнаружение:**
- egress без каузальной причины (R3: `CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN`)
- `SECRET` → `NET` без causal chain


---

## v0.6 — Hypervisor Semantics (✅ завершено)

**Цель:**
Расширить причинность выше одной ОС.

**Deliverables:**

- `vcml/hypervisor/README.md` — язык и правила кросс-VM каузальности
- VM / tenant как causal domains (DOM table)
- cross-VM causal chain semantics (`dom_crossing` record)
- R3-HV: расширение правила SECRET→NET_OUT на межVM-контекст


---

## v0.7 — Hardware Mapping (✅ завершено)

**Цель:**
Показать, что CML естественно ложится на железо.

**Deliverables:**

- `vcml/hardware/CTAG-8-16.md` — CTAG-8 (сжатый) + CTAG-16 mapping
- `vcml/hardware/riscv-pointer-masking.md` — RISC-V Smmpm/Ssnpm
- `vcml/hardware/cheri-capability-causality.md` — CHERI otype + CML

Это уровень research / architecture, не продукта.


---

## v0.8 — Monetization & Distribution (🔲 следующий)

**Цель:**
Превратить CML в устойчивый продукт.

**Deliverables:**

- PyPI release (`pip install causal-memory-layer`)
- Hosted Audit API (managed service)
- Compliance packs (SOC 2, GDPR, PCI-DSS)
- Enterprise SDK (multi-tenant, SIEM integrations)
- `PRICING.md` — Community / Pro / Enterprise tiers ✅
- `LICENSE_COMMERCIAL.md` — Open Core model ✅
- `docs/enterprise/compliance_guide.md` ✅
- `docs/sdk/quickstart.md` ✅


---

## Принцип темпа

Каждая версия должна:

- быть маленькой
- быть проверяемой
- иметь одну истину

Если версия не усиливает смысл — она не выпускается.


---

## Не-цели (важно)

- Не строим security product
- Не делаем policy engine
- Не оптимизируем производительность раньше смысла
- Не "продаём" идею раньше доказательства

CML — это слой, который должен пережить свои реализации.
