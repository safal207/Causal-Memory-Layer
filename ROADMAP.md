Causal Memory Layer — Roadmap

Этот roadmap описывает эволюцию CML как слоя реальности,
от семантики → к операционной системе → к инфраструктуре → к железу.

Мы движемся не по скорости, а по устойчивости смысла.


---

v0.1 — Foundation (✅ завершено)

Цель:
Зафиксировать Causal Memory Layer как онтологический слой, а не модуль или фичу.

Состояние:

Определён scope и non-goals

Чётко отделены:

CML (что существует как память)

vCML (как это живёт в системе)

транспорт / исполнение (out of scope)


Зафиксирован инвариант:

> A system may be functionally correct while being causally invalid.




Результат:
CML существует как цитируемый фундамент.


---

v0.2 — vCML Skeleton

Цель:
Показать, как CML может жить в реальной системе, не теряя чистоты.

Deliverables:

vcml/README.md

vcml/FORMAT.md

vcml/linux-ebpf/README.md

пустые reference-структуры (bpf/, user/)


Важно:
Нет кода исполнения. Только форма и смысл.


---

v0.3 — First Boundary (exec)

Цель:
Оживить vCML на одной границе смысла.

Фокус:
exec / запуск процесса

Deliverables:

минимальный hook (eBPF или user-space)

causal record stream (JSONL)

demo:

запуск с parent_cause

запуск без parent_cause (каузально сомнительно)




---

v0.4 — Causal Tags in Action (CTAG)

Цель:
Доказать, что каузальные теги — не теория.

Deliverables:

vcml/CTAG.md

DOM / CLASS / GEN / LHINT / SEAL

bump GEN на EXEC / PRIV

LHINT вычисляется и проверяется

простой chain-validator (vcml audit)



---

v0.5 — Multi-Boundary Memory

Цель:
Показать, что CML — память системы, а не процессов.

Добавляем:

filesystem (open/write)

network (connect/send)


Deliverables:

цепочка: exec → secret access → data egress

обнаружение:

egress без допустимой причины

SECRET → NET без causal chain




---

v0.6 — Hypervisor Semantics

Цель:
Расширить причинность выше одной ОС.

Deliverables:

hypervisor/README.md

VM / tenant как causal domains

cross-VM causal chain semantics


Без реализации. Только язык и правила.


---

v0.7 — Hardware Mapping

Цель:
Показать, что CML естественно ложится на железо.

Deliverables:

hardware/CTAG-8-16.md

hardware/riscv-pointer-masking.md

hardware/cheri-capability-causality.md


Это уровень research / architecture, не продукта.


---

Принцип темпа

Каждая версия должна:

быть маленькой

быть проверяемой

иметь одну истину


Если версия не усиливает смысл — она не выпускается.



---

Не-цели (важно)

Не строим security product

Не делаем policy engine

Не оптимизируем производительность

Не “продаём” идею раньше времени


CML — это слой, который должен пережить свои реализации.
