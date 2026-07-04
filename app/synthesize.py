from __future__ import annotations

from collections import defaultdict
from typing import Any


def _fmt_num(fact: dict[str, Any]) -> str:
    unit = fact.get("unit") or ""
    if fact.get("min_value") is not None or fact.get("max_value") is not None:
        return f"{fact.get('min_value')}–{fact.get('max_value')} {unit}".strip()
    if fact.get("numeric_value") is not None:
        return f"{fact.get('comparator') or '='}{fact.get('numeric_value')} {unit}".strip()
    return fact.get("value_text") or ""


def _source_label(source: dict[str, Any]) -> str:
    parts = [source.get("title") or "Источник"]
    if source.get("year"):
        parts.append(str(source["year"]))
    if source.get("geography"):
        parts.append(source["geography"])
    return " / ".join(parts)


def _citation(source_title: str | None, locator: str | None = None, span: list[Any] | tuple[Any, Any] | None = None) -> str:
    parts = [source_title or "без источника"]
    if locator:
        parts.append(str(locator))
    if span and span[0] is not None and span[1] is not None:
        parts.append(f"span {span[0]}-{span[1]}")
    return " · ".join(parts)


def estimate_confidence(payload: dict[str, Any]) -> float:
    scores = []
    for source in payload.get("sources", []):
        if source.get("reliability_score") is not None:
            scores.append(float(source["reliability_score"]))
    for fact in payload.get("facts", []):
        if fact.get("confidence") is not None:
            scores.append(float(fact["confidence"]))
        if fact.get("extraction_confidence") is not None:
            scores.append(float(fact["extraction_confidence"]))
    for exp in payload.get("experiments", []):
        if exp.get("reliability_score") is not None:
            scores.append(float(exp["reliability_score"]))
    if not scores:
        return 0.2
    base = sum(scores) / len(scores)
    coverage_bonus = min(0.12, 0.02 * len(payload.get("sources", [])) + 0.02 * len(payload.get("experiments", [])))
    gap_penalty = min(0.25, 0.08 * len(payload.get("gaps", [])))
    contradiction_penalty = min(0.15, 0.05 * len(payload.get("contradictions", [])))
    suspicious = sum(1 for fact in payload.get("facts", []) if fact.get("validation_status") not in {None, "valid"})
    validation_penalty = min(0.12, 0.015 * suspicious)
    return round(max(0.0, min(1.0, base + coverage_bonus - gap_penalty - contradiction_penalty - validation_penalty)), 2)


def _md_cell(value: Any, max_len: int = 120) -> str:
    text = str(value or "").replace("\n", " ").replace("|", "/").strip()
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def _append_comparison_section(lines: list[str], facts: list[dict[str, Any]], contradictions: list[dict[str, Any]]) -> None:
    lines.append("### Таблица сравнения")
    if not facts:
        lines.append("Недостаточно извлечённых фактов для сравнения.")
        lines.append("")
        return
    lines.append("| Параметр | Значение | Источник | Confidence | Доказательство |")
    lines.append("|---|---:|---|---:|---|")
    for fact in facts[:12]:
        parameter = fact.get("property") or fact.get("object_name") or fact.get("predicate")
        source = _citation(fact.get("source_title"), fact.get("evidence_locator"))
        lines.append(
            f"| {_md_cell(parameter)} | {_md_cell(_fmt_num(fact), 40)} | {_md_cell(source, 80)} | "
            f"{_md_cell(fact.get('confidence'), 20)} | {_md_cell(fact.get('evidence'), 140)} |"
        )
    if contradictions:
        lines.append("")
        lines.append("Ключевые расхождения:")
        for item in contradictions[:3]:
            lines.append(f"- {item.get('subject')} / {item.get('property')}: {item.get('comment')}")
    lines.append("")


def _append_protocol_section(lines: list[str], facts: list[dict[str, Any]], experiments: list[dict[str, Any]]) -> None:
    lines.append("### Протокол первичной проверки")
    lines.append("1. Зафиксировать исходные материалы, процесс и целевые числовые ограничения из найденных фактов.")
    lines.append("2. Сопоставить условия с экспериментами или публикациями, где указаны похожие параметры.")
    lines.append("3. Отметить факты с непроверенным или подозрительным extraction status для экспертной верификации.")
    lines.append("4. Подготовить решение только на evidence items с источником, locator/span и приемлемой надёжностью.")
    lines.append("")
    if facts:
        lines.append("Контрольные параметры:")
        for fact in facts[:8]:
            lines.append(f"- {fact.get('property') or fact.get('predicate')}: {_fmt_num(fact)}; источник: {_citation(fact.get('source_title'), fact.get('evidence_locator'))}.")
        lines.append("")
    if experiments:
        lines.append("Опорные эксперименты/протоколы:")
        for exp in experiments[:5]:
            lines.append(f"- {exp.get('experiment_key') or ''} {exp.get('title')}: {exp.get('result_summary')}")
        lines.append("")


def _append_gap_section(lines: list[str], sources: list[dict[str, Any]], facts: list[dict[str, Any]], gaps: list[str]) -> None:
    lines.append("### Gap analysis")
    if gaps:
        lines.append("Выявленные пробелы:")
        for gap in gaps:
            lines.append(f"- {gap}")
    else:
        lines.append("Явных пробелов по текущему запросу не найдено, но это не заменяет экспертную проверку полноты корпуса.")
    lines.append("")
    lines.append("Покрытие evidence:")
    lines.append(f"- Источники: {len(sources)}")
    lines.append(f"- Извлечённые факты: {len(facts)}")
    lines.append(f"- Факты с locator/span: {sum(1 for fact in facts if fact.get('evidence_locator') and fact.get('evidence_start') is not None)}")
    lines.append("")


def _append_evidence_table_section(lines: list[str], facts: list[dict[str, Any]]) -> None:
    lines.append("### Evidence table")
    if not facts:
        lines.append("Нет извлечённых фактов для evidence table.")
        lines.append("")
        return
    lines.append("| Fact ID | Predicate | Value | Source | Locator | Status |")
    lines.append("|---:|---|---|---|---|---|")
    for fact in facts[:20]:
        lines.append(
            f"| {_md_cell(fact.get('id'), 20)} | {_md_cell(fact.get('predicate'), 50)} | {_md_cell(_fmt_num(fact), 50)} | "
            f"{_md_cell(fact.get('source_title'), 80)} | {_md_cell(fact.get('evidence_locator'), 40)} | "
            f"{_md_cell(fact.get('validation_status') or 'valid', 30)} |"
        )
    lines.append("")


def synthesize_answer(payload: dict[str, Any]) -> str:
    parsed = payload.get("parsed_query", {})
    answer_mode = payload.get("answer_mode") or "review"
    sources = payload.get("sources", [])
    facts = payload.get("facts", [])
    experiments = payload.get("experiments", [])
    experts = payload.get("experts", [])
    gaps = payload.get("gaps", [])
    contradictions = payload.get("contradictions", [])
    confidence = estimate_confidence(payload)

    lines: list[str] = []
    lines.append(f"## Ответ по запросу")
    lines.append("")
    if sources:
        lines.append(f"Найдено {len(sources)} релевантных источников, {len(experiments)} экспериментов и {len(facts)} извлечённых фактов. Оценка уверенности: **{confidence:.2f}**.")
    else:
        lines.append(f"Релевантные источники не найдены. Оценка уверенности: **{confidence:.2f}**.")
    lines.append("")

    if parsed.get("materials") or parsed.get("processes") or parsed.get("geography") or parsed.get("numeric_conditions"):
        lines.append("### Что система поняла из запроса")
        lines.append(f"- Материалы: {', '.join(parsed.get('materials') or []) or 'не выделены'}")
        lines.append(f"- Процессы: {', '.join(parsed.get('processes') or []) or 'не выделены'}")
        lines.append(f"- География: {', '.join(parsed.get('geography') or []) or 'без фильтра'}")
        if parsed.get("year_from") or parsed.get("year_to"):
            lines.append(f"- Период: {parsed.get('year_from') or '...'}–{parsed.get('year_to') or '...'}")
        if parsed.get("numeric_conditions"):
            conds = []
            for c in parsed["numeric_conditions"]:
                conds.append(f"{c.get('property') or 'параметр'} {c.get('comparator')} {c.get('value') or (str(c.get('min_value')) + '–' + str(c.get('max_value')))} {c.get('unit')}")
            lines.append(f"- Числовые условия: {'; '.join(conds)}")
        lines.append("")

    if answer_mode == "comparison":
        _append_comparison_section(lines, facts, contradictions)
    elif answer_mode == "protocol":
        _append_protocol_section(lines, facts, experiments)
    elif answer_mode == "gap_analysis":
        _append_gap_section(lines, sources, facts, gaps)
    elif answer_mode == "evidence_table":
        _append_evidence_table_section(lines, facts)

    # Group facts by process/property.
    if facts:
        lines.append("### Проверенные факты и ограничения")
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for f in facts:
            key = f.get("subject_name") or f.get("property") or f.get("predicate") or "прочее"
            grouped[key].append(f)
        for key, items in list(grouped.items())[:8]:
            lines.append(f"**{key}**")
            for fact in items[:5]:
                value = _fmt_num(fact)
                source = _citation(
                    fact.get("source_title"),
                    fact.get("evidence_locator"),
                    [fact.get("evidence_start"), fact.get("evidence_end")],
                )
                evidence = fact.get("evidence") or fact.get("value_text") or ""
                numeric_match = " ✅" if fact.get("numeric_match") else ""
                validation = ""
                if fact.get("validation_status") and fact.get("validation_status") != "valid":
                    warnings = ", ".join(fact.get("validation_warnings") or [])
                    validation = f" Статус извлечения: {fact.get('validation_status')} ({warnings})."
                lines.append(f"- {fact.get('predicate')}: {fact.get('property') or fact.get('object_name') or ''} {value}{numeric_match}. Источник: {source}.{validation} Доказательство: {evidence}")
            lines.append("")

    if experiments:
        lines.append("### Эксперименты и протоколы")
        for exp in experiments[:8]:
            lines.append(f"- **{exp.get('experiment_key') or ''} {exp.get('title')}** ({exp.get('year')}, {exp.get('geography')}): {exp.get('result_summary')} Надёжность: {exp.get('reliability_score')}. Команда: {exp.get('team')}.")
        lines.append("")

    if sources:
        lines.append("### Источники")
        for idx, source in enumerate(sources[:10], 1):
            access = source.get("confidentiality") or ""
            locator = f", фрагмент: {source.get('locator')}" if source.get("locator") else ""
            lines.append(f"{idx}. **{_source_label(source)}**{locator} — тип: {source.get('source_type')}, доступ: {access}, надёжность: {source.get('reliability_score')}. {source.get('snippet') or ''}")
        lines.append("")

    if contradictions:
        lines.append("### Противоречия / зоны расхождения")
        for item in contradictions[:5]:
            lines.append(f"- **{item.get('subject')} / {item.get('property')}**: {item.get('comment')}")
            for s in item.get("sources", [])[:3]:
                lines.append(f"  - {s.get('source_title')}: диапазон {s.get('range')}, confidence={s.get('confidence')}")
        lines.append("")

    if gaps:
        lines.append("### Пробелы знаний")
        for gap in gaps:
            lines.append(f"- {gap}")
        lines.append("")

    if experts:
        lines.append("### Эксперты и команды")
        for expert in experts[:6]:
            matched = ", ".join(expert.get("matched_topics") or [])
            lines.append(f"- **{expert.get('name')}**, {expert.get('organization')} — темы: {matched or ', '.join(expert.get('expertise') or [])}; контакт: {expert.get('contact')}.")
        lines.append("")

    lines.append("### Вывод MVP")
    if gaps:
        lines.append("Ответ можно использовать как черновик аналитической справки, но перед принятием технического решения требуется экспертная верификация фактов, отмеченных как пробелы или расхождения.")
    else:
        lines.append("В найденных источниках есть достаточная связка документов, экспериментов, числовых условий и экспертов для подготовки первичного технического обзора.")
    return "\n".join(lines)


def attach_answer(payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(payload)
    payload["confidence"] = estimate_confidence(payload)
    payload["answer_markdown"] = synthesize_answer(payload)
    return payload
