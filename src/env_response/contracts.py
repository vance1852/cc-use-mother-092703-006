"""环境事件响应领域输入契约。"""

from __future__ import annotations

import re
from typing import AbstractSet, Any, Mapping

from .errors import ValidationFailed


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
EVIDENCE_KINDS = {"monitor_alert", "field_retest", "third_party", "calibration", "manual"}
CONTAMINANTS = {"voc", "pm", "noise", "wastewater", "soil", "other"}
ROLES = {"duty", "field", "dispatcher", "remediation", "reviewer", "auditor"}
DECISION_RESULTS = {"confirmed", "downgraded", "dismissed"}
REVIEW_VERDICTS = {"approved", "rejected"}


def required_text(value: object, field: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailed(f"{field} 不能为空")
    result = value.strip()
    if len(result) > maximum:
        raise ValidationFailed(f"{field} 不能超过 {maximum} 个字符")
    return result


def optional_text(value: object, field: str, maximum: int = 512) -> str | None:
    if value is None:
        return None
    return required_text(value, field, maximum)


def identifier(value: object, field: str) -> str:
    result = required_text(value, field, 64)
    if not IDENTIFIER.fullmatch(result):
        raise ValidationFailed(f"{field} 格式不正确")
    return result


def choice(value: object, field: str, allowed: AbstractSet[str]) -> str:
    result = required_text(value, field, 32)
    if result not in allowed:
        raise ValidationFailed(f"{field} 必须是 {sorted(allowed)} 之一")
    return result


def zone_codes(value: object, field: str = "zones", *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValidationFailed(f"{field} 必须是字符串数组")
    result = [item.strip() for item in value if item.strip()]
    if len(result) != len(value):
        raise ValidationFailed(f"{field} 不能含空编号")
    if not allow_empty and not result:
        raise ValidationFailed(f"{field} 至少包含一个区域")
    if len(set(result)) != len(result):
        raise ValidationFailed(f"{field} 不能包含重复区域")
    for item in result:
        if not IDENTIFIER.fullmatch(item):
            raise ValidationFailed(f"{field} 中 {item} 格式不正确")
    return result


def record_fields(value: object) -> list[dict[str, Any]]:
    """校验并发提交的现场记录，返回规范化列表。"""
    if not isinstance(value, list) or not value:
        raise ValidationFailed("records 必须是非空数组")
    records: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        field = f"records[{index}]"
        if not isinstance(item, Mapping):
            raise ValidationFailed(f"{field} 必须是对象")
        records.append(
            {
                "source_ref": identifier(item.get("source_ref"), f"{field}.source_ref"),
                "zone_code": identifier(item.get("zone_code"), f"{field}.zone_code"),
                "reading_text": required_text(item.get("reading"), f"{field}.reading", 64),
                "observed_at": required_text(item.get("observed_at"), f"{field}.observed_at", 40),
                "note": optional_text(item.get("note"), f"{field}.note", 512) or "",
            }
        )
    refs = [record["source_ref"] for record in records]
    if len(set(refs)) != len(refs):
        raise ValidationFailed("同一批次内 source_ref 重复")
    return records
