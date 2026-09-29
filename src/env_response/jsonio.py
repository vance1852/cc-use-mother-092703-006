"""确定性的规范化 JSON 与内容摘要。"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _json_default(value: object) -> object:
    raise TypeError(f"不能序列化 {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """生成跨平台一致的紧凑 JSON 文本。"""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    )


def content_digest(value: Any) -> str:
    """计算规范化内容的 SHA-256 摘要。"""

    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def stable_json(value: Any) -> str:
    """输出带缩进的稳定 JSON，便于离线验收与人工核对。"""

    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2)
