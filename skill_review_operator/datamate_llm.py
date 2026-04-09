# -*- coding: utf-8 -*-
"""
从 DataMate Python 后端拉取「模型接入」配置，并调用 OpenAI 兼容 Chat Completions。
仅使用标准库，便于算子包无额外依赖部署。

默认后端地址可通过环境变量覆盖：
  DATAMATE_BACKEND_PYTHON_URL=http://datamate-backend-python:18000
"""

from __future__ import annotations

import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

DEFAULT_BACKEND_BASE = (
    os.environ.get("DATAMATE_BACKEND_PYTHON_URL", "").strip()
    or "http://datamate-backend-python:18000"
).rstrip("/")


def _http_get_json(url: str, timeout: float = 30.0) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    return json.loads(raw)


def _http_post_json(url: str, body: Dict[str, Any], headers: Dict[str, str], timeout: float = 180.0) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    data = json.dumps(body).encode("utf-8")
    h = {"Content-Type": "application/json", **headers}
    req = urllib.request.Request(url, data=data, method="POST", headers=h)
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    return json.loads(raw)


def unwrap_success(payload: Dict[str, Any]) -> Any:
    """DataMate StandardResponse: code \"0\" 表示成功。"""
    code = str(payload.get("code", ""))
    if code != "0":
        msg = payload.get("message") or payload.get("detail") or "unknown"
        raise RuntimeError(f"API 错误: code={code} message={msg}")
    return payload.get("data")


def chat_completions_url(base_url: str) -> str:
    b = (base_url or "").strip().rstrip("/")
    if not b:
        raise ValueError("baseUrl 为空")
    if b.endswith("/v1"):
        return f"{b}/chat/completions"
    return f"{b}/v1/chat/completions"


def fetch_model_detail(backend_base: str, model_id: str, timeout: float = 30.0) -> Dict[str, Any]:
    base = backend_base.rstrip("/")
    url = f"{base}/api/models/{urllib.parse.quote(model_id)}"
    payload = _http_get_json(url, timeout=timeout)
    data = unwrap_success(payload)
    if not isinstance(data, dict):
        raise RuntimeError("模型详情格式异常")
    return data


def fetch_default_chat_model(backend_base: str, timeout: float = 30.0) -> Optional[Dict[str, Any]]:
    """返回启用的默认 CHAT 模型；若无则 None。"""
    base = backend_base.rstrip("/")
    q = urllib.parse.urlencode(
        {
            "page": 0,
            "size": 20,
            "type": "CHAT",
            "isEnabled": "true",
            "isDefault": "true",
        }
    )
    url = f"{base}/api/models/list?{q}"
    payload = _http_get_json(url, timeout=timeout)
    data = unwrap_success(payload)
    if not isinstance(data, dict):
        return None
    content = data.get("content")
    if not isinstance(content, list) or not content:
        return None
    first = content[0]
    return first if isinstance(first, dict) else None


def openai_style_chat(
    base_url: str,
    api_key: str,
    model_name: str,
    system_text: str,
    user_text: str,
    *,
    temperature: float = 0.2,
    timeout: float = 180.0,
) -> str:
    url = chat_completions_url(base_url)
    headers: Dict[str, str] = {}
    ak = (api_key or "").strip()
    if ak:
        headers["Authorization"] = f"Bearer {ak}"

    body = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_text},
            {"role": "user", "content": user_text},
        ],
        "temperature": temperature,
    }
    out = _http_post_json(url, body, headers, timeout=timeout)
    try:
        return str(out["choices"][0]["message"]["content"])
    except (KeyError, IndexError, TypeError) as e:
        raise RuntimeError(f"Chat 响应结构异常: {e}") from e


def try_parse_json_object(raw: str) -> Optional[Dict[str, Any]]:
    if not raw or not str(raw).strip():
        return None
    text = str(raw).strip()
    m = re.search(r"```json\s*([\s\S]*?)```", text, re.I)
    if m:
        text = m.group(1).strip()
    else:
        s = text.find("{")
        e = text.rfind("}")
        if s != -1 and e != -1 and e > s:
            text = text[s : e + 1]
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def resolve_usable_chat_model(
    backend_base: str,
    *,
    model_id: Optional[str],
    use_default_model: bool,
    timeout: float = 30.0,
) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    返回 (model_dict, error_message)。
    model_dict 含 modelName, baseUrl, apiKey, type, isEnabled 等。
    """
    mid = (model_id or "").strip()
    if mid:
        try:
            m = fetch_model_detail(backend_base, mid, timeout=timeout)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, RuntimeError, json.JSONDecodeError) as e:
            return None, f"无法拉取模型配置（modelId={mid!r}）：{e}"
    elif use_default_model:
        try:
            m = fetch_default_chat_model(backend_base, timeout=timeout)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, RuntimeError, json.JSONDecodeError) as e:
            return None, f"无法枚举默认模型：{e}"
        if not m:
            return None, "未配置默认 CHAT 模型，请在「设置 → 模型接入」中设置默认模型，或在算子参数中填写 modelId。"
    else:
        return None, "未指定 modelId，且未启用「使用默认模型」。"

    if not m:
        return None, "未找到可用模型配置。"
    if str(m.get("type", "")).upper() != "CHAT":
        return None, f"模型类型不是 CHAT（当前为 {m.get('type')!r}）。"
    if m.get("isEnabled") is False:
        return None, "该模型已禁用，请在模型接入中启用后重试。"

    base = (m.get("baseUrl") or "").strip()
    name = (m.get("modelName") or "").strip()
    if not base or not name:
        return None, "模型配置缺少 baseUrl 或 modelName。"

    return m, None
