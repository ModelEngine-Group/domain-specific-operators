# -*- coding: utf-8 -*-
"""
Skill 包审查算子：读取 DataMate 数据集中已落盘的 .zip / .tar.gz，输出 JSON 审查结果到 text 字段。
不包含上传逻辑；文件由数据集上传并映射为 sample['filePath']。
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict

from datamate.core.base_op import Mapper

from .review_engine import (
    detect_archive_format,
    review_result_to_json_text,
    run_skill_review,
)

def _parse_skill_meta_from_sample(sample: Dict[str, Any]) -> Dict[str, Any]:
    """从 ext_params（JSON 字符串或 dict）中读取可选的 skill 元信息。"""
    ep = sample.get("ext_params")
    if ep is None:
        return {}
    if isinstance(ep, dict):
        raw = ep
    else:
        try:
            raw = json.loads(ep) if isinstance(ep, str) else {}
        except json.JSONDecodeError:
            return {}
    if not isinstance(raw, dict):
        return {}
    skill = raw.get("skill_meta") or raw.get("skillMeta")
    if isinstance(skill, dict):
        return dict(skill)
    return {}


def _is_supported_skill_package(file_name: str) -> bool:
    n = (file_name or "").strip().lower()
    return n.endswith(".zip") or n.endswith(".tar.gz")


class SkillReviewMapper(Mapper):
    """
    对数据集中的单个 Skill 压缩包做静态规则审查。
    raw_id / 类名须与 metadata.yml 一致。
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # LLM 固定开启：模型配置从算子参数读取（独立于 DataMate 设置页模型接入）。
        self.model_provider = str(kwargs.get("modelProvider") or kwargs.get("model_provider") or "").strip()
        self.model_base_url = str(kwargs.get("modelBaseUrl") or kwargs.get("model_base_url") or "").strip()
        self.model_name = str(kwargs.get("modelName") or kwargs.get("model_name") or "").strip()
        self.model_api_key = str(kwargs.get("modelApiKey") or kwargs.get("model_api_key") or "").strip()
        try:
            self.model_temperature = float(kwargs.get("modelTemperature", kwargs.get("model_temperature", 0.2)))
        except (TypeError, ValueError):
            self.model_temperature = 0.2
        try:
            self.model_timeout_sec = int(kwargs.get("modelTimeoutSec", kwargs.get("model_timeout_sec", 180)))
        except (TypeError, ValueError):
            self.model_timeout_sec = 180

    def execute(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        file_path = sample.get(self.filepath_key) or sample.get("filePath")
        file_name = sample.get(self.filename_key) or sample.get("fileName") or ""
        if not file_path:
            raise ValueError("样本缺少 filePath，无法定位 Skill 包文件。")

        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Skill 包文件不存在: {file_path}")

        if not _is_supported_skill_package(str(file_name)):
            raise ValueError(
                "本算子仅支持 .zip 与 .tar.gz 的 Skill 包；请在数据集中上传对应格式，"
                f"当前 fileName={file_name!r}。"
            )

        fmt = detect_archive_format(file_name)
        if fmt not in ("zip", "tar.gz"):
            raise ValueError(f"无法从文件名识别压缩格式: {file_name!r}")
        # 必填模型参数硬校验（不依赖前端是否拦截）
        missing = []
        if not self.model_base_url:
            missing.append("模型 Base URL")
        if not self.model_name:
            missing.append("模型名称")
        if not self.model_api_key:
            missing.append("模型 API Key")
        if missing:
            raise ValueError(f"语义层模型配置缺失必填项：{', '.join(missing)}。请在算子参数中补全后重试。")

        skill_meta = _parse_skill_meta_from_sample(sample)
        result = run_skill_review(
            file_path,
            file_name,
            skill_meta=skill_meta,
            enable_llm=True,
            llm_provider=self.model_provider or None,
            llm_base_url=self.model_base_url or None,
            llm_model_name=self.model_name or None,
            llm_api_key=self.model_api_key or None,
            llm_temperature=self.model_temperature,
            llm_timeout_sec=self.model_timeout_sec,
        )
        sample[self.text_key] = review_result_to_json_text(result)
        # DataMate 的 FileExporter 对 zip 不会走文本落盘分支，强制标记为 txt 输出，
        # 让审查结果可落到目标数据集并在页面可下载/对比。
        base_name = os.path.splitext(str(file_name))[0] if file_name else "skill_review_result"
        sample[self.filetype_key] = "txt"
        sample[self.filename_key] = f"{base_name}.txt"

        return sample
