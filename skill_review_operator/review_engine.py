# -*- coding: utf-8 -*-
"""
Skill 包静态审查引擎（规则层，与 data2ontology skill 审查 TS 版语义对齐，纯 Python，无上传/落盘逻辑）。
输入：本地已存在的压缩包路径 + 原始文件名（用于识别 zip / tar.gz）。
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    from . import datamate_llm
except ImportError:
    import datamate_llm  # 独立加载 review_engine.py 时（无包上下文）

MAX_ARCHIVE_FILES = 200
MAX_TEXT_SAMPLES = 12
MAX_SAMPLE_BYTES = 256 * 1024
MAX_SAMPLE_CHARS = 2000
MAX_TOTAL_SAMPLE_CHARS = 16000
MAX_SECTION_ISSUES = 10
MAX_AI_FINDINGS_PER_SECTION = 3

DEFAULT_SECTION_TITLES = {
    "script": "代码静态检查",
    "format": "Skill 规范检查",
    "sensitive": "敏感信息检查",
    "prompt": "Prompt 注入检查",
}

DEFAULT_PASSED_SUMMARIES = {
    "script": "采样文件中未发现高风险的动态执行或命令调用模式。",
    "format": "当前包结构满足以 SKILL.md 为核心的 Agent Skill 基础规范检查。",
    "sensitive": "采样文件中未发现明显的明文密钥或凭证模式。",
    "prompt": "采样文件中未发现明显的 Prompt 注入或提示词泄露表达。",
}

DEFAULT_FAILED_SUMMARIES = {
    "script": "检测到潜在危险的执行能力，需修复后再提交。",
    "format": "包内缺少必要的 SKILL.md 或当前无法完成足够深度的检查，因此未通过基础规范审查。",
    "sensitive": "检测到疑似密钥或凭证信息，发布前需要移除。",
    "prompt": "检测到疑似 Prompt 注入或提示词泄露表达。",
}

DEFAULT_PASSED_OPINIONS = {
    "script": "可以继续进入发布前流程，但建议将运行时执行能力限制在明确允许的入口内。",
    "format": "在当前以 SKILL.md 为核心的基础规范下，该包可以继续进入后续审查环节。",
    "sensitive": "请通过运行时注入方式提供凭证，不要将其直接写入包体。",
    "prompt": "请继续保持提示词边界清晰，避免后续引入覆盖或泄露类指令。",
}

DEFAULT_FAILED_OPINIONS = {
    "script": "请移除动态执行路径，或通过严格白名单限制后再重新提交。",
    "format": "请补齐缺失的 SKILL.md 或必要说明文件后，重新上传新的提交包。",
    "sensitive": "请将密钥迁移到运行时配置或密钥管理系统，并上传清理后的包体。",
    "prompt": "请收紧提示词内容，移除覆盖指令、越狱和系统提示词泄露类表达。",
}

TEXT_EXTENSIONS = {
    ".md",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".sh",
    ".ps1",
    ".bat",
    ".cmd",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".sql",
}

SCRIPT_EXTENSIONS = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".sh",
    ".ps1",
    ".bat",
    ".cmd",
}

SKILL_FILE_PATTERN = re.compile(r"^skill\.md$", re.I)
MANIFEST_FILE_PATTERN = re.compile(r"^(skill|manifest)\.(json|ya?ml)$", re.I)
README_FILE_PATTERN = re.compile(r"^readme(\.[^.]+)?$", re.I)
PROMPT_FILE_PATTERN = re.compile(r"(prompt|instruction|system|template|guide)", re.I)

SCRIPT_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"\beval\s*\(", re.I), "发现通过 eval() 执行动态代码的能力。", "high"),
    (re.compile(r"new Function\s*\(", re.I), "发现通过 new Function 构造动态函数的能力。", "high"),
    (re.compile(r"\bchild_process\b", re.I), "发现 Node.js 子进程执行能力。", "high"),
    (re.compile(r"\b(exec|spawn|execFile|fork)\s*\(", re.I), "发现进程执行入口。", "high"),
    (re.compile(r"\bos\.system\s*\(", re.I), "发现通过 os.system() 执行 Shell 命令的能力。", "high"),
    (
        re.compile(r"\bsubprocess\.(run|Popen|call|check_call|check_output)\s*\(", re.I),
        "发现 subprocess 进程执行能力。",
        "high",
    ),
    (re.compile(r"\bshell\s*=\s*True\b", re.I), "发现 shell=True，命令执行风险较高。", "high"),
    (re.compile(r"\bInvoke-Expression\b", re.I), "发现 PowerShell 的 Invoke-Expression。", "high"),
    (re.compile(r"\bProcess\.Start\s*\(", re.I), "发现 .NET 的 Process.Start 进程启动能力。", "high"),
    (re.compile(r"\bcurl\b", re.I), "发现外部下载命令 curl。", "medium"),
    (re.compile(r"\bwget\b", re.I), "发现外部下载命令 wget。", "medium"),
    (re.compile(r"\bInvoke-WebRequest\b", re.I), "发现 PowerShell 的网络下载命令 Invoke-WebRequest。", "medium"),
    (re.compile(r"\brm\s+-rf\b", re.I), "发现高危删除命令 rm -rf。", "medium"),
    (re.compile(r"\bRemove-Item\b.*-Recurse", re.I), "发现递归删除命令。", "medium"),
]

SENSITIVE_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I), "发现私钥内容块。", "high"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "发现 AWS Access Key ID。", "high"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "发现 OpenAI 风格的 API Key。", "high"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "发现 GitHub Personal Access Token。", "high"),
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}\b"), "发现 Google API Key。", "high"),
    (
        re.compile(
            r"\b(api[_-]?key|secret|token|password|passwd|private[_-]?key)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]",
            re.I,
        ),
        "发现明文内联密钥/口令赋值。",
        "medium",
    ),
    (
        re.compile(r"\b(BEARER|Bearer)\s+[A-Za-z0-9._\-]{12,}\b"),
        "发现明文 Bearer Token。",
        "medium",
    ),
]

PROMPT_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (
        re.compile(
            r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|prior|above)\b.{0,30}\b(instruction|prompt|message)s?\b",
            re.I,
        ),
        "发现覆盖上文指令的提示词表达。",
        "high",
    ),
    (re.compile(r"\bjailbreak\b", re.I), "发现明确的越狱提示词表达。", "high"),
    (
        re.compile(
            r"\b(reveal|show|print)\b.{0,30}\b(system prompt|developer message|hidden instruction)s?\b",
            re.I,
        ),
        "发现提示词/系统消息泄露表达。",
        "high",
    ),
    (
        re.compile(r"\b(bypass|override)\b.{0,30}\b(safety|policy|guardrail|restriction)s?\b", re.I),
        "发现绕过安全策略的提示词表达。",
        "high",
    ),
    (re.compile(r"忽略.{0,20}(之前|先前|上面).{0,20}(指令|提示词|消息)"), "发现中文的指令覆盖表达。", "high"),
    (re.compile(r"(泄露|展示|输出).{0,20}(系统提示词|开发者消息|隐藏指令)"), "发现中文的提示词泄露表达。", "high"),
    (re.compile(r"(绕过|越过).{0,20}(限制|安全|策略|护栏)"), "发现中文的安全绕过表达。", "high"),
]


@dataclass
class PackageFileEntry:
    path: str
    size: int


@dataclass
class PackageTextSample:
    path: str
    size: int
    content: str
    truncated: bool


@dataclass
class PackageInspection:
    archive_format: str
    inspection_level: str
    files: List[PackageFileEntry] = field(default_factory=list)
    text_samples: List[PackageTextSample] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def normalize_archive_path(value: str) -> str:
    return (
        str(value or "")
        .replace("\\", "/")
        .replace("./", "")
        .lstrip("/")
        .strip()
    )


def detect_archive_format(package_name: str) -> Optional[str]:
    n = str(package_name or "").strip().lower()
    if n.endswith(".tar.gz"):
        return "tar.gz"
    if n.endswith(".zip"):
        return "zip"
    return None


def looks_text_like(value: str) -> bool:
    if not value:
        return True
    return "\x00" not in value[:2048]


def is_text_like_file(file_path: str) -> bool:
    base = os.path.basename(file_path).lower()
    ext = os.path.splitext(base)[1].lower()
    return ext in TEXT_EXTENSIONS or bool(README_FILE_PATTERN.match(base)) or bool(MANIFEST_FILE_PATTERN.match(base))


def score_sample_path(file_path: str) -> int:
    base = os.path.basename(file_path).lower()
    ext = os.path.splitext(file_path)[1].lower()
    score = 0
    if SKILL_FILE_PATTERN.match(base):
        score += 110
    if MANIFEST_FILE_PATTERN.match(base):
        score += 100
    if README_FILE_PATTERN.match(base):
        score += 90
    if PROMPT_FILE_PATTERN.search(file_path):
        score += 80
    if ext in SCRIPT_EXTENSIONS:
        score += 60
    if "config" in base:
        score += 30
    return score


def select_sample_paths(files: List[PackageFileEntry]) -> List[str]:
    text_files = [f for f in files if is_text_like_file(f.path)]
    text_files.sort(key=lambda f: score_sample_path(f.path), reverse=True)
    return [f.path for f in text_files[:MAX_TEXT_SAMPLES]]


def dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for f in findings:
        key = (f["file"], f["line"], f["reason"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def collect_findings(samples: List[PackageTextSample], patterns: List[Tuple[re.Pattern, str, str]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for sample in samples:
        lines = sample.content.splitlines()
        for idx, line in enumerate(lines):
            for pat, reason, sev in patterns:
                if pat.search(line):
                    findings.append(
                        {
                            "file": sample.path,
                            "line": idx + 1,
                            "severity": sev,
                            "reason": reason,
                            "excerpt": line.strip()[:180],
                        }
                    )
    return dedupe_findings(findings)


def format_findings(findings: List[Dict[str, Any]]) -> List[str]:
    out = []
    for f in findings:
        loc = f"{f['file']}:{f['line']}"
        ex = f"；片段：{f['excerpt']}" if f.get("excerpt") else ""
        sev = "高风险" if f["severity"] == "high" else "中风险"
        out.append(f"[规则/{sev}] {loc}：{f['reason']}{ex}")
    return out


def clamp_score(v: float) -> int:
    return max(0, min(100, int(round(v))))


def inspect_zip_package(local_path: str) -> PackageInspection:
    files: List[PackageFileEntry] = []
    text_samples: List[PackageTextSample] = []
    with zipfile.ZipFile(local_path, "r") as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()][:MAX_ARCHIVE_FILES]
        for info in infos:
            p = normalize_archive_path(info.filename)
            if not p or p.endswith("/"):
                continue
            files.append(PackageFileEntry(path=p, size=int(info.file_size)))
        remaining = MAX_TOTAL_SAMPLE_CHARS
        for sample_path in select_sample_paths(files):
            if remaining <= 0:
                break
            try:
                data = zf.read(sample_path)
            except KeyError:
                continue
            if len(data) > MAX_SAMPLE_BYTES:
                continue
            try:
                raw = data.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                continue
            if not looks_text_like(raw):
                continue
            max_chars = min(MAX_SAMPLE_CHARS, remaining)
            truncated = len(raw) > max_chars
            content = raw[:max_chars]
            remaining -= len(content)
            text_samples.append(
                PackageTextSample(
                    path=sample_path,
                    size=len(data),
                    content=content,
                    truncated=truncated,
                )
            )
    return PackageInspection(
        archive_format="zip",
        inspection_level="deep",
        files=files,
        text_samples=text_samples,
        warnings=[],
    )


def inspect_tar_gz_package(local_path: str) -> PackageInspection:
    files: List[PackageFileEntry] = []
    warnings: List[str] = []
    text_samples: List[PackageTextSample] = []
    remaining = MAX_TOTAL_SAMPLE_CHARS

    with tarfile.open(local_path, "r:gz") as tf:
        members = [m for m in tf.getmembers() if m.isfile()][:MAX_ARCHIVE_FILES]
        for m in members:
            p = normalize_archive_path(m.name)
            files.append(PackageFileEntry(path=p, size=int(m.size)))

        for sample_path in select_sample_paths(files):
            if remaining <= 0:
                break
            try:
                member = tf.getmember(sample_path)
                f = tf.extractfile(member)
                if f is None:
                    continue
                data = f.read()
            except (KeyError, tarfile.TarError) as e:
                warnings.append(f"读取 tar 包内文件 {sample_path} 失败：{e}")
                continue
            if len(data) > MAX_SAMPLE_BYTES:
                continue
            try:
                raw = data.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                continue
            if not looks_text_like(raw):
                continue
            max_chars = min(MAX_SAMPLE_CHARS, remaining)
            truncated = len(raw) > max_chars
            content = raw[:max_chars]
            remaining -= len(content)
            text_samples.append(
                PackageTextSample(path=sample_path, size=len(data), content=content, truncated=truncated)
            )

    return PackageInspection(
        archive_format="tar.gz",
        inspection_level="deep",
        files=files,
        text_samples=text_samples,
        warnings=warnings[:4],
    )


def inspect_package(local_path: str, package_name: str) -> PackageInspection:
    fmt = detect_archive_format(package_name)
    if fmt == "zip":
        return inspect_zip_package(local_path)
    if fmt == "tar.gz":
        return inspect_tar_gz_package(local_path)
    return PackageInspection(
        archive_format=fmt or "unknown",
        inspection_level="partial",
        files=[],
        text_samples=[],
        warnings=["仅支持 .zip 与 .tar.gz 格式的 Skill 包。"],
    )


def build_section(key: str, status: str, score: int, issues: List[str]) -> Dict[str, Any]:
    has_issues = len(issues) > 0
    if status == "failed":
        summary = DEFAULT_FAILED_SUMMARIES[key]
        opinion = DEFAULT_FAILED_OPINIONS[key]
    else:
        summary = DEFAULT_PASSED_SUMMARIES[key]
        opinion = DEFAULT_PASSED_OPINIONS[key]
    if has_issues and status == "passed":
        summary = f"{summary} 仍有少量提示项，建议后续跟进。"
    return {
        "key": key,
        "title": DEFAULT_SECTION_TITLES[key],
        "status": status,
        "score": clamp_score(score),
        "summary": summary,
        "opinion": opinion,
        "issues": issues,
        "detected_by": ["rules"],
        "ai_findings": [],
    }


def build_script_section(inspection: PackageInspection) -> Dict[str, Any]:
    findings = collect_findings(inspection.text_samples, SCRIPT_PATTERNS)
    high_count = sum(1 for f in findings if f["severity"] == "high")
    med_count = sum(1 for f in findings if f["severity"] == "medium")
    no_samples = len(inspection.text_samples) == 0
    failed = high_count > 0 or med_count >= 3 or (no_samples and inspection.inspection_level == "partial")
    issues = (
        (["没有可用于静态分析的脚本或文本样本。"] if no_samples else [])
        + format_findings(findings)
    )[:8]
    score = 95 - high_count * 22 - med_count * 8 - (20 if no_samples else 0)
    return build_section("script", "failed" if failed else "passed", score, issues)


def build_format_section(package_name: str, package_size: int, inspection: PackageInspection) -> Dict[str, Any]:
    skill_files = [f for f in inspection.files if SKILL_FILE_PATTERN.match(os.path.basename(f.path))]
    readme_files = [f for f in inspection.files if README_FILE_PATTERN.match(os.path.basename(f.path))]
    script_files = [f for f in inspection.files if os.path.splitext(f.path)[1].lower() in SCRIPT_EXTENSIONS]
    hard_issues = list(inspection.warnings)
    if len(inspection.files) == 0:
        hard_issues.append("压缩包中没有可供检查的文件。")
    if len(skill_files) == 0:
        hard_issues.append("缺少 SKILL.md，Skill 包至少应包含一个同名主说明文件。")
    soft_issues: List[str] = []
    if script_files and not readme_files:
        soft_issues.append("检测到脚本文件，但缺少 README；建议补充运行方式、依赖和权限说明。")
    failed = len(hard_issues) > 0
    issues = (hard_issues + soft_issues)[:8]
    score = 96 - len(hard_issues) * 25 - len(soft_issues) * 8 - (20 if package_size > 120 * 1024 * 1024 else 0)
    return build_section("format", "failed" if failed else "passed", score, issues)


def build_sensitive_section(inspection: PackageInspection) -> Dict[str, Any]:
    findings = collect_findings(inspection.text_samples, SENSITIVE_PATTERNS)
    high_count = sum(1 for f in findings if f["severity"] == "high")
    med_count = sum(1 for f in findings if f["severity"] == "medium")
    failed = high_count > 0 or med_count > 0
    score = 96 - high_count * 28 - med_count * 16
    return build_section("sensitive", "failed" if failed else "passed", score, format_findings(findings)[:8])


def build_prompt_section(inspection: PackageInspection) -> Dict[str, Any]:
    prompt_samples = [
        s
        for s in inspection.text_samples
        if PROMPT_FILE_PATTERN.search(s.path)
        or SKILL_FILE_PATTERN.match(os.path.basename(s.path))
        or README_FILE_PATTERN.match(os.path.basename(s.path))
        or MANIFEST_FILE_PATTERN.match(os.path.basename(s.path))
    ]
    samples = prompt_samples if prompt_samples else inspection.text_samples
    findings = collect_findings(samples, PROMPT_PATTERNS)
    high_count = sum(1 for f in findings if f["severity"] == "high")
    failed = high_count > 0
    score = 94 - high_count * 24 - (6 if not prompt_samples else 0)
    return build_section("prompt", "failed" if failed else "passed", score, format_findings(findings)[:8])


def truncate_text(value: str, max_length: int) -> str:
    if len(value) <= max_length:
        return value
    return f"{value[: max(0, max_length - 1)].rstrip()}…"


def localize_severity(value: str) -> str:
    return "高风险" if value == "high" else "中风险"


def localize_confidence(value: str) -> str:
    if value == "high":
        return "高置信"
    if value == "medium":
        return "中置信"
    return "低置信"


def normalize_finding_severity(value: Any) -> Optional[str]:
    normalized = str(value or "").strip().lower()
    if normalized in ("high", "medium"):
        return normalized
    return None


def normalize_semantic_confidence(value: Any) -> Optional[str]:
    normalized = str(value or "").strip().lower()
    if normalized in ("high", "medium", "low"):
        return normalized
    return None


def dedupe_semantic_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for f in findings:
        key = f"{f.get('severity')}:{f.get('confidence')}:{f.get('title')}:{f.get('evidence')}"
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def normalize_semantic_findings(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []
    findings: List[Dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        sev = normalize_finding_severity(item.get("severity"))
        conf = normalize_semantic_confidence(item.get("confidence"))
        title = truncate_text(str(item.get("title", "")).strip(), 120)
        evidence = truncate_text(str(item.get("evidence", "")).strip(), 240)
        recommendation = truncate_text(str(item.get("recommendation", "")).strip(), 180)
        if not sev or not conf or not title or not evidence or not recommendation:
            continue
        findings.append(
            {
                "severity": sev,
                "confidence": conf,
                "title": title,
                "evidence": evidence,
                "recommendation": recommendation,
            }
        )
    return dedupe_semantic_findings(findings)[:MAX_AI_FINDINGS_PER_SECTION]


def format_semantic_findings(findings: List[Dict[str, Any]]) -> List[str]:
    lines = []
    for f in findings:
        ev = truncate_text(f.get("evidence", ""), 180)
        rec = truncate_text(f.get("recommendation", ""), 140)
        ev_text = f"；证据：{ev}" if ev else ""
        rec_text = f"；建议：{rec}" if rec else ""
        lines.append(
            f"[AI/{localize_severity(f['severity'])}/{localize_confidence(f['confidence'])}] "
            f"{f['title']}{ev_text}{rec_text}"
        )
    return lines


def has_high_confidence_semantic_blocker(findings: List[Dict[str, Any]]) -> bool:
    return any(f.get("severity") == "high" and f.get("confidence") == "high" for f in findings)


def compute_semantic_penalty(findings: List[Dict[str, Any]]) -> int:
    total = 0
    for f in findings:
        base = 12 if f.get("severity") == "high" else 6
        conf = f.get("confidence")
        mult = 1.0 if conf == "high" else 0.75 if conf == "medium" else 0.5
        total += int(round(base * mult))
    return min(24, total)


def dedupe_strings(values: List[str]) -> List[str]:
    seen = set()
    out = []
    for v in values:
        t = v.strip()
        if not t or t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


def apply_narrative(
    rule_sections: List[Dict[str, Any]],
    narrative: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    if not narrative:
        return [dict(s) for s in rule_sections]

    n_sections = narrative.get("sections")
    if not isinstance(n_sections, dict):
        n_sections = {}

    merged: List[Dict[str, Any]] = []
    for section in rule_sections:
        key = section["key"]
        override = n_sections.get(key) if isinstance(n_sections.get(key), dict) else {}
        ai_raw = override.get("findings") if isinstance(override, dict) else None
        ai_findings = normalize_semantic_findings(ai_raw)
        ai_issues = format_semantic_findings(ai_findings)
        ai_penalty = compute_semantic_penalty(ai_findings)
        ai_blocker = has_high_confidence_semantic_blocker(ai_findings)

        detected_by = list(section.get("detected_by") or ["rules"])
        if ai_findings:
            detected_by = dedupe_strings([*detected_by, "ai"])

        next_status = "failed" if (section["status"] == "failed" or ai_blocker) else "passed"

        next_score = section["score"]
        if ai_blocker and section["status"] != "failed":
            next_score = clamp_score(min(section["score"] - ai_penalty, 68))
        else:
            next_score = clamp_score(section["score"] - ai_penalty)

        summary_fb = section.get("summary") or ""
        opinion_fb = section.get("opinion") or ""
        if ai_blocker and section["status"] != "failed":
            summary_fb = f"{summary_fb} AI 语义审查补充了高置信风险证据，需要修复后再提交。"
            opinion_fb = "请结合下方 AI 发现收紧风险行为边界，修复后再重新提交。"

        summary = (override.get("summary") if isinstance(override, dict) else None) or ""
        opinion = (override.get("opinion") if isinstance(override, dict) else None) or ""
        summary = summary.strip() if isinstance(summary, str) else ""
        opinion = opinion.strip() if isinstance(opinion, str) else ""
        if not summary:
            summary = summary_fb
        if not opinion:
            opinion = opinion_fb

        issues = dedupe_strings([*(section.get("issues") or []), *ai_issues])[:MAX_SECTION_ISSUES]

        merged.append(
            {
                **section,
                "status": next_status,
                "score": next_score,
                "summary": summary,
                "opinion": opinion,
                "issues": issues,
                "detected_by": detected_by,
                "ai_findings": ai_findings,
            }
        )
    return merged


def get_semantic_escalation_titles(
    rule_sections: List[Dict[str, Any]],
    merged_sections: List[Dict[str, Any]],
) -> List[str]:
    original = {s["key"]: s["status"] for s in rule_sections}
    titles = []
    for s in merged_sections:
        if original.get(s["key"]) != "failed" and s["status"] == "failed":
            if has_high_confidence_semantic_blocker(s.get("ai_findings") or []):
                titles.append(s["title"])
    return titles


def conclusion_matches_overall(conclusion: str, overall: str) -> bool:
    c = conclusion.strip()
    if overall == "approved":
        return bool(
            re.search(r"\breview approved\b|\bapproved\b|\bpassed\b|\bpublish gate\b|\b通过\b|\b批准\b", c, re.I)
        )
    return bool(re.search(r"\breject\b|\bfail\b|\b未通过\b|\b拒绝\b|\bblocked\b", c, re.I))


def default_conclusion(overall: str, failed_titles: List[str]) -> str:
    if overall == "approved":
        return "审查通过。该包可以进入待发布状态，确认版本号后即可发布。"
    if not failed_titles:
        return "审查未通过。请修复问题后上传新的提交包，再重新发起审查。"
    return f"审查未通过。请先修复 {'、'.join(failed_titles)} 中的问题，再上传新的提交包。"


def resolve_review_conclusion(
    overall: str,
    rule_sections: List[Dict[str, Any]],
    sections: List[Dict[str, Any]],
    narrative_conclusion: Optional[str],
) -> str:
    failed_titles = [s["title"] for s in sections if s["status"] == "failed"]
    semantic_escalations = get_semantic_escalation_titles(rule_sections, sections)
    if semantic_escalations:
        return (
            f"审查未通过。AI 语义审查在 {'、'.join(semantic_escalations)} "
            "中补充了高置信风险证据，请修复问题后重新上传新的提交包。"
        )
    nc = (narrative_conclusion or "").strip()
    if nc and conclusion_matches_overall(nc, overall):
        return nc
    return default_conclusion(overall, failed_titles)


def finalize_review_result(
    rule_sections: List[Dict[str, Any]],
    narrative: Optional[Dict[str, Any]],
    review_id: str,
    reviewed_at: str,
) -> Dict[str, Any]:
    sections = apply_narrative(rule_sections, narrative)
    overall = derive_overall(sections)
    risk = derive_risk(sections)
    narrative_conclusion = None
    if narrative and isinstance(narrative.get("conclusion"), str):
        narrative_conclusion = narrative["conclusion"]
    conclusion = resolve_review_conclusion(overall, rule_sections, sections, narrative_conclusion)
    return {
        "review_id": review_id,
        "score": average_score(sections),
        "overall": overall,
        "risk": risk,
        "conclusion": conclusion,
        "reviewed_at": reviewed_at,
        "sections": sections,
    }


NARRATIVE_SYSTEM_PROMPT = " ".join(
    [
        "你是 Agent Skill 包的语义审查层。",
        "只能使用输入中提供的证据，不要臆造文件、漏洞或密钥。",
        "重点关注规则审查可能遗漏的意图偏差、可疑能力组合、不安全的 Prompt 行为和运维边界不清问题。",
        "不要否定已有规则命中；只能补充上下文、补充证据或在有充分证据时加严风险。",
        "只有当采样文件或 warnings 已经明确显示风险时，才能给出 high confidence。",
        "如果某个 section 没有语义风险，findings 必须返回空数组。",
        "每个 section 最多返回 2 条 finding。",
        "只返回 JSON，不要输出解释文字。",
        "schema 的键名以及 severity/confidence 枚举值必须保持原样英文。",
        "除键名和枚举值外，所有自然语言内容都必须使用简体中文。",
        "期望 schema：",
        '{"conclusion":"string","sections":{"script":{"summary":"string","opinion":"string","findings":[{"severity":"high|medium","confidence":"high|medium|low","title":"string","evidence":"string","recommendation":"string"}]},"format":{"summary":"string","opinion":"string","findings":[]},"sensitive":{"summary":"string","opinion":"string","findings":[]},"prompt":{"summary":"string","opinion":"string","findings":[]}}}',
    ]
)


def generate_narrative(
    skill_meta: Dict[str, Any],
    inspection: PackageInspection,
    rule_sections: List[Dict[str, Any]],
    *,
    llm_provider: Optional[str],
    llm_base_url: Optional[str],
    llm_model_name: Optional[str],
    llm_api_key: Optional[str],
    llm_temperature: float,
    llm_timeout_sec: int,
) -> Dict[str, Any]:
    """
    调用算子参数配置的 OpenAI 兼容模型做语义层；失败时返回 rules-fallback 与 errorMessage。
    """
    try:
        base_url = str(llm_base_url or "").strip()
        model_name = str(llm_model_name or "").strip()
        api_key = str(llm_api_key or "").strip()
        provider = str(llm_provider or "").strip()
        if not base_url or not model_name:
            return {
                "engine": "rules-fallback",
                "model_name": None,
                "result": None,
                "error_message": "语义层未配置完整模型参数，请至少填写模型 Base URL 与模型名称。",
            }

        payload = {
            "skill": {
                "name": skill_meta.get("skillName") or skill_meta.get("name") or "",
                "category": skill_meta.get("category") or "",
                "description": skill_meta.get("description") or "",
                "tags": skill_meta.get("tags") if isinstance(skill_meta.get("tags"), list) else [],
                "package_name": skill_meta.get("package_name") or skill_meta.get("packageName") or "",
                "package_size": skill_meta.get("package_size") or skill_meta.get("packageSize") or 0,
            },
            "package": {
                "archive_format": inspection.archive_format,
                "inspection_level": inspection.inspection_level,
                "warnings": inspection.warnings,
                "files": [{"path": f.path, "size": f.size} for f in inspection.files[:80]],
                "sampled_files": [
                    {"path": s.path, "truncated": s.truncated, "content": s.content}
                    for s in inspection.text_samples
                ],
            },
            "rule_sections": [
                {
                    "key": s["key"],
                    "title": s["title"],
                    "status": s["status"],
                    "score": s["score"],
                    "issues": s["issues"],
                }
                for s in rule_sections
            ],
            "semantic_focus": [
                "指出能被采样文件直接支撑的具体语义风险。",
                "指出 Skill 宣称用途与实际暴露能力之间的不匹配。",
                "指出密钥管理、Prompt 控制和命令执行边界不清的问题。",
            ],
        }

        user_text = json.dumps(payload, ensure_ascii=False, indent=2)
        raw = datamate_llm.openai_style_chat(
            base_url,
            api_key,
            model_name,
            NARRATIVE_SYSTEM_PROMPT,
            user_text,
            temperature=max(0.0, min(2.0, float(llm_temperature))),
            timeout=max(10.0, float(llm_timeout_sec)),
        )
        parsed = datamate_llm.try_parse_json_object(raw)
        if not parsed:
            return {
                "engine": "rules-fallback",
                "model_name": None,
                "result": None,
                "error_message": "AI 语义审查没有返回可解析的 JSON，已回退到规则审查。",
            }

        display_name = f"{provider}/{model_name}" if provider else model_name
        return {
            "engine": "operator-llm",
            "model_name": display_name,
            "model_url": base_url,
            "result": parsed,
            "error_message": None,
        }
    except Exception as e:
        return {
            "engine": "rules-fallback",
            "model_name": None,
            "model_url": str(llm_base_url or "").strip() or None,
            "result": None,
            "error_message": str(e),
        }


def derive_overall(sections: List[Dict[str, Any]]) -> str:
    return "rejected" if any(s["status"] == "failed" for s in sections) else "approved"


def _has_high_risk_semantic_signal(sections: List[Dict[str, Any]]) -> bool:
    for s in sections:
        if has_high_confidence_semantic_blocker(s.get("ai_findings") or []):
            return True
    return False


def derive_risk(sections: List[Dict[str, Any]]) -> str:
    if _has_high_risk_semantic_signal(sections):
        return "high"
    failed = [s for s in sections if s["status"] == "failed"]
    if len(failed) >= 2:
        return "high"
    if len(failed) == 1:
        return "medium"
    return "low"


def average_score(sections: List[Dict[str, Any]]) -> int:
    if not sections:
        return 0
    return int(round(sum(s["score"] for s in sections) / len(sections)))


def run_skill_review(
    local_path: str,
    package_name: str,
    *,
    skill_meta: Optional[Dict[str, Any]] = None,
    enable_llm: bool = True,
    llm_provider: Optional[str] = None,
    llm_base_url: Optional[str] = None,
    llm_model_name: Optional[str] = None,
    llm_api_key: Optional[str] = None,
    llm_temperature: float = 0.2,
    llm_timeout_sec: int = 180,
) -> Dict[str, Any]:
    """
    规则层 + 可选 LLM 语义层。模型参数来自算子配置，不依赖 DataMate 设置页模型接入。
    """
    if not os.path.isfile(local_path):
        raise FileNotFoundError(f"文件不存在: {local_path}")

    fmt = detect_archive_format(package_name)
    if fmt not in ("zip", "tar.gz"):
        return {
            "review_id": f"rv_{uuid.uuid4().hex[:16]}",
            "score": 0,
            "overall": "rejected",
            "risk": "high",
            "conclusion": "仅支持 .zip 与 .tar.gz 格式的 Skill 包。",
            "reviewed_at": datetime.now(timezone.utc).isoformat(),
            "sections": [],
            "policy_version": "skill-review-py-v2",
            "review_engine": "rules-only",
            "model_name": None,
            "semantic_review": {
                "engine": "n/a",
                "configured_in_operator": True,
                "model_name": None,
                "error": None,
            },
        }

    inspection = inspect_package(local_path, package_name)
    package_size = os.path.getsize(local_path)
    rule_sections = [
        build_script_section(inspection),
        build_format_section(package_name, package_size, inspection),
        build_sensitive_section(inspection),
        build_prompt_section(inspection),
    ]

    meta: Dict[str, Any] = dict(skill_meta or {})
    meta.setdefault("package_name", package_name)
    meta.setdefault("packageName", package_name)
    meta.setdefault("package_size", package_size)
    meta.setdefault("packageSize", package_size)

    review_id = f"rv_{uuid.uuid4().hex[:16]}"
    reviewed_at = datetime.now(timezone.utc).isoformat()

    if enable_llm:
        narrative_out = generate_narrative(
            meta,
            inspection,
            rule_sections,
            llm_provider=llm_provider,
            llm_base_url=llm_base_url,
            llm_model_name=llm_model_name,
            llm_api_key=llm_api_key,
            llm_temperature=llm_temperature,
            llm_timeout_sec=llm_timeout_sec,
        )
        narrative_result = narrative_out.get("result")
        if not isinstance(narrative_result, dict):
            narrative_result = None
        merged = finalize_review_result(rule_sections, narrative_result, review_id, reviewed_at)
        sem = {
            "engine": narrative_out.get("engine"),
            "configured_in_operator": True,
            "model_name": narrative_out.get("model_name"),
            "model_url": narrative_out.get("model_url"),
            "error": narrative_out.get("error_message"),
        }
        return {
            **merged,
            "policy_version": "skill-review-py-v2",
            "review_engine": narrative_out.get("engine"),
            "model_name": narrative_out.get("model_name"),
            "model_url": narrative_out.get("model_url"),
            "semantic_review": sem,
            "narrative": sem,
            "inspection_summary": {
                "archive_format": inspection.archive_format,
                "inspection_level": inspection.inspection_level,
                "file_count": len(inspection.files),
                "warnings": inspection.warnings,
            },
        }

    merged = finalize_review_result(rule_sections, None, review_id, reviewed_at)
    sem = {
        "engine": "disabled",
        "configured_in_operator": True,
        "model_name": None,
        "model_url": None,
        "error": None,
    }
    return {
        **merged,
        "policy_version": "skill-review-py-v2",
        "review_engine": "rules-only",
        "model_name": None,
        "semantic_review": sem,
        "narrative": sem,
        "inspection_summary": {
            "archive_format": inspection.archive_format,
            "inspection_level": inspection.inspection_level,
            "file_count": len(inspection.files),
            "warnings": inspection.warnings,
        },
    }


def review_result_to_json_text(result: Dict[str, Any]) -> str:
    return json.dumps(result, ensure_ascii=False, indent=2)
