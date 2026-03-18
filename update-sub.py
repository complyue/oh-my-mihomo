#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path


BASE_DIR = Path("/ws/Net/mihomo")
PROVIDERS_DIR = BASE_DIR / "providers"
SUB_URL_FILE = BASE_DIR / "sub-url.txt"
CUSTOM_BASE_FILE = BASE_DIR / "custom-base.yaml"
CONFIG_FILE = BASE_DIR / "config.yaml"
RAW_FILE = PROVIDERS_DIR / "subscription.raw.txt"
SUBSCRIPTION_FILE = PROVIDERS_DIR / "subscription.yaml"
META_FILE = PROVIDERS_DIR / "subscription.meta.json"
DEFAULT_UA = "clash.meta"

CONTROLLED_OUTPUT_ORDER = [
    "proxies",
    "proxy-providers",
    "proxy-groups",
    "rule-providers",
    "rules",
]
LIST_SECTION_KEYS = {"proxies", "proxy-groups", "rules"}
MAP_SECTION_KEYS = {"proxy-providers", "rule-providers"}
CONTROLLED_SECTION_KEYS = LIST_SECTION_KEYS | MAP_SECTION_KEYS
SECTION_FILE_MAP = {
    "proxies": "subscription.proxies.yaml",
    "proxy-groups": "subscription.proxy-groups.yaml",
    "rules": "subscription.rules.yaml",
    "rule-providers": "subscription.rule-providers.yaml",
    "proxy-providers": "subscription.proxy-providers.yaml",
}
BASE_SECTION_FILE = PROVIDERS_DIR / "subscription.base.yaml"
DEFAULT_CUSTOM_BASE_TEMPLATE = """# 手写基础配置。
# update-sub.py 会把这里的内容，与订阅里的 proxies / proxy-groups / rules / providers 合成为最终 config.yaml。
#
# 这份极简版的原则：
# 1. 只保留你本机相关、订阅通常不会提供的基础项。
# 2. 不自定义 DNS。
# 3. 默认不额外写 rules；优先沿用订阅 rules。
# 4. 只有你明确要覆盖订阅行为时，再在这里补少量 rules。
# 5. 不要自己添加 MATCH，保留订阅末尾的“🐟 漏网之鱼”做兜底。

mixed-port: 7892
socks-port: 7891
allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: info

external-controller: 127.0.0.1:7893
external-ui: ui
external-ui-url: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip"

profile:
  store-selected: true
"""


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def decode_text(raw: bytes) -> str:
    return raw.decode("utf-8", errors="ignore").replace("\r\n", "\n")


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as tmp:
        tmp.write(content)
        tmp.flush()
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)


def load_url(url_file: Path) -> str:
    if not url_file.exists():
        raise FileNotFoundError(f"找不到订阅 URL 文件：{url_file}")

    for raw_line in url_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        return line

    raise ValueError(f"订阅 URL 文件里没有可用 URL：{url_file}")


def ensure_custom_base_file(path: Path) -> bool:
    if path.exists():
        return False
    atomic_write_text(path, DEFAULT_CUSTOM_BASE_TEMPLATE)
    return True


def fetch_bytes(url: str, user_agent: str, timeout: int) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "*/*",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def looks_like_clash_yaml(text: str) -> bool:
    patterns = [
        r"(^|\n)proxies:\s*",
        r"(^|\n)proxy-groups:\s*",
        r"(^|\n)rules:\s*",
        r"(^|\n)rule-providers:\s*",
        r"(^|\n)proxy-providers:\s*",
        r"(^|\n)mixed-port:\s*",
        r"(^|\n)port:\s*",
        r"(^|\n)socks-port:\s*",
    ]
    return any(re.search(p, text, flags=re.IGNORECASE) for p in patterns)


def looks_like_base64_blob(text: str) -> bool:
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 64:
        return False
    if any(
        token in text
        for token in [
            "proxies:",
            "proxy-groups:",
            "rules:",
            "rule-providers:",
            "proxy-providers:",
            "vmess://",
            "ss://",
            "trojan://",
            "vless://",
        ]
    ):
        return False
    return re.fullmatch(r"[A-Za-z0-9+/=]+", compact) is not None


def try_decode_base64_to_text(text: str) -> str | None:
    compact = re.sub(r"\s+", "", text)
    compact += "=" * ((-len(compact)) % 4)
    try:
        decoded = base64.b64decode(compact, validate=False)
    except Exception:
        return None
    decoded_text = decode_text(decoded).strip()
    return decoded_text or None


def normalize_subscription(raw: bytes) -> tuple[str, str]:
    text = decode_text(raw).strip()

    if looks_like_clash_yaml(text):
        return text + "\n", "yaml_direct"

    if looks_like_base64_blob(text):
        decoded = try_decode_base64_to_text(text)
        if decoded and looks_like_clash_yaml(decoded):
            return decoded.strip() + "\n", "base64_to_yaml"
        if decoded:
            raise ValueError(
                "订阅返回的是 base64，但解码后不是 Clash/Mihomo YAML。\n"
                "大概率仍是纯节点 URI 列表。\n"
                f"原始内容已保存到：{RAW_FILE}"
            )

    raise ValueError(
        "订阅内容不是可识别的 Clash/Mihomo YAML。\n"
        "当前脚本只接受：\n"
        "1. 直接返回的 Clash/Mihomo YAML；\n"
        "2. base64 包裹后的 Clash/Mihomo YAML。\n"
        "\n"
        f"原始内容已保存到：{RAW_FILE}"
    )


def split_top_level_blocks(text: str) -> tuple[list[str], dict[str, str], str]:
    lines = text.replace("\r\n", "\n").splitlines()
    order: list[str] = []
    blocks: dict[str, list[str]] = {}
    preamble: list[str] = []
    current_key: str | None = None

    for line in lines:
        match = re.match(r"^([A-Za-z0-9_-]+):(.*)$", line)
        if match and not line.startswith((" ", "\t")):
            current_key = match.group(1)
            if current_key not in blocks:
                order.append(current_key)
                blocks[current_key] = []
            blocks[current_key].append(line)
            continue

        if current_key is None:
            preamble.append(line)
        else:
            blocks[current_key].append(line)

    rendered = {
        key: "\n".join(value).rstrip() + "\n"
        for key, value in blocks.items()
        if value
    }
    preamble_text = "\n".join(preamble).rstrip()
    if preamble_text:
        preamble_text += "\n"
    return order, rendered, preamble_text


def block_body_lines(block: str | None) -> list[str]:
    if not block:
        return []
    lines = block.rstrip("\n").splitlines()
    return lines[1:] if len(lines) > 1 else []


def normalize_body_to_two_spaces(lines: list[str]) -> list[str]:
    nonblank = [line for line in lines if line.strip()]
    if not nonblank:
        return []
    min_indent = min(len(line) - len(line.lstrip(" ")) for line in nonblank)
    normalized: list[str] = []
    for line in lines:
        if not line.strip():
            normalized.append("")
            continue
        trimmed = line[min_indent:] if len(line) >= min_indent else line.lstrip(" ")
        normalized.append(f"  {trimmed}")
    return normalized


def render_merged_block(key: str, custom_block: str | None, subscription_block: str | None) -> str | None:
    merged_body: list[str] = []
    for block in (custom_block, subscription_block):
        body = normalize_body_to_two_spaces(block_body_lines(block))
        if body:
            merged_body.extend(body)
    if not merged_body:
        return None
    return f"{key}:\n" + "\n".join(merged_body).rstrip() + "\n"


def extract_mapping_child_keys(block: str | None) -> set[str]:
    keys: set[str] = set()
    for line in normalize_body_to_two_spaces(block_body_lines(block)):
        match = re.match(r"^  ([^:#][^:]*):(?:\s|$)", line)
        if match and not line.startswith("    "):
            keys.add(match.group(1).strip())
    return keys


def detect_duplicate_map_entries(key: str, custom_block: str | None, subscription_block: str | None) -> None:
    custom_keys = extract_mapping_child_keys(custom_block)
    subscription_keys = extract_mapping_child_keys(subscription_block)
    duplicated = sorted(custom_keys & subscription_keys)
    if duplicated:
        dup_text = ", ".join(duplicated)
        raise ValueError(f"{key} 存在重名项，无法安全合并：{dup_text}")


def count_top_level_list_items(block: str | None) -> int:
    count = 0
    for line in normalize_body_to_two_spaces(block_body_lines(block)):
        if re.match(r"^  -(?:\s|$)", line):
            count += 1
    return count


def count_top_level_map_items(block: str | None) -> int:
    return len(extract_mapping_child_keys(block))


def build_final_config(custom_text: str, subscription_text: str) -> tuple[str, dict[str, int]]:
    custom_order, custom_blocks, custom_preamble = split_top_level_blocks(custom_text)
    _, subscription_blocks, _ = split_top_level_blocks(subscription_text)

    parts: list[str] = [
        "# AUTO-GENERATED FILE. DO NOT EDIT.\n"
        f"# Edit {CUSTOM_BASE_FILE} and re-run update-sub.py.\n"
    ]
    if custom_preamble.strip():
        parts.append(custom_preamble.rstrip() + "\n")

    for key in custom_order:
        if key in CONTROLLED_SECTION_KEYS:
            continue
        parts.append(custom_blocks[key].rstrip() + "\n")

    merged_counts: dict[str, int] = {}
    for key in CONTROLLED_OUTPUT_ORDER:
        if key in MAP_SECTION_KEYS:
            detect_duplicate_map_entries(key, custom_blocks.get(key), subscription_blocks.get(key))
        merged = render_merged_block(key, custom_blocks.get(key), subscription_blocks.get(key))
        if merged:
            parts.append(merged.rstrip() + "\n")
            if key in LIST_SECTION_KEYS:
                merged_counts[key] = count_top_level_list_items(merged)
            elif key in MAP_SECTION_KEYS:
                merged_counts[key] = count_top_level_map_items(merged)

    final_text = "\n\n".join(part.strip("\n") for part in parts if part.strip()) + "\n"
    return final_text, merged_counts


def write_split_files(text: str) -> dict[str, str]:
    order, blocks, preamble = split_top_level_blocks(text)
    written: dict[str, str] = {}

    for section_key, filename in SECTION_FILE_MAP.items():
        if section_key in blocks:
            path = PROVIDERS_DIR / filename
            atomic_write_text(path, blocks[section_key])
            written[section_key] = str(path)

    base_parts: list[str] = []
    if preamble:
        base_parts.append(preamble.rstrip())
    for key in order:
        if key not in SECTION_FILE_MAP and key in blocks:
            base_parts.append(blocks[key].rstrip())

    base_content = "\n\n".join(part for part in base_parts if part.strip())
    if base_content:
        base_content += "\n"
        atomic_write_text(BASE_SECTION_FILE, base_content)
        written["base"] = str(BASE_SECTION_FILE)

    return written


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "从 /ws/Net/mihomo/sub-url.txt 读取订阅 URL，下载后把原始内容和订阅拆解结果写入 providers/，"
            "再把 /ws/Net/mihomo/custom-base.yaml 与订阅配置合成为最终 /ws/Net/mihomo/config.yaml。"
        )
    )
    parser.add_argument("--timeout", type=int, default=60, help="网络超时秒数，默认 60")
    parser.add_argument(
        "--user-agent",
        default=DEFAULT_UA,
        help="请求 User-Agent，默认 clash.meta",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        url = load_url(SUB_URL_FILE)
    except Exception as e:
        eprint(e)
        return 2

    created_custom_base = ensure_custom_base_file(CUSTOM_BASE_FILE)
    if created_custom_base:
        eprint(f"已初始化手写配置模板：{CUSTOM_BASE_FILE}")
        eprint("请先按需修改这个文件，再重新运行 update-sub.py。")
        return 2

    try:
        raw = fetch_bytes(url, args.user_agent, args.timeout)
    except urllib.error.HTTPError as e:
        eprint(f"下载订阅失败：HTTP {e.code} {e.reason}")
        return 1
    except urllib.error.URLError as e:
        eprint(f"下载订阅失败：{e}")
        return 1
    except Exception as e:
        eprint(f"下载订阅失败：{e}")
        return 1

    raw_text = decode_text(raw)
    atomic_write_text(RAW_FILE, raw_text)

    try:
        subscription_text, source_kind = normalize_subscription(raw)
    except ValueError as e:
        eprint(str(e))
        preview = raw_text.splitlines()[:40]
        if preview:
            eprint("\n原始内容前 40 行：")
            for line in preview:
                eprint(line)
        return 1

    atomic_write_text(SUBSCRIPTION_FILE, subscription_text)
    split_written = write_split_files(subscription_text)

    try:
        custom_text = CUSTOM_BASE_FILE.read_text(encoding="utf-8")
    except Exception as e:
        eprint(f"读取手写配置失败：{e}")
        return 1

    try:
        final_config_text, merged_counts = build_final_config(custom_text, subscription_text)
    except ValueError as e:
        eprint(f"合成 config.yaml 失败：{e}")
        return 1

    atomic_write_text(CONFIG_FILE, final_config_text)

    meta = {
        "url": url,
        "custom_base_file": str(CUSTOM_BASE_FILE),
        "config_file": str(CONFIG_FILE),
        "raw_file": str(RAW_FILE),
        "normalized_subscription_file": str(SUBSCRIPTION_FILE),
        "split_files": split_written,
        "source_kind": source_kind,
        "raw_size_bytes": len(raw),
        "merged_section_counts": merged_counts,
    }
    atomic_write_text(META_FILE, json.dumps(meta, ensure_ascii=False, indent=2) + "\n")

    print(f"订阅 URL：{url}")
    print(f"手写基础配置：{CUSTOM_BASE_FILE}")
    print(f"原始订阅内容：{RAW_FILE}")
    print(f"规范化订阅内容：{SUBSCRIPTION_FILE}")
    print(f"最终 config.yaml：{CONFIG_FILE}")
    for key, path in split_written.items():
        print(f"拆解输出 {key}: {path}")
    print(f"元信息：{META_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
