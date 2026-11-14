#!/usr/bin/env python3
"""从 fmz200/wool_scripts 的 blockAds.module 中剔除金融/支付域名。

用法: python3 filter_blockads.py <输入.module> <输出.module>
"""

import re
import sys

# 精确匹配的域名标签（按 . - _ 切分后的单个标签）
FINANCE_LABELS = {
    # 银行
    "icbc", "ccb", "abchina", "boc", "bankofchina", "cmbchina", "cmb",
    "spdb", "spdbccc", "cib", "cibfintech", "cmbc", "bankcomm", "bocom",
    "psbc", "hxb", "cebbank", "citicbank", "ecitic", "cncb", "shbank",
    "njcb", "nbcb", "hzbank", "jiangsubank", "jsbchina", "cqbank", "gzcb",
    "grcbank", "jlbank", "z-bank", "aibank", "hsbc", "hsbcfts", "scb", "dbs",
    "ocbc", "uob", "everbright", "minsheng", "ruralcredit", "cgbank",
    "yghsh", "beijingbank", "bankofbeijing", "95588", "95533", "95599",
    "95566", "95555", "95595", "95568", "95561", "95508", "95577",
    # 支付 / 清算
    "alipay", "alipayobjects", "tenpay", "wechatpay", "wxpay", "unionpay",
    "chinaums", "95516", "yeepay", "99bill", "lakala", "bestpay", "jdpay",
    "jdpays", "baifubao", "paypal", "stripe",
}

# 标签前缀匹配
FINANCE_PREFIXES = (
    "bank", "creditcard", "debitcard", "ebank", "mobilebank", "alipay",
    "tenpay", "unionpay", "psbc", "icbc", "ccb", "abchina", "cmbchina",
    "cmbc", "spdb", "pingan", "citic", "hsbc",
)

# 标签后缀匹配
FINANCE_SUFFIXES = ("bank", "pay", "wallet")

# 明确保留（防止 cib -> iciba 这类误杀）
KEEP_LABELS = {"iciba", "kingsoft"}

LABEL_SPLIT = re.compile(r"[.\-_]")

# 扫描非 hostname 行时，只认行内真实域名，避免把 jq/Script 正文里的字段名当域名
HOST_RE = re.compile(r"[a-z0-9][a-z0-9.\-]*\.[a-z0-9][a-z0-9.\-]*", re.IGNORECASE)

DROP_SECTIONS = {"Rule", "URL Rewrite", "Map Local", "Header Rewrite", "Body Rewrite"}


def labels(host):
    return [p for p in LABEL_SPLIT.split(host.lower()) if p]


def is_finance_host(host):
    """域名是否属于金融/支付，按标签边界判断，不做子串匹配。"""
    host = host.strip().lower()
    if not host or host.startswith("#"):
        return False
    parts = labels(host)
    if not parts:
        return False
    if any(p in KEEP_LABELS for p in parts):
        return False
    for p in parts:
        if p in FINANCE_LABELS:
            return True
        if p.startswith(FINANCE_PREFIXES):
            return True
        if p.endswith(FINANCE_SUFFIXES):
            return True
    return False


def domains_in(line):
    s = line.replace("\\.", ".").replace("\\/", "/")
    out = []
    for candidate in HOST_RE.findall(s):
        candidate = candidate.strip(".-")
        if "." in candidate:
            out.append(candidate)
    return out


def line_is_finance(line):
    return any(is_finance_host(d) for d in domains_in(line))


def main(src, dst):
    with open(src, "r", encoding="utf-8", newline="") as f:
        lines = f.read().splitlines(keepends=True)

    out = []
    section = None
    sections_seen = []
    stats = {"hosts_in": 0, "hosts_kept": 0, "hosts_dropped": 0, "lines_dropped": 0}
    mitm_found = False
    hostname_found = False

    for line in lines:
        stripped = line.strip()

        m = re.match(r"^\[(.+?)\]\s*$", stripped)
        if m:
            section = m.group(1).strip()
            sections_seen.append(section)
            out.append(line)
            continue

        if section == "MITM" and stripped.lower().startswith("hostname"):
            hostname_found = True
            mitm_found = True
            mm = re.match(r"^(\s*hostname\s*=\s*)(.*?)(\s*)$", line, re.IGNORECASE | re.DOTALL)
            if not mm:
                out.append(line)
                continue
            prefix, value = mm.group(1), mm.group(2)
            kept = []
            append_marker = ""
            for token in value.split(","):
                token = token.strip()
                if not token:
                    continue
                if token.upper() == "%APPEND%":
                    append_marker = "%APPEND% "
                    continue
                stats["hosts_in"] += 1
                if is_finance_host(token):
                    stats["hosts_dropped"] += 1
                else:
                    kept.append(token)
                    stats["hosts_kept"] += 1
            newline = "\n" if line.endswith("\n") else ""
            out.append(f"{prefix}{append_marker}{', '.join(kept)}{newline}")
            continue

        if section in DROP_SECTIONS and stripped and not stripped.startswith("#"):
            if line_is_finance(stripped):
                stats["lines_dropped"] += 1
                continue

        out.append(line)

    if not mitm_found or not hostname_found:
        sys.exit("上游结构变了：没有找到 [MITM] / hostname 行，已中止，不产出文件")
    if stats["hosts_in"] < 500:
        sys.exit(f"上游 hostname 数量异常（{stats['hosts_in']}），已中止")

    text = "".join(out)
    text += (
        f"# ---- 已剔除金融/支付域名：{stats['hosts_dropped']} 个 ----\n"
        f"# ---- 保留 hostname：{stats['hosts_kept']} 个 ----\n"
    )

    with open(dst, "w", encoding="utf-8", newline="") as f:
        f.write(text)

    # 复核
    leftover = [
        t.strip()
        for t in text.split("[MITM]")[-1].split(",")
        if t.strip() and not t.strip().startswith("#") and is_finance_host(t.strip())
    ]
    if leftover:
        sys.exit(f"复核失败，仍残留金融域名：{leftover[:5]}")

    print(f"sections      : {', '.join(sections_seen)}")
    print(f"hostname 总数 : {stats['hosts_in']}")
    print(f"保留          : {stats['hosts_kept']}")
    print(f"剔除金融      : {stats['hosts_dropped']}")
    print(f"正文删除行数  : {stats['lines_dropped']}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("用法: python3 filter_blockads.py <输入.module> <输出.module>")
    main(sys.argv[1], sys.argv[2])
