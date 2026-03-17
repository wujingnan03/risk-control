#!/usr/bin/env python3
"""
规则匹配脚本 —— 确定性反欺诈 + 反洗钱规则判定

所有阈值比较、交叉验证、severity 调整均在此脚本中完成，
模型不再参与规则判定，消除不确定性。

输入：profile.json（来自 user_profiling.py）
输出：fraud.json（FraudAnalysis）+ aml.json（AMLAnalysis）

用法：
  python rule_matching.py --profile profile.json --output-fraud fraud.json --output-aml aml.json
"""

import json
import sys
import argparse
from datetime import datetime


# ================================================================
# 常量
# ================================================================

DISABLED_FRD_RULES = {
    "FRD-008": "当前无 IP 信誉库数据源，无法判定 VPN/代理 IP",
}

DISABLED_AML_RULES = {
    "AML-006": "当前无外部身份核验系统，无法比对身份信息",
    "AML-007": "当前 MCP 仅支持单 UID 查询，无法进行跨账户关联检测",
    "AML-008": "当前无收入水平等外部数据，无法评估资金来源匹配度",
    "AML-011": "纯定性判断，无可量化的确定性条件",
}

ADJACENT_PROVINCES = {
    frozenset({"北京", "河北"}), frozenset({"北京", "天津"}),
    frozenset({"天津", "河北"}), frozenset({"上海", "江苏"}),
    frozenset({"上海", "浙江"}), frozenset({"广东", "广西"}),
    frozenset({"广东", "海南"}), frozenset({"广东", "福建"}),
    frozenset({"江苏", "浙江"}), frozenset({"江苏", "安徽"}),
    frozenset({"浙江", "安徽"}), frozenset({"浙江", "江西"}),
    frozenset({"湖北", "湖南"}), frozenset({"四川", "重庆"}),
    frozenset({"辽宁", "吉林"}), frozenset({"吉林", "黑龙江"}),
    frozenset({"河南", "河北"}), frozenset({"河南", "山东"}),
    frozenset({"山东", "河北"}), frozenset({"陕西", "甘肃"}),
    frozenset({"云南", "贵州"}), frozenset({"福建", "江西"}),
}

NON_MAINLAND_CERT_TYPES = {"1", "2", "3", "4", "G", "P", "H", "M", "T"}


# ================================================================
# 辅助函数
# ================================================================

def adjust_severity(base_severity, direction):
    """调整 severity 等级，direction: 'up' | 'down'"""
    levels = ["低", "中", "高"]
    idx = levels.index(base_severity) if base_severity in levels else 1
    if direction == "up":
        idx = min(idx + 1, 2)
    elif direction == "down":
        idx = max(idx - 1, 0)
    return levels[idx]


def make_rule_result(rule_id, rule_name, severity, matched, evidence=None,
                     cross_validation="", category=""):
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "triggered": matched,
        "matched": matched,
        "evidence": evidence or [],
        "cross_validation": cross_validation,
        "category": category,
    }


# ================================================================
# FRD 规则匹配
# ================================================================

def match_frd_001(profile):
    """FRD-001 多设备异常登录：近7天内使用≥3台不同设备"""
    dp = profile.get("device_profile", {})
    ip = profile.get("ip_profile", {})
    device_count = dp.get("total_unique_devices", 0)
    matched = device_count >= 3
    severity = "高"
    evidence = []
    cross = ""

    if matched:
        device_ids = dp.get("device_id_list", [])
        evidence = [
            f"近期使用{device_count}台不同设备",
            f"设备ID列表: {', '.join(device_ids[:5])}",
            f"近7天新设备占比: {dp.get('new_device_ratio_7d', 0)*100:.0f}%",
        ]
        unique_ips = ip.get("unique_ips", 0)
        if unique_ips <= 2:
            severity = adjust_severity(severity, "down")
            cross = f"设备多({device_count}台)但IP稳定({unique_ips}个)，severity降一级"
        else:
            cross = f"设备({device_count}台)和IP({unique_ips}个)同步变化，severity维持高"

    return make_rule_result("FRD-001", "多设备异常登录", severity, matched,
                            evidence, cross, "账号安全")


def match_frd_002(profile):
    """FRD-002 休眠账号突然激活：最大间隔≥90天"""
    lp = profile.get("login_profile", {})
    max_gap = lp.get("max_gap_days", 0)
    matched = max_gap >= 90
    severity = "中"
    evidence = []
    cross = ""

    if matched:
        evidence = [
            f"最大登录间隔: {max_gap}天",
            f"首次登录: {lp.get('first_login', '数据缺失')}",
            f"最近登录: {lp.get('last_login', '数据缺失')}",
        ]
        cross = "无交易数据，无法验证激活后是否立即发生交易"

    return make_rule_result("FRD-002", "休眠账号突然激活", severity, matched,
                            evidence, cross, "账号安全")


def match_frd_003(profile):
    """FRD-003 设备信息频繁变更：30天内≥50%为新设备"""
    dp = profile.get("device_profile", {})
    ratio_30d = dp.get("new_device_ratio_30d", 0)
    matched = ratio_30d >= 0.5
    severity = "中"
    evidence = []
    cross = ""

    if matched:
        evidence = [
            f"30天内新设备占比: {ratio_30d*100:.0f}%",
            f"总设备数: {dp.get('total_unique_devices', 0)}",
        ]
        type_dist = dp.get("device_type_distribution", {})
        if type_dist:
            total_devices = sum(type_dist.values())
            max_brand_count = max(type_dist.values()) if type_dist else 0
            if total_devices > 0 and max_brand_count / total_devices > 0.8:
                top_brand = max(type_dist, key=type_dist.get)
                severity = adjust_severity(severity, "down")
                cross = f"同品牌({top_brand})占比>{80}%，可能正常换机，severity降一级"
            else:
                cross = f"设备品牌分散({dict(type_dist)})，不符合正常换机模式"

    return make_rule_result("FRD-003", "设备信息频繁变更", severity, matched,
                            evidence, cross, "账号安全")


def match_frd_004(profile):
    """FRD-004 凌晨异常活跃：0:00-6:00登录占比≥30%"""
    lp = profile.get("login_profile", {})
    ip = profile.get("ip_profile", {})
    night_rate = lp.get("night_active_rate", 0)
    matched = night_rate >= 0.3
    severity = "中"
    evidence = []
    cross = ""

    if matched:
        td = lp.get("time_distribution", {})
        evidence = [
            f"凌晨(0-6点)登录占比: {night_rate*100:.1f}%",
            f"时段分布: 凌晨{td.get('night_0006', 0)*100:.0f}% / 上午{td.get('morning_0612', 0)*100:.0f}% / 下午{td.get('afternoon_1218', 0)*100:.0f}% / 晚间{td.get('evening_1824', 0)*100:.0f}%",
        ]
        foreign_rate = ip.get("foreign_ip_rate", 0)
        if foreign_rate > 0.5:
            severity = adjust_severity(severity, "down")
            cross = f"境外IP占比{foreign_rate*100:.0f}%>50%，凌晨活跃可能为时差所致，severity降一级"
        else:
            cross = f"境外IP占比{foreign_rate*100:.0f}%，国内IP为主+凌晨活跃，异常信号"

    return make_rule_result("FRD-004", "凌晨异常活跃", severity, matched,
                            evidence, cross, "行为异常")


def match_frd_005(profile):
    """FRD-005 登录频次突增：偏离度≥2倍且日均≥10次"""
    lp = profile.get("login_profile", {})
    dev = profile.get("deviation_analysis", {})
    dd = dev.get("dimension_deviations", {})
    login_dev = dd.get("login_frequency", {})

    daily_avg = lp.get("daily_avg_logins", 0)
    deviation_ratio = login_dev.get("deviation_ratio", 0)
    matched = deviation_ratio >= 2.0 and daily_avg >= 10
    severity = "中"
    evidence = []
    cross = ""

    if matched:
        evidence = [
            f"日均登录: {daily_avg}次",
            f"登录频次偏离比: {deviation_ratio}",
            f"近期值: {login_dev.get('recent', 0)}, 基线值: {login_dev.get('baseline', 0)}",
            f"基线类型: {dev.get('baseline_type', 'unknown')}",
        ]
        cross = "无交易数据，无法验证是否伴随交易行为变化"

    return make_rule_result("FRD-005", "登录频次突增", severity, matched,
                            evidence, cross, "行为异常")


def match_frd_006(profile):
    """FRD-006 IP地理位置频繁跳变：≥5个不同省份"""
    ip = profile.get("ip_profile", {})
    dp = profile.get("device_profile", {})
    dev = profile.get("deviation_analysis", {})
    dd = dev.get("dimension_deviations", {})

    provinces = ip.get("unique_provinces", 0)
    matched = provinces >= 5
    severity = "高"
    evidence = []
    cross = ""

    if matched:
        evidence = [
            f"登录IP涉及{provinces}个不同省份",
            f"省份列表: {', '.join(ip.get('province_list', [])[:7])}",
        ]
        device_dev = dd.get("device_count", {})
        device_alert = device_dev.get("alert", False)
        if not device_alert:
            cross = f"IP跨{provinces}省但设备无显著变化，疑似VPN使用"
        else:
            cross = f"IP跨{provinces}省且设备同时异常变化，风险信号更强"

    return make_rule_result("FRD-006", "IP地理位置频繁跳变", severity, matched,
                            evidence, cross, "网络异常")


def match_frd_007(profile):
    """FRD-007 境外IP登录：存在任意境外IP"""
    ip = profile.get("ip_profile", {})
    reg = profile.get("registration_profile", {})
    foreign_count = ip.get("foreign_ip_count", 0)
    matched = foreign_count > 0
    severity = "高"
    evidence = []
    cross = ""

    if matched:
        details = ip.get("foreign_ip_details", [])
        for d in details[:3]:
            evidence.append(f"境外IP: {d.get('ip', '?')} ({d.get('country', '?')}), 登录{d.get('login_count', 0)}次")
        evidence.append(f"境外IP占比: {ip.get('foreign_ip_rate', 0)*100:.1f}%")

        cert_type = str(reg.get("cert_type", ""))
        if cert_type in NON_MAINLAND_CERT_TYPES:
            severity = adjust_severity(severity, "down")
            cross = f"证件类型({cert_type})为非大陆身份证，境外登录可能合理，severity降一级"
        else:
            cross = f"证件类型({cert_type})为大陆身份证，境外登录异常"

    return make_rule_result("FRD-007", "境外IP登录", severity, matched,
                            evidence, cross, "网络异常")


def match_frd_009(profile):
    """FRD-009 注册后短时间内大额交易：注册≤7天+单笔≥50万或累计≥100万"""
    reg = profile.get("registration_profile", {})
    tx = profile.get("transaction_profile", {})

    if not tx.get("available", False):
        return None  # data_gap

    mt = tx.get("manual_trading", {})
    age = reg.get("account_age_days", 9999)
    max_buy = mt.get("max_single_buy", 0)
    total_buy = mt.get("total_buy_amount", 0)

    matched = age <= 7 and (max_buy >= 500000 or total_buy >= 1000000)
    severity = "高"
    evidence = []
    cross = ""

    if matched:
        evidence = [
            f"账龄: {age}天",
            f"最大单笔买入: {max_buy:.2f}元",
            f"买入总额: {total_buy:.2f}元",
        ]
        risk_desc = reg.get("risk_level_declared", "")
        cross = f"用户声明风险等级: {risk_desc}"

    return make_rule_result("FRD-009", "注册后短时间内大额交易", severity, matched,
                            evidence, cross, "交易异常")


def match_frd_010(profile):
    """FRD-010 交易模式突变：交易金额偏离度≥200%"""
    tx = profile.get("transaction_profile", {})

    if not tx.get("available", False):
        return None  # data_gap

    mt = tx.get("manual_trading", {})
    avg_buy = mt.get("avg_buy_amount", 0)
    max_buy = mt.get("max_single_buy", 0)
    # 简化判定：无历史交易均值对比时，用大额买入作为代理指标
    # 完整偏离检测待交易偏离维度扩展后启用
    matched = False
    severity = "中"
    evidence = []
    cross = ""

    # 当前仅在有交易数据时做基础检测
    buy_count = mt.get("buy_count", 0)
    if buy_count >= 2 and max_buy > 0 and avg_buy > 0:
        ratio = max_buy / avg_buy
        if ratio >= 3.0:
            matched = True
            evidence = [
                f"最大单笔买入({max_buy:.2f}元)是平均值({avg_buy:.2f}元)的{ratio:.1f}倍",
                f"买入笔数: {buy_count}",
            ]
            dev = profile.get("deviation_analysis", {})
            dd = dev.get("dimension_deviations", {})
            device_alert = dd.get("device_count", {}).get("alert", False)
            ip_alert = dd.get("unique_ips", {}).get("alert", False)
            if device_alert or ip_alert:
                cross = "交易模式突变同时伴随设备/IP异常，风险信号增强"
            else:
                cross = "交易模式突变但设备/IP正常"

    return make_rule_result("FRD-010", "交易模式突变", severity, matched,
                            evidence, cross, "交易异常")


def match_frd_011(profile):
    """FRD-011 用户信息与设备/IP地域不匹配"""
    reg = profile.get("registration_profile", {})
    ip = profile.get("ip_profile", {})

    reg_location = str(reg.get("created_ip_location", ""))
    province_list = ip.get("province_list", [])

    if not reg_location or reg_location == "未查询" or not province_list:
        return make_rule_result("FRD-011", "用户信息与设备/IP地域不匹配",
                                "中", False, [], "注册IP归属地或登录省份数据不足", "身份异常")

    main_province = province_list[0]
    matched = bool(main_province) and main_province not in reg_location
    severity = "中"
    evidence = []
    cross = ""

    if matched:
        evidence = [
            f"注册IP归属地: {reg_location}",
            f"主要登录省份: {main_province}",
            f"登录省份列表: {', '.join(province_list[:5])}",
        ]
        reg_province = ""
        for part in reg_location.split():
            if part:
                reg_province = part
                break
        if reg_province and main_province:
            pair = frozenset({reg_province, main_province})
            if pair in ADJACENT_PROVINCES:
                severity = adjust_severity(severity, "down")
                cross = f"{reg_province}与{main_province}为相邻省份，可能工作地与户籍地不同，severity降一级"
            else:
                cross = f"{reg_province}与{main_province}非相邻省份，地域差异显著"
        else:
            cross = "无法解析省份信息进行相邻判定"

    return make_rule_result("FRD-011", "用户信息与设备/IP地域不匹配", severity, matched,
                            evidence, cross, "身份异常")


def match_frd_012(matched_frd_results):
    """FRD-012 多维度同时触发：已启用规则命中≥3条"""
    triggered_rules = [r for r in matched_frd_results if r.get("triggered", False)]
    count = len(triggered_rules)
    matched = count >= 3
    severity = "高"
    evidence = []
    cross = ""

    if matched:
        evidence = [f"同时命中{count}条反欺诈规则"]
        for r in triggered_rules:
            evidence.append(f"  - {r['rule_id']} {r['rule_name']} (severity: {r['severity']})")
        cross = "本规则为多维度交叉验证结果"

    return make_rule_result("FRD-012", "多维度同时触发", severity, matched,
                            evidence, cross, "综合")


# ================================================================
# AML 规则匹配
# ================================================================

def match_aml_001(profile):
    """AML-001 单日大额交易报告：单日买入≥5万"""
    tx = profile.get("transaction_profile", {})
    if not tx.get("available", False):
        return None

    mt = tx.get("manual_trading", {})
    daily_max = mt.get("daily_max_buy_amount", 0)
    matched = daily_max >= 50000
    severity = "高"
    evidence = []

    if matched:
        evidence = [
            f"单日最大买入金额: {daily_max:.2f}元",
            f"大额买入(≥5万)笔数: {mt.get('large_buy_count', 0)}",
        ]

    return make_rule_result("AML-001", "单日大额交易报告", severity, matched,
                            evidence, "大额交易不等于洗钱，需结合其他规则综合判断", "大额交易")


def match_aml_002(profile):
    """AML-002 资金快进快出：同基金买后7天内卖，买入≥1万"""
    tx = profile.get("transaction_profile", {})
    if not tx.get("available", False):
        return None

    mt = tx.get("manual_trading", {})
    rapid_count = mt.get("rapid_turnaround_count", 0)
    matched = rapid_count >= 1
    severity = "高"
    evidence = []
    cross = ""

    if matched:
        evidence = [
            f"快进快出次数: {rapid_count}",
            f"涉及基金数: {mt.get('unique_funds', 0)}",
        ]
        cross = "卖出仅有份额无金额，以买入金额(≥1万)为判断依据"

    return make_rule_result("AML-002", "资金快进快出", severity, matched,
                            evidence, cross, "交易行为")


def match_aml_003(profile):
    """AML-003 交易拆分规避报告：单日≥3笔买入且单笔4-5万"""
    tx = profile.get("transaction_profile", {})
    if not tx.get("available", False):
        return None

    mt = tx.get("manual_trading", {})
    split_days = mt.get("split_buy_days", 0)
    matched = split_days >= 1
    severity = "高"
    evidence = []
    cross = ""

    if matched:
        evidence = [
            f"疑似拆分交易天数: {split_days}天",
        ]
        if split_days >= 3:
            cross = f"连续{split_days}天出现拆分模式，高度可疑"
        else:
            cross = "偶发拆分，需持续观察"

    return make_rule_result("AML-003", "交易拆分规避报告", severity, matched,
                            evidence, cross, "交易行为")


def match_aml_004(profile):
    """AML-004 频繁申赎同一产品：30天内同基金买卖各≥3次"""
    tx = profile.get("transaction_profile", {})
    if not tx.get("available", False):
        return None

    mt = tx.get("manual_trading", {})
    per_fund = mt.get("per_fund_buy_sell_counts", {})
    triggered_funds = []
    for fc, counts in per_fund.items():
        if counts.get("buy", 0) >= 3 and counts.get("sell", 0) >= 3:
            triggered_funds.append((fc, counts))

    matched = len(triggered_funds) > 0
    severity = "中"
    evidence = []

    if matched:
        for fc, counts in triggered_funds[:3]:
            evidence.append(f"基金{fc}: 买入{counts['buy']}次, 卖出{counts['sell']}次")

    return make_rule_result("AML-004", "频繁申赎同一产品", severity, matched,
                            evidence, "频繁操作但无明显收益目的时更加可疑", "交易行为")


def match_aml_005(profile):
    """AML-005 短期集中大额赎回：7天内卖出≥5笔跨多基金"""
    tx = profile.get("transaction_profile", {})
    if not tx.get("available", False):
        return None

    mt = tx.get("manual_trading", {})
    sell_count = mt.get("recent_7d_sell_count", 0)
    sell_funds = mt.get("recent_7d_sell_fund_count", 0)
    matched = sell_count >= 5 and sell_funds >= 2
    severity = "高"
    evidence = []

    if matched:
        evidence = [
            f"近7天卖出笔数: {sell_count}",
            f"涉及基金数: {sell_funds}",
        ]

    return make_rule_result("AML-005", "短期集中大额赎回", severity, matched,
                            evidence, "卖出仅有份额无金额，以笔数和基金数量替代判断", "交易行为")


def match_aml_009(profile):
    """AML-009 多账户同设备/IP：需跨账户数据，单UID模式归data_gaps"""
    return None  # 单UID模式下无法验证


def match_aml_010(profile):
    """AML-010 交易操作与登录地异常：最近登录IP≠常驻省份"""
    ip = profile.get("ip_profile", {})
    province_list = ip.get("province_list", [])

    if not province_list or len(province_list) < 2:
        return make_rule_result("AML-010", "交易操作与登录地异常", "中", False,
                                [], "省份数据不足(<2个省份)，无法判定异常", "设备网络")

    main_province = province_list[0]
    cross_rate = ip.get("cross_region_rate", 0)
    matched = cross_rate > 0.3
    severity = "中"
    evidence = []

    if matched:
        evidence = [
            f"常驻省份: {main_province}",
            f"跨省率: {cross_rate*100:.1f}%",
            f"省份列表: {', '.join(province_list[:5])}",
        ]

    return make_rule_result("AML-010", "交易操作与登录地异常", severity, matched,
                            evidence, "标注为待确认（无法判断是否出差/旅行）", "设备网络")


def match_aml_012(matched_aml_results):
    """AML-012 多项洗钱指标叠加：已启用规则命中≥3条"""
    triggered_rules = [r for r in matched_aml_results if r.get("triggered", False)]
    count = len(triggered_rules)
    matched = count >= 3
    severity = "高"
    evidence = []

    if matched:
        evidence = [f"同时命中{count}条反洗钱规则"]
        for r in triggered_rules:
            evidence.append(f"  - {r['rule_id']} {r['rule_name']} (severity: {r['severity']})")

    return make_rule_result("AML-012", "多项洗钱指标叠加", severity, matched,
                            evidence, "综合研判", "综合")


# ================================================================
# 偏离度 severity 全局调整
# ================================================================

def apply_deviation_adjustment(results, deviation_score):
    """偏离度>50时，所有命中规则severity上调一级"""
    if deviation_score <= 50:
        return
    for r in results:
        if r.get("triggered", False):
            original = r["severity"]
            r["severity"] = adjust_severity(original, "up")
            if r["severity"] != original:
                r["cross_validation"] += f"; 行为偏离度{deviation_score}分>50，severity从{original}上调至{r['severity']}"


# ================================================================
# 主匹配流程
# ================================================================

def run_fraud_matching(profile):
    """执行全部反欺诈规则匹配"""
    deviation_score = profile.get("deviation_analysis", {}).get("overall_deviation_score", 0)

    frd_matchers = [
        ("FRD-001", match_frd_001),
        ("FRD-002", match_frd_002),
        ("FRD-003", match_frd_003),
        ("FRD-004", match_frd_004),
        ("FRD-005", match_frd_005),
        ("FRD-006", match_frd_006),
        ("FRD-007", match_frd_007),
        ("FRD-009", match_frd_009),
        ("FRD-010", match_frd_010),
        ("FRD-011", match_frd_011),
    ]

    matched_rules = []
    unmatched_rules = []
    data_gaps = []
    disabled_rules = []

    for rule_id, matcher in frd_matchers:
        result = matcher(profile)
        if result is None:
            data_gaps.append(f"{rule_id}: 交易数据不可用，无法验证")
        elif result["triggered"]:
            matched_rules.append(result)
        else:
            unmatched_rules.append(f"{rule_id} {result['rule_name']}: 未命中")

    for rule_id, reason in DISABLED_FRD_RULES.items():
        disabled_rules.append(f"{rule_id}: {reason}")

    # FRD-012 基于其他规则结果
    frd_012 = match_frd_012(matched_rules)
    if frd_012["triggered"]:
        matched_rules.append(frd_012)
    else:
        unmatched_rules.append("FRD-012 多维度同时触发: 未命中")

    apply_deviation_adjustment(matched_rules, deviation_score)

    # 确定风险级别
    high_count = sum(1 for r in matched_rules if r["severity"] == "高")
    med_count = sum(1 for r in matched_rules if r["severity"] == "中")
    if high_count >= 2:
        fraud_risk_level = "高风险"
    elif high_count == 1 or med_count >= 2:
        fraud_risk_level = "中风险"
    elif med_count == 1:
        fraud_risk_level = "低风险"
    else:
        fraud_risk_level = "无风险"

    total_rules = len(frd_matchers) + len(DISABLED_FRD_RULES) + 1  # +1 for FRD-012

    conclusion_parts = []
    if matched_rules:
        conclusion_parts.append(f"命中{len(matched_rules)}条反欺诈规则(高:{high_count}, 中:{med_count})")
    if data_gaps:
        conclusion_parts.append(f"{len(data_gaps)}条规则因数据不可用无法验证")
    if not matched_rules:
        conclusion_parts.append("未命中任何反欺诈规则")

    return {
        "module": "anti_fraud",
        "uid": str(profile.get("uid", "")),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "rules_version": "v1.1",
        "total_rules_checked": total_rules,
        "rule_results": matched_rules,
        "matched_rules": matched_rules,
        "unmatched_rules_checked": unmatched_rules,
        "data_gaps": data_gaps,
        "disabled_rules": disabled_rules,
        "fraud_risk_level": fraud_risk_level,
        "deviation_impact": f"行为偏离度{deviation_score}分" + ("，已对命中规则severity上调" if deviation_score > 50 else "，未触发severity调整"),
        "conclusion": "；".join(conclusion_parts),
    }


def run_aml_matching(profile):
    """执行全部反洗钱规则匹配"""
    deviation_score = profile.get("deviation_analysis", {}).get("overall_deviation_score", 0)

    aml_matchers = [
        ("AML-001", match_aml_001),
        ("AML-002", match_aml_002),
        ("AML-003", match_aml_003),
        ("AML-004", match_aml_004),
        ("AML-005", match_aml_005),
        ("AML-009", match_aml_009),
        ("AML-010", match_aml_010),
    ]

    matched_rules = []
    unmatched_rules = []
    data_gaps = []
    disabled_rules = []

    for rule_id, matcher in aml_matchers:
        result = matcher(profile)
        if result is None:
            if rule_id == "AML-009":
                data_gaps.append(f"{rule_id}: 单UID模式下无法验证，需跨账户数据")
            else:
                data_gaps.append(f"{rule_id}: 交易数据不可用，无法验证")
        elif result["triggered"]:
            matched_rules.append(result)
        else:
            unmatched_rules.append(f"{rule_id} {result['rule_name']}: 未命中")

    for rule_id, reason in DISABLED_AML_RULES.items():
        disabled_rules.append(f"{rule_id}: {reason}")

    aml_012 = match_aml_012(matched_rules)
    if aml_012["triggered"]:
        matched_rules.append(aml_012)
    else:
        unmatched_rules.append("AML-012 多项洗钱指标叠加: 未命中")

    apply_deviation_adjustment(matched_rules, deviation_score)

    high_count = sum(1 for r in matched_rules if r["severity"] == "高")
    med_count = sum(1 for r in matched_rules if r["severity"] == "中")
    if high_count >= 2:
        aml_risk_level = "高风险"
    elif high_count == 1 or med_count >= 2:
        aml_risk_level = "中风险"
    elif med_count == 1:
        aml_risk_level = "低风险"
    else:
        aml_risk_level = "无风险"

    total_rules = len(aml_matchers) + len(DISABLED_AML_RULES) + 1

    tx_available = profile.get("transaction_profile", {}).get("available", False)
    verifiable_note = "当前MCP仅支持身份/设备/网络维度的规则验证" if not tx_available else "交易数据可用，全量规则已验证"

    conclusion_parts = []
    if matched_rules:
        conclusion_parts.append(f"命中{len(matched_rules)}条反洗钱规则(高:{high_count}, 中:{med_count})")
    if data_gaps:
        conclusion_parts.append(f"{len(data_gaps)}条规则因数据不可用无法验证")
    if not matched_rules:
        conclusion_parts.append("未命中任何反洗钱规则")

    return {
        "module": "anti_money_laundering",
        "uid": str(profile.get("uid", "")),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "rules_version": "v1.1",
        "total_rules_checked": total_rules,
        "rule_results": matched_rules,
        "matched_rules": matched_rules,
        "unmatched_rules_checked": unmatched_rules,
        "data_gaps": data_gaps,
        "disabled_rules": disabled_rules,
        "aml_risk_level": aml_risk_level,
        "verifiable_rules_note": verifiable_note,
        "deviation_impact": f"行为偏离度{deviation_score}分" + ("，已对命中规则severity上调" if deviation_score > 50 else "，未触发severity调整"),
        "conclusion": "；".join(conclusion_parts),
    }


# ================================================================
# 入口
# ================================================================

def main():
    parser = argparse.ArgumentParser(description="规则匹配（确定性反欺诈+反洗钱判定）")
    parser.add_argument("--profile", required=True, help="用户画像 JSON 文件")
    parser.add_argument("--output-fraud", required=True, help="反欺诈分析输出")
    parser.add_argument("--output-aml", required=True, help="反洗钱分析输出")
    args = parser.parse_args()

    with open(args.profile, "r", encoding="utf-8") as f:
        profile = json.load(f)

    fraud_result = run_fraud_matching(profile)
    aml_result = run_aml_matching(profile)

    with open(args.output_fraud, "w", encoding="utf-8") as f:
        json.dump(fraud_result, f, ensure_ascii=False, indent=2)

    with open(args.output_aml, "w", encoding="utf-8") as f:
        json.dump(aml_result, f, ensure_ascii=False, indent=2)

    frd_matched = len(fraud_result["matched_rules"])
    aml_matched = len(aml_result["matched_rules"])
    print(f"规则匹配完成: FRD={frd_matched}条命中({fraud_result['fraud_risk_level']}), "
          f"AML={aml_matched}条命中({aml_result['aml_risk_level']})")
    print(f"输出: {args.output_fraud}, {args.output_aml}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
