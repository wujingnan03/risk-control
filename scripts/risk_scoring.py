#!/usr/bin/env python3
"""
风险评分计算脚本 —— 专家评分卡模型（Expert Scorecard）

模型选型说明：
============
当前阶段无标注样本训练 ML 模型，因此采用金融风控行业标准的专家评分卡：
- 连续变量分箱（binning）打分，而非布尔二值化，保留变量的区分度
- 维度内取最高分箱得分（单维度不重复叠加）
- 交叉项乘数：多维度同时异常时风险非线性增长
- 行为偏离度作为乘数（放大器），不独立加分
- 规则命中（FRD/AML）独立加分

评分流程：
  维度分箱得分(0~75) → 规则命中加分(0~不限) → 求和 → 偏离度乘数 → 交叉项乘数 → 归一化到0-100

数据验证层级：
  L0 硬阻断：用户信息+登录日志缺失 → 拒绝评分，返回错误码
  L1 降级评分：设备/IP归属地缺失 → 对应维度不计分，降级标注
  L2 可选增强：交易数据缺失 → 交易维度不计分（接口开发中，预期内）

用法：python risk_scoring.py --profile profile.json --fraud fraud.json --aml aml.json --output score.json
"""

import json
import sys
import argparse
from datetime import datetime


# ================================================================
# 第一部分：强数据验证
# ================================================================

def validate_data_completeness(profile):
    """
    验证数据完整性，返回 (can_score, level, missing_details)。
    
    can_score: bool, False 时拒绝评分
    level: "L0_REJECT" | "L1_DEGRADED" | "L2_FULL"
    missing_details: list of strings
    """
    missing = []
    
    # --- L0 硬阻断检查 ---
    # 用户基本信息
    reg = profile.get("registration_profile", {})
    if not reg or not reg.get("uid"):
        missing.append("L0:registration_profile 缺失或无 uid")
    
    # 登录日志
    login = profile.get("login_profile", {})
    total_logins = login.get("total_logins", 0)
    if total_logins == 0:
        missing.append("L0:login_profile 无登录记录（total_logins=0）")
    
    l0_missing = [m for m in missing if m.startswith("L0")]
    if l0_missing:
        return False, "L0_REJECT", missing
    
    # --- L1 降级检查 ---
    device = profile.get("device_profile", {})
    if device.get("total_unique_devices", 0) == 0:
        missing.append("L1:device_profile 无设备数据")
    
    ip = profile.get("ip_profile", {})
    if ip.get("unique_ips", 0) == 0:
        missing.append("L1:ip_profile 无 IP 数据")
    
    l1_missing = [m for m in missing if m.startswith("L1")]
    if l1_missing:
        return True, "L1_DEGRADED", missing
    
    # --- L2 可选检查 ---
    tx = profile.get("transaction_profile", {})
    if not tx.get("available", False):
        missing.append("L2:transaction_profile 不可用（接口开发中）")
    
    l2_missing = [m for m in missing if m.startswith("L2")]
    if l2_missing:
        return True, "L2_PARTIAL", missing
    
    return True, "FULL", missing


# ================================================================
# 第二部分：评分卡定义 —— 分箱表
# ================================================================
# 
# 每个维度的分箱表格式：[(上限, 得分), ...]
# 取值落入哪个箱就得多少分，从上到下匹配第一个满足条件的箱
# 每个维度有一个 max_score，归一化时使用

SCORECARD = {
    # --- 设备维度 (满分 15) ---
    "device": {
        "max_score": 15,
        "variables": {
            "unique_devices": {
                "extract": lambda p: p.get("device_profile", {}).get("total_unique_devices", 0),
                "bins": [
                    # (上限, 得分) — 值 <= 上限时取该得分
                    (1, 0),     # 1台设备：正常
                    (2, 2),     # 2台：基本正常
                    (3, 5),     # 3台：轻微异常
                    (5, 10),    # 4-5台：显著异常
                    (999, 15),  # 6+台：极端异常
                ],
            },
            "new_device_ratio_7d": {
                "extract": lambda p: p.get("device_profile", {}).get("new_device_ratio_7d", 0),
                "bins": [
                    (0.2, 0),
                    (0.4, 3),
                    (0.6, 8),
                    (0.8, 12),
                    (1.0, 15),
                ],
            },
        },
    },

    # --- 登录行为维度 (满分 15) ---
    "login_behavior": {
        "max_score": 15,
        "variables": {
            "night_active_rate": {
                "extract": lambda p: p.get("login_profile", {}).get("night_active_rate", 0),
                "bins": [
                    (0.05, 0),   # ≤5%：正常
                    (0.15, 3),   # 5-15%：轻微
                    (0.30, 8),   # 15-30%：显著
                    (0.50, 12),  # 30-50%：高度异常
                    (1.0, 15),   # >50%：极端
                ],
            },
            "daily_avg_logins": {
                "extract": lambda p: p.get("login_profile", {}).get("daily_avg_logins", 0),
                "bins": [
                    (3, 0),      # ≤3次/天：正常
                    (8, 3),      # 3-8次：略多
                    (15, 8),     # 8-15次：异常
                    (30, 12),    # 15-30次：高度异常
                    (9999, 15),  # >30次：极端
                ],
            },
        },
    },

    # --- IP 地理维度 (满分 15) ---
    "ip_geography": {
        "max_score": 15,
        "variables": {
            "unique_provinces": {
                "extract": lambda p: p.get("ip_profile", {}).get("unique_provinces", 0),
                "bins": [
                    (2, 0),      # 1-2省：正常（居住+工作）
                    (4, 4),      # 3-4省：关注
                    (6, 9),      # 5-6省：显著异常
                    (999, 15),   # 7+省：极端
                ],
            },
            "foreign_ip_rate": {
                "extract": lambda p: p.get("ip_profile", {}).get("foreign_ip_rate", 0),
                "bins": [
                    (0, 0),       # 无境外IP
                    (0.1, 6),     # <10%：偶发
                    (0.3, 10),    # 10-30%：频繁
                    (1.0, 15),    # >30%：主要从境外登录
                ],
            },
        },
    },

    # --- 账户维度 (满分 10) ---
    "account": {
        "max_score": 10,
        "variables": {
            "account_age_days": {
                "extract": lambda p: p.get("registration_profile", {}).get("account_age_days", 9999),
                "bins": [
                    # 注意：账龄越短风险越高，所以分箱是反向的
                    (3, 10),      # ≤3天：极高风险新号
                    (7, 8),       # 4-7天
                    (30, 5),      # 8-30天
                    (180, 2),     # 1-6个月
                    (99999, 0),   # >6个月：老号
                ],
                "reverse": True,  # 值越小分越高
            },
            "max_gap_days": {
                "extract": lambda p: p.get("login_profile", {}).get("max_gap_days", 0),
                "bins": [
                    (30, 0),      # <30天间隔：正常
                    (90, 3),      # 1-3个月
                    (180, 7),     # 3-6个月
                    (99999, 10),  # >6个月休眠后激活
                ],
            },
        },
    },

    # --- 主动交易维度 (满分 20, 不含定投, 不可用时整维度跳过) ---
    "manual_trading": {
        "max_score": 20,
        "requires_tx": True,  # 标记：交易数据不可用时跳过整个维度
        "variables": {
            "rapid_turnaround_count": {
                "extract": lambda p: p.get("transaction_profile", {}).get("manual_trading", {}).get("rapid_turnaround_count", 0),
                "bins": [
                    (0, 0),
                    (1, 8),
                    (2, 14),
                    (999, 20),
                ],
            },
            "split_buy_days": {
                "extract": lambda p: p.get("transaction_profile", {}).get("manual_trading", {}).get("split_buy_days", 0),
                "bins": [
                    (0, 0),
                    (1, 12),
                    (999, 20),
                ],
            },
            "max_single_buy": {
                "extract": lambda p: p.get("transaction_profile", {}).get("manual_trading", {}).get("max_single_buy", 0),
                "bins": [
                    (50000, 0),       # ≤5万：正常
                    (200000, 4),      # 5-20万
                    (500000, 10),     # 20-50万
                    (9999999999, 16), # >50万
                ],
            },
        },
    },
}


def score_dimension(dimension_config, profile):
    """
    计算单个维度的得分。
    
    逻辑：维度内多个变量各自分箱打分，取最高分（不叠加，避免同一风险被重复计算）。
    返回 (score, max_possible, details)
    """
    max_score = dimension_config["max_score"]
    var_scores = []
    details = []

    for var_name, var_config in dimension_config["variables"].items():
        raw_value = var_config["extract"](profile)
        bins = var_config["bins"]
        is_reverse = var_config.get("reverse", False)

        # 分箱匹配
        matched_score = 0
        matched_bin = None
        if is_reverse:
            # 反向分箱：值越小分越高，从小到大匹配
            for threshold, score in bins:
                if raw_value <= threshold:
                    matched_score = score
                    matched_bin = f"<={threshold}"
                    break
        else:
            for threshold, score in bins:
                if raw_value <= threshold:
                    matched_score = score
                    matched_bin = f"<={threshold}"
                    break

        var_scores.append(matched_score)
        details.append({
            "variable": var_name,
            "raw_value": round(raw_value, 4) if isinstance(raw_value, float) else raw_value,
            "bin": matched_bin,
            "score": matched_score,
        })

    # 维度得分 = 维度内最高变量分（不叠加）
    dim_score = max(var_scores) if var_scores else 0
    # 但不超过维度上限
    dim_score = min(dim_score, max_score)

    return dim_score, max_score, details


# ================================================================
# 第三部分：规则命中加分
# ================================================================

# 规则严重程度 → 加分值
RULE_SEVERITY_POINTS = {
    "高": 8,
    "中": 4,
    "低": 2,
    "high": 8,
    "medium": 4,
    "low": 2,
}


def score_rule_matches(analysis, module_name):
    """
    计算规则命中加分。
    仅对 triggered/matched 为 true 的规则计分，
    disabled_rules 和 data_gaps 不参与计分。
    """
    if not analysis:
        return 0, [{"note": f"无{module_name}分析数据"}]

    score = 0
    details = []
    rules = analysis.get("rule_results", analysis.get("matched_rules", []))

    if not isinstance(rules, list):
        return 0, [{"note": f"{module_name}的rule_results格式异常"}]

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        triggered = rule.get("triggered", rule.get("matched", False))
        if triggered:
            severity = rule.get("severity", "低")
            points = RULE_SEVERITY_POINTS.get(severity, 0)
            score += points
            details.append({
                "rule_id": rule.get("rule_id", "unknown"),
                "severity": severity,
                "points": points,
            })

    disabled_count = len(analysis.get("disabled_rules", []))
    gap_count = len(analysis.get("data_gaps", []))
    if disabled_count > 0 or gap_count > 0:
        details.append({
            "note": f"{module_name}: {disabled_count}条规则已禁用, {gap_count}条数据不可用, 均不计分",
        })

    return score, details


# ================================================================
# 第四部分：乘数因子
# ================================================================

def compute_deviation_multiplier(profile):
    """
    行为偏离度乘数。
    偏离度不独立加分，而是作为"放大器"——偏离度越高，其他维度的得分被放大越多。
    
    返回 (multiplier, details)
    """
    deviation = profile.get("deviation_analysis", {})
    deviation_score = deviation.get("overall_deviation_score", 0)
    baseline_type = deviation.get("baseline_type", "unknown")

    if deviation_score <= 20:
        multiplier = 1.0
        label = "无显著偏离"
    elif deviation_score <= 50:
        multiplier = 1.10
        label = "轻度偏离"
    elif deviation_score <= 75:
        multiplier = 1.20
        label = "显著偏离"
    else:
        multiplier = 1.35
        label = "极端偏离"

    return multiplier, {
        "deviation_score": deviation_score,
        "baseline_type": baseline_type,
        "multiplier": multiplier,
        "label": label,
        "note": "偏离度作为乘数放大其他维度得分，不独立加分",
    }


def compute_cross_term_multiplier(dimension_scores):
    """
    交叉项乘数：多维度同时异常时，风险非线性增长。
    
    逻辑：统计有多少个维度得分 > 0，维度越多乘数越大。
    这是因为"新账号 + 多设备 + 境外IP + 快进快出"的组合风险远大于四者单独相加。
    
    返回 (multiplier, details)
    """
    active_dims = []
    for dim_name, dim_score, _ in dimension_scores:
        if dim_score > 0:
            active_dims.append(dim_name)

    n = len(active_dims)
    if n <= 1:
        multiplier = 1.0
    elif n == 2:
        multiplier = 1.05
    elif n == 3:
        multiplier = 1.15
    elif n == 4:
        multiplier = 1.30
    else:
        multiplier = 1.45  # 5+维度同时异常

    return multiplier, {
        "active_dimension_count": n,
        "active_dimensions": active_dims,
        "multiplier": multiplier,
        "note": "多维度同时异常时风险非线性增长",
    }


# ================================================================
# 第五部分：风险等级与处置建议
# ================================================================

RISK_LEVELS = [
    (0, 25, "低风险"),
    (26, 50, "中风险"),
    (51, 75, "高风险"),
    (76, 100, "极高风险"),
]

ACTION_TEMPLATES = {
    "低风险": {
        "recommendation": "正常监控，无需特殊处置",
        "immediate_actions": ["维持正常交易权限"],
        "monitoring_actions": ["常规交易监控"],
        "escalation_needed": False,
    },
    "中风险": {
        "recommendation": "列入关注名单，加强交易监控",
        "immediate_actions": ["列入关注名单", "加强大额交易审核"],
        "monitoring_actions": ["每日交易行为监控", "异常交易实时告警"],
        "escalation_needed": False,
    },
    "高风险": {
        "recommendation": "限制大额交易，人工复核，评估是否提交可疑交易报告",
        "immediate_actions": ["限制单笔交易金额上限", "大额交易需人工审核", "通知合规部门"],
        "monitoring_actions": ["实时交易监控", "登录行为监控", "每周人工复核"],
        "escalation_needed": True,
    },
    "极高风险": {
        "recommendation": "暂停交易权限，立即人工审查，提交可疑交易报告",
        "immediate_actions": ["暂停所有交易权限", "冻结赎回操作", "立即提交可疑交易报告", "报告合规部门和风控负责人"],
        "monitoring_actions": ["24小时账户监控", "关联账户排查"],
        "escalation_needed": True,
    },
}


def determine_risk_level(score):
    for low, high, level in RISK_LEVELS:
        if low <= score <= high:
            return level
    return "极高风险"


def build_action_detail(risk_level, fraud_analysis, aml_analysis):
    template = ACTION_TEMPLATES.get(risk_level, ACTION_TEMPLATES["高风险"])
    result = {
        "recommendation": template["recommendation"],
        "immediate_actions": list(template["immediate_actions"]),
        "monitoring_actions": list(template["monitoring_actions"]),
        "escalation_needed": template["escalation_needed"],
    }

    # 根据具体命中规则补充针对性建议
    for analysis in [fraud_analysis, aml_analysis]:
        if not analysis:
            continue
        for rule in analysis.get("rule_results", analysis.get("matched_rules", [])):
            triggered = rule.get("triggered", rule.get("matched", False))
            if not triggered:
                continue
            severity = rule.get("severity", "")
            rule_name = rule.get("rule_name", rule.get("rule_id", ""))
            if severity in ("高", "high"):
                if any(kw in rule_name for kw in ["境外", "foreign"]):
                    result["immediate_actions"].append("核实用户是否有合法境外登录需求")
                if any(kw in rule_name for kw in ["设备", "device", "多设备"]):
                    result["immediate_actions"].append("要求用户进行设备绑定确认")
                if any(kw in rule_name for kw in ["大额", "拆分"]):
                    result["immediate_actions"].append("大额交易逐笔审核")
                if any(kw in rule_name for kw in ["快进快出", "turnaround"]):
                    result["monitoring_actions"].append("监控是否持续出现快进快出模式")

    result["immediate_actions"] = list(dict.fromkeys(result["immediate_actions"]))
    result["monitoring_actions"] = list(dict.fromkeys(result["monitoring_actions"]))
    return result


# ================================================================
# 第六部分：主流程
# ================================================================

def compute_score(profile, fraud_analysis=None, aml_analysis=None):
    """
    核心评分函数（纯内存计算，不依赖文件 I/O）。
    
    可直接被 run_pipeline.py 等上层脚本调用，也可通过 main() 的 CLI 调用。
    
    返回：(result_dict, exit_code)
      exit_code 0 = 成功，1 = L0 数据缺失拒绝评分
    """
    # ---- Step 0: 强数据验证 ----
    can_score, data_level, missing_details = validate_data_completeness(profile)

    if not can_score:
        result = {
            "risk_score": None,
            "risk_level": "拒绝评分",
            "reject_reason": "核心数据缺失，无法生成可靠评分",
            "missing_data": missing_details,
            "data_validation_level": data_level,
            "action_detail": {
                "recommendation": "核心数据缺失，拒绝评分。请检查 MCP 连接状态并确认 UID 有效",
                "immediate_actions": [
                    "检查 queryUserInfoByUid 是否正常返回",
                    "检查 queryLoginLogList 是否正常返回",
                    "确认 UID 是否存在且有效",
                ],
                "monitoring_actions": [],
                "escalation_needed": False,
            },
            "scoring_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scoring_version": "v2.0-expert-scorecard",
            "scoring_model": "REJECTED",
        }
        return result, 1

    # ---- Step 1: 各维度分箱计分 ----
    tx_available = profile.get("transaction_profile", {}).get("available", False)
    dimension_scores = []
    dimension_details = {}
    degraded_dimensions = []

    for dim_name, dim_config in SCORECARD.items():
        if dim_config.get("requires_tx") and not tx_available:
            degraded_dimensions.append(dim_name)
            dimension_details[dim_name] = {
                "score": 0, "max": dim_config["max_score"],
                "status": "跳过（交易数据不可用）",
                "variables": [],
            }
            continue

        if dim_name == "device" and profile.get("device_profile", {}).get("total_unique_devices", 0) == 0:
            degraded_dimensions.append(dim_name)
            dimension_details[dim_name] = {
                "score": 0, "max": dim_config["max_score"],
                "status": "跳过（设备数据不可用）",
                "variables": [],
            }
            continue

        if dim_name == "ip_geography" and profile.get("ip_profile", {}).get("unique_ips", 0) == 0:
            degraded_dimensions.append(dim_name)
            dimension_details[dim_name] = {
                "score": 0, "max": dim_config["max_score"],
                "status": "跳过（IP数据不可用）",
                "variables": [],
            }
            continue

        score, max_possible, details = score_dimension(dim_config, profile)
        dimension_scores.append((dim_name, score, max_possible))
        dimension_details[dim_name] = {
            "score": score, "max": max_possible,
            "status": "正常",
            "variables": details,
        }

    base_score = sum(s for _, s, _ in dimension_scores)
    max_possible_base = sum(m for _, _, m in dimension_scores)

    # ---- Step 2: 规则命中加分 ----
    fraud_score, fraud_details = score_rule_matches(fraud_analysis, "反欺诈")
    aml_score, aml_details = score_rule_matches(aml_analysis, "反洗钱")
    rule_score = fraud_score + aml_score

    # ---- Step 3: 偏离度乘数 ----
    deviation_multiplier, deviation_details = compute_deviation_multiplier(profile)

    # ---- Step 4: 交叉项乘数 ----
    cross_multiplier, cross_details = compute_cross_term_multiplier(dimension_scores)

    # ---- Step 5: 综合计算 ----
    raw_combined = base_score + rule_score
    after_deviation = raw_combined * deviation_multiplier
    after_cross = after_deviation * cross_multiplier

    theoretical_max = max_possible_base + 60
    theoretical_max_with_multipliers = theoretical_max * 1.35 * 1.45

    if theoretical_max_with_multipliers > 0:
        normalized_score = min(round(after_cross / theoretical_max_with_multipliers * 100), 100)
    else:
        normalized_score = 0

    high_rule_count = sum(1 for d in fraud_details + aml_details if isinstance(d, dict) and d.get("severity") in ("高", "high"))
    if high_rule_count >= 1 and normalized_score < 30:
        normalized_score = 30

    # ---- Step 6: 映射风险等级 ----
    risk_level = determine_risk_level(normalized_score)
    action_detail = build_action_detail(risk_level, fraud_analysis, aml_analysis)

    result = {
        "risk_score": normalized_score,
        "risk_level": risk_level,
        "data_validation_level": data_level,
        "degraded_dimensions": degraded_dimensions,
        "missing_data": missing_details if missing_details else None,
        "score_breakdown": {
            "model": "expert_scorecard_v2",
            "formula": "(维度基础分 + 规则命中分) × 偏离度乘数 × 交叉项乘数 → 归一化0-100",
            "dimension_base_score": base_score,
            "dimension_max_possible": max_possible_base,
            "dimension_details": dimension_details,
            "rule_score": rule_score,
            "fraud_rule_score": fraud_score,
            "fraud_rule_details": fraud_details,
            "aml_rule_score": aml_score,
            "aml_rule_details": aml_details,
            "deviation_multiplier": deviation_details,
            "cross_term_multiplier": cross_details,
            "raw_combined": round(raw_combined, 2),
            "after_deviation": round(after_deviation, 2),
            "after_cross": round(after_cross, 2),
            "normalized_score": normalized_score,
            "floor_applied": high_rule_count >= 1 and normalized_score == 30,
        },
        "action_detail": action_detail,
        "scoring_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scoring_version": "v2.0-expert-scorecard",
    }
    return result, 0


def main():
    parser = argparse.ArgumentParser(description="风险评分计算（专家评分卡模型）")
    parser.add_argument("--profile", required=True, help="用户画像 JSON 文件")
    parser.add_argument("--fraud", required=False, default=None, help="反欺诈分析 JSON 文件")
    parser.add_argument("--aml", required=False, default=None, help="反洗钱分析 JSON 文件")
    parser.add_argument("--output", required=True, help="输出 JSON 文件")
    args = parser.parse_args()

    with open(args.profile, "r", encoding="utf-8") as f:
        profile = json.load(f)

    fraud_analysis = None
    if args.fraud:
        with open(args.fraud, "r", encoding="utf-8") as f:
            fraud_analysis = json.load(f)

    aml_analysis = None
    if args.aml:
        with open(args.aml, "r", encoding="utf-8") as f:
            aml_analysis = json.load(f)

    result, exit_code = compute_score(profile, fraud_analysis, aml_analysis)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    if exit_code != 0:
        print(f"❌ 拒绝评分: {result.get('missing_data')}")
    else:
        print(f"评分完成: {result['risk_score']} ({result['risk_level']}) [模型: expert_scorecard_v2]")
        print(f"数据验证: {result['data_validation_level']}, 降级维度: {result['degraded_dimensions'] or '无'}")
        print(f"输出: {args.output}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
