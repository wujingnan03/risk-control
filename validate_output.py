#!/usr/bin/env python3
"""
输出校验脚本
验证最终报告 JSON 是否符合 output_schema.md 定义的结构
返回校验结果：通过/失败 + 具体问题列表

用法：python validate_output.py --input report.json --type final_report|user_profile|fraud|aml|feature
"""

import json
import sys
import argparse


class ValidationError:
    def __init__(self, field, message, severity="ERROR"):
        self.field = field
        self.message = message
        self.severity = severity  # ERROR = 必须修复, WARNING = 建议修复

    def to_dict(self):
        return {"field": self.field, "message": self.message, "severity": self.severity}


def validate_not_empty(data, field_path, errors):
    """验证字段非空"""
    keys = field_path.split(".")
    current = data
    for k in keys:
        if isinstance(current, dict):
            current = current.get(k)
        else:
            current = None
            break

    if current is None or current == "" or current == []:
        errors.append(ValidationError(field_path, f"必填字段为空"))
        return False
    return True


def validate_type(data, field_path, expected_type, errors):
    """验证字段类型"""
    keys = field_path.split(".")
    current = data
    for k in keys:
        if isinstance(current, dict):
            current = current.get(k)
        else:
            return True  # 字段不存在，由 not_empty 检查

    if current is not None and not isinstance(current, expected_type):
        errors.append(ValidationError(
            field_path,
            f"类型错误: 期望 {expected_type.__name__}, 实际 {type(current).__name__}"
        ))
        return False
    return True


def validate_enum(data, field_path, valid_values, errors):
    """验证字段值在允许范围内"""
    keys = field_path.split(".")
    current = data
    for k in keys:
        if isinstance(current, dict):
            current = current.get(k)
        else:
            return True

    if current is not None and current not in valid_values:
        errors.append(ValidationError(
            field_path,
            f"值不在允许范围内: '{current}', 允许值: {valid_values}"
        ))
        return False
    return True


def validate_range(data, field_path, min_val, max_val, errors):
    """验证数值范围"""
    keys = field_path.split(".")
    current = data
    for k in keys:
        if isinstance(current, dict):
            current = current.get(k)
        else:
            return True

    if current is not None and isinstance(current, (int, float)):
        if current < min_val or current > max_val:
            if not (current == -1 and min_val == 0):  # -1 允许作为"数据不足"标记
                errors.append(ValidationError(
                    field_path,
                    f"值超出范围: {current}, 允许范围: [{min_val}, {max_val}]"
                ))
                return False
    return True


def validate_final_report(data):
    """验证最终报告结构"""
    errors = []

    # 必填顶层字段
    required_fields = [
        "report_id", "uid", "assessment_time", "data_quality_summary",
        "risk_score", "risk_level", "risk_tags",
        "fraud_analysis", "aml_analysis",
        "action_recommendation", "evidence_chain",
    ]
    for field in required_fields:
        validate_not_empty(data, field, errors)

    # report_id 格式
    report_id = data.get("report_id", "")
    if report_id and not report_id.startswith("RFC-"):
        errors.append(ValidationError("report_id", "格式错误: 应以 'RFC-' 开头"))

    # risk_score 范围
    validate_range(data, "risk_score", 0, 100, errors)

    # risk_level 枚举
    validate_enum(data, "risk_level",
                  ["低风险", "中风险", "高风险", "极高风险", "数据不足"], errors)

    # risk_score 与 risk_level 一致性
    score = data.get("risk_score")
    level = data.get("risk_level")
    if score is not None and level:
        expected_map = {
            (-1, -1): "数据不足",
            (0, 30): "低风险",
            (31, 60): "中风险",
            (61, 80): "高风险",
            (81, 100): "极高风险",
        }
        for (lo, hi), expected_level in expected_map.items():
            if lo <= score <= hi and level != expected_level:
                errors.append(ValidationError(
                    "risk_level",
                    f"与评分不一致: 评分={score}, 级别应为'{expected_level}', 实际为'{level}'"
                ))

    # risk_tags 类型
    validate_type(data, "risk_tags", list, errors)

    # evidence_chain 非空且结构正确
    evidence = data.get("evidence_chain", [])
    if isinstance(evidence, list):
        if len(evidence) == 0:
            errors.append(ValidationError("evidence_chain", "证据链不能为空数组"))
        for i, e in enumerate(evidence):
            for field in ["conclusion", "evidence", "data_source", "severity"]:
                if not e.get(field):
                    errors.append(ValidationError(
                        f"evidence_chain[{i}].{field}",
                        "证据链条目必填字段缺失"
                    ))
            validate_enum({"s": e.get("severity")}, "s", ["高", "中", "低"], errors)

    # action_recommendation 非空
    if not data.get("action_recommendation"):
        errors.append(ValidationError("action_recommendation", "处置建议不能为空"))

    # fraud_analysis 子结构
    fraud = data.get("fraud_analysis", {})
    if isinstance(fraud, dict) and fraud:
        validate_not_empty(fraud, "module", errors)
        validate_not_empty(fraud, "fraud_risk_level", errors)
        validate_enum({"l": fraud.get("fraud_risk_level")}, "l",
                      ["无风险", "低风险", "中风险", "高风险"], errors)

    # aml_analysis 子结构
    aml = data.get("aml_analysis", {})
    if isinstance(aml, dict) and aml:
        validate_not_empty(aml, "module", errors)
        validate_not_empty(aml, "aml_risk_level", errors)
        validate_enum({"l": aml.get("aml_risk_level")}, "l",
                      ["无风险", "低风险", "中风险", "高风险"], errors)

    return errors


def validate_user_profile(data):
    """验证用户画像结构"""
    errors = []

    required_fields = ["uid", "profile_generated_at", "profile_source",
                       "device_profile", "login_profile", "ip_profile",
                       "transaction_profile", "deviation_analysis"]
    for field in required_fields:
        validate_not_empty(data, field, errors)

    validate_enum(data, "profile_source", ["script", "manual_fallback"], errors)

    dp = data.get("device_profile", {})
    if isinstance(dp, dict):
        validate_type({"v": dp.get("total_unique_devices")}, "v", int, errors)

    lp = data.get("login_profile", {})
    if isinstance(lp, dict):
        validate_type({"v": lp.get("total_logins")}, "v", int, errors)
        nr = lp.get("night_active_rate")
        if isinstance(nr, (int, float)):
            validate_range({"v": nr}, "v", 0, 1, errors)

    dev = data.get("deviation_analysis", {})
    if isinstance(dev, dict):
        validate_range(dev, "overall_deviation_score", 0, 100, errors)

    return errors


def validate_rule_analysis(data, module_name, expected_risk_field, expected_total_rules):
    """通用规则分析校验（fraud/aml共用）"""
    errors = []
    validate_not_empty(data, "module", errors)
    validate_not_empty(data, expected_risk_field, errors)
    validate_not_empty(data, "conclusion", errors)

    matched = data.get("matched_rules", data.get("rule_results", []))
    if isinstance(matched, list):
        for i, r in enumerate(matched):
            for field in ["rule_id", "rule_name", "triggered", "severity", "evidence"]:
                if field not in r:
                    errors.append(ValidationError(
                        f"matched_rules[{i}].{field}", "必填字段缺失"))
            if r.get("triggered") and not r.get("evidence"):
                errors.append(ValidationError(
                    f"matched_rules[{i}].evidence",
                    f"{r.get('rule_id', '?')}: 命中规则必须有非空evidence"))
            sev = r.get("severity", "")
            if sev not in ("高", "中", "低"):
                errors.append(ValidationError(
                    f"matched_rules[{i}].severity",
                    f"severity值'{sev}'不合法，应为 高/中/低"))

    unmatched = data.get("unmatched_rules_checked", [])
    data_gaps = data.get("data_gaps", [])
    disabled = data.get("disabled_rules", [])

    total_count = len(matched) + len(unmatched) + len(data_gaps) + len(disabled)
    if expected_total_rules and total_count != expected_total_rules:
        errors.append(ValidationError(
            "rule_count",
            f"{module_name}规则总数不匹配: matched({len(matched)}) + "
            f"unmatched({len(unmatched)}) + data_gaps({len(data_gaps)}) + "
            f"disabled({len(disabled)}) = {total_count}, 期望{expected_total_rules}",
            severity="WARNING"))

    return errors


def validate_fraud_analysis(data):
    """验证反欺诈分析结构（12条FRD规则）"""
    return validate_rule_analysis(data, "反欺诈", "fraud_risk_level", 12)


def validate_aml_analysis(data):
    """验证反洗钱分析结构（12条AML规则）"""
    return validate_rule_analysis(data, "反洗钱", "aml_risk_level", 12)


VALIDATORS = {
    "final_report": validate_final_report,
    "user_profile": validate_user_profile,
    "fraud": validate_fraud_analysis,
    "aml": validate_aml_analysis,
}


def main():
    parser = argparse.ArgumentParser(description="输出格式校验")
    parser.add_argument("--input", required=True, help="待校验的 JSON 文件")
    parser.add_argument("--type", required=True, choices=VALIDATORS.keys(), help="校验类型")
    parser.add_argument("--output", required=False, help="校验结果输出文件（可选）")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    validator = VALIDATORS[args.type]
    errors = validator(data)

    error_count = sum(1 for e in errors if e.severity == "ERROR")
    warning_count = sum(1 for e in errors if e.severity == "WARNING")

    result = {
        "validation_passed": error_count == 0,
        "error_count": error_count,
        "warning_count": warning_count,
        "issues": [e.to_dict() for e in errors],
    }

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

    if error_count == 0:
        print(f"✅ 校验通过 (警告: {warning_count})")
    else:
        print(f"❌ 校验失败: {error_count} 个错误, {warning_count} 个警告")
        for e in errors:
            print(f"  [{e.severity}] {e.field}: {e.message}")

    return 0 if error_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
