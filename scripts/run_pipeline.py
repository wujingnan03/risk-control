#!/usr/bin/env python3
"""
风控分析一体化流水线（内存模式）

将 user_profiling → rule_matching → risk_scoring 串联为单次调用，
全程在内存中完成，不生成任何中间文件。

用法：
  python3 run_pipeline.py --input raw_data.json
  python3 run_pipeline.py --input raw_data.json --full    # 输出完整 JSON（含 score_breakdown）
  python3 run_pipeline.py --input raw_data.json --json    # stdout 输出完整 score JSON（供管道使用）

默认输出：简洁的风险结论摘要（文本）
"""

import json
import sys
import argparse
import os

# 将脚本所在目录加入 path，确保可以 import 同目录下的模块
_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from user_profiling import build_profile
from rule_matching import run_fraud_matching, run_aml_matching
from risk_scoring import compute_score


def run_pipeline(raw_data):
    """
    内存流水线主函数。
    
    输入：raw_data dict（来自 MCP 采集的原始数据）
    返回：(score_result, fraud_result, aml_result, profile, exit_code)
    """
    # A2: 用户画像
    profile = build_profile(raw_data)

    # A3+A4: 规则匹配
    fraud_result = run_fraud_matching(profile)
    aml_result = run_aml_matching(profile)

    # A5: 综合评分
    score_result, exit_code = compute_score(profile, fraud_result, aml_result)

    return score_result, fraud_result, aml_result, profile, exit_code


def format_summary(score_result, fraud_result, aml_result, profile):
    """生成人类可读的文本摘要，供 LLM 直接使用。"""
    uid = profile.get("registration_profile", {}).get("uid", "unknown")
    score = score_result.get("risk_score")
    level = score_result.get("risk_level", "未知")
    validation = score_result.get("data_validation_level", "")
    degraded = score_result.get("degraded_dimensions", [])
    action = score_result.get("action_detail", {})

    frd_matched = [r["rule_id"] for r in fraud_result.get("matched_rules", [])]
    aml_matched = [r["rule_id"] for r in aml_result.get("matched_rules", [])]
    frd_gaps = fraud_result.get("data_gaps", [])
    aml_gaps = aml_result.get("data_gaps", [])

    lines = []
    lines.append("=" * 50)
    lines.append(f"  风控分析结果  UID: {uid}")
    lines.append("=" * 50)

    if score is None:
        lines.append(f"⛔ 拒绝评分: {score_result.get('reject_reason', '')}")
        lines.append(f"   缺失数据: {score_result.get('missing_data', [])}")
    else:
        lines.append(f"  风险评分: {score} / 100")
        lines.append(f"  风险级别: {level}")
        lines.append(f"  数据完整性: {validation}{' (降级: ' + ', '.join(degraded) + ')' if degraded else ''}")
        lines.append("")

        # 评分拆解
        bd = score_result.get("score_breakdown", {})
        lines.append(f"  评分拆解:")
        lines.append(f"    维度基础分: {bd.get('dimension_base_score', 0)}")
        lines.append(f"    规则命中分: {bd.get('rule_score', 0)}")
        lines.append(f"    偏离度乘数: ×{bd.get('deviation_multiplier', {}).get('multiplier', 1.0)}")
        lines.append(f"    交叉项乘数: ×{bd.get('cross_term_multiplier', {}).get('multiplier', 1.0)}")
        lines.append("")

        # 反欺诈命中
        lines.append(f"  反欺诈规则: {len(frd_matched)} 条命中 / {len(frd_gaps)} 条数据缺失")
        for r in fraud_result.get("matched_rules", []):
            ev = r.get("evidence", [])
            ev_str = ev[0] if ev else ""
            lines.append(f"    ✗ {r['rule_id']} [{r['severity']}] {r['rule_name']}: {ev_str}")

        # 反洗钱命中
        lines.append(f"  反洗钱规则: {len(aml_matched)} 条命中 / {len(aml_gaps)} 条数据缺失")
        for r in aml_result.get("matched_rules", []):
            ev = r.get("evidence", [])
            ev_str = ev[0] if ev else ""
            lines.append(f"    ✗ {r['rule_id']} [{r['severity']}] {r['rule_name']}: {ev_str}")

        # 数据缺失说明
        all_gaps = frd_gaps + aml_gaps
        if all_gaps:
            lines.append("")
            lines.append(f"  数据缺失（共 {len(all_gaps)} 条规则无法验证）:")
            for g in all_gaps[:3]:
                lines.append(f"    - {g}")
            if len(all_gaps) > 3:
                lines.append(f"    - ...（另 {len(all_gaps) - 3} 条）")

        # 处置建议
        lines.append("")
        lines.append(f"  处置建议: {action.get('recommendation', '')}")
        imm = action.get("immediate_actions", [])
        if imm:
            for a in imm:
                lines.append(f"    • {a}")

    lines.append("=" * 50)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="风控流水线（内存模式，无中间文件）")
    parser.add_argument("--input", required=True, help="原始数据 JSON 文件（MCP 采集后的 raw_data.json）")
    parser.add_argument("--full", action="store_true", help="输出完整 score JSON 到 stdout")
    parser.add_argument("--json", action="store_true", dest="json_out",
                        help="输出完整 score JSON 到 stdout（机器可读，适合管道）")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    score_result, fraud_result, aml_result, profile, exit_code = run_pipeline(raw_data)

    if args.json_out or args.full:
        # 机器可读模式：输出完整 JSON
        output = {
            "score": score_result,
            "fraud": fraud_result,
            "aml": aml_result,
        }
        print(json.dumps(output, ensure_ascii=False, indent=2))
    else:
        # 默认：人类可读摘要
        print(format_summary(score_result, fraud_result, aml_result, profile))

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
