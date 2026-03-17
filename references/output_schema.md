# 输出结构定义（Output Schema v2）

适配实际 MCP 接口字段。所有分析输出必须严格遵循以下结构。

**核心约束**：
- 所有字段不得为空字符串，数据不足时填 `"数据缺失"` 或 `null`
- 不得编造任何数据点，所有数值来源于 MCP 查询或 Python 脚本计算
- 每条风险结论必须附带 evidence 字段
- 交易数据当前 MCP 不可用，相关字段统一填占位值

---

## 1. UserProfile（用户行为画像）

由 `scripts/user_profiling.py` 输出。

```json
{
  "uid": "string",
  "profile_generated_at": "ISO时间戳",
  "profile_source": "script | manual_fallback",

  "registration_profile": {
    "uid": "number",
    "status": "string, 如'正常用户'",
    "risk_level_declared": "string, 如'积极型'(来自MCP riskDesc)",
    "risk_value": "number|null (来自MCP risk)",
    "account_type": "number|null",
    "cert_type": "string, 如'0'=身份证",
    "gender": "number|null, 2=女",
    "reg_date": "string|null, YYYY-MM-DD",
    "open_date": "string|null, YYYY-MM-DD",
    "account_age_days": "int, 注册至今天数",
    "is_open_trade": "boolean|null",
    "risk_assessment_done": "boolean|null (来自MCP riskStatus)",
    "created_ip": "string, 注册IP",
    "created_ip_location": "string, 注册IP归属地(需queryIpLocation)",
    "flavor": "string, 渠道标识"
  },

  "device_profile": {
    "total_unique_devices": "int, 来自登录日志deviceId去重计数",
    "device_type_distribution": {"iPhone": 2, "Android": 1},
    "platform_distribution": {"IOS": 2, "Android": 1},
    "client_distribution": {"Fund": 3},
    "new_device_ratio_7d": "float(0-1), 近7天新增设备占比",
    "new_device_ratio_30d": "float(0-1), 近30天新增设备占比",
    "most_used_device_id": "string, 登录最多的deviceId",
    "device_id_list": ["string, 所有deviceId按使用频次排序"],
    "device_list_raw_count": "int, queryLoginDeviceList返回条数"
  },

  "login_profile": {
    "total_logins": "int",
    "data_span_days": "int, 首末登录间隔天数",
    "daily_avg_logins": "float",
    "active_days": "int",
    "time_distribution": {
      "night_0006": "float(0-1)",
      "morning_0612": "float(0-1)",
      "afternoon_1218": "float(0-1)",
      "evening_1824": "float(0-1)"
    },
    "night_active_rate": "float(0-1), 等于night_0006",
    "first_login": "string, YYYY-MM-DD HH:mm:ss",
    "last_login": "string",
    "max_gap_days": "int, 最大登录间隔",
    "grant_type_distribution": {"refresh_token": 80, "password": 5},
    "data_note": "string, 如'已达接口返回上限(100条)'"
  },

  "ip_profile": {
    "unique_ips": "int, 排除脱敏IP后的去重数",
    "unique_provinces": "int",
    "unique_cities": "int",
    "domestic_ip_count": "int",
    "foreign_ip_count": "int",
    "foreign_ip_rate": "float(0-1)",
    "cross_region_rate": "float(0-1)",
    "province_list": ["string, 按出现频次排序"],
    "foreign_ip_details": [{"ip": "str", "country": "str", "login_count": "int"}],
    "isp_distribution": {"电信": 5, "移动": 3},
    "ip_details": [{"ip":"str","count":"int","country":"str","province":"str","city":"str","isp":"str","is_domestic":"bool"}]
  },

  "transaction_profile": {
    "available": false,
    "data_source": "MCP无交易数据接口",
    "note": "交易数据需通过其他渠道提供"
  },

  "deviation_analysis": {
    "baseline_type": "self | population",
    "baseline_data_days": "int",
    "recent_window_days": 7,
    "dimension_deviations": {
      "login_frequency": {"recent": "float", "baseline": "float", "deviation_ratio": "float", "alert": "bool"},
      "device_count": {"recent": 0, "baseline": 0, "deviation_ratio": 0, "alert": false},
      "unique_ips": {"recent": 0, "baseline": 0, "deviation_ratio": 0, "alert": false},
      "night_active_rate": {"recent": 0, "baseline": 0, "deviation_ratio": 0, "alert": false},
      "cross_region_rate": {"recent": 0, "baseline": 0, "deviation_ratio": 0, "alert": false}
    },
    "overall_deviation_score": "int(0-100)",
    "deviation_summary": "string, 自然语言偏离摘要"
  }
}
```

**字段规则**：
- 数值字段无数据时填 0，不填 null
- bool 字段无数据时填 false
- 字符串字段无数据时填 `"数据缺失"`
- `transaction_profile.available` 始终为 false（MCP 不支持）

---

## 2. FraudAnalysis（反欺诈分析）

由 `scripts/rule_matching.py` 输出。

```json
{
  "module": "anti_fraud",
  "uid": "string",
  "generated_at": "ISO时间戳",
  "rules_version": "v1.1",
  "total_rules_checked": "int, 全部规则数(含禁用)",
  "rule_results": [
    {
      "rule_id": "FRD-001",
      "rule_name": "多设备异常登录",
      "severity": "高 | 中 | 低",
      "triggered": true,
      "matched": true,
      "evidence": ["近期使用5台不同设备", "设备ID列表: a1b2, c3d4, ..."],
      "cross_validation": "IP稳定(2个)，severity降一级",
      "category": "账号安全"
    }
  ],
  "matched_rules": "同 rule_results（兼容字段）",
  "unmatched_rules_checked": ["FRD-004 凌晨异常活跃: 未命中"],
  "data_gaps": ["FRD-009: 交易数据不可用，无法验证"],
  "disabled_rules": ["FRD-008: 当前无IP信誉库数据源，无法判定VPN/代理IP"],
  "fraud_risk_level": "无风险 | 低风险 | 中风险 | 高风险",
  "deviation_impact": "行为偏离度78分，已对命中规则severity上调",
  "conclusion": "string"
}
```

**字段规则**：
- `matched_rules` + `unmatched_rules_checked` + `data_gaps` + `disabled_rules` 的条目总数 = 规则库全部规则数
- `evidence` 数组由脚本自动提取，包含具体数据值
- FRD-008 始终归入 `disabled_rules`（非 data_gaps）
- 无交易数据时 FRD-009/FRD-010 归入 `data_gaps`

---

## 3. AMLAnalysis（反洗钱分析）

由 `scripts/rule_matching.py` 输出。

```json
{
  "module": "anti_money_laundering",
  "uid": "string",
  "generated_at": "ISO时间戳",
  "rules_version": "v1.1",
  "total_rules_checked": "int, 全部规则数(含禁用)",
  "rule_results": [
    {
      "rule_id": "AML-010",
      "rule_name": "交易操作与登录地异常",
      "severity": "中",
      "triggered": true,
      "matched": true,
      "evidence": ["常驻省份: 浙江", "跨省率: 45%"],
      "cross_validation": "标注为待确认（无法判断是否出差/旅行）",
      "category": "设备网络"
    }
  ],
  "matched_rules": "同 rule_results（兼容字段）",
  "unmatched_rules_checked": ["AML-010: 未命中"],
  "data_gaps": [
    "AML-001: 交易数据不可用，无法验证",
    "AML-002: 交易数据不可用，无法验证",
    "AML-003: 交易数据不可用，无法验证",
    "AML-004: 交易数据不可用，无法验证",
    "AML-005: 交易数据不可用，无法验证",
    "AML-009: 单UID模式下无法验证，需跨账户数据"
  ],
  "disabled_rules": [
    "AML-006: 当前无外部身份核验系统",
    "AML-007: 当前MCP仅支持单UID查询，无法进行跨账户关联检测",
    "AML-008: 当前无收入水平等外部数据",
    "AML-011: 纯定性判断，无可量化的确定性条件"
  ],
  "aml_risk_level": "无风险 | 低风险 | 中风险 | 高风险",
  "verifiable_rules_note": "string",
  "deviation_impact": "string",
  "conclusion": "string"
}
```

**字段规则**：
- `matched_rules` + `unmatched_rules_checked` + `data_gaps` + `disabled_rules` 的条目总数 = 规则库全部规则数
- AML-006/007/008/011 始终归入 `disabled_rules`（非 data_gaps）
- 交易相关规则（001-005）无交易数据时归入 `data_gaps`
- 当前可验证的启用规则：AML-009(需多UID)、AML-010(登录地异常)、AML-012(叠加)

---

## 4. FinalReport（综合报告）

```json
{
  "report_id": "RFC-{uid}-{yyyyMMddHHmmss}",
  "uid": "string",
  "assessment_time": "ISO时间戳",

  "data_quality": {
    "user_info": "完整 | 部分缺失 | 无数据",
    "device_list": "完整 | 无数据",
    "login_logs": "完整 | 已达上限(100条) | 无数据",
    "ip_locations": "已解析X个/共Y个IP",
    "transaction_data": "不可用(MCP无接口)",
    "overall": "完整 | 部分缺失 | 数据严重不足"
  },

  "risk_score": "int(0-100), 数据不足时为-1",
  "risk_level": "低风险 | 中风险 | 高风险 | 极高风险 | 数据不足",
  "risk_tags": ["多设备异常", "IP跳变", "行为偏离"],

  "score_breakdown": {
    "indicator_score": "int, 画像风险指标得分",
    "fraud_score": "int, 反欺诈规则命中得分",
    "aml_score": "int, 反洗钱规则命中得分",
    "deviation_score": "int(0-15), 行为偏离加权分",
    "raw_total": "int, 未封顶原始分"
  },

  "fraud_analysis": "FraudAnalysis对象",
  "aml_analysis": "AMLAnalysis对象",

  "disposition_recommendation": {
    "action": "放行 | 人工复核 | 限制交易 | 冻结账户 | 上报监管",
    "reason": "string",
    "urgency": "立即 | 24小时内 | 常规",
    "immediate_actions": ["string"],
    "monitoring_actions": ["string"],
    "escalation_needed": "bool"
  },

  "evidence_chain": [
    {
      "conclusion": "多设备异常登录",
      "evidence": "近7日5台不同设备(deviceId: a1b2, c3d4, e5f6, g7h8, i9j0)",
      "data_source": "queryLoginLogList.deviceId",
      "severity": "高 | 中 | 低"
    }
  ],

  "deviation_impact": {
    "overall_deviation_score": "int(0-100)",
    "baseline_type": "self | population",
    "alert_dimensions": ["登录频次", "设备数"],
    "summary": "string"
  },

  "confidence_note": "string, 说明分析可信度，标注数据限制（如：交易数据不可用导致7条AML规则无法验证）",

  "user_profile_summary": "UserProfile对象",

  "debug": {
    "mcp_calls": [{"api": "str", "params": {}, "success": true, "rows_returned": 0}],
    "script_outputs": {},
    "rule_matching_log": []
  }
}
```

**字段规则**：
- `report_id` 格式: `RFC-{uid}-{yyyyMMddHHmmss}`，全局唯一
- `risk_score` 为 -1 时，`risk_level` 必须为 `"数据不足"`
- `evidence_chain` 至少包含一条记录
- `debug` 仅在调试模式下填充，正常模式为空对象 `{}`
- `confidence_note` 必须提及交易数据不可用的影响

---

## 5. BatchSummary（多用户汇总，≥2个UID时输出）

```json
{
  "batch_id": "BATCH-{yyyyMMddHHmmss}",
  "total_uids": "int",
  "analysis_time": "ISO时间戳",
  "results": [
    {
      "uid": "string",
      "risk_score": "int",
      "risk_level": "string",
      "top_risk_tags": ["string"],
      "deviation_score": "int"
    }
  ],
  "priority_order": ["uid按风险评分降序排列"],
  "cross_uid_findings": {
    "shared_devices": [{"device_id": "str", "uids": ["str"]}],
    "shared_ips": [{"ip": "str", "uids": ["str"]}]
  }
}
```

---

## 6. FeatureExtraction（模式B 样本归纳）

```json
{
  "extraction_id": "FE-{label}-{yyyyMMddHHmmss}",
  "label": "欺诈 | 洗钱 | 投诉",
  "sample_size": "int",
  "valid_samples": "int",
  "analysis_time": "ISO时间戳",
  "statistical_summary": {
    "device_count_stats": {"mean": 0, "median": 0, "std": 0, "max": 0, "min": 0},
    "daily_avg_logins_stats": {},
    "unique_ips_stats": {},
    "night_active_rate_stats": {},
    "account_age_days_stats": {},
    "deviation_score_stats": {}
  },
  "rule_trigger_rates": {
    "FRD-001": "float(0-1), 样本中触发比例",
    "FRD-006": 0,
    "AML-010": 0,
    "...": "每条启用规则的触发率"
  },
  "cross_uid_associations": {
    "shared_devices": [],
    "shared_ips": []
  },
  "findings": [
    {
      "pattern": "多设备+凌晨活跃+IP跳变",
      "frequency": "80%样本命中",
      "dimensions": ["device", "login_time", "ip"],
      "suggested_rule": "...",
      "suggested_threshold": "...",
      "confidence": "高 | 中 | 低"
    }
  ],
  "recommended_rule_additions": [
    {
      "rule_id": "NEW-001",
      "target_module": "anti_fraud | anti_money_laundering",
      "name": "string",
      "description": "string",
      "condition": "string",
      "severity": "高 | 中 | 低",
      "rationale": "string"
    }
  ]
}
```

---

## 稳定性保障清单

1. 所有定义字段必须出现，不得遗漏
2. severity 只允许 `高 / 中 / 低`，risk_level 只允许定义的枚举值
3. action 只允许 `放行 / 人工复核 / 限制交易 / 冻结账户 / 上报监管`
4. 每个 matched_rule 必须有 ≥1 条 evidence
5. MCP 未返回数据时对应字段填 null 或"数据缺失"，在 data_gaps/data_quality 说明
6. risk_score 和规则匹配由 Python 脚本计算，模型不得自行赋分或判定规则命中
7. 交易相关规则因 MCP 不支持，一律归入 data_gaps，绝不标为"未命中"
8. 已禁用规则归入 `disabled_rules`（非 data_gaps），区分"数据暂不可用"和"规则已禁用"
9. `matched_rules + unmatched_rules_checked + data_gaps + disabled_rules` 条目总数 = 规则库全部规则数
