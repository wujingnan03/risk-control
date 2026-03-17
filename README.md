# 基金交易风控技能 (fund-risk-control)

适用于基金销售平台的反欺诈（Anti-Fraud）和反洗钱（AML）风控分析 Agent Skill。

[![GitHub](https://img.shields.io/badge/GitHub-wujingnan03%2Frisk--control-blue)](https://github.com/wujingnan03/risk-control)

---

## 核心设计原则

| 原则 | 说明 |
|------|------|
| **确定性输出** | 所有规则匹配、阈值判定、评分由 Python 脚本执行，不依赖 LLM 自由估算 |
| **不编造数据** | 所有结论必须来自 MCP 接口或脚本计算，无数据时明确填"数据缺失" |
| **证据链完整** | 每条风险判定附带原始数据 evidence，可追溯到具体 MCP 查询结果 |
| **模块化可调试** | 每个步骤独立输出中间 JSON，便于排查和单步测试 |

---

## 架构概览

```
MCP 数据采集
    │
    ▼
user_profiling.py    → profile.json
（画像 + 行为偏离检测）
    │
    ▼
rule_matching.py     → fraud.json + aml.json
（确定性规则匹配，含交叉验证 + severity 调整）
    │
    ▼
risk_scoring.py      → score.json
（专家评分卡：分箱打分 + 偏离度乘数 + 交叉项乘数）
    │
    ▼
LLM 组装自然语言报告（FinalReport）
```

---

## 文件结构

```
risk_control/
├── SKILL.md                    # Skill 主文件（Agent 读取此文件）
├── README.md                   # 本文件
│
├── user_profiling.py           # 步骤 A2：用户画像 + 行为偏离检测
├── rule_matching.py            # 步骤 A3+A4：确定性规则匹配（反欺诈 + 反洗钱）
├── risk_scoring.py             # 步骤 A5：专家评分卡
├── validate_output.py          # 输出格式校验
│
├── anti_fraud_rules.md         # 反欺诈规则库（12 条，11 条启用，1 条禁用）
├── anti_money_laundering.md    # 反洗钱规则库（12 条，8 条启用，4 条禁用）
├── output_schema.md            # 所有输出 JSON 的结构定义
├── business_context.md         # 业务背景与正常用户基线
├── evals.json                  # 测试用例
└── fund-risk-control.skill     # Cursor skill 打包文件（旧版，供参考）
```

---

## 快速开始

### 1. 环境要求

- Python 3.6+（零外部依赖，全部使用标准库）
- MCP 服务：`user-snowball-crm`（见下方接口说明）
- 支持 MCP 调用 + shell 命令执行的 Agent 环境（如 Cursor、Claude Code）

### 2. 在 Cursor 中安装

将整个目录复制到 Cursor 的 skill 目录，或直接在工作区中使用（SKILL.md 会被自动识别）。

### 3. 触发关键词

直接说以下任意一句即可触发 Skill：
- "分析 UID xxxxx 的风险"
- "查一下这个用户：xxxxx"
- "对 UID xxxxx 做反洗钱检查"
- "帮我看看 xxxxx 有没有问题"

---

## MCP 接口说明

| 工具名 | 服务名 | 用途 | 关键参数 |
|--------|--------|------|----------|
| `queryUserInfoByUid` | `user-snowball-crm` | 用户基本信息（状态/风险等级/注册IP等） | `arg0`: uid (integer) |
| `queryLoginLogList` | `user-snowball-crm` | 登录日志（时间/IP/设备/授权类型） | `arg0`: uid, `arg1`: 天数(最大90), `arg2`: 条数(最大100) |
| `queryLoginDeviceList` | `user-snowball-crm` | 设备列表（设备/平台/客户端/版本） | `arg0`: uid, `arg1`: "last_360" |
| `queryIpLocation` | `user-snowball-crm` | IP 归属地（国家/省份/城市/运营商） | `arg0`: IP 地址字符串 |
| `queryUserTransactions` | `user-snowball-crm` | 交易记录（开发中，暂不可用） | `arg0`: uid |

---

## 脚本执行顺序

```bash
# Step 1: 准备原始数据
# 将 MCP 采集到的数据组装为 raw_data.json

# Step 2: 生成用户画像（含行为偏离检测）
python3 user_profiling.py --input raw_data.json --output profile.json

# Step 3: 规则匹配（确定性，A3+A4）
python3 rule_matching.py \
  --profile profile.json \
  --output-fraud fraud.json \
  --output-aml aml.json

# Step 4: 风险评分（A5）
python3 risk_scoring.py \
  --profile profile.json \
  --fraud fraud.json \
  --aml aml.json \
  --output score.json

# Step 5: 输出格式校验（可选）
python3 validate_output.py --input fraud.json --type fraud
python3 validate_output.py --input aml.json --type aml
python3 validate_output.py --input score.json --type final_report
```

---

## 规则库概览

### 反欺诈规则（FRD）

| ID | 规则名称 | 严重程度 | 状态 |
|----|---------|---------|------|
| FRD-001 | 多设备异常登录 | 高 | 启用 |
| FRD-002 | 休眠账号突然激活 | 中 | 启用 |
| FRD-003 | 设备信息频繁变更 | 中 | 启用 |
| FRD-004 | 凌晨异常活跃 | 中 | 启用 |
| FRD-005 | 登录频次突增 | 中 | 启用 |
| FRD-006 | IP 地理位置频繁跳变 | 高 | 启用 |
| FRD-007 | 境外 IP 登录 | 高 | 启用 |
| FRD-008 | 已知代理/VPN IP 段 | 中 | **已禁用**（无 IP 信誉库） |
| FRD-009 | 注册后短时间内大额交易 | 高 | 启用 |
| FRD-010 | 交易模式突变 | 中 | 启用 |
| FRD-011 | 用户信息与 IP 地域不匹配 | 中 | 启用 |
| FRD-012 | 多维度同时触发 | 高 | 启用 |

### 反洗钱规则（AML）

| ID | 规则名称 | 严重程度 | 状态 |
|----|---------|---------|------|
| AML-001 | 单日大额交易报告 | 高 | 启用 |
| AML-002 | 资金快进快出 | 高 | 启用 |
| AML-003 | 交易拆分规避报告 | 高 | 启用 |
| AML-004 | 频繁申赎同一产品 | 中 | 启用 |
| AML-005 | 短期集中大额赎回 | 高 | 启用 |
| AML-006 | 客户身份信息异常 | 中 | **已禁用**（无外部身份核验系统） |
| AML-007 | 代理人/关联人代操作 | 高 | **已禁用**（无跨账户关联数据） |
| AML-008 | 资金来源与客户身份不匹配 | 高 | **已禁用**（无收入等外部数据） |
| AML-009 | 多账户同设备/IP | 高 | 启用（单 UID 模式归 data_gap） |
| AML-010 | 交易操作与登录地异常 | 中 | 启用 |
| AML-011 | 无合理经济目的交易 | 高 | **已禁用**（纯定性判断） |
| AML-012 | 多项洗钱指标叠加 | 高 | 启用 |

---

## 评分模型说明

采用**专家评分卡（Expert Scorecard）**：

```
最终分 = 归一化( (维度基础分 + 规则命中分) × 偏离度乘数 × 交叉项乘数 )
```

| 维度 | 满分 | 核心变量 |
|------|------|---------|
| 设备 | 15 | 设备数、新设备率 |
| 登录行为 | 15 | 凌晨活跃率、日均登录次数 |
| IP 地理 | 15 | 跨省数、境外IP率 |
| 账户 | 10 | 账龄、休眠间隔 |
| 主动交易 | 20 | 快进快出次数、拆分天数、最大单笔 |

风险级别映射：0-25 低风险 / 26-50 中风险 / 51-75 高风险 / 76-100 极高风险

---

## 移植到其他 Agent

详见 [SKILL.md 末尾的移植指南](./SKILL.md#移植到其他-agent)。

核心步骤：
1. 复制整个目录到目标 agent 的 skill 目录
2. 将 MCP 服务名 `user-snowball-crm` 替换为目标环境中的实际服务名
3. 确认 4 个 MCP 工具名称在新环境中有对应工具
4. 确认 Python 3.6+ 可用（脚本无外部依赖）

---

## 版本历史

| 版本 | 日期 | 变更说明 |
|------|------|---------|
| v1.1 | 2026-03 | 新增 `rule_matching.py`，规则匹配从 LLM 迁移至 Python 脚本；禁用 5 条无数据支撑规则；修复 `parse_datetime` bug |
| v1.0 | 2025-01 | 初始版本，用户画像 + 专家评分卡 |
