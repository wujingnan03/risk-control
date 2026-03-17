---
name: fund-risk-control
description: >
  基金交易风控技能：识别用户洗钱和欺诈风险。适用于雪球基金销售平台的风控场景。
  当用户提到以下任何一种情况时触发此技能：分析用户风险、反洗钱检查、反欺诈检查、
  风控分析、AML检查、用户画像分析、可疑交易识别、风险评分、风险排查、UID风险分析、
  欺诈检测、洗钱检测、批量样本归纳、欺诈特征提炼、风控规则维护、行为偏离检测。
  即使用户只是简单地给出一个或多个UID要求"查一下"或"看看有没有问题"，也应触发此技能。
---

# 基金交易风控技能

## 核心原则

1. **不编造事实**：所有结论必须有MCP数据或Python脚本计算作为支撑。无数据时填"数据缺失"，不推测
2. **确定性输出**：数值计算由Python脚本执行，不由模型自由估算。输出结构严格遵循schema
3. **规则匹配确定性**：所有规则的阈值判定、交叉验证、severity调整均由 `rule_matching.py` 脚本执行，模型不参与规则判定，确保相同输入产生相同结果
4. **证据链完整**：每条风险判定必须附带原始数据evidence，可追溯到具体MCP查询结果
5. **模块化可调试**：每个模块独立输出中间结果，便于排查和验证

---

## 脚本路径约定

本技能的 Python 脚本和参考文档位于 SKILL.md 同级的 `scripts/` 和 `references/` 目录下。

执行 shell 命令时，**必须使用绝对路径**，因为 Agent 的工作目录通常是用户项目目录，而非技能安装目录。

约定：`SKILL_DIR` 表示本 SKILL.md 文件所在目录的绝对路径。Agent 在首次执行脚本前，应根据 SKILL.md 的实际位置确定此路径。例如：
- Cursor 安装目录：`~/.cursor/skills/fund-risk-control`
- 工作区引用：`/path/to/risk_control`

后文所有命令中的 `$SKILL_DIR` 均指此路径。

---

## 两种工作模式

### 模式A：用户风险分析（支持单个或多个UID）
输入：一个或多个可疑UID
流程：逐个执行 → 数据采集 → 行为画像（含偏离检测）→ 反欺诈 → 反洗钱 → 综合评分 → 最终汇总

### 模式B：样本归纳（规则提炼）
输入：一批已标记的欺诈/风险UID
流程：批量数据采集 → 逐个画像 → 交叉比对 → 模式归纳 → 输出建议规则

---

## 模式A 详细流程

### 多用户处理策略

当用户提供多个UID时：
1. 逐个UID执行完整的 A1→A5 流程，每个UID独立生成报告
2. 全部完成后，输出一份**汇总表**：UID列表 + 各自的风险评分和级别 + 需要优先关注的UID
3. 如果UID数量 > 10，提示用户"数量较多，建议分批处理（每批5-10个）以保证分析质量"
4. 如果UID之间存在关联（共享设备/IP），在汇总中单独标注

### A1. 数据采集

通过 MCP 服务 `user-snowball-crm` 按以下顺序采集数据：

```
1. queryUserInfoByUid(arg0=uid)
   → 用户基本信息+注册IP
   返回: uid, status, statusDesc, risk, riskDesc, accountType, flavor,
         cerType, gender, regDate(yyyyMMdd), openDate(yyyyMMdd),
         createdAt(毫秒时间戳), isOpenTrade, riskStatus, createdIp

2. queryLoginDeviceList(arg0=uid, arg1="last_360")
   → 设备列表（一年历史）
   返回数组: [{device, platform, client, version}]
   注意: 无 deviceId！设备唯一标识只能从登录日志获取

3. queryLoginLogList(arg0=uid, arg1=90, arg2=100)
   → 登录日志（默认90天，上限100条）
   ⚠ 模式B 或 初次评分为高风险/极高风险 时，改用 arg1=365, arg2=150 补查
   返回数组: [{loginTime(ms), ipAddress, grantType, deviceId,
              deviceType, clientId, clientVersion, flavor}]
   注意: ipAddress 可能脱敏为"***"，需跳过
   注意: 达到上限时需标注"数据可能不完整"

4. 提取登录日志中不重复IP + 注册IP(createdIp)

5. 对每个IP调 queryIpLocation(arg0=ip)
   → IP归属地
   返回: {ip: "x.x.x.x", info: ["国家","省份","城市","","运营商"]}
   注意: 某些位置可能为空字符串

6. queryUserTransactions(arg0=uid)
   → 用户交易记录
   ⚠ 接口开发中，MCP尚未注册此工具，不可用时走 L2 降级
```

**数据验证与准入（强制执行，不可绕过）**：

| 层级 | 数据 | 缺失时行为 | 理由 |
|------|------|-----------|------|
| **L0 硬阻断** | queryUserInfoByUid | **拒绝评分**，流程终止 | 无身份信息，所有分析无锚点 |
| **L0 硬阻断** | queryLoginLogList | **拒绝评分**，流程终止 | 画像、偏离、IP 分析全依赖此数据 |
| **L1 降级评分** | queryLoginDeviceList | 继续，设备维度不计分，降级标注 | 登录日志中有 deviceId 可部分补偿 |
| **L1 降级评分** | queryIpLocation | 继续，IP 地理维度不计分，降级标注 | 仍可统计 IP 数量 |
| **L2 可选增强** | queryUserTransactions | 继续，交易维度整体跳过 | 接口开发中，属于预期内缺失 |

L0 阻断时脚本返回 exit code 1，模型应直接向用户报告数据问题，不尝试用不完整数据继续分析。用户直接粘贴数据时，解析后按相同流程分析（仍需满足 L0 最低要求）。

### A2 ~ A5. 一体化流水线（推荐）

将MCP返回的原始数据组装为JSON后，**一条命令完成全部分析，不产生任何中间文件**：

```bash
python3 $SKILL_DIR/scripts/run_pipeline.py --input raw_data.json
```

输出人类可读的风险结论摘要。如需机器可读的完整 JSON（含 score_breakdown / fraud / aml）：

```bash
python3 $SKILL_DIR/scripts/run_pipeline.py --input raw_data.json --json
```

流水线内部依次执行：用户画像（含行为偏离检测）→ 规则匹配（反欺诈+反洗钱）→ 专家评分卡评分。所有阈值判定、交叉验证、评分计算均由脚本确定性完成。

基于脚本输出，模型补充以下内容（严格基于数据，不编造）：
- **behavior_summary**：基于脚本 `deviation_analysis` 输出的自然语言行为总结
- **risk_tags**：汇总各模块的关键风险标签
- **evidence_chain**：按时间线整理证据链，每条结论关联到具体数据点
- **confidence_note**：说明分析可信度，特别标注降级维度的影响
- **action_recommendation**：处置建议，基于风险级别 + 命中规则类型

最终输出遵循 `references/output_schema.md` 中的 FinalReport 结构。

**调试模式**：当用户要求"调试"或"看中间结果"时，改为分步执行各脚本，每步输出完整 JSON 中间结果后等待用户确认再继续。分步命令：

```bash
# A2: 用户画像 + 行为偏离检测
python3 $SKILL_DIR/scripts/user_profiling.py --input raw_data.json --output profile.json

# A3+A4: 确定性规则匹配（反欺诈 + 反洗钱），模型不参与规则判定
python3 $SKILL_DIR/scripts/rule_matching.py --profile profile.json --output-fraud fraud.json --output-aml aml.json

# A5: 专家评分卡评分
python3 $SKILL_DIR/scripts/risk_scoring.py --profile profile.json --fraud fraud.json --aml aml.json --output score.json
```

### A6. 多用户汇总（仅多UID时）

当分析 ≥ 2 个UID时，在所有单用户报告之后输出汇总，包含：各UID的风险评分和级别、按风险评分降序的优先级排序、以及跨UID关联发现（共享设备ID、共享IP、操作时间重叠）。输出遵循 `references/output_schema.md` 中的 BatchSummary 结构。

---

## 模式B 详细流程（样本归纳）

### 输入
用户提供一批UID，并标注类别（如"这些是投诉欺诈UID"或"这些是历史风险UID"）

### 流程

1. **批量数据采集**：对每个UID执行模式A的A1步骤（模式B统一使用 `arg1=365, arg2=150` 拉取完整历史）
2. **逐个画像**：对每个UID执行模式A的A2步骤（批量模式：`--batch`）
3. **交叉比对**（Python计算）：
   - 统计共性特征（如：80%的样本使用≥3台设备）
   - 统计异常维度分布（如：90%有深夜登录、70%有IP跳跃）
   - 识别关联关系（如：多个UID共享设备/IP）
4. **模式归纳**：
   - 提炼出高频共性特征作为 pattern
   - 将 pattern 转化为可执行规则建议（含阈值、证据要求）
   - 标识不符合共性模式的离群样本
5. **输出**：遵循 `references/output_schema.md` 中的 FeatureExtraction 结构

### 规则更新建议
归纳完成后，将新发现的模式以建议形式呈现给用户。用户确认后手动添加到 `references/anti_fraud_rules.md` 或 `references/anti_money_laundering.md`。自动追加不启用——规则库变更需人工审核。

### 群体基线更新
如果用户提供的是**正常用户**UID列表，可用批量画像的统计结果更新群体基线值。脚本会输出 `population_baseline` 字段，用户确认后可替换 `user_profiling.py` 中的硬编码基线。

---

## 规则与数据限制

以下规则因**数据源不可用**归入 `data_gaps`（由 `rule_matching.py` 自动处理）：

| 规则 | 原因 |
|------|------|
| FRD-009 注册后短时间大额交易 | 交易数据接口开发中 |
| FRD-010 交易模式突变 | 交易数据接口开发中 |
| AML-001 单日大额交易报告 | 交易数据接口开发中 |
| AML-002 资金快进快出 | 交易数据接口开发中 |
| AML-003 交易拆分规避报告 | 交易数据接口开发中 |
| AML-004 频繁申赎同一产品 | 交易数据接口开发中 |
| AML-005 短期集中大额赎回 | 交易数据接口开发中 |
| AML-009 多账户同设备/IP | 单UID模式下无法验证，需跨账户数据 |

以下规则**已禁用**，归入 `disabled_rules`（非 data_gaps）：

| 规则 | 禁用原因 |
|------|---------|
| FRD-008 已知代理/VPN IP段 | 无IP信誉库 |
| AML-006 客户身份信息异常 | 无外部身份核验系统 |
| AML-007 代理人/关联人代操作 | 无跨账户关联数据 |
| AML-008 资金来源与客户身份不匹配 | 无收入等外部数据 |
| AML-011 无合理经济目的交易 | 纯定性判断，无可量化条件 |

---

## 输出要求（稳定性保障）

1. **结构一致性**：同一模式的输出，字段结构完全相同，不因数据内容变化而增减字段
2. **枚举值约束**：
   - severity: 只允许 高 / 中 / 低
   - risk_level: 只允许 低风险 / 中风险 / 高风险 / 极高风险 / 数据不足
   - action: 只允许 放行 / 人工复核 / 限制交易 / 冻结账户 / 上报监管
3. **评分确定性**：所有数值评分和规则匹配由 Python 脚本计算，模型不得自行赋分或判定规则命中
4. **证据溯源**：evidence 中的每条记录必须可追溯到某次MCP查询的具体返回值
5. **空值处理**：数据缺失用 null + data_gaps说明，永远不用"未知"、"可能"等模糊词填充数据字段

---

## Reference文件索引

| 文件 | 内容 | 何时读取 |
|------|------|----------|
| references/output_schema.md | 输出JSON结构定义 | 每次分析前必读 |
| references/anti_fraud_rules.md | 反欺诈规则库（11条启用+1条禁用） | 了解规则定义时参考 |
| references/anti_money_laundering.md | 反洗钱规则库（8条启用+4条禁用） | 了解规则定义时参考 |
| references/business_context.md | 雪球基金业务知识+正常用户基线 | 需要理解业务上下文时读取 |
| scripts/run_pipeline.py | **一体化流水线**（内存模式，无中间文件） | **推荐：A2~A5一次执行** |
| scripts/user_profiling.py | 用户画像+偏离检测计算 | 分步调试时A2单独执行 |
| scripts/rule_matching.py | 确定性规则匹配（反欺诈+反洗钱） | 分步调试时A3+A4单独执行 |
| scripts/risk_scoring.py | 风险评分计算 | 分步调试时A5单独执行 |
| scripts/validate_output.py | 输出格式校验 | 分步调试时最终输出后执行 |
