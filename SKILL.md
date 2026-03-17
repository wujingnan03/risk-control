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

通过MCP接口采集用户数据。按以下顺序调用：

```
1. queryUserInfoByUid(arg0=uid)                              → 用户基本信息+注册IP
2. queryLoginDeviceList(arg0=uid, arg1="last_360")           → 设备列表（一年历史）
3. queryLoginLogList(arg0=uid, arg1=365, arg2=150)           → 登录日志（365天，上限150条）
4. 提取登录日志中不重复IP + 注册IP(createdIp)
5. 对每个IP调 queryIpLocation(arg0=ip)                       → IP归属地
6. queryUserTransactions(arg0=uid)                            → 用户交易记录 [开发中，见下方说明]
```

**交易数据接口说明（queryUserTransactions，开发中）**：

该接口当前尚在开发中。当接口可用时，按上述第6步调用；接口不可用时走降级策略。

返回字段：
| 字段 | 说明 | 备注 |
|------|------|------|
| createdAt | 创建时间 | 订单生成时间 |
| tradeDate | 交易日期（T日） | 实际交割日 |
| tradeType | 交易类型 | 买入/卖出/定投/分红/投顾调仓等 |
| fundName | 基金名称 | |
| fundCode | 基金代码 | |
| amount | 金额（元） | 仅买入、定投时有值，其余为null |
| shares | 份额 | 仅卖出、分红时有值，其余为null |

注意事项：
- **amount 和 shares 不会同时有值**：买入/定投 → 有amount无shares；卖出/分红 → 有shares无amount
- **投顾调仓等类型**：amount和shares均可能为null，此类交易仅记录行为，不纳入金额统计
- 脚本处理时需按 tradeType 分类统计，不可对 null 值做数学运算

**交易数据三条分流线**（脚本自动分类，数据无需预处理）：

| 分流线 | 包含类型 | 性质 | 风控用途 |
|--------|---------|------|---------|
| **manual_trading** | 买入、卖出 | 用户主动发起 | 所有风控规则的核心输入（频次、金额、快进快出、拆分） |
| **auto_invest_summary** | 定投 | 系统自动执行 | 独立概况，仅定投本身异常时告警 |
| **dividend_summary** | 分红 | 基金公司下发的被动到账 | 仅记录，不纳入交易频次和份额统计 |
| 其他 | 投顾调仓等 | — | 仅计数 |

分红不算主动交易：分红是基金公司按规则发起的被动行为，用户无法控制时机和份额。混入主动交易会虚高交易频次，分红份额会污染卖出份额统计。

**数据验证与准入（强制执行，不可绕过）**：

| 层级 | 数据 | 缺失时行为 | 理由 |
|------|------|-----------|------|
| **L0 硬阻断** | queryUserInfoByUid | **拒绝评分**，返回错误码，流程终止 | 无身份信息，所有分析无锚点 |
| **L0 硬阻断** | queryLoginLogList | **拒绝评分**，返回错误码，流程终止 | 画像、偏离、IP 分析全依赖此数据 |
| **L1 降级评分** | queryLoginDeviceList | 继续，设备维度不计分，降级标注 | 登录日志中有 deviceId 可部分补偿 |
| **L1 降级评分** | queryIpLocation | 继续，IP 地理维度不计分，降级标注 | 仍可统计 IP 数量 |
| **L2 可选增强** | queryUserTransactions | 继续，交易维度整体跳过 | 接口开发中，属于预期内缺失 |

**L0 阻断时的响应格式**：
```json
{
  "risk_score": null,
  "risk_level": "拒绝评分",
  "reject_reason": "核心数据缺失，无法生成可靠评分",
  "missing_data": ["L0:login_profile 无登录记录"],
  "action_detail": { "recommendation": "请检查 MCP 连接状态并确认 UID 有效" }
}
```

L0 阻断时脚本返回非零退出码（exit code 1），模型收到后应直接向用户报告数据问题，不尝试用不完整数据继续分析。

**其他降级规则**：
- 用户直接粘贴了数据 → 解析用户提供的数据，按相同流程分析（仍需满足 L0 最低要求）
- 绝不因数据缺失而编造数据填充

### A2. 用户行为画像（含偏离检测）

读取 `references/output_schema.md` 中的 UserProfile 结构。

将MCP返回的原始数据组装为JSON，运行脚本：

```bash
python3 scripts/user_profiling.py --input raw_data.json --output profile.json
```

脚本会自动计算：
- **基础画像**：设备异常、登录时间分布、IP地理分析、交易异常等
- **行为偏离检测**：将用户近期行为与基线对比，输出偏离度评分

#### 行为偏离检测机制

偏离检测用于回答："这个用户最近的行为和之前相比，是否发生了显著变化？"

**双基线策略**（由脚本自动选择）：

| 条件 | 使用的基线 | 说明 |
|------|-----------|------|
| 用户有 ≥ 14天 的历史登录数据 | **自我基线**（该用户历史行为） | 近7天 vs 更早期数据 |
| 用户历史数据 < 14天 | **群体基线**（正常用户统计值） | 用户指标 vs 群体均值 |

**自我基线计算方式**：
- 将登录日志按时间切分为两段：近期窗口（最近7天）vs 历史窗口（7天前的全部数据）
- 分别计算各维度指标：登录频次、设备数、不同IP数、凌晨活跃率等
- 偏离度 = (近期值 - 历史值) / max(历史值, 下限值)
- 下限值防止除零：登录频次最小为1，设备数最小为1，IP数最小为1

**群体基线**（硬编码在脚本中，基于正常基金用户行为统计）：
```
日均登录: 2.5次    (std=1.8)
设备数/月: 1.5台   (std=0.7)  
不同IP数/月: 3个   (std=2.0)
凌晨活跃率: 5%     (std=8%)
跨省IP率: 15%      (std=12%)
```
> 以上为经验初始值。后续可用模式B跑一批正常用户UID，用统计结果替换。

**偏离度评分**（0-100）：
- 0-20：行为正常，无显著偏离
- 21-50：轻度偏离，需结合其他维度判断
- 51-80：显著偏离，高度关注
- 81-100：极端偏离，强烈异常信号

脚本输出中的 `deviation_analysis` 字段包含：
```json
{
  "baseline_type": "self | population",
  "baseline_data_days": 83,
  "recent_window_days": 7,
  "dimension_deviations": {
    "login_frequency": { "recent": 12.3, "baseline": 3.1, "deviation_ratio": 2.97, "alert": true },
    "device_count": { "recent": 4, "baseline": 1, "deviation_ratio": 3.0, "alert": true },
    "unique_ips": { "recent": 8, "baseline": 2, "deviation_ratio": 3.0, "alert": true },
    "night_active_rate": { "recent": 0.45, "baseline": 0.05, "deviation_ratio": 8.0, "alert": true },
    "cross_province_rate": { "recent": 0.6, "baseline": 0.1, "deviation_ratio": 5.0, "alert": true }
  },
  "overall_deviation_score": 78,
  "deviation_summary": "该用户近7天行为与历史基线存在显著偏离：登录频次增长297%，新增3台未见设备，IP跨省率从10%飙升至60%"
}
```

模型在脚本输出基础上，补充 `behavior_summary` 字段（自然语言总结），此总结必须完全基于脚本输出的数据点，不得添加脚本未检测到的信息。

### A3 + A4. 规则匹配（反欺诈 + 反洗钱）

**由 Python 脚本确定性执行，模型不参与规则判定。**

将 A2 输出的画像传入规则匹配脚本：

```bash
python3 scripts/rule_matching.py --profile profile.json --output-fraud fraud.json --output-aml aml.json
```

脚本自动完成：
- 逐条检查所有**已启用**规则的阈值条件
- 对命中规则执行交叉验证（如 FRD-001: IP稳定则severity降一级）
- 偏离度 > 50 时对所有命中规则 severity 上调一级
- 自动提取 evidence（具体数据点）
- 将已禁用规则归入 `disabled_rules`，数据不可用的规则归入 `data_gaps`

**已禁用规则**（无数据源支撑，从匹配流程中排除）：
- FRD-008 已知代理/VPN IP段（无IP信誉库）
- AML-006 客户身份信息异常（无外部身份核验系统）
- AML-007 代理人/关联人代操作（无跨账户关联数据）
- AML-008 资金来源与客户身份不匹配（无收入等外部数据）
- AML-011 无合理经济目的交易（纯定性判断，无可量化条件）

模型仅负责：
1. 检查脚本退出码（非零 → 报告错误）
2. 将 fraud.json + aml.json 传入下一步评分

输出格式遵循 `references/output_schema.md` 中的 FraudAnalysis / AMLAnalysis 结构。

### A5. 综合评分与总结

#### 评分模型：专家评分卡（Expert Scorecard v2）

采用金融风控行业标准的专家评分卡，而非简单布尔加权。核心区别：连续变量分箱打分，保留区分度（3台设备和10台设备得分不同）；多维度异常时乘数放大（非线性增长）。

**评分公式**：
```
最终分 = 归一化( (维度基础分 + 规则命中分) × 偏离度乘数 × 交叉项乘数 )
```

**五个评分维度**（连续变量分箱，维度内取最高变量分不叠加）：

| 维度 | 满分 | 核心变量 | 分箱示例 |
|------|------|---------|---------|
| 设备 | 15 | 设备数(0/2/5/10/15)、新设备率 | 1台→0, 3台→5, 6+台→15 |
| 登录行为 | 15 | 凌晨活跃率、日均登录次数 | ≤5%→0, 30%→8, >50%→15 |
| IP地理 | 15 | 跨省数、境外IP率 | 2省→0, 5省→9, 7+省→15 |
| 账户 | 10 | 账龄(反向)、休眠间隔 | >6月→0, ≤3天→10 |
| 主动交易 | 20 | 快进快出次数、拆分天数、最大单笔 | 交易不可用时整维度跳过 |

**两个乘数因子**：
- **偏离度乘数**（1.0~1.35）：偏离度越高，基础分被放大越多。偏离度本身不加分。
- **交叉项乘数**（1.0~1.45）：异常维度越多，乘数越大。≥4维度同时异常 → ×1.30

**风险级别映射**：0-25 低风险 / 26-50 中风险 / 51-75 高风险 / 76-100 极高风险

**保底规则**：有任意高严重度规则命中时，最低分不低于 30（中风险）

执行命令：
```bash
python3 scripts/risk_scoring.py --profile profile.json --fraud fraud.json --aml aml.json --output score.json
```

**注意**：如果脚本返回 exit code 1（L0 数据缺失拒绝评分），不可忽略继续。应直接向用户报告数据问题。

基于脚本输出的评分，模型完成以下补充（严格基于数据，不编造）：
- **risk_tags**：汇总各模块的关键风险标签
- **evidence_chain**：按时间线整理证据链，每条结论关联到具体数据点
- **confidence_note**：说明分析的可信度，特别标注降级维度的影响
- **action_recommendation**：处置建议，基于风险级别 + 命中规则类型

最终输出遵循 `references/output_schema.md` 中的 FinalReport 结构。

### A6. 多用户汇总（仅多UID时）

当分析 ≥ 2 个UID时，在所有单用户报告之后输出汇总：

```json
{
  "batch_summary": {
    "total_uids": 5,
    "analysis_time": "2025-xx-xx",
    "results": [
      { "uid": "111", "risk_score": 72, "risk_level": "高风险", "top_risk_tag": "多设备异常" },
      { "uid": "222", "risk_score": 35, "risk_level": "中风险", "top_risk_tag": "IP跳变" }
    ],
    "priority_order": ["111", "333", "222", "555", "444"],
    "cross_uid_findings": [
      "UID 111 和 UID 333 共享同一设备ID: xxx",
      "UID 222 和 UID 444 的登录IP存在重叠"
    ]
  }
}
```

**关联分析**：多UID模式下，检查是否存在：
- 共享设备（同一设备ID出现在多个UID的设备列表中）
- 共享IP（同一IP出现在多个UID的登录日志中）
- 操作时间重叠（多个UID在相同时间段活跃）
如果发现关联，在 `cross_uid_findings` 中记录，并在相关用户的报告中标注。

---

## 模式B 详细流程（样本归纳）

### 输入
用户提供一批UID，并标注类别（如"这些是投诉欺诈UID"或"这些是历史风险UID"）

### 流程

1. **批量数据采集**：对每个UID执行模式A的A1步骤
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

## 调试模式

当用户明确要求"调试"或"debug"或"看中间结果"时：

1. 每个步骤执行后，先输出该步骤的完整JSON中间结果
2. 等待用户确认后再执行下一步
3. 允许用户在中间步骤修改数据或调整参数后继续

调试模式下的输出格式：
```
=== 步骤N: [步骤名称] ===
输入数据: <简要描述>
输出结果:
{完整JSON}
=== 步骤N 完成，是否继续？ ===
```

---

## MCP接口使用规范

### 接口与参数

```
MCP服务: user-snowball-crm

1. queryUserInfoByUid
   参数: arg0 (integer) — 用户uid
   返回: uid, status, statusDesc, risk, riskDesc, accountType, flavor,
         cerType, gender, regDate(yyyyMMdd), openDate(yyyyMMdd),
         createdAt(毫秒时间戳), isOpenTrade, riskStatus, createdIp

2. queryLoginDeviceList
   参数: arg0 (integer) — 用户uid
         arg1 (string)  — 时间范围，推荐 "last_360"（覆盖一年设备历史）
                          可选值: last_7/last_30/last_90/last_180/last_360/last_1080
   返回数组: [{device, platform, client, version}]
   注意: 无 deviceId！设备唯一标识只能从登录日志获取

3. queryLoginLogList
   参数: arg0 (integer) — 用户uid
         arg1 (integer) — 查询最近N天的日志，默认7天，最大365天（推荐传365）
         arg2 (integer) — 返回条数限制，默认20条，最大150条（推荐传150）
   返回数组: [{loginTime(ms), ipAddress, grantType, deviceId,
              deviceType, clientId, clientVersion, flavor}]
   注意: ipAddress 可能脱敏显示为"***"，需跳过
   注意: 150条上限可能不完整，需在输出中标注

4. queryIpLocation
   参数: arg0 (string) — IP地址，如 "8.8.8.8"
   返回: {ip: "x.x.x.x", info: ["中国","浙江","杭州","","电信"]}
   info数组: [国家, 省份/地区, 城市, 未知, 运营商]
   注意: 某些位置可能为空字符串

5. queryUserTransactions  [⚠️ 开发中，MCP中尚未注册此工具，接口不可用时走降级]
   参数: arg0 (integer) — 用户uid（预期参数，待接口上线后确认）
   返回数组: [{
     createdAt: "创建时间",
     tradeDate: "T日交易日期",
     tradeType: "买入|卖出|定投|分红|投顾调仓|...",
     fundName: "基金名称",
     fundCode: "基金代码",
     amount: "金额(元), 仅买入/定投有值, 其余null",
     shares: "份额, 仅卖出/分红有值, 其余null"
   }]
   字段互斥规则:
   - 买入/定投 → amount有值, shares为null
   - 卖出/分红 → shares有值, amount为null
   - 投顾调仓等 → amount和shares均可能为null（仅记录行为）
```

### 调用策略

1. 先调 queryUserInfoByUid(arg0=uid) → 获取基本信息和注册IP
2. 调 queryLoginDeviceList(arg0=uid, arg1="last_360") → 设备类型分布
3. 调 queryLoginLogList(arg0=uid, arg1=365, arg2=150) → 登录日志（拉满365天150条）
4. 从登录日志提取不重复IP（排除脱敏IP"***"）+ 注册IP(createdIp)
5. 对每个不重复IP调 queryIpLocation(arg0=ip) → 归属地

### 参数选择理由

- **设备 last_360**：一年的历史能发现"从来没出现过的新设备"，提升新设备异常检测灵敏度
- **登录 365天 150条**：拉满给偏离检测足够的历史窗口（需≥14天才能用自我基线）
- **150条上限处理**：如果返回刚好150条，标注"数据可能不完整，统计为下限估计"

### 数据不可用时的处理

如果MCP未连接或工具不可用：
1. 提示用户可以手动粘贴数据（JSON格式）
2. 或提示用户检查MCP连接状态
3. 基于已有数据尽可能分析，但明确标注局限性

**关键限制提醒**：

当前MCP无交易数据接口，以下规则因交易数据不可用归入 `data_gaps`（由 rule_matching.py 自动处理）：
- FRD-009 注册后短时间大额交易
- FRD-010 交易模式突变
- AML-001~005（大额/快进快出/拆分/频繁申赎/集中赎回）
- AML-009 多账户同设备/IP（单UID模式下无法验证）

以下规则已禁用（归入 `disabled_rules`，非 data_gaps）：
- FRD-008 已知代理/VPN IP段（无IP信誉库）
- AML-006 客户身份信息异常（无外部身份核验系统）
- AML-007 代理人/关联人代操作（无跨账户关联数据）
- AML-008 资金来源与客户身份不匹配（无收入等外部数据）
- AML-011 无合理经济目的交易（纯定性判断）

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
6. **偏离度一致性**：相同数据输入到 user_profiling.py 应得到相同的偏离度评分

---

## Reference文件索引

| 文件 | 内容 | 何时读取 |
|------|------|----------|
| references/output_schema.md | 输出JSON结构定义 | 每次分析前必读 |
| references/anti_fraud_rules.md | 反欺诈规则库（11条启用+1条禁用） | 了解规则定义时参考 |
| references/anti_money_laundering.md | 反洗钱规则库（8条启用+4条禁用） | 了解规则定义时参考 |
| references/business_context.md | 雪球基金业务知识+正常用户基线 | 需要理解业务上下文时读取 |
| scripts/user_profiling.py | 用户画像+偏离检测计算 | A2执行 |
| scripts/rule_matching.py | 确定性规则匹配（反欺诈+反洗钱） | A3+A4执行 |
| scripts/risk_scoring.py | 风险评分计算 | A5执行 |
| scripts/validate_output.py | 输出格式校验 | 最终输出后执行 |

---

## 移植到其他 Agent

本 Skill 可以运行在任何支持 MCP 调用和 shell 命令执行的 Agent 环境中。Python 脚本**零外部依赖**，仅使用标准库。

### 移植步骤

**第 1 步：复制文件**

将整个 `risk_control/` 目录复制到目标 Agent 的 skill 目录，或直接在新工作区中引用。

**第 2 步：替换 MCP 服务名**

将 SKILL.md 和脚本中所有 `user-snowball-crm` 替换为目标环境的实际服务名。

**第 3 步：确认 MCP 工具映射**

目标环境需提供以下等效工具（函数签名可不同，但返回字段须一致）：

| 本 Skill 使用的工具名 | 返回的关键字段 | 用途 |
|----------------------|--------------|------|
| `queryUserInfoByUid(arg0=uid)` | uid, status, risk, regDate, createdIp, cerType 等 | 用户基本信息 |
| `queryLoginLogList(arg0=uid, arg1=90, arg2=100)` | loginTime(ms), ipAddress, deviceId, grantType 等 | 登录日志 |
| `queryLoginDeviceList(arg0=uid, arg1="last_360")` | device, platform, client, version | 设备列表 |
| `queryIpLocation(arg0=ip)` | info: [国家, 省份, 城市, ?, 运营商] | IP 归属地 |

**第 4 步：确认 Python 环境**

```bash
python3 --version  # 需要 3.6+
```

所有脚本仅依赖标准库：`json`, `sys`, `argparse`, `datetime`, `collections`, `statistics`。

**第 5 步：更新 SKILL.md 中的脚本路径**

脚本路径使用相对路径（`python user_profiling.py`）时无需修改。若使用绝对路径，替换为实际部署路径。

### 快速验证

移植后可用测试 UID 跑一遍完整流程验证：

```bash
# 1. 准备测试数据（替换为真实 MCP 返回数据）
cat > /tmp/test_raw.json << 'EOF'
{
  "user_info": {"uid": 123, "status": "0", "statusDesc": "正常用户", "risk": 3,
    "riskDesc": "平衡型", "cerType": "0", "regDate": "20220101",
    "createdAt": 1640995200000, "isOpenTrade": true, "createdIp": "1.2.3.4"},
  "login_logs": [
    {"loginTime": 1700000000000, "ipAddress": "1.2.3.4",
     "grantType": "refresh_token", "deviceId": "TEST-DEVICE-001"}
  ],
  "devices": [{"device": "iPhone", "platform": "IOS", "client": "Fund", "version": "7.0"}],
  "ip_locations": {"1.2.3.4": ["中国", "北京", "北京", "", "电信"]}
}
EOF

# 2. 执行流水线
python3 user_profiling.py --input /tmp/test_raw.json --output /tmp/profile.json
python3 rule_matching.py --profile /tmp/profile.json --output-fraud /tmp/fraud.json --output-aml /tmp/aml.json
python3 risk_scoring.py --profile /tmp/profile.json --fraud /tmp/fraud.json --aml /tmp/aml.json --output /tmp/score.json

# 3. 检查输出
cat /tmp/score.json | python3 -m json.tool | head -20
```

### 已知限制（影响可移植性）

| 限制 | 说明 | 解决方案 |
|------|------|----------|
| 交易数据 | `queryUserTransactions` 尚在开发中，AML-001~005 规则归入 data_gaps | 接口上线后更新 `rule_matching.py` 中的 `match_aml_00x` 函数 |
| 跨账户关联 | AML-007/009 需要多 UID 比对，单 UID 模式下受限 | 在批量模式下已通过 `_find_shared_devices` 支持，单用户模式归 data_gaps |
| IP 信誉库 | FRD-008 需要 IP 类型判断（家庭/数据中心/VPN），已禁用 | 接入 IP2Location 或 MaxMind 数据库后可重新启用 |
| 外部身份核验 | AML-006/007/008 需要公安系统或收入数据，已禁用 | 接入相应数据接口后重新启用对应规则 |
