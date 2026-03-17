#!/usr/bin/env python3
"""
用户行为画像计算脚本（v2 - 适配实际 MCP 接口字段）

MCP 接口字段映射：
  queryUserInfoByUid  → uid, status, statusDesc, risk, riskDesc, accountType, flavor,
                        cerType, gender, regDate, openDate, createdAt, isOpenTrade,
                        riskStatus, createdIp
  queryLoginDeviceList → device, platform, client, version（无 deviceId！）
  queryLoginLogList    → loginTime(ms), ipAddress, grantType, deviceId, deviceType,
                        clientId, clientVersion, flavor
  queryIpLocation      → ip, info[] (如 ["中国","中国","","","移动"])

关键约束：
  - 设备列表无唯一ID，设备指纹追踪依赖登录日志的 deviceId
  - 登录日志：模式A默认 100 条 / 90 天，模式B/高风险 150 条 / 365 天
  - MCP 无交易数据接口，交易画像始终标记为不可用
  - IP 归属地为数组格式，需特殊解析

用法：
  单用户：python user_profiling.py --input raw_data.json --output profile.json
  批量：  python user_profiling.py --input batch_data.json --output batch_profile.json --batch
"""

import json
import sys
import argparse
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import statistics


# ============================================================
# 群体基线（正常基金用户经验统计值，可通过模式B更新）
# ============================================================
POPULATION_BASELINE = {
    "login_frequency": {"mean": 2.5, "std": 1.8},       # 日均登录次数
    "device_count": {"mean": 1.5, "std": 0.7},           # 7天内不同设备数
    "unique_ips": {"mean": 3.0, "std": 2.0},              # 7天内不同IP数
    "night_active_rate": {"mean": 0.05, "std": 0.08},     # 凌晨0-6点登录占比
    "cross_region_rate": {"mean": 0.15, "std": 0.12},     # 跨省IP占比
}

DEVIATION_WEIGHTS = {
    "login_frequency": 25,
    "device_count": 20,
    "unique_ips": 20,
    "night_active_rate": 20,
    "cross_region_rate": 15,
}

RECENT_WINDOW_DAYS = 7
MIN_HISTORY_DAYS = 14  # 历史数据不足此天数时使用群体基线


# ============================================================
# 工具函数
# ============================================================

def parse_timestamp_ms(ts):
    """解析毫秒级时间戳"""
    if ts is None:
        return None
    try:
        ts_val = int(ts)
        if ts_val > 1e12:
            ts_val = ts_val / 1000
        return datetime.fromtimestamp(ts_val)
    except (ValueError, TypeError, OSError):
        return None


def parse_date_str(date_str):
    """解析 yyyyMMdd 格式日期"""
    if not date_str:
        return None
    formats = ["%Y%m%d", "%Y-%m-%d", "%Y/%m/%d"]
    for fmt in formats:
        try:
            return datetime.strptime(str(date_str).strip(), fmt)
        except (ValueError, TypeError):
            continue
    return None


def parse_datetime(val):
    """解析日期时间，支持时间戳和多种字符串格式"""
    if not val:
        return None
    result = parse_timestamp_ms(val)
    if result:
        return result
    return parse_date_str(val)


def safe_div(a, b, default=0.0):
    return round(a / b, 4) if b and b != 0 else default


def parse_ip_location(ip_info):
    """
    解析 queryIpLocation 返回的 info 数组。
    格式: ["中国", "中国/省级", "城市", "?", "运营商"]
    有时某些位置为空字符串。

    返回: {"country": str, "province": str, "city": str, "isp": str, "is_domestic": bool}
    """
    result = {"country": "", "province": "", "city": "", "isp": "", "is_domestic": False}

    if not ip_info:
        return result

    # ip_info 可能是 dict 也可能直接是 list
    info_array = ip_info
    if isinstance(ip_info, dict):
        info_array = ip_info.get("info", [])

    if not isinstance(info_array, list) or len(info_array) == 0:
        return result

    # 位置0: 国家
    country = str(info_array[0]).strip() if len(info_array) > 0 else ""
    # 位置1: 可能是 "中国" 或省级信息（如 "浙江"）
    # 逻辑：如果位置1和位置0不同，则位置1是省份；否则从位置2或其他推断
    region1 = str(info_array[1]).strip() if len(info_array) > 1 else ""
    city = str(info_array[2]).strip() if len(info_array) > 2 else ""
    isp = str(info_array[4]).strip() if len(info_array) > 4 else ""

    result["country"] = country
    result["isp"] = isp
    result["city"] = city

    # 判断是否国内
    china_keywords = ["中国", "china", "CN"]
    is_domestic = any(kw.lower() in country.lower() for kw in china_keywords)
    result["is_domestic"] = is_domestic

    # 提取省份
    # 情况1: info[1] 包含省份信息（如 "浙江" 或 "北京"）
    # 情况2: info[1] 还是 "中国"（此时省份可能在 city 或缺失）
    if region1 and region1 != country:
        result["province"] = region1
    elif city:
        # 如果 region1 == country（如都是"中国"），则 city 字段可能是省份
        result["province"] = city
    else:
        result["province"] = ""

    return result


# ============================================================
# 画像计算模块
# ============================================================

def compute_device_profile(device_list, login_logs, now):
    """
    设备画像。
    注意：device_list 没有 deviceId，只有 device/platform/client/version。
    真正的设备唯一标识来自 login_logs 的 deviceId。
    """
    profile = {
        "total_unique_devices": 0,
        "device_type_distribution": {},
        "platform_distribution": {},
        "client_distribution": {},
        "new_device_ratio_7d": 0.0,
        "new_device_ratio_30d": 0.0,
        "most_used_device_id": "数据缺失",
        "device_id_list": [],
        "device_list_raw_count": 0,
    }

    # 从 device_list 提取类型分布
    profile["device_list_raw_count"] = len(device_list) if device_list else 0
    if device_list:
        type_counter = Counter()
        platform_counter = Counter()
        client_counter = Counter()
        for d in device_list:
            type_counter[str(d.get("device", "unknown"))] += 1
            platform_counter[str(d.get("platform", "unknown"))] += 1
            client_counter[str(d.get("client", "unknown"))] += 1
        profile["device_type_distribution"] = dict(type_counter)
        profile["platform_distribution"] = dict(platform_counter)
        profile["client_distribution"] = dict(client_counter)

    # 从 login_logs 提取 deviceId 统计（这才是真正的设备指纹）
    if login_logs:
        device_ids = Counter()
        device_first_seen = {}
        for log in login_logs:
            did = str(log.get("deviceId", "")).strip()
            if not did:
                continue
            device_ids[did] += 1
            lt = parse_timestamp_ms(log.get("loginTime"))
            if lt and (did not in device_first_seen or lt < device_first_seen[did]):
                device_first_seen[did] = lt

        profile["total_unique_devices"] = len(device_ids)
        profile["device_id_list"] = [did for did, _ in device_ids.most_common()]
        if device_ids:
            profile["most_used_device_id"] = device_ids.most_common(1)[0][0]

        seven_days_ago = now - timedelta(days=7)
        thirty_days_ago = now - timedelta(days=30)
        new_7d = sum(1 for did, first in device_first_seen.items() if first >= seven_days_ago)
        new_30d = sum(1 for did, first in device_first_seen.items() if first >= thirty_days_ago)
        profile["new_device_ratio_7d"] = safe_div(new_7d, len(device_ids))
        profile["new_device_ratio_30d"] = safe_div(new_30d, len(device_ids))

    return profile


def compute_login_profile(login_logs, now):
    """登录行为画像"""
    profile = {
        "total_logins": 0,
        "data_span_days": 0,
        "daily_avg_logins": 0.0,
        "active_days": 0,
        "time_distribution": {
            "night_0006": 0.0,
            "morning_0612": 0.0,
            "afternoon_1218": 0.0,
            "evening_1824": 0.0,
        },
        "night_active_rate": 0.0,
        "first_login": "数据缺失",
        "last_login": "数据缺失",
        "max_gap_days": 0,
        "grant_type_distribution": {},
        "data_note": "",
    }

    if not login_logs:
        profile["data_note"] = "无登录日志数据"
        return profile

    # 解析登录时间
    login_times = []
    grant_types = Counter()
    for log in login_logs:
        lt = parse_timestamp_ms(log.get("loginTime"))
        if lt:
            login_times.append(lt)
        gt = log.get("grantType", "unknown")
        grant_types[str(gt)] += 1

    profile["grant_type_distribution"] = dict(grant_types)

    if not login_times:
        profile["data_note"] = "登录时间戳全部解析失败"
        profile["total_logins"] = len(login_logs)
        return profile

    login_times.sort()
    profile["total_logins"] = len(login_times)
    profile["first_login"] = login_times[0].strftime("%Y-%m-%d %H:%M:%S")
    profile["last_login"] = login_times[-1].strftime("%Y-%m-%d %H:%M:%S")

    # 活跃天数和日均
    active_dates = set(lt.date() for lt in login_times)
    profile["active_days"] = len(active_dates)
    data_span = max((login_times[-1].date() - login_times[0].date()).days, 1)
    profile["data_span_days"] = data_span
    profile["daily_avg_logins"] = round(len(login_times) / data_span, 2)

    # 时段分布
    bins = {"night_0006": 0, "morning_0612": 0, "afternoon_1218": 0, "evening_1824": 0}
    for lt in login_times:
        h = lt.hour
        if 0 <= h < 6:
            bins["night_0006"] += 1
        elif 6 <= h < 12:
            bins["morning_0612"] += 1
        elif 12 <= h < 18:
            bins["afternoon_1218"] += 1
        else:
            bins["evening_1824"] += 1

    total = len(login_times)
    profile["time_distribution"] = {k: safe_div(v, total) for k, v in bins.items()}
    profile["night_active_rate"] = profile["time_distribution"]["night_0006"]

    # 最大间隔
    if len(active_dates) >= 2:
        sorted_dates = sorted(active_dates)
        gaps = [(sorted_dates[i + 1] - sorted_dates[i]).days for i in range(len(sorted_dates) - 1)]
        profile["max_gap_days"] = max(gaps) if gaps else 0

    # 数据量提示
    if len(login_logs) >= 100:
        profile["data_note"] = "已达接口返回上限(100条)，实际登录可能更多，统计为下限估计"

    return profile


def compute_ip_profile(login_logs, ip_locations):
    """
    IP 维度画像。
    ip_locations 格式: { "ip地址": {"ip": "x.x.x.x", "info": ["中国","浙江","杭州","","电信"]} }
    或简化格式: { "ip地址": ["中国","浙江","杭州","","电信"] }
    """
    profile = {
        "unique_ips": 0,
        "unique_provinces": 0,
        "unique_cities": 0,
        "domestic_ip_count": 0,
        "foreign_ip_count": 0,
        "foreign_ip_rate": 0.0,
        "cross_region_rate": 0.0,
        "province_list": [],
        "foreign_ip_details": [],
        "isp_distribution": {},
        "ip_details": [],
    }

    if not login_logs:
        return profile

    # 从登录日志提取所有IP
    ip_counter = Counter()
    for log in login_logs:
        ip = str(log.get("ipAddress", "")).strip()
        if ip and ip != "***" and len(ip) > 3:  # 跳过脱敏IP
            ip_counter[ip] += 1

    profile["unique_ips"] = len(ip_counter)

    if not ip_locations or not ip_counter:
        return profile

    # 解析每个IP的归属地
    provinces = Counter()
    cities = set()
    isps = Counter()
    domestic = 0
    foreign = 0
    foreign_details = []
    ip_detail_list = []

    for ip, count in ip_counter.items():
        raw_loc = ip_locations.get(ip)
        if raw_loc is None:
            ip_detail_list.append({"ip": ip, "count": count, "location": "未查询"})
            continue

        # 兼容两种格式
        if isinstance(raw_loc, list):
            parsed = parse_ip_location({"info": raw_loc})
        elif isinstance(raw_loc, dict):
            if "info" in raw_loc:
                parsed = parse_ip_location(raw_loc)
            else:
                parsed = parse_ip_location({"info": []})
        else:
            parsed = parse_ip_location(None)

        ip_detail_list.append({
            "ip": ip,
            "count": count,
            "country": parsed["country"],
            "province": parsed["province"],
            "city": parsed["city"],
            "isp": parsed["isp"],
            "is_domestic": parsed["is_domestic"],
        })

        if parsed["is_domestic"]:
            domestic += 1
            if parsed["province"]:
                provinces[parsed["province"]] += 1
            if parsed["city"]:
                cities.add(parsed["city"])
        else:
            foreign += 1
            foreign_details.append({
                "ip": ip,
                "country": parsed["country"],
                "login_count": count,
            })

        if parsed["isp"]:
            isps[parsed["isp"]] += 1

    total_classified = domestic + foreign
    profile["domestic_ip_count"] = domestic
    profile["foreign_ip_count"] = foreign
    profile["unique_provinces"] = len(provinces)
    profile["unique_cities"] = len(cities)
    profile["province_list"] = [p for p, _ in provinces.most_common()]
    profile["foreign_ip_details"] = foreign_details
    profile["foreign_ip_rate"] = safe_div(foreign, total_classified)
    profile["cross_region_rate"] = safe_div(max(len(provinces) - 1, 0), max(len(provinces), 1))
    profile["isp_distribution"] = dict(isps)
    profile["ip_details"] = ip_detail_list

    return profile


def compute_registration_profile(user_info, ip_locations):
    """从用户基本信息提取注册画像"""
    profile = {
        "uid": user_info.get("uid", "unknown"),
        "status": user_info.get("statusDesc", user_info.get("status", "数据缺失")),
        "risk_level_declared": user_info.get("riskDesc", "数据缺失"),
        "risk_value": user_info.get("risk", None),
        "account_type": user_info.get("accountType", None),
        "cert_type": user_info.get("cerType", "数据缺失"),
        "gender": user_info.get("gender", None),
        "reg_date": None,
        "open_date": None,
        "account_age_days": 0,
        "is_open_trade": user_info.get("isOpenTrade", None),
        "risk_assessment_done": user_info.get("riskStatus", None),
        "created_ip": user_info.get("createdIp", "数据缺失"),
        "created_ip_location": "未查询",
        "flavor": user_info.get("flavor", ""),
    }

    # 注册日期
    reg_date = parse_date_str(user_info.get("regDate"))
    if reg_date:
        profile["reg_date"] = reg_date.strftime("%Y-%m-%d")
        profile["account_age_days"] = (datetime.now() - reg_date).days

    open_date = parse_date_str(user_info.get("openDate"))
    if open_date:
        profile["open_date"] = open_date.strftime("%Y-%m-%d")

    # 如果没有 regDate，尝试用 createdAt 时间戳
    if not reg_date:
        created_at = parse_timestamp_ms(user_info.get("createdAt"))
        if created_at:
            profile["reg_date"] = created_at.strftime("%Y-%m-%d")
            profile["account_age_days"] = (datetime.now() - created_at).days

    # 注册IP归属地
    created_ip = user_info.get("createdIp", "")
    if created_ip and ip_locations and created_ip in ip_locations:
        raw_loc = ip_locations[created_ip]
        if isinstance(raw_loc, list):
            parsed = parse_ip_location({"info": raw_loc})
        elif isinstance(raw_loc, dict):
            parsed = parse_ip_location(raw_loc)
        else:
            parsed = parse_ip_location(None)
        parts = [parsed["province"], parsed["city"], parsed["isp"]]
        profile["created_ip_location"] = " ".join(p for p in parts if p)

    return profile


def compute_transaction_profile(transactions):
    """
    交易画像计算——按行为主动性分三条线。
    
    分流原则：
    - manual_trading：买入、卖出 → 用户主动发起，风控规则的核心输入
    - auto_invest_summary：定投 → 系统自动执行的预设行为，独立统计
    - dividend_summary：分红 → 基金公司下发的被动到账，独立统计
    - 投顾调仓等其他类型 → 仅计数，不参与计算
    
    为什么分红不算主动交易：
    分红是基金公司按分红规则发起的被动行为，用户无法控制时机和金额。
    混入主动交易会虚高交易频次，且分红份额会污染卖出份额统计。
    
    输入: queryUserTransactions(uid) 返回的交易记录数组
    字段: createdAt, tradeDate, tradeType, fundName, fundCode, amount, shares
    字段互斥: 买入/定投→amount有值; 卖出/分红→shares有值; 其余可能都无
    """
    profile = {
        "available": False,
        "data_source": "queryUserTransactions",
        "total_transactions": 0,
        "trade_type_distribution": {},

        # ====== 主动交易统计（风控核心输入，仅买入+卖出） ======
        "manual_trading": {
            "buy_count": 0,
            "sell_count": 0,
            "total_manual_trades": 0,
            # 金额（仅手动买入有 amount）
            "total_buy_amount": 0.0,
            "avg_buy_amount": 0.0,
            "max_single_buy": 0.0,
            "large_buy_count": 0,       # 单笔 ≥ 5万
            "large_buy_ratio": 0.0,
            # 份额（仅主动卖出有 shares，不含分红）
            "total_sell_shares": 0.0,
            # 基金集中度（仅主动交易涉及的基金）
            "unique_funds": 0,
            "fund_distribution": {},
            # 时间维度
            "first_trade_date": "数据缺失",
            "last_trade_date": "数据缺失",
            "active_trade_days": 0,
            "daily_max_trades": 0,
            "daily_max_buy_amount": 0.0,
            # 风控关键指标（全部基于主动交易）
            "rapid_turnaround_count": 0,
            "split_buy_days": 0,
            "high_frequency_trade_days": 0,
            # 供规则匹配使用的额外指标
            "per_fund_buy_sell_counts": {},
            "recent_7d_sell_count": 0,
            "recent_7d_sell_fund_count": 0,
        },

        # ====== 定投概况（系统自动执行，独立统计） ======
        "auto_invest_summary": {
            "total_auto_invest_count": 0,       # 定投执行总次数
            "unique_auto_invest_funds": 0,       # 定投涉及几只基金
            "auto_invest_fund_list": [],         # 定投基金列表 [{fundCode, fundName, count, total_amount}]
            "min_single_amount": 0.0,            # 单笔最小
            "max_single_amount": 0.0,            # 单笔最大
            "avg_single_amount": 0.0,            # 单笔平均
            "total_amount": 0.0,                 # 定投总金额
            # 定投专属告警（仅这几种情况定投才参与风控）
            "alerts": {
                "sudden_new_plans": False,        # 7天内新增≥5个不同基金的定投
                "large_single_alert": False,      # 单笔定投≥5万
                "excessive_plans_alert": False,    # 同时在投≥10只不同基金
            },
            "alert_details": [],
        },

        # ====== 分红记录（基金公司下发的被动行为，独立统计） ======
        "dividend_summary": {
            "total_dividend_count": 0,          # 分红到账次数
            "total_dividend_shares": 0.0,       # 分红总份额（红利再投资）
            "unique_dividend_funds": 0,         # 涉及几只基金有分红
            "dividend_fund_list": [],           # [{fundCode, fundName, count}]
            "note": "分红为基金公司发起的被动行为，不纳入主动交易频次和份额统计",
        },

        # ====== 其他类型（仅计数） ======
        "other_trade_count": 0,

        "note": "",
    }

    if not transactions:
        profile["note"] = "交易接口不可用或无交易数据"
        return profile

    profile["available"] = True
    profile["total_transactions"] = len(transactions)

    # === Step 1: 分类所有交易 ===
    type_map = {
        "买入": "buy", "buy": "buy", "申购": "buy", "purchase": "buy",
        "卖出": "sell", "sell": "sell", "赎回": "sell", "redeem": "sell",
        "定投": "auto_invest", "autoinvest": "auto_invest",
        "分红": "dividend", "dividend": "dividend",
    }
    type_counter = Counter()

    manual_txs = []       # 主动交易（仅买入/卖出）
    auto_invest_txs = []  # 定投（系统自动执行）
    dividend_txs = []     # 分红（基金公司下发）
    other_count = 0

    for tx in transactions:
        trade_type_raw = str(tx.get("tradeType", "")).strip()
        trade_type_lower = trade_type_raw.lower()
        type_counter[trade_type_raw] += 1

        category = "other"
        for keyword, cat in type_map.items():
            if keyword in trade_type_lower:
                category = cat
                break

        # 解析日期
        trade_date_str = tx.get("tradeDate", tx.get("createdAt", ""))
        trade_dt = parse_datetime(trade_date_str)

        enriched = {
            "category": category,
            "fundCode": str(tx.get("fundCode", "")),
            "fundName": str(tx.get("fundName", "")),
            "amount": _safe_float(tx.get("amount")),
            "shares": _safe_float(tx.get("shares")),
            "trade_date": trade_dt,
        }

        if category == "auto_invest":
            auto_invest_txs.append(enriched)
        elif category == "dividend":
            dividend_txs.append(enriched)
        elif category in ("buy", "sell"):
            manual_txs.append(enriched)
        else:
            other_count += 1

    profile["trade_type_distribution"] = dict(type_counter)
    profile["other_trade_count"] = other_count

    # === Step 2: 主动交易统计 ===
    mt = profile["manual_trading"]
    buy_amounts = []
    sell_shares_list = []
    trade_dates = []
    fund_trades = defaultdict(list)   # {fundCode: [{category, date, amount}]}
    daily_trades = defaultdict(list)  # {date_key: [tx]}
    fund_counter = Counter()

    for tx in manual_txs:
        cat = tx["category"]
        if cat == "buy":
            mt["buy_count"] += 1
            if tx["amount"] is not None:
                buy_amounts.append(tx["amount"])
        elif cat == "sell":
            mt["sell_count"] += 1
            if tx["shares"] is not None:
                sell_shares_list.append(tx["shares"])

        if tx["fundCode"]:
            fund_counter[tx["fundCode"]] += 1
            fund_trades[tx["fundCode"]].append(tx)

        if tx["trade_date"]:
            trade_dates.append(tx["trade_date"])
            date_key = tx["trade_date"].strftime("%Y-%m-%d")
            daily_trades[date_key].append(tx)

    mt["total_manual_trades"] = len(manual_txs)

    # 金额统计（仅手动买入）
    if buy_amounts:
        mt["total_buy_amount"] = round(sum(buy_amounts), 2)
        mt["avg_buy_amount"] = round(statistics.mean(buy_amounts), 2)
        mt["max_single_buy"] = round(max(buy_amounts), 2)
        large_threshold = 50000
        mt["large_buy_count"] = sum(1 for a in buy_amounts if a >= large_threshold)
        mt["large_buy_ratio"] = safe_div(mt["large_buy_count"], len(buy_amounts))

    # 份额统计
    if sell_shares_list:
        mt["total_sell_shares"] = round(sum(sell_shares_list), 2)

    # 基金集中度
    mt["unique_funds"] = len(fund_counter)
    mt["fund_distribution"] = dict(fund_counter.most_common(10))

    # 时间维度
    if trade_dates:
        trade_dates.sort()
        mt["first_trade_date"] = trade_dates[0].strftime("%Y-%m-%d")
        mt["last_trade_date"] = trade_dates[-1].strftime("%Y-%m-%d")
        mt["active_trade_days"] = len(set(d.strftime("%Y-%m-%d") for d in trade_dates))

    # 单日统计（仅主动交易）
    for date_key, day_txs in daily_trades.items():
        mt["daily_max_trades"] = max(mt["daily_max_trades"], len(day_txs))

        day_buy_total = sum(t["amount"] for t in day_txs if t["amount"] is not None and t["category"] == "buy")
        mt["daily_max_buy_amount"] = max(mt["daily_max_buy_amount"], day_buy_total)

        # 拆分检测：单日≥3笔手动买入，且单笔在4-5万
        day_manual_buys = [t["amount"] for t in day_txs if t["amount"] is not None and t["category"] == "buy"]
        if len(day_manual_buys) >= 3:
            near_threshold = sum(1 for a in day_manual_buys if 40000 <= a <= 50000)
            if near_threshold >= 3:
                mt["split_buy_days"] += 1

        # 高频交易日（单日≥5笔主动交易）
        if len(day_txs) >= 5:
            mt["high_frequency_trade_days"] += 1

    mt["daily_max_buy_amount"] = round(mt["daily_max_buy_amount"], 2)

    # 快进快出检测（仅主动买入 vs 主动卖出，定投不参与）
    rapid_count = 0
    for fund_code, trades in fund_trades.items():
        buys = [t for t in trades if t["category"] == "buy" and t["trade_date"] is not None]
        sells = [t for t in trades if t["category"] == "sell" and t["trade_date"] is not None]
        for b in buys:
            buy_amount = b["amount"] or 0
            if buy_amount < 10000:
                continue
            for s in sells:
                delta = s["trade_date"] - b["trade_date"]
                if timedelta(0) < delta <= timedelta(days=7):
                    rapid_count += 1
                    break
    mt["rapid_turnaround_count"] = rapid_count

    # per-fund buy/sell counts (供 AML-004 判定)
    per_fund_bs = {}
    for fund_code, trades in fund_trades.items():
        buy_c = sum(1 for t in trades if t["category"] == "buy")
        sell_c = sum(1 for t in trades if t["category"] == "sell")
        per_fund_bs[fund_code] = {"buy": buy_c, "sell": sell_c}
    mt["per_fund_buy_sell_counts"] = per_fund_bs

    # 近7天卖出统计 (供 AML-005 判定)
    now_tx = datetime.now()
    recent_7d_cutoff = now_tx - timedelta(days=7)
    recent_sells = [t for t in manual_txs
                    if t["category"] == "sell" and t["trade_date"] and t["trade_date"] >= recent_7d_cutoff]
    mt["recent_7d_sell_count"] = len(recent_sells)
    mt["recent_7d_sell_fund_count"] = len(set(t["fundCode"] for t in recent_sells if t["fundCode"]))

    # === Step 3: 定投概况（独立统计） ===
    ai = profile["auto_invest_summary"]
    ai["total_auto_invest_count"] = len(auto_invest_txs)

    if auto_invest_txs:
        ai_amounts = [tx["amount"] for tx in auto_invest_txs if tx["amount"] is not None]
        ai_fund_counter = Counter()
        ai_fund_amounts = defaultdict(lambda: {"count": 0, "total_amount": 0.0, "fundName": ""})
        ai_dates_by_fund = defaultdict(set)  # 用于检测"短期新增"

        for tx in auto_invest_txs:
            fc = tx["fundCode"]
            if fc:
                ai_fund_counter[fc] += 1
                ai_fund_amounts[fc]["count"] += 1
                ai_fund_amounts[fc]["fundName"] = tx["fundName"]
                if tx["amount"] is not None:
                    ai_fund_amounts[fc]["total_amount"] += tx["amount"]
                if tx["trade_date"]:
                    ai_dates_by_fund[fc].add(tx["trade_date"].strftime("%Y-%m-%d"))

        ai["unique_auto_invest_funds"] = len(ai_fund_counter)
        ai["auto_invest_fund_list"] = [
            {
                "fundCode": fc,
                "fundName": info["fundName"],
                "count": info["count"],
                "total_amount": round(info["total_amount"], 2),
            }
            for fc, info in ai_fund_amounts.items()
        ]

        if ai_amounts:
            ai["min_single_amount"] = round(min(ai_amounts), 2)
            ai["max_single_amount"] = round(max(ai_amounts), 2)
            ai["avg_single_amount"] = round(statistics.mean(ai_amounts), 2)
            ai["total_amount"] = round(sum(ai_amounts), 2)

        # --- 定投专属告警 ---
        # 1. 短期新增大量定投：7天内首次出现≥5只不同基金的定投
        #    检测方式：找最近7天内首次出现的定投基金数
        now = datetime.now()
        recent_7d = now - timedelta(days=7)
        new_funds_7d = set()
        for fc, dates in ai_dates_by_fund.items():
            sorted_dates = sorted(dates)
            if sorted_dates:
                first_date = parse_datetime(sorted_dates[0])
                if first_date and first_date >= recent_7d:
                    new_funds_7d.add(fc)
        if len(new_funds_7d) >= 5:
            ai["alerts"]["sudden_new_plans"] = True
            ai["alert_details"].append(
                f"近7天内新增{len(new_funds_7d)}只基金的定投：{', '.join(list(new_funds_7d)[:5])}"
            )

        # 2. 单笔定投金额过大
        if ai_amounts and max(ai_amounts) >= 50000:
            ai["alerts"]["large_single_alert"] = True
            ai["alert_details"].append(
                f"存在单笔定投≥5万元，最大单笔: {round(max(ai_amounts), 2)}元"
            )

        # 3. 同时在投基金过多
        if ai["unique_auto_invest_funds"] >= 10:
            ai["alerts"]["excessive_plans_alert"] = True
            ai["alert_details"].append(
                f"定投涉及{ai['unique_auto_invest_funds']}只不同基金，数量异常"
            )

    # === Step 4: 分红记录（被动行为，独立统计） ===
    ds = profile["dividend_summary"]
    ds["total_dividend_count"] = len(dividend_txs)

    if dividend_txs:
        div_shares = [tx["shares"] for tx in dividend_txs if tx["shares"] is not None]
        if div_shares:
            ds["total_dividend_shares"] = round(sum(div_shares), 2)

        div_fund_counter = Counter()
        for tx in dividend_txs:
            if tx["fundCode"]:
                div_fund_counter[tx["fundCode"]] += 1
        ds["unique_dividend_funds"] = len(div_fund_counter)
        ds["dividend_fund_list"] = [
            {"fundCode": fc, "count": cnt}
            for fc, cnt in div_fund_counter.most_common(10)
        ]

    return profile


def _safe_float(val):
    """安全转换为float，None/非数值返回None"""
    if val is None:
        return None
    try:
        return float(val)
    except (ValueError, TypeError):
        return None


# ============================================================
# 行为偏离检测
# ============================================================

def compute_deviation_analysis(login_logs, ip_locations, now):
    """
    行为偏离检测：对比近期行为与基线。
    自动选择自我基线（历史数据充足时）或群体基线（新用户兜底）。
    """
    result = {
        "baseline_type": "population",
        "baseline_data_days": 0,
        "recent_window_days": RECENT_WINDOW_DAYS,
        "dimension_deviations": {},
        "overall_deviation_score": 0,
        "deviation_summary": "",
    }

    if not login_logs:
        result["deviation_summary"] = "无登录日志，无法计算行为偏离"
        return result

    # 解析带时间的日志
    timed_logs = []
    for log in login_logs:
        lt = parse_timestamp_ms(log.get("loginTime"))
        if lt:
            timed_logs.append({"time": lt, "log": log})

    if not timed_logs:
        result["deviation_summary"] = "登录时间戳全部解析失败，无法计算行为偏离"
        return result

    timed_logs.sort(key=lambda x: x["time"])
    earliest = timed_logs[0]["time"]
    latest = timed_logs[-1]["time"]
    total_data_days = max((latest.date() - earliest.date()).days, 1)
    result["baseline_data_days"] = total_data_days

    # 切分时间窗口
    cutoff = now - timedelta(days=RECENT_WINDOW_DAYS)
    recent_logs = [t for t in timed_logs if t["time"] >= cutoff]
    history_logs = [t for t in timed_logs if t["time"] < cutoff]

    use_self_baseline = total_data_days >= MIN_HISTORY_DAYS and len(history_logs) >= 3

    if use_self_baseline:
        result["baseline_type"] = "self"
        history_days = max((cutoff.date() - earliest.date()).days, 1)
        baseline = _window_metrics(history_logs, ip_locations, history_days)
    else:
        result["baseline_type"] = "population"
        baseline = {k: v["mean"] for k, v in POPULATION_BASELINE.items()}

    recent_days = max(RECENT_WINDOW_DAYS, 1)
    recent = _window_metrics(recent_logs, ip_locations, recent_days)

    # 计算偏离度
    deviations = {}
    alert_dims = []
    weighted_score = 0

    for dim in DEVIATION_WEIGHTS:
        recent_val = recent.get(dim, 0)
        baseline_val = baseline.get(dim, 0)
        floor = 0.01 if "rate" in dim else 1.0
        denom = max(baseline_val, floor)
        ratio = round((recent_val - baseline_val) / denom, 2)

        is_alert = ratio > 1.5
        if is_alert:
            alert_dims.append(dim)

        deviations[dim] = {
            "recent": round(recent_val, 4),
            "baseline": round(baseline_val, 4),
            "deviation_ratio": ratio,
            "alert": is_alert,
        }

        dim_score = min(max(ratio, 0) / 3.0, 1.0) * DEVIATION_WEIGHTS[dim]
        weighted_score += dim_score

    max_possible = sum(DEVIATION_WEIGHTS.values())
    overall_score = min(round(weighted_score / max_possible * 100), 100)

    result["dimension_deviations"] = deviations
    result["overall_deviation_score"] = overall_score

    # 生成摘要
    dim_labels = {
        "login_frequency": "登录频次",
        "device_count": "设备数",
        "unique_ips": "不同IP数",
        "night_active_rate": "凌晨活跃率",
        "cross_region_rate": "跨省IP率",
    }

    if not alert_dims:
        result["deviation_summary"] = "该用户近期行为与基线无显著偏离"
    else:
        parts = []
        for dim in alert_dims:
            d = deviations[dim]
            label = dim_labels.get(dim, dim)
            pct = round(d["deviation_ratio"] * 100)
            parts.append(f"{label}偏离{pct}%（近期{d['recent']} vs 基线{d['baseline']}）")
        baseline_label = "自身历史" if use_self_baseline else "正常用户群体"
        result["deviation_summary"] = (
            f"该用户近{RECENT_WINDOW_DAYS}天行为与{baseline_label}基线存在显著偏离：" +
            "；".join(parts)
        )

    return result


def _window_metrics(timed_logs, ip_locations, window_days):
    """计算一个时间窗口内的行为指标"""
    login_count = len(timed_logs)
    login_frequency = round(login_count / max(window_days, 1), 2)

    # 设备数（通过 deviceId）
    device_ids = set()
    ips = set()
    night_count = 0
    for t in timed_logs:
        did = str(t["log"].get("deviceId", "")).strip()
        if did:
            device_ids.add(did)
        ip = str(t["log"].get("ipAddress", "")).strip()
        if ip and ip != "***" and len(ip) > 3:
            ips.add(ip)
        if 0 <= t["time"].hour < 6:
            night_count += 1

    device_count = len(device_ids)
    unique_ips = len(ips)
    night_active_rate = safe_div(night_count, login_count)

    # 跨省率
    provinces = set()
    for ip in ips:
        raw_loc = ip_locations.get(ip) if ip_locations else None
        if raw_loc is None:
            continue
        if isinstance(raw_loc, list):
            parsed = parse_ip_location({"info": raw_loc})
        elif isinstance(raw_loc, dict):
            parsed = parse_ip_location(raw_loc)
        else:
            continue
        if parsed["is_domestic"] and parsed["province"]:
            provinces.add(parsed["province"])

    cross_region_rate = safe_div(max(len(provinces) - 1, 0), max(len(provinces), 1))

    return {
        "login_frequency": login_frequency,
        "device_count": device_count,
        "unique_ips": unique_ips,
        "night_active_rate": night_active_rate,
        "cross_region_rate": cross_region_rate,
    }


# ============================================================
# 主构建函数
# ============================================================

def build_profile(raw_data):
    """构建单用户完整画像（含偏离检测）"""
    uid = raw_data.get("uid", "unknown")
    now = datetime.now()

    user_info = raw_data.get("user_info", {})
    device_list = raw_data.get("devices", [])
    login_logs = raw_data.get("login_logs", [])
    ip_locations = raw_data.get("ip_locations", {})

    reg_profile = compute_registration_profile(user_info, ip_locations)
    device_profile = compute_device_profile(device_list, login_logs, now)
    login_profile = compute_login_profile(login_logs, now)
    ip_profile = compute_ip_profile(login_logs, ip_locations)
    tx_profile = compute_transaction_profile(raw_data.get("transactions", None))
    deviation = compute_deviation_analysis(login_logs, ip_locations, now)

    return {
        "uid": uid,
        "profile_generated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "profile_source": "script",
        "registration_profile": reg_profile,
        "device_profile": device_profile,
        "login_profile": login_profile,
        "ip_profile": ip_profile,
        "transaction_profile": tx_profile,
        "deviation_analysis": deviation,
    }


def build_batch_statistics(profiles):
    """批量模式：统计汇总"""
    if not profiles:
        return {}

    stats = {}
    numeric_fields = {
        "device_count": [p["device_profile"]["total_unique_devices"] for p in profiles],
        "daily_avg_logins": [p["login_profile"]["daily_avg_logins"] for p in profiles],
        "unique_ips": [p["ip_profile"]["unique_ips"] for p in profiles],
        "unique_provinces": [p["ip_profile"]["unique_provinces"] for p in profiles],
        "night_active_rate": [p["login_profile"]["night_active_rate"] for p in profiles],
        "account_age_days": [p["registration_profile"]["account_age_days"] for p in profiles],
        "deviation_score": [p["deviation_analysis"]["overall_deviation_score"] for p in profiles],
    }

    for field, values in numeric_fields.items():
        if values:
            stats[f"{field}_stats"] = {
                "mean": round(statistics.mean(values), 4),
                "median": round(statistics.median(values), 4),
                "std": round(statistics.stdev(values), 4) if len(values) > 1 else 0.0,
                "max": round(max(values), 4),
                "min": round(min(values), 4),
            }

    # 跨UID关联检测
    stats["cross_uid_shared_devices"] = _find_shared_devices(profiles)
    stats["cross_uid_shared_ips"] = _find_shared_ips(profiles)

    return stats


def _find_shared_devices(profiles):
    """检测多个UID是否共享设备ID"""
    device_to_uids = defaultdict(set)
    for p in profiles:
        uid = p["uid"]
        # 从原始数据中无法直接获取设备ID列表，
        # 这里通过 most_used_device_id 做简化检测
        did = p["device_profile"].get("most_used_device_id", "")
        if did and did != "数据缺失":
            device_to_uids[did].add(str(uid))
    return [
        {"device_id": did, "uids": list(uids)}
        for did, uids in device_to_uids.items()
        if len(uids) > 1
    ]


def _find_shared_ips(profiles):
    """检测多个UID是否共享IP"""
    ip_to_uids = defaultdict(set)
    for p in profiles:
        uid = p["uid"]
        for detail in p["ip_profile"].get("ip_details", []):
            ip = detail.get("ip", "")
            if ip:
                ip_to_uids[ip].add(str(uid))
    return [
        {"ip": ip, "uids": list(uids)}
        for ip, uids in ip_to_uids.items()
        if len(uids) > 1
    ]


# ============================================================
# 入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="用户行为画像计算（v2 适配MCP字段）")
    parser.add_argument("--input", required=True, help="输入 JSON 文件路径")
    parser.add_argument("--output", required=True, help="输出 JSON 文件路径")
    parser.add_argument("--batch", action="store_true", help="批量模式")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    if args.batch:
        if not isinstance(raw_data, list):
            raw_data = [raw_data]
        profiles = [build_profile(rd) for rd in raw_data]
        result = {
            "mode": "batch",
            "total": len(profiles),
            "profiles": profiles,
            "statistics": build_batch_statistics(profiles),
        }
    else:
        result = build_profile(raw_data)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"画像计算完成，输出: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
