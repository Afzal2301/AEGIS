"""
Aegis triage function - evidence-based, rule-agnostic.

Flow:
  1. Work out the main suspect IP (not just from a port-scan rule).
  2. Collect evidence in CODE (flows, timeline, past alerts, past activity,
     Microsoft threat intel, AbuseIPDB).
  3. Score the evidence with transparent rules (every point is explained).
  4. Ask the LLM to reason over the evidence (it can nudge the score +/-15).
  5. Code decides verdict + action. Confidence = how much evidence we actually had.

Env vars (rename to match yours):
  LAW_WORKSPACE_ID   Log Analytics workspace ID (law-aegis)
  GROQ_API_KEY       Groq key
  GROQ_MODEL         optional, default llama-3.3-70b-versatile
  ABUSEIPDB_KEY      optional
  EXPECTED_OPEN_PORTS optional, default "22"
"""
import json
import logging
import os
import re
import ipaddress
import statistics
import urllib.request
from datetime import datetime, timedelta, timezone

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

WORKSPACE_ID = os.environ.get("LAW_WORKSPACE_ID", "")
EXPECTED_PORTS = {int(p) for p in os.environ.get("EXPECTED_OPEN_PORTS", "22").split(",") if p.strip()}
SENSITIVE_PORTS = {21, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017}

_logs_client = None


def logs_client():
    global _logs_client
    if _logs_client is None:
        _logs_client = LogsQueryClient(DefaultAzureCredential())
    return _logs_client


# ---------------------------------------------------------------- helpers
def run_kql(query, start, end):
    """Run KQL. Time range comes ONLY from timespan (no time filter inside KQL).
    Returns list of dict rows, or None if the query failed."""
    try:
        resp = logs_client().query_workspace(WORKSPACE_ID, query, timespan=(start, end))
        if resp.status not in (LogsQueryStatus.SUCCESS, LogsQueryStatus.PARTIAL):
            return None
        table = resp.tables[0] if resp.tables else None
        if table is None:
            return []
        cols = [c if isinstance(c, str) else c.name for c in table.columns]
        return [dict(zip(cols, row)) for row in table.rows]
    except Exception as e:
        logging.warning("KQL failed: %s", e)
        return None


def parse_time(value):
    try:
        t = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def valid_ip(value):
    try:
        return ipaddress.ip_address(str(value).strip())
    except Exception:
        return None


def pick_suspect(rule_name, src_ip, dst_ip):
    """Priority: public IP in the incident title > any public IP > src_ip."""
    for m in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", rule_name or ""):
        ip = valid_ip(m)
        if ip and not ip.is_private:
            return str(ip)
    for cand in (src_ip, dst_ip):
        ip = valid_ip(cand)
        if ip and not ip.is_private:
            return str(ip)
    ip = valid_ip(src_ip) or valid_ip(dst_ip)
    return str(ip) if ip else None


def src_filter(ip):
    return f'(SrcIp == "{ip}" or SrcPublicIps contains "{ip}")'


def as_list(v):
    """Log Analytics 'dynamic' columns can arrive as a JSON string. Always return a list."""
    if v is None:
        return []
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        try:
            parsed = json.loads(v)
            return parsed if isinstance(parsed, list) else [parsed]
        except Exception:
            return []
    return []


# --------------------------------------------------------- evidence layer
def collect_flow_evidence(ip, start, end):
    q = f"""
    NTANetAnalytics
    | where {src_filter(ip)}
    | extend Allowed = FlowStatus =~ "Allowed"
    | summarize flows=count(),
                distinct_ports=dcount(DestPort),
                distinct_targets=dcount(DestIp),
                allowed=countif(Allowed),
                denied=countif(not(Allowed)),
                first_seen=min(TimeGenerated),
                last_seen=max(TimeGenerated),
                allowed_ports=make_set_if(toint(DestPort), Allowed, 25),
                top_ports=make_set(toint(DestPort), 15),
                targets=make_set(DestIp, 10)
    """
    rows = run_kql(q, start, end)
    if rows is None:
        return None
    if not rows or not rows[0].get("flows"):
        return {"flows": 0}
    r = rows[0]
    for k in ("first_seen", "last_seen"):
        r[k] = str(r.get(k))
    for k in ("allowed_ports", "top_ports", "targets"):
        r[k] = as_list(r.get(k))
    return r


def collect_timeline(ip, start, end):
    q = f"""
    NTANetAnalytics
    | where {src_filter(ip)}
    | summarize n=count() by bin(TimeGenerated, 5m)
    | order by TimeGenerated asc
    | take 288
    """
    rows = run_kql(q, start, end)
    if not rows:
        return {"active_bins": 0, "regularity_cv": None}
    counts = [int(r["n"]) for r in rows]
    cv = None
    if len(counts) >= 6 and statistics.mean(counts) > 0:
        cv = round(statistics.pstdev(counts) / statistics.mean(counts), 2)
    return {"active_bins": len(counts), "regularity_cv": cv}


def collect_history(ip, start):
    now_back_30 = start - timedelta(days=30)
    alerts = run_kql(
        f"""SecurityAlert | where Entities has "{ip}"
            | summarize prior_alerts=count(), names=make_set(AlertName, 8)""",
        now_back_30, start)
    days = run_kql(
        f"""NTANetAnalytics | where {src_filter(ip)}
            | summarize prior_days_seen=dcount(bin(TimeGenerated, 1d))""",
        start - timedelta(days=14), start)
    if alerts is None and days is None:
        return None
    out = {"prior_alerts": 0, "names": [], "prior_days_seen": 0}
    if alerts:
        out["prior_alerts"] = int(alerts[0].get("prior_alerts") or 0)
        out["names"] = as_list(alerts[0].get("names"))
    if days:
        out["prior_days_seen"] = int(days[0].get("prior_days_seen") or 0)
    return out


def collect_threat_intel(ip, end):
    rows = run_kql(
        f"""ThreatIntelIndicators
            | where ObservableValue == "{ip}" and IsActive == true
            | summarize hits=count(), max_confidence=max(Confidence), tags=make_set(tostring(Tags), 5)""",
        end - timedelta(days=30), end)
    if rows is None:
        return None
    if not rows or not rows[0].get("hits"):
        return {"hits": 0}
    rows[0]["tags"] = as_list(rows[0].get("tags"))
    return rows[0]


def collect_abuseipdb(ip):
    key = os.environ.get("ABUSEIPDB_KEY") or os.environ.get("ABUSEIPDB_API_KEY") or os.environ.get("ABUSEIPDB_APIKEY")
    if not key:
        return None
    try:
        req = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            headers={"Key": key, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            d = json.loads(resp.read())["data"]
        return {"abuse_score": d.get("abuseConfidenceScore"),
                "reports": d.get("totalReports"),
                "country": d.get("countryCode"),
                "isp": d.get("isp"),
                "usage": d.get("usageType")}
    except Exception as e:
        logging.warning("AbuseIPDB failed: %s", e)
        return None


# ------------------------------------------------------------ scoring layer
def score_evidence(ev):
    """Every point added is listed in `factors` so the result is explainable."""
    s, factors = 0, []

    def add(points, why):
        nonlocal s
        s += points
        factors.append(f"({points:+d}) {why}")

    f = ev["flow"] or {}
    ports = int(f.get("distinct_ports") or 0)
    allowed = int(f.get("allowed") or 0)
    denied = int(f.get("denied") or 0)
    targets = int(f.get("distinct_targets") or 0)

    if ports >= 100:
        add(30, f"{ports} distinct destination ports probed")
    elif ports >= 50:
        add(22, f"{ports} distinct destination ports probed")
    elif ports >= 10:
        add(10, f"{ports} distinct destination ports probed")
    if targets >= 5:
        add(10, f"{targets} different hosts targeted (sweep)")

    allowed_ports = set()
    for p in as_list(f.get("allowed_ports")):
        try:
            allowed_ports.add(int(p))
        except (TypeError, ValueError):
            pass
    unexpected = allowed_ports - EXPECTED_PORTS
    sensitive = allowed_ports & SENSITIVE_PORTS
    if sensitive:
        add(25, f"traffic ALLOWED to sensitive ports {sorted(sensitive)}")
    elif unexpected:
        add(15, f"traffic ALLOWED to unexpected ports {sorted(unexpected)}")
    elif allowed and ports >= 10:
        add(5, "some probes reached an open service (expected port only)")
    if ports >= 10 and denied and denied >= 0.9 * (allowed + denied):
        add(0, "almost all probes were blocked by the NSG (low impact)")

    tl = ev.get("timeline") or {}
    if ports <= 3 and tl.get("active_bins", 0) >= 6 and tl.get("regularity_cv") is not None and tl["regularity_cv"] < 0.5:
        add(15, f"regular repeating pattern over {tl['active_bins']} windows (beacon-like)")

    ti = ev.get("threat_intel") or {}
    if ti.get("hits"):
        add(25, f"Microsoft threat intel match ({ti['hits']} indicators)")

    ab = ev.get("abuseipdb") or {}
    sc = ab.get("abuse_score")
    if sc is not None:
        if sc >= 75:
            add(25, f"AbuseIPDB score {sc}/100")
        elif sc >= 25:
            add(10, f"AbuseIPDB score {sc}/100")

    h = ev.get("history") or {}
    if h.get("prior_alerts"):
        add(10, f"{h['prior_alerts']} earlier alerts involving this IP")
    if h.get("prior_days_seen", 0) >= 2:
        add(5, f"seen on {h['prior_days_seen']} earlier days (persistent)")

    if ((ab.get("abuse_score") or 0) >= 75 or ti.get("hits")) and s < 40:
        add(40 - s, "known-bad reputation: minimum 'suspicious' regardless of flow volume")

    return min(s, 100), factors


def coverage_confidence(ev):
    """Confidence = how much evidence we actually had, not a model guess."""
    c = 0
    f = ev["flow"]
    if f is not None:
        c += 50 if f.get("flows") else 25
    if ev["threat_intel"] is not None:
        c += 15
    if ev["abuseipdb"] is not None:
        c += 15
    if ev["history"] is not None:
        c += 20
    return c


def decide(final_score, flows, external):
    if not flows:
        return "insufficient_data", "notify_analyst"
    if final_score >= 75:
        return "malicious", ("block_source" if external else "isolate_host")
    if final_score >= 40:
        return "suspicious", "notify_analyst"
    return "benign", "close"


# ---------------------------------------------------------------- LLM layer
SYSTEM_PROMPT = """You are a senior SOC analyst triaging a Microsoft Sentinel incident.
You get an EVIDENCE bundle gathered by code. Rules:
- Use ONLY the evidence. Never invent IPs, ports, counts, or threat intel.
- You have no internet access. "No threat-intel hit" does NOT mean safe.
- Internet background scanning is common. Blocked-only traffic = low impact.
- Missing evidence (null) means that source was unavailable. Say so.
- Judge the incident type from the rule name; it may not be a port scan.
Return ONLY a JSON object with keys:
  summary (2-3 plain sentences),
  blast_radius (what could be reached or affected, from evidence),
  mitre (list of MITRE ATT&CK technique IDs that fit),
  escalation_note (one sentence for a human analyst),
  adjustment (integer -15..15 to add to the code score),
  adjustment_reason (one sentence; why, citing evidence)."""


def ask_llm(rule_name, ev, base_score, factors):
    try:
        from groq import Groq
        client = Groq(api_key=os.environ["GROQ_API_KEY"])
        payload = {"rule_name": rule_name, "evidence": ev,
                   "code_score": base_score, "score_factors": factors}
        resp = client.chat.completions.create(
            model=os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b"),
            messages=[{"role": "system", "content": SYSTEM_PROMPT},
                      {"role": "user", "content": json.dumps(payload, default=str)}],
            response_format={"type": "json_object"},
            temperature=0.1,
            max_tokens=2500)
        data = json.loads(resp.choices[0].message.content)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        logging.warning("LLM failed: %s", e)
        return {}


def hunting_query(ip):
    return (f'NTANetAnalytics\n| where SrcIp == "{ip}" or SrcPublicIps contains "{ip}"\n'
            f'| summarize flows=count(), ports=dcount(DestPort), '
            f'allowed=countif(FlowStatus =~ "Allowed") by bin(TimeGenerated, 15m), DestIp\n'
            f'| order by TimeGenerated desc')


# ------------------------------------------------------------------ endpoint
@app.route(route="triage", methods=["POST"])
def triage_incident(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except ValueError:
        body = {}
    try:
        rule_name = str(body.get("rule_name", ""))
        ip = pick_suspect(rule_name, body.get("src_ip"), body.get("dst_ip"))
        if not ip:
            return func.HttpResponse(json.dumps({
                "verdict": "insufficient_data", "risk_score": 0, "confidence": 0,
                "recommended_action": "notify_analyst",
                "summary": "No usable IP address in the incident.",
                "hunting_query": "", "blast_radius": "", "escalation_note": "Check incident entities manually.",
                "mitre": [], "score_factors": []}), mimetype="application/json")

        alert_time = parse_time(body.get("time"))
        # Playbook runs AFTER the scan, so look back well before "now".
        start, end = alert_time - timedelta(hours=6), alert_time + timedelta(minutes=30)
        external = not valid_ip(ip).is_private

        ev = {
            "suspect_ip": ip,
            "direction": "external" if external else "internal",
            "window": {"start": start.isoformat(), "end": end.isoformat()},
            "flow": collect_flow_evidence(ip, start, end),
            "timeline": collect_timeline(ip, start, end),
            "history": collect_history(ip, start),
            "threat_intel": collect_threat_intel(ip, end),
            "abuseipdb": collect_abuseipdb(ip) if external else None,
        }

        base, factors = score_evidence(ev)
        llm = ask_llm(rule_name, ev, base, factors)

        adj = llm.get("adjustment", 0)
        adj = max(-15, min(15, adj)) if isinstance(adj, int) else 0
        final = max(0, min(100, base + adj))
        if adj:
            factors.append(f"({adj:+d}) analyst model: {llm.get('adjustment_reason', '')}")

        flows = (ev["flow"] or {}).get("flows", 0)
        verdict, action = decide(final, flows, external)
        # Safety: the AI may lower or explain a score, but it can never trigger containment.
        if action in ("block_source", "isolate_host") and base < 75:
            action = "notify_analyst"
            factors.append("(info) containment withheld: code score alone is below 75, AI adjustment cannot trigger it")
        confidence = coverage_confidence(ev)

        result = {
            "verdict": verdict,
            "risk_score": final,
            "confidence": confidence,
            "recommended_action": action,
            "summary": llm.get("summary") or f"Rule '{rule_name}' fired for {ip}. Code score {base}/100.",
            "blast_radius": llm.get("blast_radius", ""),
            "escalation_note": llm.get("escalation_note", ""),
            "mitre": llm.get("mitre", []) if isinstance(llm.get("mitre"), list) else [],
            "hunting_query": hunting_query(ip),
            "suspect_ip": ip,
            "score_factors": factors,
            "evidence_sources": {k: (ev[k] is not None) for k in ("flow", "history", "threat_intel", "abuseipdb")},
        }
        return func.HttpResponse(json.dumps(result, default=str), mimetype="application/json")
    except Exception as e:
        logging.exception("triage failed")
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500, mimetype="application/json")
