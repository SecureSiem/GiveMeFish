#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GiveMeFish - Advanced Phishing Email Analysis (Production)
Author: Vaibhav Handekar (adapted)
Version: 3.1
"""

from __future__ import annotations
import argparse, os, re, sys, json, time, hashlib, datetime, socket, ssl
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
from typing import List, Dict, Optional, Any

# ---------------------------
# Optional deps (graceful degrade)
# ---------------------------
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

try:
    import requests
    from bs4 import BeautifulSoup
except Exception:
    requests = None
    BeautifulSoup = None

try:
    import whois as whoislib
except Exception:
    whoislib = None

try:
    import openai
except Exception:
    openai = None

try:
    from oletools.olevba import VBA_Parser
except Exception:
    VBA_Parser = None

try:
    import spf
except Exception:
    spf = None

try:
    import dkim
except Exception:
    dkim = None

try:
    import dns.resolver
except Exception:
    dns = None

# ---------------------------
# Config / API keys
# ---------------------------
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GSB_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
if openai and OPENAI_API_KEY:
    try:
        openai.api_key = OPENAI_API_KEY
    except Exception:
        pass

# ---------------------------
# Constants
# ---------------------------
REQUEST_TIMEOUT = 12
SHORTENER_DOMAINS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","rb.gy","shorturl.at","tiny.one","bitly.com"
}
SUSPICIOUS_KEYWORDS = [
    "secure","account","login","update","verify","confirm","bank","password","signin","reset","invoice"
]
SUSPICIOUS_EXTENSIONS = {
    ".exe",".scr",".pif",".jar",".js",".vbs",".bat",".ps1",".docm",".xlsm",".doc",".xls",".html",".hta",".iso",".img",".zip",".rar",".7z"
}

# Terminal colors
RED  = "\033[0;31m"
GRN  = "\033[1;92m"
YLW  = "\033[1;33m"
BLUE = "\033[0;34m"
WHT  = "\033[0m"
BOLD = "\033[1m"

def banner():
    print(f"""{GRN}{BOLD}
   ██████╗ ██╗██╗   ██╗███████╗███╗   ███╗███████╗███████╗██╗███████╗██╗  ██╗
  ██╔══    ██║██║   ██║██╔════╝████╗ ████║██╔════╝██╔════╝██║██╔════╝██║  ██║
  ██║  ██║ ██║██║   ██║█████╗  ██╔████╔██║█████╗  █████╗  ██║███████╗███████║
  ██║▄▄ ██║██║╚██╗ ██╔╝██╔══╝  ██║╚██╔╝██║██╔══╝  ██╔══╝  ██║╚════██║██╔══██║
  ╚██████╔╝██║ ╚████╔╝ ███████╗██║ ╚═╝ ██║███████╗██║     ██║███████║██║  ██║
   ╚══▀▀═╝ ╚═╝  ╚═══╝  ╚══════╝╚═╝     ╚═╝╚══════╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝
{WHT}                 {YLW}GiveMeFish - Advanced Phishing Detection{WHT}
                        Author: {BOLD}Vaibhav Handekar{WHT}
    """)

# ---------------------------
# Utility
# ---------------------------
def load_email_message(path: str):
    with open(path, "rb") as fh:
        raw = fh.read()
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    return msg, raw

def extract_body_from_message(msg) -> str:
    try:
        body = msg.get_body(preferencelist=('html','plain'))
        if body:
            return body.get_content()
    except Exception:
        pass
    parts=[]
    for part in msg.walk():
        if part.get_content_type()=="text/plain":
            try: parts.append(part.get_content())
            except Exception: pass
    return "\n\n".join(parts)

def extract_urls_from_text(text: str) -> List[Dict[str,str]]:
    urls=[]
    if BeautifulSoup and text:
        try:
            soup = BeautifulSoup(text, "html.parser")
            for a in soup.find_all("a", href=True):
                urls.append({"href": a['href'].strip(), "anchor": (a.get_text() or "").strip()})
        except Exception:
            pass
    if text:
        url_re = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
        for m in url_re.findall(text):
            urls.append({"href": m, "anchor": ""})
    out=[]; seen=set()
    for u in urls:
        if u['href'] not in seen:
            out.append(u); seen.add(u['href'])
    return out

def domain_from_url(url: str) -> Optional[str]:
    try: return urlparse(url).hostname
    except Exception: return None

def is_ip_host(host: str) -> bool:
    if not host: return False
    try:
        socket.inet_aton(host); return True
    except Exception:
        return ":" in host  # ipv6 naive

def compute_hashes(data: bytes) -> Dict[str,str]:
    return {"md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()}

# ---------------------------
# SPF / DKIM / DMARC
# ---------------------------
def extract_ips_from_received(received_headers: List[str]) -> List[str]:
    ips=[]
    for h in received_headers:
        ips.extend(re.findall(r'\[?(\d{1,3}(?:\.\d{1,3}){3})\]?', h))
    return ips

def spf_check_dns(ip: str, mail_from: str, helo: str) -> Dict[str,Any]:
    if not spf:
        return {"skipped": "pyspf not installed"}
    try:
        res, explanation = spf.check2(i=ip or "", s=mail_from or "", h=helo or "")
        return {"result": res, "explanation": explanation}
    except Exception as e:
        return {"error": str(e)}

def get_dkim_signature_domains(msg) -> List[str]:
    domains=[]
    try:
        for sig in msg.get_all('DKIM-Signature') or []:
            m = re.search(r'\bd=([^;]+)', sig); 
            if m: domains.append(m.group(1).strip())
    except Exception:
        pass
    return domains

def dkim_verify_dns(raw_bytes: bytes) -> Dict[str,Any]:
    if not dkim:
        return {"skipped": "dkimpy not installed"}
    try:
        ok = dkim.verify(raw_bytes)
        return {"result": bool(ok)}
    except Exception as e:
        return {"error": str(e)}

def dmarc_policy_for(domain: str) -> Dict[str,Any]:
    if not dns:
        return {"skipped":"dnspython not installed"}
    try:
        ans = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=6)
        txts=[]
        for r in ans:
            try: txts.append(b"".join(r.strings).decode("utf-8"))
            except Exception: txts.append(str(r))
        p=None
        for t in txts:
            m = re.search(r'\bp=([a-zA-Z0-9_-]+)', t)
            if m: p=m.group(1); break
        return {"raw": txts, "policy": p}
    except Exception as e:
        return {"error": str(e)}

def evaluate_dmarc(from_domain: str, spf_res: Dict[str,Any], dkim_res: Dict[str,Any], dkim_domains: List[str]) -> Dict[str,Any]:
    policy = dmarc_policy_for(from_domain) if from_domain else {"skipped": "no_from_domain"}
    passed=False; reasons=[]
    try:
        if spf_res and spf_res.get("result")=="pass":
            reasons.append("spf_pass"); passed=True
        if dkim_res and dkim_res.get("result") is True:
            aligned=False
            for d in dkim_domains:
                dlow=d.lower(); fd=(from_domain or "").lower()
                if dlow.endswith(fd) or fd.endswith(dlow):
                    aligned=True; break
            if aligned: reasons.append("dkim_pass_and_aligned"); passed=True
            else: reasons.append("dkim_pass_but_not_aligned")
    except Exception:
        pass
    return {"dmarc_policy": policy, "dmarc_pass": passed, "reasons": reasons}

# ---------------------------
# VT / GSB
# ---------------------------
VT_HEADERS = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}

def vt_check_file_hash(sha256: str) -> Dict[str,Any]:
    if not VT_API_KEY or requests is None:
        return {"skipped": "vt_key_or_requests_missing"}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=VT_HEADERS, timeout=REQUEST_TIMEOUT)
        if r.status_code==200: return {"raw": r.json()}
        elif r.status_code==404: return {"not_found": True}
        return {"error": f"status_{r.status_code}", "detail": r.text}
    except Exception as e:
        return {"error": str(e)}

def vt_check_url(url: str) -> Dict[str,Any]:
    if not VT_API_KEY or requests is None:
        return {"skipped": "vt_key_or_requests_missing"}
    try:
        submit = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=VT_HEADERS, timeout=REQUEST_TIMEOUT)
        if submit.status_code not in (200,201):
            return {"error": f"submit_failed_{submit.status_code}", "detail": submit.text}
        vt_id = submit.json().get("data",{}).get("id")
        if not vt_id: return {"error":"missing_vt_id"}
        time.sleep(1)
        lookup = requests.get(f"https://www.virustotal.com/api/v3/urls/{vt_id}", headers=VT_HEADERS, timeout=REQUEST_TIMEOUT)
        if lookup.status_code==200: return {"raw": lookup.json()}
        return {"error": f"lookup_{lookup.status_code}", "detail": lookup.text}
    except Exception as e:
        return {"error": str(e)}

def google_safe_browsing_check(urls: List[str]) -> Dict[str,Any]:
    if not GSB_API_KEY or requests is None:
        return {"skipped":"gsb_key_or_requests_missing"}
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    payload = {
        "client": {"clientId":"GiveMeFish","clientVersion":"1.0"},
        "threatInfo": {
            "threatTypes":["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes":["ANY_PLATFORM"],
            "threatEntryTypes":["URL"],
            "threatEntries":[{"url": u} for u in urls]
        }
    }
    try:
        r = requests.post(endpoint, json=payload, timeout=REQUEST_TIMEOUT)
        if r.status_code==200: return {"raw": r.json()}
        return {"error": f"status_{r.status_code}", "detail": r.text}
    except Exception as e:
        return {"error": str(e)}

# ---------------------------
# WHOIS / TLS / Redirects
# ---------------------------
def whois_domain_info(domain: str) -> Dict[str,Any]:
    if not whoislib: return {"skipped":"whois_library_missing"}
    try:
        w = whoislib.whois(domain)
        created = getattr(w, "creation_date", None)
        if isinstance(w, dict) and created is None:
            created = w.get("creation_date")
        if isinstance(created, list): created = created[0] if created else None
        age_days=None
        if isinstance(created, datetime.datetime):
            created_dt=created
        elif isinstance(created, str):
            try: created_dt=datetime.datetime.fromisoformat(created)
            except Exception: created_dt=None
        else:
            created_dt=None
        if created_dt: age_days=(datetime.datetime.utcnow()-created_dt).days
        return {"creation_date": str(created), "age_days": age_days}
    except Exception as e:
        return {"error": str(e)}

def follow_redirects(url: str) -> Dict[str,Any]:
    if requests is None: return {"final": url, "chain":[url], "error":"requests_missing"}
    try:
        r = requests.get(url, allow_redirects=True, timeout=REQUEST_TIMEOUT, headers={"User-Agent":"GiveMeFish/1.0"})
        return {"final": r.url, "chain":[h.url for h in r.history]+[r.url], "status_code": r.status_code}
    except Exception as e:
        return {"final": url, "chain":[url], "error": str(e)}

def check_tls_cert(host: str) -> Dict[str,Any]:
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((host,443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert=ssock.getpeercert()
                return {"issuer": cert.get("issuer"), "subject": cert.get("subject"), "notAfter": cert.get("notAfter")}
    except Exception as e:
        return {"error": str(e)}

# ---------------------------
# Attachments
# ---------------------------
def extract_attachments_from_msg(msg) -> List[Dict[str,Any]]:
    out=[]
    try:
        for part in msg.iter_attachments():
            filename = part.get_filename() or "unknown"
            ctype = part.get_content_type()
            try: data = part.get_payload(decode=True) or b""
            except Exception: data=b""
            out.append({"filename": filename, "content_type": ctype, "size": len(data), "data": data})
    except Exception:
        pass
    if not out:
        for part in msg.walk():
            disp=part.get_content_disposition()
            if disp=="attachment" or part.get_filename():
                filename=part.get_filename() or "unknown"
                ctype=part.get_content_type()
                try: data=part.get_payload(decode=True) or b""
                except Exception: data=b""
                out.append({"filename": filename, "content_type": ctype, "size": len(data), "data": data})
    return out

def analyze_attachment(att: Dict[str,Any], do_vt=True, auto_upload=False) -> Dict[str,Any]:
    filename=att["filename"]; data=att["data"] or b""
    ext=os.path.splitext(filename)[1].lower()
    out={"filename": filename, "content_type": att.get("content_type"), "size": att.get("size",0),
         "suspicious_extension": ext in SUSPICIOUS_EXTENSIONS}
    out["hashes"]=compute_hashes(data)
    if VBA_Parser and ext in {".doc",".docm",".xls",".xlsm",".ppt",".pptm"}:
        try:
            parser=VBA_Parser(filename, data=data)
            has=parser.detect_vba_macros()
            out["macro_check"]={"checked": True, "has_macros": bool(has)}
            parser.close()
        except Exception as e:
            out["macro_check"]={"error": str(e)}
    else:
        out["macro_check"]={"checked": False, "reason":"oletools_missing_or_not_office"}
    if do_vt and VT_API_KEY:
        out["virustotal"]=vt_check_file_hash(out["hashes"]["sha256"])
        if auto_upload and out["virustotal"].get("not_found") and requests:
            try:
                res=requests.post("https://www.virustotal.com/api/v3/files", headers=VT_HEADERS, files={"file": (filename, data)}, timeout=REQUEST_TIMEOUT)
                out["virustotal_upload"]={"status_code": res.status_code}
            except Exception as e:
                out["virustotal_upload"]={"error": str(e)}
    else:
        out["virustotal"]={"skipped": not VT_API_KEY}
    return out

# ---------------------------
# Heuristics
# ---------------------------
def check_shortener(domain: str) -> bool:
    if not domain: return False
    d=domain.lower()
    if d.startswith("www."): d=d[4:]
    return any(d==s or d.endswith("."+s) for s in SHORTENER_DOMAINS)

def punycode_or_homoglyph(domain: str):
    if not domain: return False, None
    if domain.lower().startswith("xn--") or any(lbl.lower().startswith("xn--") for lbl in domain.split(".")):
        return True, "punycode"
    if any(ord(c)>127 for c in domain): return True, "unicode-homoglyph"
    return False, None

def heuristic_score(header: Dict[str,Any], url_entries: List[Dict[str,Any]], sender_domain: Optional[str]) -> (int,List[str]):
    score=0; signals=[]
    if not header.get("DKIM-Signature"):
        score+=5; signals.append("missing_dkim")
    auth=(header.get("Authentication-Results") or "").lower()
    if "spf=pass" not in auth and "spf=neutral" not in auth:
        score+=4; signals.append("spf_not_pass")
    if "dmarc" in auth and "fail" in auth:
        score+=6; signals.append("dmarc_failed")
    for u in url_entries:
        href=u.get("href",""); host=domain_from_url(href) or ""; hl=host.lower() if host else ""
        if is_ip_host(hl): score+=8; signals.append("ip_in_url")
        if check_shortener(hl): score+=6; signals.append("shortener_domain")
        puny,_=punycode_or_homoglyph(hl)
        if puny: score+=7; signals.append("punycode_or_homoglyph")
        anchor=(u.get("anchor") or "").strip()
        if anchor:
            doms=re.findall(r'([A-Za-z0-9.-]+\.[A-Za-z]{2,})', anchor)
            if doms and hl and doms[0].lower() not in hl: score+=6; signals.append("anchor_href_mismatch")
        if href.startswith("http://"): score+=3; signals.append("insecure_http")
        if any(tok in href.lower() for tok in SUSPICIOUS_KEYWORDS): score+=2; signals.append("suspicious_token")
        if sender_domain and hl and sender_domain.lower() not in hl: score+=2; signals.append("sender_domain_mismatch")
    return score, signals

def interpret_score10(s: float) -> str:
    if s >= 8.0: return "HIGH RISK 🚨"
    if s >= 4.0: return "MEDIUM RISK ⚠️"
    return "LOW RISK ✅"

# ---------------------------
# AI opinion (optional)
# ---------------------------
def ai_opinion(text: str) -> Dict[str,Any]:
    if not openai or not OPENAI_API_KEY:
        return {"skipped":"openai_missing"}
    try:
        prompt = text if len(text)<=4000 else text[:4000]
        resp = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[
                {"role":"system","content":"You are a security analyst. Briefly list phishing indicators and give a LOW/MEDIUM/HIGH risk rating."},
                {"role":"user","content": prompt}
            ],
            max_tokens=250, temperature=0
        )
        content = resp["choices"][0]["message"]["content"]
        return {"raw": content}
    except Exception as e:
        return {"error": str(e)}

# ---------------------------
# Pretty printers
# ---------------------------
def line(title: str):
    bar="="*30
    print(f"{bar}\n{title}\n{bar}")

def kcv(k, v):  # key: value aligned
    print(f"{k:<11}: {v}")

def vt_parse_detection_stats(vt_raw: dict) -> (int,int,list):
    """Return positives,total,engine_list (names that flagged)."""
    try:
        stats = vt_raw["data"]["attributes"]["last_analysis_stats"]
        total = sum(stats.values())
        positives = stats.get("malicious",0) + stats.get("suspicious",0)
        engines=[]
        details = vt_raw["data"]["attributes"].get("last_analysis_results", {})
        for eng, res in details.items():
            if res.get("category") in ("malicious","suspicious"):
                engines.append(eng)
        return positives, total, sorted(engines)
    except Exception:
        return 0, 0, []

def gsb_is_unsafe(gsb: dict) -> (bool, list):
    try:
        matches = gsb.get("raw",{}).get("matches",[])
        kinds = list({m.get("threatType","UNKNOWN") for m in matches})
        return (len(matches)>0, kinds)
    except Exception:
        return (False, [])

def score_table(spf_res, dkim_res, dmarc_eval, vt_results, gsb_results, ai_text) -> (float, list):
    """Return (final_score_out_of_10, rows) where rows are tuples (Indicator, Result, Weight, Score)."""
    rows=[]
    total=0.0

    # SPF
    spf_pass = (spf_res.get("result")=="pass")
    w=2.0; s=0.0 if spf_pass else w
    rows.append(("SPF Check", "PASS" if spf_pass else "FAIL", w, s)); total+=s

    # DKIM
    dk_ok = (dkim_res.get("result") is True)
    w=1.5; s=0.0 if dk_ok else w
    rows.append(("DKIM Check", "PASS" if dk_ok else "FAIL", w, s)); total+=s

    # DMARC
    dm_pass = bool(dmarc_eval.get("dmarc_pass"))
    w=2.0; s=0.0 if dm_pass else w
    rows.append(("DMARC Check", "PASS" if dm_pass else "FAIL", w, s)); total+=s

    # VT (URLs + attachments aggregate)
    vt_pos=0; vt_total=0
    for x in vt_results:
        p,t,_ = vt_parse_detection_stats(x)
        vt_pos += p; vt_total += t
    # Map any positives to full weight, none->0
    w=2.0; s=w if vt_pos>0 else 0.0
    vt_label = f"{vt_pos} engines flagged" if vt_total>0 else ("N/A" if not vt_results else "0 flagged")
    rows.append(("VirusTotal", vt_label, w, s)); total+=s

    # GSB
    unsafe=False; kinds=[]
    for g in gsb_results:
        u, k = gsb_is_unsafe(g)
        if u: unsafe=True; kinds = list(set(kinds + k))
    w=2.0; s=w if unsafe else 0.0
    rows.append(("Safe Browsing", "UNSAFE: " + ", ".join(kinds) if unsafe else "SAFE", w, s)); total+=s

    # AI
    ai_high=False
    if isinstance(ai_text, str):
        ai_high = "high" in ai_text.lower()
    w=2.0; s=w if ai_high else 0.0
    rows.append(("AI Heuristic", "HIGH RISK" if ai_high else "OK", w, s)); total+=s

    # cap to 10
    final = min(10.0, round(total, 2))
    return final, rows

def print_table(rows):
    print(f"{'-'*66}")
    print(f"| {'Indicator':<23} | {'Result':<18} | {'Weight':>6} | {'Score':>5} |")
    print(f"{'-'*66}")
    for ind,res,w,s in rows:
        print(f"| {ind:<23} | {res:<18} | {w:>6.1f} | {s:>5.1f} |")
    print(f"{'-'*66}")

# ---------------------------
# Analyze pipeline
# ---------------------------
def analyze_email(path: str, no_network=False, output=None, verbose=False, auto_upload=False) -> Dict[str,Any]:
    msg, raw = load_email_message(path)

    header = {k: msg.get(k) for k in ("From","To","Subject","Date","Message-ID","Return-Path","Authentication-Results","Received-SPF")}
    header["DKIM-Signature"] = bool(msg.get_all("DKIM-Signature"))

    # From domain
    from_field = header.get("From") or ""
    m = re.search(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})', from_field)
    from_domain = m.group(1) if m else None

    # Envelope from
    env = header.get("Return-Path") or ""
    mm = re.search(r'<([^>]+)>', env)
    mail_from = mm.group(1) if mm else (env.strip() if env else None)

    # Received IP & HELO
    recv = msg.get_all("Received") or []
    ips = extract_ips_from_received(recv)
    first_ip = ips[0] if ips else None
    helo=None
    if recv:
        hm=re.search(r'from\s+([^\s]+)', recv[0], re.IGNORECASE)
        if hm: helo=hm.group(1)

    # SPF / DKIM / DMARC
    spf_res={"skipped":"no_network_or_missing"}; dkim_res={"skipped":"no_network_or_missing"}
    dkim_domains=get_dkim_signature_domains(msg)
    if not no_network:
        spf_res = spf_check_dns(first_ip or "", mail_from or "", helo or "")
        dkim_res = dkim_verify_dns(raw)
    dmarc_eval = evaluate_dmarc(from_domain or "", spf_res, dkim_res, dkim_domains) if from_domain else {"skipped":"no From domain"}

    # Body & URLs
    body_text = extract_body_from_message(msg)
    url_entries = extract_urls_from_text(body_text)

    report = {
        "meta": {"path": path, "timestamp": datetime.datetime.utcnow().isoformat()+"Z"},
        "header": header,
        "from_domain": from_domain,
        "ips_in_received": ips,
        "spf": spf_res,
        "dkim": {"signature_domains": dkim_domains, "result": dkim_res},
        "dmarc": dmarc_eval,
        "urls": [],
        "attachments": [],
        "heuristic": {},
        "ai": None
    }

    # Per-URL intel
    vt_url_packets=[]
    gsb_packets=[]
    for u in url_entries:
        entry={"href": u["href"], "anchor": u.get("anchor","")}
        if not no_network:
            red = follow_redirects(u["href"]); entry.update({"final": red.get("final"), "redirect_chain": red.get("chain"), "status_code": red.get("status_code")})
            fin_host = domain_from_url(entry.get("final") or entry["href"])
            if fin_host:
                entry["tls"] = check_tls_cert(fin_host)
                entry["whois"] = whois_domain_info(fin_host)
            if VT_API_KEY:
                vt_res=vt_check_url(u["href"]); entry["virustotal"]=vt_res; vt_url_packets.append(vt_res)
            if GSB_API_KEY:
                gsb=google_safe_browsing_check([u["href"]]); entry["gsb"]=gsb; gsb_packets.append(gsb)
        else:
            entry["note"]="network checks skipped"
        report["urls"].append(entry)

    # Attachments
    atts=extract_attachments_from_msg(msg)
    vt_att_packets=[]
    for a in atts:
        res = analyze_attachment(a, do_vt=(not no_network), auto_upload=auto_upload)
        report["attachments"].append(res)
        if res.get("virustotal",{}).get("raw"):
            vt_att_packets.append(res["virustotal"])

    # Heuristics (legacy score kept in report)
    score_raw, signals = heuristic_score(header, url_entries, from_domain)
    report["heuristic"]={"legacy_score": score_raw, "signals": signals}

    # AI opinion (optional)
    if not no_network and OPENAI_API_KEY and openai:
        summarized = json.dumps({"header": header, "body": body_text[:2000]}, ensure_ascii=False)
        report["ai"] = ai_opinion(summarized)
    else:
        report["ai"] = {"skipped":"openai_missing_or_network_disabled"}

    # ---------------------------
    # Pretty output
    # ---------------------------
    line("📧 Email Metadata")
    kcv("From", header.get("From"))
    kcv("Subject", header.get("Subject"))
    kcv("Date", header.get("Date"))
    kcv("Message-ID", header.get("Message-ID"))

    line("🔐 Authentication Checks")
    # SPF
    spf_str = spf_res.get("result","SKIPPED").upper() if "result" in spf_res else ("SKIPPED" if "skipped" in spf_res else ("ERROR" if "error" in spf_res else "UNKNOWN"))
    print(f"SPF: {spf_str}")
    if "explanation" in spf_res and spf_res.get("explanation"):
        print(f"  → {spf_res['explanation']}")
    if header.get("Received-SPF"):
        print(f"  → Received-SPF: {header.get('Received-SPF')}")
    # DKIM
    dk = dkim_res.get("result")
    print(f"\nDKIM: {'PASS' if dk is True else ('FAIL' if dk is False else 'SKIPPED')}")
    if dkim_domains:
        print(f"  → Signature domain(s): {', '.join(dkim_domains)}")
    # DMARC
    dm = dmarc_eval
    dm_pol = dm.get("dmarc_policy",{}).get("policy")
    dm_pass = dm.get("dmarc_pass")
    print(f"\nDMARC: {'PASS' if dm_pass else 'FAIL' if dm_pass is False else 'SKIPPED'}")
    if dm_pol or dm.get("dmarc_policy",{}).get("raw"):
        raw = dm.get("dmarc_policy",{}).get("raw")
        if raw: print(f"  → Policy record: {raw[0] if isinstance(raw,list) and raw else raw}")
        if dm_pol: print(f"  → Parsed policy: p={dm_pol}")
    if dm.get("reasons"): print(f"  → Alignment: {', '.join(dm.get('reasons'))}")

    # Threat Intel
    line("🧪 Threat Intelligence")
    # URLs summary
    if report["urls"]:
        print(f"URLs found: {len(report['urls'])}")
        for i,u in enumerate(report["urls"],1):
            print(f"  {i}. {u['href']}")
            if u.get("final") and u.get("final")!=u["href"]:
                print(f"     → Final: {u['final']}")
            if u.get("whois",{}).get("age_days") is not None:
                print(f"     → Domain age: {u['whois']['age_days']} days")
            if u.get("tls") and not u["tls"].get("error"):
                iss = u["tls"].get("issuer")
                print(f"     → TLS Issuer: {iss}")
            # VT per URL
            vt = u.get("virustotal")
            if vt and vt.get("raw"):
                p,t,engs = vt_parse_detection_stats(vt.get("raw"))
                print(f"     → VirusTotal: {p} / {t} engines flagged")
                if p>0:
                    print(f"        Engines: {', '.join(engs[:8])}{' ...' if len(engs)>8 else ''}")
            elif vt and vt.get("error"):
                print(f"     → VirusTotal error: {vt.get('error')}")
            # GSB
            gsb = u.get("gsb")
            if gsb:
                unsafe,kinds = gsb_is_unsafe(gsb)
                print(f"     → Google Safe Browsing: {'UNSAFE ('+', '.join(kinds)+')' if unsafe else 'SAFE'}")

    # Attachments
    if report["attachments"]:
        print("\nAttachments:")
        for a in report["attachments"]:
            print(f"  • {a['filename']} (size: {a['size']} bytes)")
            if a.get("suspicious_extension"): print("     → ⚠ Suspicious extension")
            mc=a.get("macro_check")
            if mc and mc.get("checked"):
                print(f"     → Macros: {'FOUND' if mc.get('has_macros') else 'none'}")
            vt=a.get("virustotal")
            if vt and vt.get("raw"):
                p,t,engs = vt_parse_detection_stats(vt.get("raw"))
                print(f"     → VT (file): {p} / {t} engines flagged")
                if p>0:
                    print(f"        Engines: {', '.join(engs[:8])}{' ...' if len(engs)>8 else ''}")

    # AI
    line("🤖 OpenAI Heuristic Analysis")
    ai_text=""
    if report["ai"].get("raw"):
        ai_text = report["ai"]["raw"].strip()
        print(ai_text)
    elif report["ai"].get("skipped"):
        print(f"(skipped: {report['ai']['skipped']})")
    elif report["ai"].get("error"):
        print(f"(error: {report['ai']['error']})")

    # Risk Score (0–10) table
    vt_packets = [v for v in vt_url_packets if v.get("raw")] + [v for v in vt_att_packets if v.get("raw")]
    gsb_packets = gsb_packets
    final10, rows = score_table(spf_res, dkim_res, dmarc_eval, [p.get("raw") for p in vt_packets], gsb_packets, ai_text)
    line("📊 Final Risk Score")
    print_table(rows)
    print(f"\nScore: {final10:.1f} / 10")
    print(f"Verdict: {BOLD}{interpret_score10(final10)}{WHT}")

    # Optional: JSON dump / save
    report["final_score_10"] = final10
    report["final_verdict"] = interpret_score10(final10)

    if verbose:
        print("\nFull JSON report:")
        print(json.dumps(report, indent=2, ensure_ascii=False))

    if output:
        try:
            with open(output, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2, ensure_ascii=False)
            print(f"\n{GRN}[✔] Report written to {output}{WHT}")
        except Exception as e:
            print(f"{RED}[x] Failed to save report: {e}{WHT}")

    return report

# ---------------------------
# CLI
# ---------------------------
def cli():
    banner()
    p = argparse.ArgumentParser(prog="GiveMeFish", description="GiveMeFish - Advanced Phishing Email Analysis")
    p.add_argument("-E","--eml", required=True, help="Path to .eml file")
    p.add_argument("-o","--output", help="Write JSON report to file")
    p.add_argument("--no-network", action="store_true", help="Skip network lookups (VT/GSB/WHOIS/redirects/TLS/DNS)")
    p.add_argument("--verbose", action="store_true", help="Print full JSON report")
    p.add_argument("--auto-upload", action="store_true", help="Upload attachment to VT if hash not found (use carefully)")
    args=p.parse_args()

    if not VT_API_KEY: print(f"{YLW}[!] VIRUSTOTAL_API_KEY not set; VT checks skipped.{WHT}")
    if not GSB_API_KEY: print(f"{YLW}[!] GOOGLE_SAFE_BROWSING_KEY not set; GSB checks skipped.{WHT}")
    if not OPENAI_API_KEY: print(f"{YLW}[!] OPENAI_API_KEY not set; AI opinion skipped.{WHT}")

    analyze_email(args.eml, no_network=args.no_network, output=args.output, verbose=args.verbose, auto_upload=args.auto_upload)

if __name__=="__main__":
    cli()
