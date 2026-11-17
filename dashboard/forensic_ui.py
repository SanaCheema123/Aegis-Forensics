"""Visual styling and reusable components for the Streamlit website."""

from modules.event_timestamps import chronological_findings, finding_time

import html
import math
import re
from collections import Counter

import streamlit as st

e = html.escape

SEV_COLORS = {
    "Critical": "#EF4444",
    "High": "#F97316",
    "Medium": "#F59E0B",
    "Low": "#38BDF8",
}
SEV_ORDER = ["Critical", "High", "Medium", "Low"]
TONES = {
    "red": "#EF4444",
    "orange": "#F97316",
    "amber": "#F59E0B",
    "blue": "#3B82F6",
    "teal": "#22C55E",
    "cyan": "#38BDF8",
    "violet": "#8B5CF6",
    "neutral": "#8B97B5",
    "green": "#2DD4BF",
}

ICONS = {
    "alert": '<path d="M12 3l9.5 17h-19z"/><path d="M12 10v4M12 17.5v.01"/>',
    "eye": '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    "check": '<circle cx="12" cy="12" r="9"/><path d="M8 12.5l3 3 5-6"/>',
    "shield": '<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z"/>',
    "bolt": '<path d="M13 2L4 14h7l-1 8 9-12h-7z"/>',
    "file": '<path d="M6 2h8l5 5v15H6z"/><path d="M14 2v5h5"/>',
    "grid": '<rect x="3" y="3" width="8" height="8" rx="1.5"/><rect x="13" y="3" width="8" height="5" rx="1.5"/>'
    '<rect x="13" y="11" width="8" height="10" rx="1.5"/><rect x="3" y="14" width="8" height="7" rx="1.5"/>',
    "lock": '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 018 0v3"/>',
    "bug": '<path d="M9 9a3 3 0 016 0v6a3 3 0 01-6 0z"/><path d="M4 12h5M15 12h5M5 6l3 2M19 6l-3 2M5 18l3-2M19 18l-3-2"/>',
    "cpu": '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
    "target": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><circle cx="12" cy="12" r=".8"/>',
}
NAV = [
    "Dashboard",
    "Security Scanner",
    "Live Protection",
    "Investigations",
    "Reports & History",
]
MOBILE_NAV = [*NAV, "Settings"]
SECTION_PAGES = {
    "Dashboard": ("Home",),
    "Security Scanner": (
        "File Scan",
        "Image Scan",
        "Folder Scan",
        "Laptop Scan",
        "URL Scan",
        "Network CSV",
        "YARA Rules",
    ),
    "Live Protection": (
        "Real-Time Protection",
        "Live Security Alerts",
        "Windows Review",
    ),
    "Investigations": ("Investigation", "Evidence"),
    "Reports & History": ("AI Forensic Reports", "Security Scan History"),
    "Settings": ("About",),
}
SECTION_PAGE_TARGETS = {
    "File Scan": "Malware Scanner",
    "Image Scan": "Malware Scanner",
    "Folder Scan": "Scan My Laptop",
    "Laptop Scan": "Scan My Laptop",
    "URL Scan": "URL Security Checker",
    "Network CSV": "Investigation",
}
NAVIGATION_DESTINATIONS = {
    "Dashboard": ("Dashboard", "Home"),
    "Home": ("Dashboard", "Home"),
    "Security Scanner": ("Security Scanner", "File Scan"),
    "File Scan": ("Security Scanner", "File Scan"),
    "Image Scan": ("Security Scanner", "Image Scan"),
    "Folder Scan": ("Security Scanner", "Folder Scan"),
    "Laptop Scan": ("Security Scanner", "Laptop Scan"),
    "Scan My Laptop": ("Security Scanner", "Laptop Scan"),
    "Malware Scanner": ("Security Scanner", "File Scan"),
    "URL Scan": ("Security Scanner", "URL Scan"),
    "URL Security Checker": ("Security Scanner", "URL Scan"),
    "Network CSV": ("Security Scanner", "Network CSV"),
    "YARA Rules": ("Security Scanner", "YARA Rules"),
    "Live Protection": ("Live Protection", "Real-Time Protection"),
    "Real-Time Protection": ("Live Protection", "Real-Time Protection"),
    "Live Security Alerts": ("Live Protection", "Live Security Alerts"),
    "Windows Review": ("Live Protection", "Windows Review"),
    "Investigations": ("Investigations", "Investigation"),
    "Investigation": ("Investigations", "Investigation"),
    "Evidence": ("Investigations", "Evidence"),
    "Reports & History": ("Reports & History", "AI Forensic Reports"),
    "AI Forensic Reports": ("Reports & History", "AI Forensic Reports"),
    "Security Scan History": ("Reports & History", "Security Scan History"),
    "Settings": ("Settings", "About"),
    "About": ("Settings", "About"),
    "Rules": ("Security Scanner", "YARA Rules"),
    "Workspace": ("Investigations", "Investigation"),
    "Safety Scan": ("Security Scanner", "File Scan"),
}

TECHNIQUES = {
    "T1078": "Valid Accounts",
    "T1110": "Brute Force",
    "T1136.001": "Create Local Account",
    "T1098": "Account Manipulation",
    "T1070.001": "Clear Windows Event Logs",
    "T1059.001": "PowerShell",
    "T1059": "Command and Scripting",
    "T1027": "Obfuscated Files",
    "T1505.003": "Web Shell",
    "T1190": "Exploit Public-Facing App",
    "T1595": "Active Scanning",
    "T1003": "OS Credential Dumping",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1218": "System Binary Proxy",
}
TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
HOST_COLS = (
    "host",
    "hostname",
    "computer",
    "dest_host",
    "destination",
    "dest_ip",
    "dst_ip",
)


def svg(name, color="currentColor", size=20):
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.8" '
        f'stroke-linecap="round" stroke-linejoin="round">{ICONS[name]}</svg>'
    )


def _rgba(hex_color, alpha):
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


CSS = """
:root { --bg:#F5F6FA; --panel:#FFFFFF; --panel2:#F7F8FC; --line:#E8E9F0; --text:#242235; --muted:#77778B;
        --cyan:#A020F0; --teal:#16A879; --indigo:#7C3AED; --violet:#A020F0; }
html, body, [class*="css"], .stMarkdown, button, input, textarea, select { font-family:'Inter', sans-serif; }
.stApp { background:var(--bg); }
.block-container { padding:1.2rem clamp(1rem,2.3vw,2.25rem) 3rem; max-width:1600px; }
.block-container > div { gap:1.15rem; }
.stTabs [data-baseweb="tab-list"] { gap:.35rem; padding-bottom:.25rem; }
.stDeployButton, [data-testid="stToolbar"], [data-testid="stDecoration"], footer { display:none !important; }
header[data-testid="stHeader"] { background:transparent; }
h2, h3 { font-weight:700 !important; }
[data-testid="stSidebar"] { width:250px !important; min-width:250px !important; max-width:250px !important;
    background:#FFFFFF; border-right:1px solid #ECECF2; }
[data-testid="stSidebar"] [data-testid="stSidebarContent"] { padding:1.25rem 1rem; }

/* Site header and primary navigation */
.site-head { display:flex; align-items:center; justify-content:space-between; gap:18px; padding:8px 0 18px;
             border-bottom:1px solid var(--line); margin-bottom:12px; }
.site-brand { display:flex; align-items:center; gap:11px; color:var(--text); text-decoration:none; }
.site-mark { display:flex; align-items:center; justify-content:center; width:42px; height:42px; border-radius:13px;
             background:linear-gradient(145deg,rgba(55,215,232,.17),rgba(99,102,241,.22)); border:1px solid rgba(55,215,232,.25); }
.site-name { font-size:1.05rem; font-weight:800; letter-spacing:-.03em; line-height:1.1; }
.site-kicker { color:var(--muted); font-size:.68rem; font-weight:700; letter-spacing:.13em; text-transform:uppercase; margin-top:4px; }
.site-note { color:#AAB8D0; font-size:.83rem; }
.stRadio div[role="radiogroup"] { display:flex; flex-wrap:wrap; gap:4px; border-bottom:1px solid var(--line); padding:0 0 10px; }
.stRadio div[role="radiogroup"] label { border:1px solid transparent; border-radius:9px; padding:5px 9px; margin:0;
                                        transition:all .18s ease; }
.stRadio div[role="radiogroup"] label[data-testid="stRadioOption"] { width:auto; min-width:max-content; flex:0 0 auto; }
.stRadio div[role="radiogroup"] label[data-testid="stRadioOption"] > div { width:max-content; min-width:max-content; }
.stRadio div[role="radiogroup"] label[data-testid="stRadioOption"] > div > div:first-child { display:none; }
.stRadio div[role="radiogroup"] label p { color:#9AA8C2; font-weight:600; font-size:.84rem; }
.stRadio div[role="radiogroup"] label p { width:max-content; min-width:max-content; white-space:nowrap; }
.stRadio div[role="radiogroup"] label:hover { background:rgba(255,255,255,.04); }
.stRadio div[role="radiogroup"] label:has(input:checked) { background:rgba(55,215,232,.1); border-color:rgba(55,215,232,.25); }
.stRadio div[role="radiogroup"] label:has(input:checked) p { color:#76E6EC; }
.stRadio > label { display:none; }

/* Home page */
.hero { position:relative; overflow:hidden; border:1px solid rgba(93,125,177,.25); border-radius:24px; padding:clamp(28px,6vw,70px);
        margin:18px 0 30px; background:radial-gradient(ellipse at 85% 18%,rgba(45,212,191,.2),transparent 37%),
        radial-gradient(ellipse at 8% 100%,rgba(99,102,241,.15),transparent 42%),linear-gradient(135deg,#F1F8FC,#E4EDF8 70%); }
.hero:after { content:""; position:absolute; width:280px; height:280px; right:-90px; bottom:-150px; border:1px solid rgba(55,215,232,.16);
              border-radius:50%; box-shadow:0 0 0 35px rgba(55,215,232,.025),0 0 0 70px rgba(55,215,232,.02); }
.hero-copy { position:relative; z-index:1; max-width:760px; }
.eyebrow { color:#76E6EC; font-size:.74rem; font-weight:800; letter-spacing:.15em; text-transform:uppercase; margin-bottom:16px; }
.hero h1 { color:#172033; font-size:clamp(2.5rem,6vw,4.6rem); line-height:1.03; letter-spacing:-.055em; font-weight:800; margin:0 0 18px; }
.hero h1 span { color:#087F8C; }
.hero p { color:#475569; font-size:1.04rem; line-height:1.75; max-width:620px; margin:0; }
.hero-points { display:flex; flex-wrap:wrap; gap:10px 22px; margin-top:26px; color:#334155; font-size:.83rem; font-weight:600; }
.hero-point { display:flex; gap:8px; align-items:center; }
.hero-point b { color:#0F8A77; font-size:1rem; }
.section-intro { margin:34px 0 16px; }
.section-intro h2 { color:#302E42; font-size:1.5rem; letter-spacing:-.035em; margin:0 0 5px; }
.section-intro p { color:var(--muted); margin:0; font-size:.92rem; }
.feature-card { min-height:180px; padding:22px; border:1px solid var(--line); border-radius:15px;
                background:linear-gradient(155deg,#FFFFFF,#F1F5FA); }
.feature-icon { display:flex; align-items:center; justify-content:center; width:42px; height:42px; border-radius:12px;
                margin-bottom:17px; background:rgba(55,215,232,.1); border:1px solid rgba(55,215,232,.17); }
.feature-card h3 { color:#172033; font-size:1rem; margin:0 0 8px; }
.feature-card p { color:#64748B; font-size:.86rem; line-height:1.6; margin:0; }
.home-cta { display:flex; align-items:center; justify-content:space-between; gap:20px; flex-wrap:wrap; margin:28px 0 16px;
            padding:22px 24px; border:1px solid rgba(55,215,232,.18); border-radius:15px; background:#E8F6F6; }
.home-cta h3 { color:#172033; margin:0 0 4px; font-size:1rem; }
.home-cta p { color:var(--muted); margin:0; font-size:.84rem; }
.site-footer { color:#687895; font-size:.77rem; border-top:1px solid var(--line); padding-top:18px; margin-top:34px; }
.about-panel { background:linear-gradient(155deg,#FFFFFF,#F1F5FA); border:1px solid var(--line); border-radius:15px; padding:22px; }
.about-panel h3 { color:#172033; margin:0 0 8px; font-size:1rem; }
.about-panel p { color:#64748B; font-size:.87rem; line-height:1.65; margin:0; }
@media (max-width:700px) {
  .site-note { display:none; }
  .stRadio div[role="radiogroup"] { overflow-x:visible; flex-wrap:wrap; }
  .stRadio div[role="radiogroup"] label { flex:none; }
}

/* Page header */
.page-head { display:flex; justify-content:space-between; align-items:flex-start; gap:20px; flex-wrap:wrap; margin-bottom:18px; }
.page-head h1 { font-size:1.7rem; font-weight:800; margin:0; padding:0; color:var(--text); line-height:1.2; }
.page-head .sub { color:var(--muted); font-size:0.92rem; margin-top:4px; }
.pills { display:flex; gap:8px; flex-wrap:wrap; }
.pill-i { background:var(--panel); border:1px solid var(--line); border-radius:20px; padding:6px 14px; font-size:0.82rem; color:#B7C4D8; }
.pill-i b { color:var(--text); }
.pill-i.ex { border-color:rgba(55,215,232,.5); color:var(--cyan); font-family:'JetBrains Mono',monospace; }

/* KPI, mini stats, card text */
.kpi { background:linear-gradient(160deg,#FFFFFF,#F1F5FA); border:1px solid var(--line); border-radius:14px; padding:18px 20px; }
.k-icon, .m-icon { display:flex; align-items:center; justify-content:center; border-radius:10px; }
.k-icon { width:40px; height:40px; margin-bottom:14px; }
.k-val { font-size:2rem; font-weight:800; color:#172033; line-height:1.1; }
.k-label { color:#64748B; font-size:0.85rem; font-weight:500; margin-top:4px; }
.mini { display:flex; align-items:center; gap:14px; background:linear-gradient(160deg,#FFFFFF,#F1F5FA); border:1px solid var(--line);
        border-radius:14px; padding:13px 16px; margin-bottom:10px; }
.m-icon { width:36px; height:36px; flex:none; }
.m-val { font-size:1.35rem; font-weight:800; color:#172033; line-height:1.1; }
.m-label { color:#64748B; font-size:0.8rem; }
.c-title { font-weight:700; color:#302E42; font-size:1rem; }
.c-sub { color:#64748B; font-size:0.8rem; margin:2px 0 10px 0; }
.empty { color:#64748B; font-size:0.88rem; padding:14px 2px; }
.g-label { text-align:center; font-weight:700; font-size:1rem; margin-top:-6px; }

/* Bars */
.bar-row { display:grid; grid-template-columns:minmax(120px,1.3fr) 2fr 26px; gap:10px; align-items:center; margin:9px 0; font-size:0.82rem; }
.b-name { color:#B7C4D8; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.b-track { background:rgba(255,255,255,.06); border-radius:6px; height:8px; overflow:hidden; }
.b-fill { height:100%; border-radius:6px; background:linear-gradient(90deg,var(--indigo),var(--cyan)); }
.b-n { color:var(--muted); text-align:right; }
.rb-bar { display:flex; height:10px; border-radius:6px; overflow:hidden; margin:6px 0 14px 0; background:rgba(255,255,255,.06); }
.rb-row { display:flex; align-items:center; gap:10px; margin:8px 0; font-size:0.85rem; color:#B7C4D8; }
.rb-dot { width:9px; height:9px; border-radius:50%; flex:none; }
.rb-row .n { margin-left:auto; color:var(--muted); }

/* Timeline and action list */
.tl { position:relative; margin-left:6px; }
.tl-item { position:relative; padding:0 0 16px 24px; border-left:2px solid var(--line); margin-left:5px; }
.tl-item:last-child { border-left-color:transparent; }
.tl-dot { position:absolute; left:-7px; top:2px; width:12px; height:12px; border-radius:50%; box-shadow:0 0 0 4px rgba(255,255,255,.04); }
.tl-t { color:var(--text); font-weight:600; font-size:0.9rem; }
.tl-m { color:var(--muted); font-size:0.76rem; font-family:'JetBrains Mono',monospace; margin-top:2px; }
.act-row { display:flex; align-items:center; gap:14px; background:#F3F6FB; border:1px solid var(--line);
           border-radius:10px; padding:12px 16px; margin:8px 0; }
.act-main { flex:1; min-width:0; }
.act-t { color:#172033; font-weight:600; font-size:0.92rem; }
.act-s { color:#64748B; font-size:0.78rem; margin-top:2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.act-r { color:#64748B; font-size:0.78rem; font-family:'JetBrains Mono',monospace; white-space:nowrap; }
.sev { display:inline-block; padding:2px 10px; border-radius:5px; font-size:0.74rem; font-weight:700; color:#fff; letter-spacing:.02em; }

/* Chain-of-custody chips and landing steps */
.strip { display:flex; gap:10px; flex-wrap:wrap; margin:0 0 18px 0; }
.chip { display:inline-flex; align-items:center; gap:8px; padding:7px 14px; border-radius:10px; font-size:0.84rem; font-weight:600;
        background:var(--panel); border:1px solid var(--line); color:var(--text); }
.chip .dot { width:9px; height:9px; border-radius:50%; background:var(--muted); }
.chip.ok .dot { background:var(--teal); box-shadow:0 0 0 3px rgba(45,212,191,.18); }
.chip.bad .dot { background:#EF4444; box-shadow:0 0 0 3px rgba(239,68,68,.18); }
.chip .v { color:var(--muted); font-weight:500; }
.steps { display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:14px; margin:6px 0 18px 0; }
.step { background:linear-gradient(160deg,#FFFFFF,#F1F5FA); border:1px solid var(--line); border-radius:14px; padding:18px 20px; }
.step .n { width:28px; height:28px; border-radius:50%; background:rgba(55,215,232,.12); color:var(--cyan); border:1px solid rgba(55,215,232,.45);
           display:flex; align-items:center; justify-content:center; font-weight:800; font-size:0.85rem; margin-bottom:12px; }
.step .h { font-weight:700; color:#172033; margin-bottom:6px; }
.step .d { color:#64748B; font-size:0.88rem; line-height:1.5; }
.hashline { background:#E6F6F5; border:1px solid rgba(55,215,232,.35); border-radius:10px; padding:9px 13px;
            font-family:'JetBrains Mono',monospace; font-size:0.8rem; word-break:break-all; color:#075E68; }

/* Evidence portal */
.v-head { display:grid; grid-template-columns:0.7fr 3.2fr 2.8fr 1.3fr 1.8fr; gap:12px; padding:12px 16px; margin-top:6px;
          background:#E9EDFF; border:1px solid var(--line); border-radius:12px 12px 0 0;
          color:#4338CA; font-size:0.74rem; font-weight:700; letter-spacing:.06em; text-transform:uppercase; }
.v-id { background:#E7EDF5; border-radius:6px; padding:4px 10px; font-family:'JetBrains Mono',monospace; font-size:0.85rem; color:#334155; }
.v-file { display:flex; align-items:center; gap:12px; }
.v-ficon { width:38px; height:38px; border-radius:9px; background:rgba(55,215,232,.1); border:1px solid rgba(55,215,232,.3);
           display:flex; align-items:center; justify-content:center; flex:none; }
.v-name { color:#172033; font-weight:700; font-size:0.92rem; word-break:break-all; }
.v-date { color:#64748B; font-size:0.76rem; font-family:'JetBrains Mono',monospace; margin-top:2px; }
.v-chip { display:inline-block; padding:2px 9px; border-radius:6px; background:#E9EDFF; color:#4338CA; font-size:0.74rem; margin-right:8px; }
.v-mono { color:#64748B; font-size:0.76rem; font-family:'JetBrains Mono',monospace; }
.v-status { display:inline-block; padding:3px 11px; border-radius:20px; font-size:0.76rem; font-weight:700; }
.v-sep { border-top:1px solid var(--line); margin:6px 0; }

/* Widgets */
[data-testid="stVerticalBlockBorderWrapper"] { border-color:var(--line) !important; border-radius:14px !important; }
[data-testid="stMetric"] { background:linear-gradient(160deg,#FFFFFF,#F1F5FA); border:1px solid var(--line); border-radius:12px; padding:12px 16px; }
[data-testid="stMetricLabel"] p { color:#64748B; font-size:0.84rem; font-weight:600; }
[data-testid="stMetricValue"] { color:#172033; font-weight:800; }
[data-testid="stFileUploaderDropzone"] { background:#F3F6FB; border:1.5px dashed #A7B6C9; border-radius:14px; padding:24px; }
[data-testid="stFileUploaderDropzone"]:hover { border-color:var(--cyan); }
div[data-baseweb="input"], div[data-baseweb="select"] > div { background:#F3F6FB !important; border-radius:10px !important; }
.stButton > button, .stDownloadButton > button { background:transparent; border:1px solid rgba(55,215,232,.45); color:var(--cyan);
        border-radius:10px; font-weight:600; }
.stButton > button:hover, .stDownloadButton > button:hover { border-color:var(--cyan); background:rgba(55,215,232,.08); color:#fff; }
.stButton > button[kind="primary"], button[data-testid="stBaseButton-primary"] { background:linear-gradient(135deg,#6366F1,#8B5CF6) !important;
        border:0 !important; color:#fff !important; }
button[data-baseweb="tab"] { color:#D6DEEB; font-weight:600; padding:10px 16px; }
button[data-baseweb="tab"][aria-selected="true"] { color:#76E6EC; }
[data-baseweb="tab-highlight"] { background:var(--cyan) !important; }
[data-testid="stExpander"] { border:1px solid var(--line); border-radius:12px; background:#F3F6FB; color:#172033; }
[data-testid="stDataFrame"] { border:1px solid var(--line); border-radius:12px; overflow:hidden; background:#F3F6FB; }
[data-testid="stAlert"] { border-radius:12px; }

/* Dashboard layout inspired by the supplied reference */
.sidebar-brand { display:flex; align-items:center; gap:10px; padding:4px 5px 22px; border-bottom:1px solid #EEEFF4; margin-bottom:19px; }
.sidebar-logo { display:flex; align-items:center; justify-content:center; width:38px; height:38px; border-radius:12px;
                background:linear-gradient(145deg,#F8E8FF,#E9D5FF); color:#9D24E8; }
.sidebar-brand-name { color:#252238; font-size:1.02rem; font-weight:800; letter-spacing:-.04em; }
.sidebar-brand-kicker { color:#A020F0; font-size:.58rem; font-weight:800; letter-spacing:.1em; text-transform:uppercase; }
.sidebar-section { color:#9A99A9; font-size:.66rem; font-weight:800; letter-spacing:.11em; margin:14px 0 8px 8px; }
[data-testid="stSidebar"] div[role="radiogroup"] { display:flex; flex-direction:column; gap:4px; }
[data-testid="stSidebar"] div[role="radiogroup"] label { width:100%; border:0; border-radius:9px; padding:8px 10px; margin:0; }
[data-testid="stSidebar"] div[role="radiogroup"] label p { color:#656579; font-size:.84rem; font-weight:600; }
[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) { background:linear-gradient(100deg,#A020F0,#8438EB); }
[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) p { color:#FFFFFF; }
[data-testid="stSidebar"] div[role="radiogroup"] label:hover { background:#F4EAFE; }
[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked):hover { background:linear-gradient(100deg,#A020F0,#8438EB); }
[data-testid="stSidebar"] .stRadio > label { display:none; }
.sidebar-status { margin-top:26px; padding:12px; border:1px solid #E9E6F2; border-radius:12px; background:#FBFAFD; }
.sidebar-status-title { color:#343247; font-size:.76rem; font-weight:700; }
.sidebar-status-sub { color:#88879A; font-size:.68rem; margin-top:3px; }
.status-dot { display:inline-block; width:7px; height:7px; border-radius:50%; background:#19B67A; margin-right:6px; }
.dashboard-topbar { display:flex; align-items:center; justify-content:space-between; gap:16px; margin-bottom:20px; }
.dashboard-crumb { color:#8A899A; font-size:.76rem; }
.dashboard-title { color:#262439; font-size:1.55rem; font-weight:800; letter-spacing:-.04em; margin:0; }
.dashboard-subtitle { color:#858497; font-size:.84rem; margin-top:3px; }
.dashboard-hero { position:relative; display:flex; align-items:center; justify-content:space-between; gap:24px; min-height:178px;
    overflow:hidden; padding:27px 34px; border-radius:16px; margin:0 0 20px;
    background:linear-gradient(112deg,#B41BEA 0%,#9719E8 48%,#7427E7 100%); box-shadow:0 12px 28px rgba(142,35,221,.16); }
.dashboard-hero:after { content:""; position:absolute; right:28%; top:-115px; width:280px; height:280px; border-radius:50%;
    border:1px solid rgba(255,255,255,.16); box-shadow:0 0 0 28px rgba(255,255,255,.035),0 0 0 58px rgba(255,255,255,.025); }
.dashboard-hero-copy { position:relative; z-index:1; max-width:620px; }
.dashboard-hero h2 { color:#FFFFFF; font-size:1.8rem; line-height:1.15; letter-spacing:-.04em; margin:0 0 7px; }
.dashboard-hero p { color:rgba(255,255,255,.82); font-size:.86rem; margin:0; }
.dashboard-hero-art { position:relative; z-index:1; display:flex; align-items:center; justify-content:center;
    width:116px; height:116px; margin-right:10px; border:1px solid rgba(255,255,255,.28); border-radius:22px;
    background:linear-gradient(145deg,rgba(255,255,255,.24),rgba(255,255,255,.08)); color:white; }
.dashboard-hero-art:after { content:""; position:absolute; inset:8px; border:1px solid rgba(255,255,255,.2); border-radius:16px; }
.dashboard-hero-art svg { filter:drop-shadow(0 5px 12px rgba(45,8,75,.22)); }
.st-key-dashboard_hero { position:relative; overflow:hidden; padding:25px 30px 20px; margin:0 0 20px;
    border-radius:16px; background:linear-gradient(112deg,#B41BEA 0%,#9719E8 48%,#7427E7 100%);
    box-shadow:0 12px 28px rgba(142,35,221,.16); }
.st-key-dashboard_hero:after { content:""; position:absolute; right:28%; top:-115px; width:280px; height:280px;
    border-radius:50%; border:1px solid rgba(255,255,255,.16); pointer-events:none;
    box-shadow:0 0 0 28px rgba(255,255,255,.035),0 0 0 58px rgba(255,255,255,.025); }
.dashboard-hero-title { color:#FFFFFF; font-size:1.8rem; font-weight:800; line-height:1.15; letter-spacing:-.04em; margin:0 0 7px; }
.dashboard-hero-description { color:rgba(255,255,255,.82); font-size:.86rem; margin:0 0 12px; }
.st-key-dashboard_hero [data-testid="stButton"] button { min-height:34px; background:rgba(255,255,255,.13);
    border:1px solid rgba(255,255,255,.3); color:#FFFFFF; }
.st-key-dashboard_hero [data-testid="stButton"] button[kind="primary"],
.st-key-dashboard_hero button[data-testid="stBaseButton-primary"] { background:#FFFFFF !important; color:#8617C8 !important; }
.dashboard-stat { min-height:98px; padding:15px 16px; border:1px solid #ECECF2; border-radius:13px; background:#FFFFFF;
    box-shadow:0 3px 12px rgba(35,29,61,.035); }
.dashboard-stat-head { display:flex; align-items:center; justify-content:space-between; gap:8px; }
.dashboard-stat-label { color:#77768A; font-size:.74rem; font-weight:600; }
.dashboard-stat-icon { width:32px; height:32px; display:flex; align-items:center; justify-content:center; border-radius:10px; }
.dashboard-stat-value { color:#27253A; font-size:1.42rem; font-weight:800; line-height:1.2; margin-top:9px; }
.dashboard-stat-note { color:#8A899A; font-size:.67rem; margin-top:2px; }
.dashboard-panel { height:100%; min-height:245px; padding:18px; border:1px solid #ECECF2; border-radius:14px; background:#FFFFFF;
    box-shadow:0 3px 12px rgba(35,29,61,.035); }
.dashboard-panel-title { color:#302E42; font-size:.94rem; font-weight:750; }
.dashboard-panel-subtitle { color:#9291A2; font-size:.7rem; margin-top:3px; margin-bottom:14px; }
.recent-evidence { display:flex; align-items:center; gap:10px; padding:10px 0; border-top:1px solid #F0F0F4; }
.recent-file-icon { width:34px; height:34px; display:flex; align-items:center; justify-content:center; flex:none;
    color:#8B35E5; background:#F4EAFF; border-radius:9px; }
.recent-file-name { color:#3A394D; font-size:.75rem; font-weight:650; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.recent-file-meta { color:#9695A5; font-size:.65rem; margin-top:2px; }
.recent-empty { padding:20px 0; color:#89889A; font-size:.78rem; line-height:1.5; }
.section-heading { display:flex; align-items:center; justify-content:space-between; gap:12px; margin:21px 0 12px; }
.section-heading-title { color:#302E42; font-size:1rem; font-weight:750; }
.section-heading-subtitle { color:#9291A2; font-size:.72rem; margin-top:3px; }
div[data-testid="stButton"] button { border-radius:9px; font-weight:650; }
[data-testid="stSidebar"] div[data-testid="stButton"] button { font-size:.76rem; }
.stApp .dashboard-title { font-size:1.55rem !important; }
/* Product-wide finish: readable contrast, quieter surfaces, and consistent actions. */
.stApp { color:#29283A; background:#F6F7FB; }
.block-container { max-width:1480px; padding-top:1.65rem; padding-bottom:3.5rem; }
.page-head { padding:0 0 16px; border-bottom:1px solid #E8EAF1; margin-bottom:22px; }
.page-head h1 { color:#242338; font-size:1.9rem; letter-spacing:-.045em; }
.page-head .sub { color:#6E7082; font-size:.95rem; line-height:1.55; }
h2, h3 { color:#29283A; letter-spacing:-.025em; }
p, [data-testid="stMarkdownContainer"] { color:#424357; }
[data-testid="stSidebar"] { box-shadow:3px 0 18px rgba(32,28,54,.035); }
[data-testid="stSidebar"] div[role="radiogroup"] label { transition:background .16s ease, color .16s ease; }
[data-testid="stSidebar"] div[role="radiogroup"] label p { color:#59596D; }
[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) { box-shadow:0 4px 10px rgba(132,56,235,.2); }
[data-testid="stSidebar"] div[role="radiogroup"] label:focus-within { outline:2px solid #8B5CF6; outline-offset:2px; }
[data-testid="stMetric"] { min-height:92px; background:#FFFFFF; box-shadow:0 3px 12px rgba(33,31,52,.035); }
[data-testid="stMetricLabel"] p { color:#636478; }
[data-testid="stMetricValue"] { color:#25243A; }
[data-testid="stVerticalBlockBorderWrapper"] { background:#FFFFFF; box-shadow:0 3px 14px rgba(33,31,52,.025); }
[data-testid="stAlert"] { border:1px solid #E2E5EE; box-shadow:0 2px 8px rgba(33,31,52,.025); }
[data-testid="stAlert"] p { color:#36364A; }
[data-testid="stFileUploaderDropzone"] { background:#FAFAFD; border-color:#B8B9C9; }
div[data-baseweb="input"] { border:1px solid #E0E2EA; }
div[data-baseweb="input"]:focus-within { border-color:#8B5CF6; box-shadow:0 0 0 2px rgba(139,92,246,.13); }
.stButton > button, .stDownloadButton > button { min-height:40px; border-color:#D9D7E5; background:#FFFFFF; color:#5B36A6; transition:all .16s ease; }
.stButton > button:hover, .stDownloadButton > button:hover { border-color:#8B5CF6; background:#F6F0FF; color:#55249C; }
.stButton > button:focus-visible, .stDownloadButton > button:focus-visible { outline:3px solid rgba(139,92,246,.35); outline-offset:2px; }
.stButton > button[kind="primary"], button[data-testid="stBaseButton-primary"] { background:linear-gradient(135deg,#8C35D6,#7136C8) !important;
    box-shadow:0 4px 10px rgba(113,54,200,.18); }
.stButton > button[kind="primary"]:hover, button[data-testid="stBaseButton-primary"]:hover { background:linear-gradient(135deg,#7B29C4,#632BB8) !important; }
[data-testid="stExpander"] { background:#FFFFFF; border-color:#E4E5ED; }
[data-testid="stDataFrame"] { background:#FFFFFF; border-color:#E2E4EC; }
.c-title, .act-t, .tl-t { color:#29283A; }
.c-sub, .empty, .tl-m, .act-s, .act-r { color:#66687C; }
.b-name, .rb-row { color:#56586C; }
.b-track, .rb-bar { background:#E8E9F0; }
.dashboard-subtitle, .dashboard-crumb { color:#68697C; }
.section-heading-subtitle, .recent-empty, .recent-file-meta { color:#6D6E80; }
.dashboard-stat-note, .sidebar-status-sub { color:#68697C; }
.sidebar-status-title { color:#37364A; }
.site-note, .pill-i { color:#626478; }
.pill-i.ex { color:#6234AC; border-color:#D5C8EA; }
.hashline { color:#155E52; background:#EAF7F3; border-color:#B9E4D7; }
button[data-baseweb="tab"] { color:#5D5E71; }
button[data-baseweb="tab"][aria-selected="true"] { color:#6E32B5; }
[data-baseweb="tab-highlight"] { background:#8438EB !important; }
@media (max-width:700px) {
  .block-container { padding:1rem 1rem 2.5rem; }
  .page-head h1 { font-size:1.55rem; }
  [data-testid="stSidebar"] { min-width:0 !important; }
}
@media (max-width:850px) {
  .dashboard-hero { padding:23px; }
  .dashboard-hero-art { width:88px; height:88px; margin-right:0; }
}
@media (max-width:600px) {
  .dashboard-hero-art { display:none; }
  .dashboard-hero { min-height:150px; }
}
"""

CSS += """
.threat-summary { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:12px; margin:.8rem 0 1rem; }
.threat-summary-item { padding:13px 15px; border:1px solid var(--line); border-radius:12px; background:var(--panel); }
.threat-summary-label { color:var(--muted); font-size:.78rem; font-weight:600; }
.threat-summary-value { color:var(--text); font-size:1.35rem; font-weight:700; margin-top:3px; }
.threat-card { display:flex; gap:13px; padding:15px; margin:9px 0; border:1px solid var(--line); border-left:4px solid #8B97B5;
  border-radius:12px; background:var(--panel); box-shadow:0 2px 8px rgba(30,35,60,.035); }
.threat-card-icon { flex:0 0 23px; padding-top:2px; }
.threat-critical { border-left-color:#EF4444; }
.threat-high { border-left-color:#F97316; }
.threat-medium { border-left-color:#F5B73A; }
.threat-low { border-left-color:#4C9BE8; }
.threat-card-content { min-width:0; flex:1; }
.threat-card-heading { display:flex; gap:9px; align-items:center; flex-wrap:wrap; color:var(--text); }
.threat-severity { border:1px solid; border-radius:999px; padding:2px 8px; font-size:.7rem; font-weight:700; }
.threat-certainty { color:var(--muted); font-size:.72rem; }
.threat-affected { color:var(--muted); font-size:.78rem; margin-top:5px; overflow-wrap:anywhere; }
.threat-explanation { color:var(--text); font-size:.88rem; line-height:1.5; margin:.55rem 0; overflow-wrap:anywhere; }
.threat-recommendation { padding:8px 10px; border-radius:8px; background:var(--panel2); color:var(--text); font-size:.82rem; line-height:1.45; }
@media(max-width:650px) {
  .threat-summary { grid-template-columns:1fr; gap:8px; }
  .threat-card { padding:12px; }
}
"""

DARK_THEME_CSS = """
:root {
  color-scheme:dark;
  --bg:#080D19; --panel:#101827; --panel2:#151F31; --line:#27344A;
  --text:#F1F5F9; --muted:#94A3B8; --cyan:#3B82F6; --teal:#22C55E;
  --indigo:#3B82F6; --violet:#8B5CF6;
}
html, body, [class*="css"], button, input, textarea, select {
  font-family:system-ui,-apple-system,"Segoe UI",sans-serif;
}
.stApp, [data-testid="stAppViewContainer"], body { background:#080D19; color:#F1F5F9; }
.block-container { max-width:1480px; padding:1.15rem clamp(1rem,3vw,2.5rem) 3rem; }
.stApp p, .stApp label, .stApp li, .stApp [data-testid="stMarkdownContainer"] { color:#D9E2EF; }
.stApp h1, .stApp h2, .stApp h3, .stApp h4 {
  color:#F1F5F9 !important; font-family:system-ui,-apple-system,"Segoe UI",sans-serif;
  font-weight:650 !important; letter-spacing:-.02em; line-height:1.25;
  opacity:1 !important; text-shadow:none !important;
}
.stApp h1 { font-size:1.72rem !important; }
.stApp h2 { font-size:1.24rem !important; }
.stApp h3 { font-size:1.05rem !important; }
a { color:#A78BFA; }
header[data-testid="stHeader"] { display:none !important; height:0 !important; }
aside[data-testid="stSidebar"], [data-testid="stSidebar"], button[data-testid="collapsedControl"] {
  display:none !important; width:0 !important; min-width:0 !important;
}
.st-key-aegis_top_nav {
  position:sticky; top:0; z-index:999; margin:-1.15rem calc(-1 * clamp(1rem,3vw,2.5rem)) 1.15rem;
  padding:.65rem clamp(1rem,3vw,2.5rem); background:#101827;
  border-bottom:1px solid #27344A; box-shadow:0 3px 12px rgba(0,0,0,.16);
}
.st-key-aegis_top_nav [data-testid="stHorizontalBlock"] { align-items:center; gap:1rem; }
.st-key-aegis_top_nav [data-testid="column"] { min-width:0; }
.top-brand { display:flex; align-items:center; gap:.68rem; min-height:48px; }
.top-brand-mark { display:flex; align-items:center; justify-content:center; width:38px; height:38px;
  border:1px solid #34445D; border-radius:10px; background:#151F31; color:#A78BFA; }
.top-brand-name { color:#F1F5F9; font-size:.9rem; font-weight:750; line-height:1.15; white-space:nowrap; }
.top-brand-caption { color:#94A3B8; font-size:.63rem; margin-top:3px; white-space:nowrap; }
.st-key-aegis_desktop_nav, .st-key-aegis_mobile_nav { padding:0; }
.st-key-aegis_top_nav .stRadio > label, .st-key-aegis_top_nav .stSelectbox > label { display:none; }
.st-key-aegis_desktop_nav [data-testid="stHorizontalBlock"] { align-items:center; gap:.15rem; }
.st-key-aegis_desktop_nav .stButton > button {
  min-height:42px; padding:.4rem .35rem; border:0 !important;
  border-bottom:2px solid transparent !important; border-radius:0;
  background:transparent !important; color:#94A3B8 !important;
  font-size:.78rem; font-weight:600; white-space:nowrap; box-shadow:none !important;
}
.st-key-aegis_desktop_nav .stButton > button:hover {
  background:#151F31 !important; color:#F1F5F9 !important;
}
.st-key-aegis_desktop_nav button[data-testid="stBaseButton-primary"] {
  border-bottom-color:#8B5CF6 !important; background:transparent !important;
  color:#F1F5F9 !important;
}
.st-key-aegis_desktop_nav button[data-testid="stBaseButton-primary"]:hover {
  background:#151F31 !important; color:#FFFFFF !important;
}
.st-key-aegis_mobile_nav { display:none; }
.st-key-aegis_nav_actions [data-testid="stHorizontalBlock"] { gap:.45rem; }
.st-key-aegis_nav_actions button { min-height:38px; padding:.35rem .65rem; }
.st-key-aegis_page_nav { margin:-.5rem 0 1.1rem; }
.st-key-aegis_page_nav div[role="radiogroup"] {
  display:flex; flex-wrap:wrap; gap:.35rem; border:0; padding:0;
}
.st-key-aegis_page_nav div[role="radiogroup"] label {
  min-height:36px; padding:.38rem .7rem; border:1px solid #27344A; border-radius:8px;
  background:#101827;
}
.st-key-aegis_page_nav div[role="radiogroup"] label p { color:#94A3B8; font-size:.78rem; }
.st-key-aegis_page_nav div[role="radiogroup"] label:has(input:checked) {
  border-color:#8B5CF6; background:#201A37;
}
.st-key-aegis_page_nav div[role="radiogroup"] label:has(input:checked) p { color:#F1F5F9; }
.page-head { padding:0 0 .65rem; margin:0 0 .9rem; border-bottom:1px solid #27344A; }
.page-head h1 { margin:0; font-size:1.6rem !important; line-height:1.25; }
.page-head .sub { color:#94A3B8; font-size:.84rem; line-height:1.45; margin-top:.22rem; }
.dashboard-topbar { margin:0 0 1rem; }
.dashboard-title { color:#F1F5F9; font-size:1.72rem; font-weight:650; line-height:1.25; }
.dashboard-subtitle, .dashboard-crumb { color:#94A3B8; }
.dashboard-hero, .st-key-dashboard_hero {
  background:#101827; border:1px solid #27344A; box-shadow:none;
}
.dashboard-hero-title, .dashboard-hero h2 { color:#F1F5F9; text-shadow:none; }
.dashboard-hero-description, .dashboard-hero p { color:#94A3B8; }
.dashboard-stat, .dashboard-panel, [data-testid="stMetric"],
[data-testid="stVerticalBlockBorderWrapper"] {
  background:#151F31 !important; border-color:#27344A !important; box-shadow:none;
}
[data-testid="stMetricLabel"] p, .dashboard-stat-label { color:#94A3B8 !important; }
[data-testid="stMetricValue"], .dashboard-stat-value { color:#F1F5F9 !important; }
.dashboard-stat-note, .dashboard-panel-subtitle, .section-heading-subtitle,
.recent-file-meta, .recent-empty { color:#94A3B8 !important; }
.dashboard-panel-title, .section-heading-title, .recent-file-name { color:#F1F5F9; }
.step, .about-panel, .section-intro { background:#151F31; border-color:#27344A; }
.step .h, .v-name, .c-title, .act-t, .tl-t { color:#F1F5F9; }
.step .d, .c-sub, .empty, .tl-m, .act-s, .act-r, .b-name, .rb-row { color:#94A3B8; }
.b-track, .rb-bar { background:#27344A; }
.chip, .threat-summary-item { background:#151F31; border-color:#27344A; color:#D9E2EF; }
.threat-card { background:#151F31; border-color:#27344A; box-shadow:none; }
.threat-medium { border-left-color:#F59E0B; }
.threat-low { border-left-color:#38BDF8; }
.threat-card-heading, .threat-explanation, .threat-recommendation { color:#F1F5F9; }
.threat-affected, .threat-certainty, .threat-summary-label { color:#94A3B8; }
.threat-recommendation { background:#101827; }
.hashline { color:#A7F3D0; background:#102B2A; border-color:#24564F; }
[data-testid="stExpander"] { background:#101827; border-color:#27344A; color:#D9E2EF; }
[data-testid="stAlert"] { background:#101827; border-color:#27344A; }
[data-testid="stAlert"] p { color:#D9E2EF; }
[data-testid="stDataFrame"], [data-testid="stTable"] { background:#101827; border-color:#27344A; }
[data-testid="stFileUploaderDropzone"] { background:#101827; border:1px dashed #51617A; color:#F1F5F9; }
[data-testid="stFileUploaderDropzone"] * { color:#D9E2EF; }
div[data-baseweb="input"], div[data-baseweb="select"] > div,
div[data-baseweb="textarea"] {
  background:#101827 !important; border-color:#27344A !important; color:#F1F5F9 !important;
}
input, textarea, [data-baseweb="select"] *, [role="option"], [role="listbox"] {
  color:#F1F5F9 !important;
}
input::placeholder, textarea::placeholder { color:#94A3B8 !important; opacity:1; }
[data-testid="stSelectbox"] input, [data-testid="stMultiSelect"] input,
[data-testid="stTextInput"] input, [data-testid="stTextArea"] textarea,
input[role="combobox"] {
  background:#101827 !important; color:#F1F5F9 !important;
  border-color:#27344A !important; caret-color:#F1F5F9;
}
[data-testid="stSelectbox"] button, [data-testid="stMultiSelect"] button {
  background:#101827 !important; border:0 !important; color:#94A3B8 !important;
}
[data-testid="stSelectbox"] button:hover, [data-testid="stMultiSelect"] button:hover {
  background:#151F31 !important; color:#F1F5F9 !important;
}
[data-baseweb="popover"], [role="listbox"] { background:#151F31 !important; }
input[type="checkbox"] { accent-color:#8B5CF6; }
.stCheckbox label, .stRadio label { color:#D9E2EF; }
.stButton > button, .stDownloadButton > button {
  min-height:40px; background:#151F31 !important; border:1px solid #27344A; color:#F1F5F9 !important;
}
button[data-testid="stBaseButton-secondary"] {
  background:#151F31 !important; border-color:#27344A !important; color:#F1F5F9 !important;
}
.stButton > button:hover, .stDownloadButton > button:hover {
  background:#1C2940; border-color:#8B5CF6; color:#FFFFFF;
}
button[data-testid="stBaseButton-secondary"]:hover {
  background:#1C2940 !important; border-color:#8B5CF6 !important; color:#FFFFFF !important;
}
.stButton > button[kind="primary"], button[data-testid="stBaseButton-primary"] {
  background:#8B5CF6 !important; border-color:#8B5CF6 !important;
  color:#FFFFFF !important; border:0 !important;
}
button[data-testid="stBaseButton-primary"]:hover {
  background:#7C3AED !important; border-color:#7C3AED !important;
}
button[data-baseweb="tab"] { color:#94A3B8; }
button[data-baseweb="tab"][aria-selected="true"] { color:#F1F5F9; }
[data-baseweb="tab-highlight"] { background:#8B5CF6 !important; }
button[data-baseweb="tab"]:hover { color:#F1F5F9; }
hr, .page-head, .site-head { border-color:#27344A; }
.site-footer { color:#94A3B8; border-color:#27344A; }
.page-head .pills { margin-top:.4rem; }
/* Dark controls, pagination, popovers, and disclosure panels */
.stNumberInput [data-baseweb="input"], .stNumberInput input {
  background:#101827 !important; color:#F1F5F9 !important; border-color:#27344A !important;
}
.stNumberInput button, [data-testid="stNumberInput"] button {
  background:#151F31 !important; color:#D9E2EF !important; border-color:#27344A !important;
}
.stNumberInput button:hover, [data-testid="stNumberInput"] button:hover {
  background:#201A37 !important; color:#FFFFFF !important; border-color:#8B5CF6 !important;
}
[data-baseweb="popover"], [data-baseweb="menu"], [role="listbox"],
[data-testid="stTooltipHoverTarget"] + div, [role="tooltip"] {
  background:#151F31 !important; color:#F1F5F9 !important; border-color:#34445D !important;
}
[data-baseweb="popover"] *, [data-baseweb="menu"] *, [role="listbox"] *, [role="tooltip"] * {
  color:#E2E8F0 !important;
}
[data-baseweb="popover"] [aria-selected="true"], [role="option"]:hover {
  background:#292044 !important; color:#FFFFFF !important;
}
[data-testid="stExpander"] {
  background:#101827 !important; border:1px solid #27344A !important; border-radius:10px;
}
[data-testid="stExpander"] summary, [data-testid="stExpander"] details,
[data-testid="stExpander"] [data-testid="stExpanderDetails"] {
  background:#101827 !important; color:#D9E2EF !important;
}
[data-testid="stExpander"] summary:hover { color:#FFFFFF !important; }
[data-testid="stDataFrame"], [data-testid="stTable"] {
  background:#101827 !important; color:#D9E2EF !important; border-color:#27344A !important;
}
.page-head .pills { align-self:center; }
.threat-card { padding:12px 14px; gap:10px; margin:7px 0; }
.threat-card-heading { gap:8px; }
.threat-affected { margin-top:3px; font-size:.76rem; }
.threat-explanation { margin:.35rem 0; font-size:.84rem; line-height:1.42; }
.threat-recommendation { padding:6px 9px; font-size:.78rem; line-height:1.4; }
.threat-meta { display:flex; flex-wrap:wrap; gap:.3rem .8rem; color:#94A3B8; font-size:.73rem; margin-top:3px; }
.st-key-monitor_directories textarea { min-height:74px !important; }
@media(max-width:650px) {
  .threat-meta { gap:.25rem .55rem; }
  .page-head { gap:8px; margin-bottom:.7rem; }
  .page-head .pills { margin-top:0; }
}
@media (max-width:1000px) {
  .st-key-aegis_top_nav [data-testid="stHorizontalBlock"] { flex-wrap:wrap; }
  .block-container { padding-top:1rem; }
}
@media (max-width:1180px) and (min-width:801px) {
  .st-key-aegis_desktop_nav .stButton > button { padding:.38rem .2rem; font-size:.72rem; }
}
@media (max-width:800px) {
  .st-key-aegis_desktop_nav { display:none; }
  .st-key-aegis_mobile_nav { display:block; }
  .st-key-aegis_top_nav { position:sticky; top:0; margin-top:-1rem; padding:.55rem 1rem; }
  .st-key-aegis_top_nav [data-testid="stHorizontalBlock"] { align-items:center; gap:.45rem; }
  .st-key-aegis_top_nav [data-testid="stColumn"] { min-width:140px; }
  .st-key-aegis_nav_actions [data-testid="stHorizontalBlock"] { flex-wrap:nowrap !important; }
  .st-key-aegis_nav_actions [data-testid="stColumn"] { min-width:0 !important; flex:1 1 50% !important; }
  .st-key-aegis_nav_actions button { width:100%; font-size:.75rem; }
  .st-key-aegis_mobile_nav [data-baseweb="select"] > div { min-height:42px; }
  [data-testid="stHorizontalBlock"] { flex-wrap:wrap; gap:.65rem; }
  [data-testid="stColumn"] { min-width:min(100%,250px); }
}
@media (max-width:650px) {
  .block-container { padding:.8rem .75rem 2rem; }
  .dashboard-hero, .st-key-dashboard_hero { padding:19px; }
  .dashboard-hero-title, .dashboard-hero h2 { font-size:1.35rem; }
  .st-key-aegis_top_nav { margin-left:-.75rem; margin-right:-.75rem; padding:.5rem .75rem; }
  .top-brand-caption { display:none; }
  .top-brand-mark { width:34px; height:34px; }
  .st-key-aegis_nav_actions button { min-height:42px; padding:.25rem .4rem; }
  .st-key-aegis_page_nav div[role="radiogroup"] { gap:.25rem; }
  .st-key-aegis_page_nav div[role="radiogroup"] label { padding:.32rem .5rem; }
}
"""


def inject_css():
    st.markdown(f"<style>{CSS}{DARK_THEME_CSS}</style>", unsafe_allow_html=True)


# ----------------------------------------------------------------------------- website chrome
def top_brand():
    st.markdown(
        f'<div class="top-brand"><span class="top-brand-mark">{svg("shield", "#8B5CF6", 22)}</span>'
        '<span><div class="top-brand-name">AEGIS FORENSICS</div>'
        '<div class="top-brand-caption">Digital investigation platform</div></span></div>',
        unsafe_allow_html=True,
    )


def dashboard_stat(icon, value, label, note, tone="violet"):
    color = TONES.get(tone, TONES["violet"])
    return (
        f'<div class="dashboard-stat"><div class="dashboard-stat-head"><span class="dashboard-stat-label">{e(label)}</span>'
        f'<span class="dashboard-stat-icon" style="background:{_rgba(color, 0.12)};color:{color}">{svg(icon, color, 17)}</span></div>'
        f'<div class="dashboard-stat-value">{e(str(value))}</div><div class="dashboard-stat-note">{e(note)}</div></div>'
    )


def dashboard_recent_file(name, metadata):
    return (
        f'<div class="recent-evidence"><div class="recent-file-icon">{svg("file", "#8B35E5", 17)}</div>'
        f'<div style="min-width:0"><div class="recent-file-name">{e(name)}</div>'
        f'<div class="recent-file-meta">{e(metadata)}</div></div></div>'
    )


def landing_hero():
    return (
        '<section class="hero"><div class="hero-copy"><div class="eyebrow">AI-assisted digital forensics</div>'
        '<h1>Turn complex evidence<br>into <span>clear answers.</span></h1>'
        '<p>Bring digital evidence into one focused workspace. Explore suspicious activity, review explainable findings, '
        'and prepare evidence-grounded reports with integrity at every step.</p>'
        '<div class="hero-points"><span class="hero-point"><b>✓</b> Evidence integrity</span>'
        '<span class="hero-point"><b>✓</b> Explainable findings</span>'
        '<span class="hero-point"><b>✓</b> Investigation-ready reports</span></div></div></section>'
    )


def feature_card(icon, title, description, tone="cyan"):
    color = TONES.get(tone, TONES["cyan"])
    return (
        f'<div class="feature-card"><div class="feature-icon">{svg(icon, color, 21)}</div>'
        f'<h3>{e(title)}</h3><p>{e(description)}</p></div>'
    )


def about_panel(title, description):
    return (
        f'<div class="about-panel"><h3>{e(title)}</h3><p>{e(description)}</p></div>'
    )


def page_header(title, subtitle, filename=None):
    pills = []
    if filename:
        pills.append(f'<span class="pill-i ex">{e(filename)}</span>')
    st.markdown(
        f'<div class="page-head"><div><h1>{e(title)}</h1>'
        f'<div class="sub">{e(subtitle)}</div></div>'
        f'<div class="pills">{"".join(pills)}</div></div>',
        unsafe_allow_html=True,
    )


def sev_badge(sev: str) -> str:
    return f'<span class="sev" style="background:{SEV_COLORS.get(sev, "#5B6B82")}">{e(str(sev))}</span>'


def threat_alert_card(
    title: str,
    severity: str,
    affected: str,
    explanation: str,
    recommendation: str,
    icon: str = "alert",
    certainty: str = "",
    detection_type: str = "",
    timestamp: str = "",
) -> str:
    """Return a compact, escaped alert card for user-facing threat summaries."""
    severity_name = severity if severity in SEV_COLORS else "Low"
    color = SEV_COLORS[severity_name]
    certainty_markup = (
        f'<span class="threat-certainty">{e(certainty)}</span>' if certainty else ""
    )
    metadata = " · ".join(value for value in (detection_type, timestamp) if value)
    metadata_markup = f'<div class="threat-meta">{e(metadata)}</div>' if metadata else ""
    return (
        f'<article class="threat-card threat-{severity_name.lower()}">'
        f'<div class="threat-card-icon" style="color:{color}">{svg(icon, color, 19)}</div>'
        '<div class="threat-card-content">'
        f'<div class="threat-card-heading"><strong>{e(title)}</strong>'
        f'<span class="threat-severity" style="color:{color};border-color:{color}">{e(severity_name)}</span>'
        f'{certainty_markup}</div>'
        f'<div class="threat-affected">{e(affected)}</div>'
        f'{metadata_markup}'
        f'<p class="threat-explanation">{e(explanation)}</p>'
        f'<div class="threat-recommendation"><strong>Next step</strong> {e(recommendation)}</div>'
        '</div></article>'
    )


# ----------------------------------------------------------------------------- dashboard widgets
def kpi(icon, value, label, tone="neutral"):
    c = TONES.get(tone, TONES["neutral"])
    return (
        f'<div class="kpi"><div class="k-icon" style="background:{_rgba(c, .14)}">{svg(icon, c, 20)}</div>'
        f'<div class="k-val">{e(str(value))}</div><div class="k-label">{e(label)}</div></div>'
    )


def mini_stat(icon, value, label, tone="neutral"):
    c = TONES.get(tone, TONES["neutral"])
    return (
        f'<div class="mini"><div class="m-icon" style="background:{_rgba(c, .14)}">{svg(icon, c, 18)}</div>'
        f'<div><div class="m-val">{e(str(value))}</div><div class="m-label">{e(label)}</div></div></div>'
    )


def card_header(title, sub=""):
    return f'<div class="c-title">{e(title)}</div><div class="c-sub">{e(sub)}</div>'


def risk_score(counts):
    """0-100, saturating. Weights: Critical 40, High 20, Medium 8, Low 2."""
    w = (
        40 * counts.get("Critical", 0)
        + 20 * counts.get("High", 0)
        + 8 * counts.get("Medium", 0)
        + 2 * counts.get("Low", 0)
    )
    return round(100 * (1 - math.exp(-w / 60)))


def risk_label(score):
    return (
        ("Low", "#2DD4BF")
        if score < 35
        else ("Elevated", "#F5B73A") if score < 65 else ("Severe", "#EF4444")
    )


def gauge(score):
    try:
        import plotly.graph_objects as go
    except Exception:
        return None
    color = risk_label(score)[1]
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"font": {"size": 46, "color": "#E6ECF8"}},
            gauge={
                "axis": {
                    "range": [0, 100],
                    "tickcolor": "#3A4766",
                    "tickfont": {"color": "#7E8BA8", "size": 10},
                },
                "bar": {"color": color, "thickness": 0.3},
                "bgcolor": "rgba(0,0,0,0)",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 35], "color": "rgba(45,212,191,.16)"},
                    {"range": [35, 65], "color": "rgba(245,183,58,.16)"},
                    {"range": [65, 100], "color": "rgba(239,68,68,.16)"},
                ],
            },
        )
    )
    fig.update_layout(
        height=210,
        margin=dict(l=20, r=20, t=10, b=0),
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif"),
    )
    return fig


def mitre_html(findings, limit=6):
    c = Counter()
    for f in findings:
        for t in set(TECH_RE.findall(str(f.get("mitre", "")))):
            c[t] += 1
    if not c:
        return '<div class="empty">No ATT&amp;CK techniques are mapped from the findings.</div>'
    top = c.most_common(limit)
    mx = top[0][1]
    return "".join(
        f'<div class="bar-row"><div class="b-name">{e(t)} {e(TECHNIQUES.get(t, ""))}</div>'
        f'<div class="b-track"><div class="b-fill" style="width:{100 * n / mx:.0f}%"></div></div><div class="b-n">{n}</div></div>'
        for t, n in top
    )


def risk_breakdown_html(counts):
    total = sum(counts.get(s, 0) for s in SEV_ORDER)
    if not total:
        return (
            '<div class="empty">No findings, so there is nothing to break down.</div>'
        )
    bar = "".join(
        f'<div style="width:{100 * counts[s] / total:.1f}%;background:{SEV_COLORS[s]}"></div>'
        for s in SEV_ORDER
        if counts.get(s)
    )
    rows = "".join(
        f'<div class="rb-row"><span class="rb-dot" style="background:{SEV_COLORS[s]}"></span>{s}'
        f'<span class="n">{counts[s]} ({100 * counts[s] / total:.0f}%)</span></div>'
        for s in SEV_ORDER
        if counts.get(s)
    )
    return f'<div class="rb-bar">{bar}</div>{rows}'


def timeline_html(findings, limit=8):
    timed = chronological_findings(findings)[:limit]
    if not timed:
        return '<div class="empty">No finding carries a resolved timestamp.</div>'
    items = "".join(
        f'<div class="tl-item"><span class="tl-dot" style="background:{SEV_COLORS.get(f["severity"], "#8B97B5")}"></span>'
        f'<div class="tl-t">{e(str(f["rule"]))} {sev_badge(f["severity"])}</div>'
        f'<div class="tl-m">{e(stamp.isoformat())} | {e(f["id"])}</div></div>'
        for stamp, f in timed
    )
    return f'<div class="tl">{items}</div>'


def action_html(findings, limit=8):
    if not findings:
        return '<div class="empty">Nothing needs action: no rule or YARA finding in this file.</div>'
    rank = {s: i for i, s in enumerate(SEV_ORDER)}
    rows = sorted(findings, key=lambda f: (rank.get(f["severity"], 9), f["id"]))
    out = []
    for f in rows[:limit]:
        sub = e(str(f.get("description", ""))[:110])
        time_value = finding_time(f)
        right = e(time_value.text) if time_value.utc is not None else ("Unresolved time" if f.get("first_seen") is not None else e(f["id"]))
        out.append(
            f'<div class="act-row">{sev_badge(f["severity"])}<div class="act-main">'
            f'<div class="act-t">{e(str(f["rule"]))}</div><div class="act-s">{e(f["id"])} | {sub}</div></div>'
            f'<div class="act-r">{right}</div></div>'
        )
    if len(rows) > limit:
        out.append(
            f'<div class="empty">+{len(rows) - limit} more in the Rule findings and YARA scan tabs.</div>'
        )
    return "".join(out)


def topology(raw_df, findings):
    """Source IP -> host graph from the CSV itself. Red = IP or host named in a finding."""
    try:
        import plotly.graph_objects as go
    except Exception:
        return None
    if raw_df is None or len(raw_df) == 0:
        return None
    cols = {str(c).lower(): c for c in raw_df.columns}
    src = cols.get("source_ip")
    host = next((cols[k] for k in HOST_COLS if k in cols), None)
    if src is None or host is None:
        return None
    d = raw_df[[src, host]].dropna().astype(str)
    pairs = d.groupby([src, host]).size().reset_index(name="n")
    if pairs.empty:
        return None
    pairs = pairs[pairs[src].isin(pairs.groupby(src)["n"].sum().nlargest(10).index)]
    pairs = pairs[pairs[host].isin(pairs.groupby(host)["n"].sum().nlargest(6).index)]

    bad_ips, bad_hosts = set(), set()
    for f in findings:
        bad_ips |= set(
            IP_RE.findall(f"{f.get('source_ips', '')} {f.get('description', '')}")
        )
        bad_hosts |= {h for h in re.split(r"[,\s]+", str(f.get("hosts", ""))) if h}

    srcs = list(pairs.groupby(src)["n"].sum().sort_values(ascending=False).index)
    hosts = list(pairs.groupby(host)["n"].sum().sort_values(ascending=False).index)

    def ys(items):
        n = len(items)
        return {k: (0.5 if n == 1 else 1 - i / (n - 1)) for i, k in enumerate(items)}

    ysrc, yhost = ys(srcs), ys(hosts)
    mx = pairs["n"].max()
    t = [i / 24 for i in range(25)]
    smooth = [x * x * (3 - 2 * x) for x in t]
    fig = go.Figure()
    for _, r in pairs.iterrows():
        y0, y1 = ysrc[r[src]], yhost[r[host]]
        yy = [y0 + (y1 - y0) * s for s in smooth]
        col = "239,68,68" if r[src] in bad_ips else "45,212,191"
        w = 1.5 + 5 * r["n"] / mx
        fig.add_trace(
            go.Scatter(
                x=t,
                y=yy,
                mode="lines",
                hoverinfo="skip",
                showlegend=False,
                line=dict(width=w + 6, color=f"rgba({col},.12)"),
            )
        )
        fig.add_trace(
            go.Scatter(
                x=t,
                y=yy,
                mode="lines",
                showlegend=False,
                hoverinfo="text",
                text=f"{r[src]} to {r[host]}: {r['n']} events",
                line=dict(width=w, color=f"rgba({col},.85)"),
            )
        )
    for items, ypos, x, bads, pos in (
        (srcs, ysrc, 0, bad_ips, "middle left"),
        (hosts, yhost, 1, bad_hosts, "middle right"),
    ):
        fig.add_trace(
            go.Scatter(
                x=[x] * len(items),
                y=[ypos[i] for i in items],
                mode="markers+text",
                text=items,
                textposition=pos,
                textfont=dict(color="#B7C4D8", size=11),
                hoverinfo="skip",
                showlegend=False,
                marker=dict(
                    size=13,
                    color=["#EF4444" if i in bads else "#2DD4BF" for i in items],
                    line=dict(width=6, color="rgba(255,255,255,.08)"),
                ),
            )
        )
    fig.update_xaxes(visible=False, range=[-0.55, 1.55])
    fig.update_yaxes(visible=False, range=[-0.12, 1.12])
    fig.update_layout(
        height=300,
        margin=dict(l=0, r=0, t=0, b=0),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    return fig


def style_fig(fig, height=270, showlegend=None):
    fig.update_layout(
        template="plotly_dark",
        height=height,
        margin=dict(l=0, r=0, t=10, b=0),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color="#B7C4D8"),
    )
    if showlegend is not None:
        fig.update_layout(showlegend=showlegend)
    fig.update_layout(template="plotly_white")
    fig.update_xaxes(gridcolor="#ECEEF3", zerolinecolor="#E1E3EA")
    fig.update_yaxes(gridcolor="#ECEEF3", zerolinecolor="#E1E3EA")
    return fig


# ----------------------------------------------------------------------------- evidence portal
def vault_head():
    return (
        '<div class="v-head"><div>Evidence ID</div><div>File details</div><div>Record</div>'
        "<div>Status</div><div>Actions</div></div>"
    )


def vault_file(name, modified):
    return (
        f'<div class="v-file"><div class="v-ficon">{svg("file", "#37D7E8", 18)}</div>'
        f'<div><div class="v-name">{e(name)}</div><div class="v-date">{e(modified)}</div></div></div>'
    )


def vault_record(cases):
    if not cases:
        return '<span class="v-mono">No upload record in any audit log</span>'
    return f'<span class="v-chip">{e(cases)}</span>'


def vault_status(status):
    styles = {
        "verified": ("Verified", "#2DD4BF"),
        "modified": ("Hash mismatch", "#EF4444"),
        "norecord": ("No record", "#F5B73A"),
        None: ("Not verified", "#8B97B5"),
    }
    label, c = styles.get(status, styles[None])
    return f'<span class="v-status" style="color:{c};background:{_rgba(c, .14)};border:1px solid {_rgba(c, .4)}">{label}</span>'
