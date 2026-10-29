import html

import altair as alt
import pandas as pd
import requests
import streamlit as st


# ============================================================
# CONFIGURATION
# ============================================================

BACKEND_URL = "http://127.0.0.1:8000"

DEFAULT_REPORT = (
    "An attacker scanned the company's public web servers and found an unpatched "
    "file upload vulnerability in an internet-facing ASP.NET application. They uploaded "
    "a web shell disguised as an image file and used it to run system commands remotely. "
    "Using the web shell, they enumerated local user accounts and ran a credential dumping "
    "tool against the LSASS process to obtain administrator password hashes. "
    "With the stolen credentials, they connected over RDP to an internal database server "
    "and copied a PowerShell script to the server's startup folder so it would run after each reboot. "
    "They then used PsExec to push a ransomware executable to several file servers. "
    "Before encrypting, the attacker deleted volume shadow copies with vssadmin and stopped "
    "the backup service. The ransomware encrypted shared folders and dropped a ransom note "
    "demanding payment in cryptocurrency."
)

LEVEL_COLORS = {"Strong": "#16a34a", "Moderate": "#d97706", "Weak": "#e11d48"}
LEVEL_ORDER = ["Strong", "Moderate", "Weak"]
SIGNAL_COLORS = {"ML": "#0891b2", "Semantic": "#7c3aed", "Evidence": "#f59e0b"}
SIGNALS = ["ML", "Semantic", "Evidence"]
TEXT_DARK = "#1e293b"
GRID = "#e2e8f0"

KILL_CHAIN = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="MITRE ATT&CK Technique Mapper",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# STYLES
# ============================================================

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@500;700&display=swap');

    :root {
        --ink: #0f172a;
        --ink-soft: #334155;
        --muted: #64748b;
        --line: #e2e8f0;
        --brand-1: #4338ca;
        --brand-2: #7e22ce;
        --brand-3: #be185d;
        --brand-4: #0e7490;
    }

    html, body, [class*="css"], .stMarkdown, .stMarkdown p,
    .stTextArea textarea, .stButton button, [data-testid="stMetric"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
    }

    .block-container { padding-top: 2rem; padding-bottom: 3rem; max-width: 1200px; }
    #MainMenu, footer, header[data-testid="stHeader"] { visibility: hidden; height: 0; }

    /* ---------- Animations ---------- */
    @keyframes fadeUp {
        from { opacity: 0; transform: translateY(14px); }
        to   { opacity: 1; transform: translateY(0); }
    }
    @keyframes gradientShift {
        0%   { background-position: 0% 50%; }
        50%  { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }
    @keyframes pulse {
        0%   { box-shadow: 0 0 0 0 rgba(22,163,74,0.6); }
        70%  { box-shadow: 0 0 0 8px rgba(22,163,74,0); }
        100% { box-shadow: 0 0 0 0 rgba(22,163,74,0); }
    }
    @keyframes growBar { from { width: 0%; } }
    @keyframes floatOrb {
        0%, 100% { transform: translate(0, 0) scale(1); }
        50%      { transform: translate(-24px, 16px) scale(1.08); }
    }
    @keyframes spinIn {
        from { opacity: 0; transform: scale(0.85) rotate(-6deg); }
        to   { opacity: 1; transform: scale(1) rotate(0); }
    }
    @media (prefers-reduced-motion: reduce) {
        *, *::before, *::after { animation: none !important; transition: none !important; }
    }

    /* ---------- Hero ---------- */
    .hero {
        position: relative; overflow: hidden;
        border-radius: 22px; padding: 36px 42px; margin-bottom: 1.4rem;
        background: linear-gradient(120deg, var(--brand-1), var(--brand-2), var(--brand-3), var(--brand-4));
        background-size: 300% 300%;
        animation: gradientShift 16s ease infinite, fadeUp 0.7s ease both;
        box-shadow: 0 20px 48px rgba(67, 56, 202, 0.30);
        color: #ffffff;
    }
    .hero::before, .hero::after {
        content: ""; position: absolute; border-radius: 50%; filter: blur(6px);
        animation: floatOrb 10s ease-in-out infinite; pointer-events: none;
    }
    .hero::before {
        width: 280px; height: 280px; right: -60px; top: -100px;
        background: radial-gradient(circle, rgba(255,255,255,0.28), rgba(255,255,255,0) 70%);
    }
    .hero::after {
        width: 200px; height: 200px; left: 42%; bottom: -120px;
        background: radial-gradient(circle, rgba(250,204,21,0.30), rgba(250,204,21,0) 70%);
        animation-delay: -3s;
    }
    .hero-eyebrow {
        position: relative; z-index: 1; display: inline-block;
        font-size: 0.78rem; font-weight: 800; letter-spacing: 0.14em; text-transform: uppercase;
        color: #ffffff; background: rgba(255,255,255,0.18);
        border: 1px solid rgba(255,255,255,0.4); padding: 4px 12px;
        border-radius: 999px; margin-bottom: 14px;
    }
    .hero-title {
        position: relative; z-index: 1; font-size: 2.4rem; font-weight: 900;
        letter-spacing: -0.02em; line-height: 1.15; color: #ffffff;
        text-shadow: 0 2px 10px rgba(0,0,0,0.25);
    }
    .hero-sub {
        position: relative; z-index: 1; font-size: 1.05rem; font-weight: 500;
        color: #ffffff; margin-top: 10px; max-width: 760px; line-height: 1.65; opacity: 0.95;
    }
    .hero-tags { position: relative; z-index: 1; margin-top: 18px; }
    .hero-tag {
        display: inline-block; padding: 6px 14px; margin: 0 8px 8px 0;
        border-radius: 999px; font-size: 0.84rem; font-weight: 700; color: #ffffff;
        background: rgba(255,255,255,0.20); border: 1px solid rgba(255,255,255,0.45);
    }

    /* ---------- Status pill ---------- */
    .status {
        display: inline-flex; align-items: center; gap: 10px;
        padding: 9px 16px; border-radius: 999px; font-size: 0.95rem; font-weight: 700;
        border: 1px solid transparent; margin-bottom: 0.5rem; animation: fadeUp 0.5s ease both;
    }
    .status-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
    .status-ok   { background: #dcfce7; color: #14532d; border-color: #86efac; }
    .status-ok .status-dot { background: #16a34a; animation: pulse 2s infinite; }
    .status-warn { background: #fef3c7; color: #78350f; border-color: #fcd34d; }
    .status-warn .status-dot { background: #d97706; }
    .status-err  { background: #ffe4e6; color: #881337; border-color: #fda4af; }
    .status-err .status-dot { background: #e11d48; }

    /* ---------- Section headers ---------- */
    .section-title {
        font-size: 1.45rem; font-weight: 800; color: var(--ink);
        margin: 2.2rem 0 0.15rem 0; letter-spacing: -0.01em; animation: fadeUp 0.5s ease both;
    }
    .section-sub { font-size: 0.98rem; font-weight: 500; color: var(--muted); margin-bottom: 1.1rem; }

    /* ---------- KPI cards ---------- */
    .kpi {
        position: relative; overflow: hidden; border-radius: 18px; padding: 20px 22px;
        min-height: 112px; color: #ffffff;
        background: linear-gradient(135deg, var(--c1), var(--c2));
        box-shadow: 0 12px 26px rgba(15,23,42,0.18);
        animation: fadeUp 0.6s ease both; transition: transform 0.25s ease, box-shadow 0.25s ease;
    }
    .kpi:hover { transform: translateY(-3px); box-shadow: 0 18px 34px rgba(15,23,42,0.26); }
    .kpi-label {
        font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.1em;
        font-weight: 800; color: #ffffff; padding-right: 40px; line-height: 1.3;
    }
    .kpi-value {
        font-size: 1.9rem; font-weight: 900; margin-top: 8px;
        font-family: 'JetBrains Mono', monospace; color: #ffffff;
    }
    .kpi-icon { position: absolute; right: 14px; top: 14px; font-size: 1.7rem; opacity: 0.35; }

    /* ---------- Gauge ---------- */
    .gauge-wrap { display: flex; justify-content: center; padding: 8px 0; }
    .gauge {
        width: 200px; height: 200px; border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        animation: spinIn 0.8s ease both; box-shadow: 0 10px 24px rgba(15,23,42,0.12);
    }
    .gauge-inner {
        width: 150px; height: 150px; border-radius: 50%; background: #0f172a;
        display: flex; flex-direction: column; align-items: center; justify-content: center; color: #ffffff;
    }
    .gauge-value { font-size: 2rem; font-weight: 900; font-family: 'JetBrains Mono', monospace; color: #ffffff; }
    .gauge-label {
        font-size: 0.72rem; font-weight: 800; letter-spacing: 0.1em; text-transform: uppercase;
        color: #cbd5e1; text-align: center; padding: 0 10px;
    }

    /* ---------- Technique cards ---------- */
    .tcard {
        border-radius: 18px; padding: 22px 26px; margin-bottom: 14px;
        background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
        border: 1px solid rgba(167,139,250,0.40); box-shadow: 0 12px 28px rgba(15,23,42,0.18);
        color: #f8fafc; animation: fadeUp 0.6s ease both; animation-delay: var(--delay, 0s);
    }
    .tcard-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 18px; flex-wrap: wrap; }
    .tech-id {
        font-family: 'JetBrains Mono', monospace; font-size: 1rem; font-weight: 700;
        color: #67e8f9; letter-spacing: 0.03em;
    }
    .tech-name { font-size: 1.3rem; font-weight: 800; margin-top: 2px; color: #ffffff; }
    .score-badge { text-align: right; min-width: 150px; }
    .score-value { font-family: 'JetBrains Mono', monospace; font-size: 1.6rem; font-weight: 900; line-height: 1.05; }
    .score-raw { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #cbd5e1; margin-top: 4px; }
    .score-level { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 800; margin-top: 4px; }
    .bar { height: 10px; border-radius: 999px; background: rgba(148,163,184,0.25); overflow: hidden; margin: 16px 0 14px 0; }
    .bar-fill { height: 100%; border-radius: 999px; animation: growBar 1s ease-out both; }
    .chip {
        display: inline-block; padding: 5px 13px; margin: 3px 6px 3px 0; border-radius: 999px;
        font-size: 0.8rem; font-weight: 700; color: #ffffff;
        background: linear-gradient(90deg, #4f46e5, #0891b2); box-shadow: 0 3px 8px rgba(6,182,212,0.22);
    }
    .meta-line { font-size: 0.95rem; margin: 6px 0; color: #e2e8f0; line-height: 1.6; }
    .meta-line b { color: #fde68a; font-weight: 700; }
    .evidence-box {
        margin-top: 14px; padding: 14px 18px; border-left: 4px solid #22d3ee;
        border-radius: 12px; background: rgba(34,211,238,0.12);
        font-size: 0.95rem; line-height: 1.65; color: #f1f5f9;
    }
    .evidence-label {
        font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.1em;
        font-weight: 800; color: #67e8f9; margin-bottom: 6px;
    }

    /* ---------- Attack sequence ---------- */
    .seq {
        position: relative; display: flex; gap: 18px; align-items: flex-start;
        border-radius: 16px; padding: 18px 22px; margin-bottom: 12px;
        background: #ffffff; border: 1px solid var(--line); border-left: 6px solid #7c3aed;
        box-shadow: 0 8px 20px rgba(15,23,42,0.07); color: var(--ink);
        animation: fadeUp 0.5s ease both; animation-delay: var(--delay, 0s);
    }
    .seq-num {
        flex-shrink: 0; width: 44px; height: 44px; border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        font-weight: 900; font-size: 1.05rem; color: #ffffff;
        background: linear-gradient(135deg, #7c3aed, #db2777); box-shadow: 0 6px 14px rgba(124,58,237,0.35);
        animation: spinIn 0.5s ease both; animation-delay: var(--delay, 0s);
    }
    .seq-body { flex: 1; min-width: 0; }
    .seq-title { font-size: 1.08rem; font-weight: 800; margin-top: 8px; color: var(--ink); }
    .seq-id { font-family: 'JetBrains Mono', monospace; color: #6d28d9; font-weight: 800; margin-right: 8px; }
    .seq-ev { margin-top: 8px; font-size: 0.94rem; color: var(--ink-soft); line-height: 1.6; }
    .seq-score {
        font-family: 'JetBrains Mono', monospace; font-weight: 900; font-size: 1.05rem;
        white-space: nowrap; padding: 6px 12px; border-radius: 12px;
        background: #f1f5f9; text-align: right;
    }
    .seq-score small { display: block; font-size: 0.72rem; font-weight: 600; color: var(--muted); }

    /* ---------- Input area ---------- */
    .stTextArea textarea {
        font-size: 1rem !important; line-height: 1.65 !important; color: var(--ink) !important;
        background: #ffffff !important; border: 1.5px solid #c7d2fe !important;
        border-radius: 14px !important; padding: 14px 16px !important;
    }
    .stTextArea textarea:focus {
        border-color: #6366f1 !important; box-shadow: 0 0 0 3px rgba(99,102,241,0.18) !important;
    }

    /* ---------- Buttons ---------- */
    .stButton > button {
        border-radius: 14px; font-weight: 800; min-height: 52px;
        border: 1px solid #c7d2fe; color: var(--ink); background: #ffffff;
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .stButton > button p { font-size: 1.02rem !important; font-weight: 800 !important; color: inherit !important; }
    .stButton > button:hover {
        transform: translateY(-2px); box-shadow: 0 10px 22px rgba(99,102,241,0.22);
        border-color: #6366f1; color: #4338ca;
    }
    .stButton > button[kind="primary"],
    [data-testid="stBaseButton-primary"] {
        background: linear-gradient(90deg, #4f46e5, #7e22ce, #db2777) !important;
        border: none !important; color: #ffffff !important; box-shadow: 0 10px 24px rgba(79,70,229,0.30);
    }
    .stButton > button[kind="primary"]:hover,
    [data-testid="stBaseButton-primary"]:hover { color: #ffffff !important; box-shadow: 0 14px 30px rgba(79,70,229,0.40); }
    .stButton > button[kind="primary"] p,
    [data-testid="stBaseButton-primary"] p { color: #ffffff !important; }

    /* ---------- Metric cards ---------- */
    [data-testid="stMetric"] {
        background: #ffffff; border: 1px solid var(--line); border-radius: 14px;
        padding: 14px 16px; box-shadow: 0 6px 16px rgba(15,23,42,0.06);
    }
    [data-testid="stMetricLabel"] p { font-weight: 700 !important; color: var(--muted) !important; font-size: 0.88rem !important; }
    [data-testid="stMetricValue"] { font-weight: 800 !important; color: var(--ink) !important; font-family: 'JetBrains Mono', monospace; }

    /* ---------- Chart panels ---------- */
    .chart-panel {
        background: #ffffff; border: 1px solid var(--line); border-radius: 18px;
        padding: 18px 20px 8px 20px; box-shadow: 0 8px 22px rgba(15,23,42,0.06);
        margin-bottom: 14px;
    }
    .chart-title { font-size: 1.05rem; font-weight: 800; color: var(--ink); margin: 0; }
    .chart-note { font-size: 0.84rem; color: var(--muted); margin: 2px 0 8px 0; }

    /* ---------- Expanders ---------- */
    [data-testid="stExpander"] { border-radius: 14px !important; border: 1px solid var(--line) !important; background: #ffffff; margin-bottom: 8px; }
    [data-testid="stExpander"] summary p { font-weight: 700 !important; color: var(--ink) !important; }

    /* ---------- Sidebar ---------- */
    [data-testid="stSidebar"] { background: linear-gradient(180deg, #0f172a 0%, #1e1b4b 100%); }
    [data-testid="stSidebar"] h3 { color: #ffffff !important; font-weight: 800; }
    [data-testid="stSidebar"] p, [data-testid="stSidebar"] div { color: #f1f5f9; }
    .side-item {
        display: flex; justify-content: space-between; gap: 10px; padding: 10px 0;
        border-bottom: 1px solid rgba(148,163,184,0.25); font-size: 0.93rem;
    }
    .side-item span:first-child { color: #cbd5e1; font-weight: 600; }
    .side-item span:last-child { color: #67e8f9; font-weight: 800; text-align: right; }
    .side-note { font-size: 0.93rem; line-height: 1.75; color: #f1f5f9; }
    .side-note b { color: #fbbf24; }

    /* ---------- Tabs ---------- */
    .stTabs [data-baseweb="tab-list"] { gap: 8px; border-bottom: none; }
    .stTabs [data-baseweb="tab"] { border-radius: 999px; padding: 8px 18px; background: #f1f5f9; border: 1px solid var(--line); }
    .stTabs [data-baseweb="tab"] p { font-weight: 700 !important; color: var(--ink-soft) !important; font-size: 0.95rem !important; }
    .stTabs [aria-selected="true"] { background: linear-gradient(90deg, #4f46e5, #db2777) !important; border-color: transparent !important; }
    .stTabs [aria-selected="true"] p { color: #ffffff !important; }
    .stTabs [data-baseweb="tab-highlight"] { display: none; }

    /* ---------- Alerts & headings ---------- */
    [data-testid="stAlert"] { border-radius: 14px; }
    [data-testid="stAlert"] p { font-size: 0.95rem; font-weight: 500; }
    h4 { color: var(--ink) !important; font-weight: 800 !important; }

    .footer { text-align: center; font-size: 0.92rem; font-weight: 600; color: var(--muted); padding-top: 0.5rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# HELPERS
# ============================================================

def esc(value) -> str:
    """Escape backend-provided text before injecting it into HTML."""
    return html.escape(str(value))


def to_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def fmt_raw(value) -> str:
    """Show raw model values compactly, keeping tiny and negative numbers readable."""
    return f"{to_float(value):.4g}"


def split_tactics(tactics) -> list:
    if isinstance(tactics, list):
        return [str(t).strip() for t in tactics if str(t).strip()]
    return [t.strip() for t in str(tactics or "").split(",") if t.strip()]


def tactic_rank(name: str) -> int:
    key = str(name).strip().lower().replace(" ", "-")
    return KILL_CHAIN.index(key) if key in KILL_CHAIN else len(KILL_CHAIN)


def level_of(strength: float) -> str:
    if strength >= 70:
        return "Strong"
    if strength >= 40:
        return "Moderate"
    return "Weak"


def relative_strength(values: list) -> list:
    """
    Scale values to 0-100 across the full range of this report.
    Lowest value becomes 0, highest becomes 100. Negative values are handled
    correctly, which fixes the all-zero problem with signed model scores.
    """
    if not values:
        return []
    lo, hi = min(values), max(values)
    if hi == lo:
        return [50.0 for _ in values]
    return [(v - lo) / (hi - lo) * 100.0 for v in values]


def strength_basis(results: list):
    """Use final_score when the backend provides it, otherwise average the three signals."""
    finals = [to_float(r.get("final_score")) for r in results]
    if any(f != 0 for f in finals):
        return finals, "final score"
    composite = [
        (to_float(r.get("ml_score")) + to_float(r.get("semantic_score")) + to_float(r.get("evidence_score"))) / 3
        for r in results
    ]
    return composite, "signal average"


def status_pill(kind: str, text: str) -> str:
    return f'<div class="status status-{kind}"><span class="status-dot"></span>{esc(text)}</div>'


def kpi_card(label: str, value, icon: str, c1: str, c2: str, delay: float) -> str:
    return (
        f'<div class="kpi" style="--c1:{c1}; --c2:{c2}; animation-delay:{delay}s;">'
        f'<div class="kpi-icon">{icon}</div>'
        f'<div class="kpi-label">{esc(label)}</div>'
        f'<div class="kpi-value">{esc(value)}</div>'
        f'</div>'
    )


def chart_panel(title: str, note: str = "") -> None:
    """Opens a styled card header above a chart."""
    note_html = f'<div class="chart-note">{esc(note)}</div>' if note else ""
    st.markdown(
        f'<div class="chart-panel"><div class="chart-title">{esc(title)}</div>{note_html}</div>',
        unsafe_allow_html=True,
    )


def style_chart(chart):
    """Consistent, clean styling for every chart."""
    return (
        chart.configure_view(strokeWidth=0)
        .configure_axis(
            labelFontSize=12,
            titleFontSize=13,
            titleFontWeight=700,
            labelFontWeight=600,
            labelColor=TEXT_DARK,
            titleColor=TEXT_DARK,
            gridColor=GRID,
            domainColor="#cbd5e1",
            tickColor="#cbd5e1",
        )
        .configure_legend(
            labelFontSize=12,
            titleFontSize=13,
            labelFontWeight=600,
            labelColor=TEXT_DARK,
            titleColor=TEXT_DARK,
        )
        .configure_title(fontSize=14, color=TEXT_DARK)
    )


def level_scale():
    return alt.Scale(domain=LEVEL_ORDER, range=[LEVEL_COLORS[k] for k in LEVEL_ORDER])


def signal_scale():
    return alt.Scale(domain=SIGNALS, range=[SIGNAL_COLORS[s] for s in SIGNALS])


def build_technique_df(results: list) -> pd.DataFrame:
    basis, basis_name = strength_basis(results)
    strengths = relative_strength(basis)

    rows = []
    for r, raw_basis, strength in zip(results, basis, strengths):
        tid = str(r.get("technique_id", "?"))
        tname = str(r.get("technique_name", "Unknown"))
        rows.append({
            "ID": tid,
            "Technique": tname,
            "Label": f"{tid} · {tname}",
            "Raw": raw_basis,
            "Strength": round(strength, 1),
            "Level": level_of(strength),
            "ML": to_float(r.get("ml_score")),
            "Semantic": to_float(r.get("semantic_score")),
            "Evidence": to_float(r.get("evidence_score")),
            "Tactics": split_tactics(r.get("tactics", "")),
        })

    df = pd.DataFrame(rows)
    if df.empty:
        df = pd.DataFrame(columns=["ID", "Technique", "Label", "Raw", "Strength", "Level",
                                   "ML", "Semantic", "Evidence", "Tactics"])
    df.attrs["basis"] = basis_name
    return df


def build_sequence_df(sequence: list) -> pd.DataFrame:
    raws = [to_float(s.get("score")) for s in sequence]
    strengths = relative_strength(raws)

    rows = []
    for index, (step, raw, strength) in enumerate(zip(sequence, raws, strengths), start=1):
        rows.append({
            "Step": int(to_float(step.get("step"), index)),
            "Tactic": str(step.get("tactic") or "unknown"),
            "Technique": f"{step.get('technique_id', '')} {step.get('technique_name', '')}".strip(),
            "Raw": raw,
            "Strength": round(strength, 1),
            "Level": level_of(strength),
        })

    return pd.DataFrame(rows, columns=["Step", "Tactic", "Technique", "Raw", "Strength", "Level"])


# ============================================================
# CHARTS
# ============================================================

def strength_bar_chart(df: pd.DataFrame):
    """Horizontal bars, strongest detection at the top."""
    order = list(df["Label"])
    height = max(200, 40 * len(df) + 40)

    bars = (
        alt.Chart(df)
        .mark_bar(cornerRadiusEnd=6, height=22)
        .encode(
            y=alt.Y("Label:N", sort=order, title=None,
                    axis=alt.Axis(labelLimit=340, labelFontWeight=600, labelPadding=8)),
            x=alt.X("Strength:Q", title="Relative strength (0–100)",
                    scale=alt.Scale(domain=[0, 100])),
            color=alt.Color("Level:N", scale=level_scale(),
                            legend=alt.Legend(title="Level", orient="top")),
            tooltip=[
                alt.Tooltip("Technique:N", title="Technique"),
                alt.Tooltip("ID:N", title="ID"),
                alt.Tooltip("Strength:Q", title="Strength", format=".1f"),
                alt.Tooltip("Raw:Q", title="Raw score", format=".4g"),
                alt.Tooltip("Level:N", title="Level"),
            ],
        )
    )

    labels = (
        alt.Chart(df)
        .mark_text(align="left", dx=6, fontWeight=700, fontSize=12, color=TEXT_DARK)
        .encode(
            y=alt.Y("Label:N", sort=order),
            x=alt.X("Strength:Q", scale=alt.Scale(domain=[0, 100])),
            text=alt.Text("Strength:Q", format=".0f"),
        )
    )

    return style_chart((bars + labels).properties(height=height))


def signal_grouped_chart(df: pd.DataFrame):
    """Raw ML, semantic and evidence values per technique, with a zero line."""
    long_df = df.melt(
        id_vars=["ID", "Label"], value_vars=SIGNALS,
        var_name="Signal", value_name="Value",
    )
    order = list(df["Label"])

    bars = (
        alt.Chart(long_df)
        .mark_bar(cornerRadiusTopLeft=3, cornerRadiusTopRight=3)
        .encode(
            x=alt.X("Label:N", sort=order, title=None,
                    axis=alt.Axis(labelAngle=-35, labelLimit=260, labelFontWeight=600)),
            xOffset=alt.XOffset("Signal:N", sort=SIGNALS),
            y=alt.Y("Value:Q", title="Raw signal value"),
            color=alt.Color("Signal:N", scale=signal_scale(),
                            legend=alt.Legend(title="Signal", orient="top")),
            tooltip=[
                alt.Tooltip("Label:N", title="Technique"),
                alt.Tooltip("Signal:N", title="Signal"),
                alt.Tooltip("Value:Q", title="Raw value", format=".4g"),
            ],
        )
    )

    zero = alt.Chart(pd.DataFrame({"y": [0]})).mark_rule(color="#475569", strokeDash=[4, 4]).encode(y="y:Q")

    return style_chart((bars + zero).properties(height=340))


def signal_heatmap(df: pd.DataFrame):
    """Diverging heatmap: blue for positive, red for negative, white near zero."""
    long_df = df.melt(
        id_vars=["ID", "Label"], value_vars=SIGNALS,
        var_name="Signal", value_name="Value",
    )
    order = list(df["Label"])
    limit = max(abs(long_df["Value"].min() if not long_df.empty else 0),
                abs(long_df["Value"].max() if not long_df.empty else 0), 0.0001)

    base = alt.Chart(long_df)
    rects = base.mark_rect(cornerRadius=4).encode(
        x=alt.X("Signal:N", title=None, sort=SIGNALS,
                axis=alt.Axis(orient="top", labelFontWeight=800, labelFontSize=13)),
        y=alt.Y("Label:N", sort=order, title=None,
                axis=alt.Axis(labelLimit=300, labelFontWeight=600)),
        color=alt.Color(
            "Value:Q",
            scale=alt.Scale(scheme="redblue", domain=[-limit, limit], domainMid=0, reverse=True),
            legend=alt.Legend(title="Raw value", orient="bottom", gradientLength=300),
        ),
        tooltip=[
            alt.Tooltip("Label:N", title="Technique"),
            alt.Tooltip("Signal:N", title="Signal"),
            alt.Tooltip("Value:Q", title="Raw value", format=".4g"),
        ],
    )

    text = base.mark_text(fontWeight=700, fontSize=12).encode(
        x=alt.X("Signal:N", sort=SIGNALS),
        y=alt.Y("Label:N", sort=order),
        text=alt.Text("Value:Q", format=".2f"),
        color=alt.condition(f"abs(datum.Value) > {limit * 0.55}", alt.value("#ffffff"), alt.value(TEXT_DARK)),
    )

    height = max(220, 34 * len(df) + 80)
    return style_chart((rects + text).properties(height=height))


def tactic_donut(df: pd.DataFrame):
    exploded = df[["ID", "Tactics"]].explode("Tactics").dropna()
    exploded = exploded[exploded["Tactics"] != ""]
    counts = exploded.groupby("Tactics").size().reset_index(name="Techniques")

    chart = (
        alt.Chart(counts)
        .mark_arc(innerRadius=70, outerRadius=130, padAngle=0.02, cornerRadius=5)
        .encode(
            theta=alt.Theta("Techniques:Q"),
            color=alt.Color("Tactics:N", scale=alt.Scale(scheme="category20"),
                            legend=alt.Legend(title="Tactic", orient="bottom", columns=2)),
            tooltip=[
                alt.Tooltip("Tactics:N", title="Tactic"),
                alt.Tooltip("Techniques:Q", title="Techniques"),
            ],
        )
        .properties(height=340)
    )
    return style_chart(chart)


def tactic_bar_chart(df: pd.DataFrame):
    exploded = df[["ID", "Tactics"]].explode("Tactics").dropna()
    exploded = exploded[exploded["Tactics"] != ""]
    counts = exploded.groupby("Tactics").size().reset_index(name="Techniques")
    counts = counts.sort_values("Techniques", ascending=False)
    order = list(counts["Tactics"])

    chart = (
        alt.Chart(counts)
        .mark_bar(cornerRadiusEnd=5, color="#6366f1")
        .encode(
            y=alt.Y("Tactics:N", sort=order, title=None,
                    axis=alt.Axis(labelLimit=200, labelFontWeight=600)),
            x=alt.X("Techniques:Q", title="Techniques mapped", axis=alt.Axis(tickMinStep=1)),
            tooltip=[alt.Tooltip("Tactics:N", title="Tactic"),
                     alt.Tooltip("Techniques:Q", title="Techniques")],
        )
    )
    labels = (
        alt.Chart(counts)
        .mark_text(align="left", dx=5, fontWeight=700, color=TEXT_DARK)
        .encode(
            y=alt.Y("Tactics:N", sort=order),
            x="Techniques:Q",
            text="Techniques:Q",
        )
    )
    height = max(220, 34 * len(counts) + 60)
    return style_chart((chart + labels).properties(height=height))


def kill_chain_matrix(seq_df: pd.DataFrame):
    """Tactics in kill-chain order (rows), attack steps across (columns)."""
    tactics = sorted(seq_df["Tactic"].unique(), key=tactic_rank)
    height = max(260, 40 * len(tactics) + 60)

    base = alt.Chart(seq_df)
    x_enc = alt.X("Step:O", title="Attack step", axis=alt.Axis(labelAngle=0, labelFontWeight=700))
    y_enc = alt.Y("Tactic:N", sort=tactics, title=None,
                  axis=alt.Axis(labelLimit=200, labelFontWeight=600))

    line = base.mark_line(color="#94a3b8", strokeWidth=2, opacity=0.7).encode(
        x=alt.X("Step:Q", axis=alt.Axis(tickMinStep=1, format="d", title="Attack step")),
        y=y_enc,
        order=alt.Order("Step:Q"),
    )

    points = base.mark_circle(size=260, stroke="#ffffff", strokeWidth=2).encode(
        x=x_enc,
        y=y_enc,
        color=alt.Color("Level:N", scale=level_scale(),
                        legend=alt.Legend(title="Level", orient="top")),
        tooltip=[
            alt.Tooltip("Step:O", title="Step"),
            alt.Tooltip("Tactic:N", title="Tactic"),
            alt.Tooltip("Technique:N", title="Technique"),
            alt.Tooltip("Strength:Q", title="Strength", format=".1f"),
            alt.Tooltip("Raw:Q", title="Raw score", format=".4g"),
        ],
    )

    return style_chart((line + points).properties(height=height))


def step_strength_chart(seq_df: pd.DataFrame):
    chart = (
        alt.Chart(seq_df)
        .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
        .encode(
            x=alt.X("Step:O", title="Attack step", axis=alt.Axis(labelAngle=0, labelFontWeight=700)),
            y=alt.Y("Strength:Q", title="Relative strength (0–100)", scale=alt.Scale(domain=[0, 100])),
            color=alt.Color("Level:N", scale=level_scale(),
                            legend=alt.Legend(title="Level", orient="top")),
            tooltip=[
                alt.Tooltip("Step:O", title="Step"),
                alt.Tooltip("Tactic:N", title="Tactic"),
                alt.Tooltip("Technique:N", title="Technique"),
                alt.Tooltip("Strength:Q", title="Strength", format=".1f"),
                alt.Tooltip("Raw:Q", title="Raw score", format=".4g"),
            ],
        )
        .properties(height=340)
    )
    return style_chart(chart)


# ============================================================
# COMPONENT RENDERERS
# ============================================================

def gauge_html(percentage: float, label: str) -> str:
    pct = max(0.0, min(percentage, 100.0))
    color = LEVEL_COLORS[level_of(pct)]
    return (
        f'<div class="gauge-wrap">'
        f'<div class="gauge" style="background:conic-gradient({color} {pct}%, rgba(148,163,184,0.25) 0);">'
        f'<div class="gauge-inner">'
        f'<div class="gauge-value">{pct:.0f}</div>'
        f'<div class="gauge-label">{esc(label)}</div>'
        f'</div></div></div>'
    )


def render_technique_card(result: dict, index: int, strength: float) -> None:
    technique_id = result.get("technique_id", "Unknown")
    technique_name = result.get("technique_name", "Unknown")
    tactics = split_tactics(result.get("tactics", ""))
    raw = to_float(result.get("final_score"))
    evidence = result.get("evidence", "")
    context = result.get("context", "")
    status = result.get("status", "")
    explanation = result.get("explanation", "")

    level = level_of(strength)
    color = LEVEL_COLORS[level]
    delay = round(index * 0.06, 2)

    chips = "".join(f'<span class="chip">{esc(t)}</span>' for t in tactics)
    context_html = f'<div class="meta-line"><b>Context:</b> {esc(context)}</div>' if context else ""
    status_html = f'<div class="meta-line"><b>Status:</b> {esc(status)}</div>' if status else ""
    evidence_html = (
        f'<div class="evidence-box"><div class="evidence-label">🔎 Evidence</div>{esc(evidence)}</div>'
    ) if evidence else ""

    st.markdown(
        f'<div class="tcard" style="--delay:{delay}s;">'
        f'<div class="tcard-head">'
        f'<div><div class="tech-id">{esc(technique_id)}</div>'
        f'<div class="tech-name">{esc(technique_name)}</div></div>'
        f'<div class="score-badge">'
        f'<div class="score-value" style="color:{color};">{strength:.0f} / 100</div>'
        f'<div class="score-raw">raw score {fmt_raw(raw)}</div>'
        f'<div class="score-level" style="color:{color};">{level} strength</div>'
        f'</div></div>'
        f'<div class="bar"><div class="bar-fill" '
        f'style="width:{min(strength, 100):.1f}%; background:linear-gradient(90deg, {color}, #ffffff80);"></div></div>'
        f'<div>{chips}</div>'
        f'{context_html}{status_html}{evidence_html}'
        f'</div>',
        unsafe_allow_html=True,
    )

    if explanation:
        with st.expander("💡 Why was this technique detected?"):
            st.write(explanation)

    with st.expander("🧪 Model details"):
        c1, c2, c3 = st.columns(3)
        c1.metric("ML score", fmt_raw(result.get("ml_score", 0)))
        c2.metric("Semantic score", fmt_raw(result.get("semantic_score", 0)))
        c3.metric("Evidence score", fmt_raw(result.get("evidence_score", 0)))


def render_sequence_step(step: dict, index: int, strength: float) -> None:
    raw = to_float(step.get("score"))
    color = LEVEL_COLORS[level_of(strength)]
    delay = round(index * 0.08, 2)

    st.markdown(
        f'<div class="seq" style="--delay:{delay}s;">'
        f'<div class="seq-num" style="--delay:{delay}s;">{esc(step.get("step", index + 1))}</div>'
        f'<div class="seq-body">'
        f'<span class="chip">{esc(step.get("tactic", ""))}</span>'
        f'<div class="seq-title"><span class="seq-id">{esc(step.get("technique_id", ""))}</span>'
        f'{esc(step.get("technique_name", ""))}</div>'
        f'<div class="seq-ev">{esc(step.get("evidence", ""))}</div>'
        f'</div>'
        f'<div class="seq-score" style="color:{color};">{strength:.0f}'
        f'<small>raw {fmt_raw(raw)}</small></div>'
        f'</div>',
        unsafe_allow_html=True,
    )


def submit_feedback(analysis_id, technique_id, correct: bool) -> None:
    try:
        response = requests.post(
            f"{BACKEND_URL}/feedback",
            json={"analysis_id": analysis_id, "technique_id": technique_id, "correct": correct},
            timeout=10,
        )
        if response.status_code == 200:
            if correct:
                st.balloons()
            st.success("Feedback recorded. Thank you!")
        else:
            st.error(response.text)
    except Exception as error:
        st.error(str(error))


# ============================================================
# HERO
# ============================================================

st.markdown(
    """
    <div class="hero">
        <span class="hero-eyebrow">Threat Intelligence Platform</span>
        <div class="hero-title">🛡️ MITRE ATT&amp;CK Technique Mapper</div>
        <div class="hero-sub">
            Turn raw incident reports into mapped adversary techniques,
            visual insights, and a reconstructed attack sequence.
        </div>
        <div class="hero-tags">
            <span class="hero-tag">ATT&amp;CK v19.2</span>
            <span class="hero-tag">TF-IDF + Linear SVM</span>
            <span class="hero-tag">Hybrid ML + Semantic</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# BACKEND HEALTH CHECK
# ============================================================

try:
    health_response = requests.get(f"{BACKEND_URL}/health", timeout=5)

    if health_response.status_code == 200:
        health_data = health_response.json()
        if health_data.get("mapper_loaded"):
            st.markdown(status_pill("ok", "Backend connected • ML model loaded"), unsafe_allow_html=True)
        else:
            st.markdown(status_pill("err", "Backend running, but ML mapper is not loaded"), unsafe_allow_html=True)
    else:
        st.markdown(status_pill("warn", "Backend responded with an unexpected status"), unsafe_allow_html=True)

except requests.exceptions.RequestException:
    st.markdown(status_pill("err", "Backend is offline. Start the FastAPI server first"), unsafe_allow_html=True)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:
    st.markdown("### ⚙️ System")
    st.markdown(
        '<div class="side-item"><span>ATT&amp;CK version</span><span>19.2</span></div>'
        '<div class="side-item"><span>Classifier</span><span>TF-IDF + SVM</span></div>'
        '<div class="side-item"><span>Architecture</span><span>Hybrid ML + Semantic</span></div>',
        unsafe_allow_html=True,
    )

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("### 🔎 How it works")
    st.markdown(
        '<div class="side-note">'
        "<b>1.</b> Paste an incident or threat report.<br>"
        "<b>2.</b> The system identifies likely MITRE ATT&amp;CK techniques.<br>"
        "<b>3.</b> Explore the charts, evidence, and attack path.<br>"
        "<b>4.</b> Give analyst feedback to improve future models."
        "</div>",
        unsafe_allow_html=True,
    )

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("### 🎨 Strength legend")
    st.markdown(
        '<div class="side-note">'
        '<span style="color:#4ade80;font-weight:800;">● Strong</span> 70–100<br>'
        '<span style="color:#fbbf24;font-weight:800;">● Moderate</span> 40–69<br>'
        '<span style="color:#fb7185;font-weight:800;">● Weak</span> 0–39'
        '<br><br>Strength is relative to the other detections in the same report.'
        "</div>",
        unsafe_allow_html=True,
    )


# ============================================================
# INPUT
# ============================================================

st.markdown('<div class="section-title">📄 Threat Report</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="section-sub">Paste the incident narrative, log summary, or threat intel write-up.</div>',
    unsafe_allow_html=True,
)

report = st.text_area(
    "Threat report",
    value=DEFAULT_REPORT,
    height=200,
    placeholder="Enter threat intelligence report...",
    label_visibility="collapsed",
)

analyze_button = st.button("🚀  Analyze Report", type="primary", use_container_width=True)


# ============================================================
# ANALYSIS
# ============================================================

def run_analysis(text: str) -> None:
    """Send a report to the backend and store the result in session state."""
    try:
        response = requests.post(
            f"{BACKEND_URL}/analyze",
            json={"report": text},
            timeout=120,
        )
        if response.status_code != 200:
            st.error("Analysis failed.")
            st.code(response.text)
        else:
            st.session_state["analysis"] = response.json()
            st.session_state["analysed_text"] = text
    except requests.exceptions.RequestException as error:
        st.error("Could not connect to the backend.")
        st.code(str(error))


if "analysis" not in st.session_state:
    with st.spinner("🧠 Running sample analysis..."):
        run_analysis(DEFAULT_REPORT)

if analyze_button:
    if not report.strip():
        st.warning("Please enter a threat report.")
    elif len(report.strip()) < 10:
        st.warning("Please enter a more detailed threat report.")
    else:
        with st.spinner("🧠 Analyzing threat report..."):
            run_analysis(report)


# ============================================================
# RESULTS
# ============================================================

if "analysis" in st.session_state:

    data = st.session_state["analysis"]
    results = data.get("results", [])
    sequence = data.get("attack_sequence", [])
    analysis_id = data.get("analysis_id")
    mitre_version = data.get("mitre_version", "Unknown")

    tech_df = build_technique_df(results)
    if not tech_df.empty:
        tech_df = tech_df.sort_values("Strength", ascending=False).reset_index(drop=True)
    seq_df = build_sequence_df(sequence)

    basis_name = tech_df.attrs.get("basis", "final score")
    has_techniques = not tech_df.empty
    has_sequence = not seq_df.empty

    strong_count = int((tech_df["Strength"] >= 70).sum()) if has_techniques else 0
    avg_strength = round(float(tech_df["Strength"].mean()), 1) if has_techniques else 0.0
    unique_tactics = int(tech_df["Tactics"].explode().dropna().nunique()) if has_techniques else 0

    # ---------- Summary ----------
    st.divider()
    st.markdown('<div class="section-title">📊 Analysis Summary</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">A live snapshot of this analysis run.</div>', unsafe_allow_html=True)

    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        st.markdown(kpi_card("Detected", len(results), "🎯", "#4f46e5", "#7c3aed", 0.0), unsafe_allow_html=True)
    with k2:
        st.markdown(kpi_card("Strong (70+)", strong_count, "✅", "#047857", "#0891b2", 0.08), unsafe_allow_html=True)
    with k3:
        st.markdown(kpi_card("Attack steps", len(sequence), "🔗", "#be185d", "#ea580c", 0.16), unsafe_allow_html=True)
    with k4:
        st.markdown(kpi_card("Tactics covered", unique_tactics, "🗺️", "#0e7490", "#4f46e5", 0.24), unsafe_allow_html=True)
    with k5:
        st.markdown(
            kpi_card("Analysis ID", analysis_id if analysis_id is not None else "—", "🧾", "#a16207", "#c2410c", 0.32),
            unsafe_allow_html=True,
        )

    st.caption(f"MITRE ATT&CK version {mitre_version}")

    if has_techniques and basis_name == "signal average":
        st.info(
            "The backend returned 0 as the final score for every technique, so strength is "
            "calculated from the average of the ML, semantic, and evidence scores."
        )

    # ---------- Visual insights ----------
    st.divider()
    st.markdown('<div class="section-title">📈 Visual Insights</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-sub">Strength, signal breakdown, tactic coverage, and attack progression.</div>',
        unsafe_allow_html=True,
    )

    if not has_techniques and not has_sequence:
        st.info("Not enough data to render visual insights.")
    else:
        tab1, tab2, tab3, tab4 = st.tabs([
            "📊 Strength",
            "🔥 Signal analysis",
            "🗺️ Tactic coverage",
            "⏱️ Attack timeline",
        ])

        with tab1:
            if not has_techniques:
                st.info("No techniques to chart.")
            else:
                g_col, c_col = st.columns([1, 2])
                with g_col:
                    chart_panel("Average strength", f"Based on the {basis_name}.")
                    st.markdown(gauge_html(avg_strength, "Average"), unsafe_allow_html=True)
                    st.metric("Top raw score", fmt_raw(tech_df["Raw"].max()))
                with c_col:
                    chart_panel("Strength by technique", "Scaled so the strongest detection reaches 100. Hover for raw values.")
                    st.altair_chart(strength_bar_chart(tech_df), use_container_width=True)

        with tab2:
            if not has_techniques:
                st.info("No signal data to chart.")
            else:
                s_col1, s_col2 = st.columns(2)
                with s_col1:
                    chart_panel("Signal comparison", "Raw ML, semantic and evidence values for each technique.")
                    st.altair_chart(signal_grouped_chart(tech_df), use_container_width=True)
                with s_col2:
                    chart_panel("Signal heatmap", "Blue is positive, red is negative, white is near zero.")
                    st.altair_chart(signal_heatmap(tech_df), use_container_width=True)

        with tab3:
            if not has_techniques or tech_df["Tactics"].explode().dropna().empty:
                st.info("No tactic data to chart.")
            else:
                t_col1, t_col2 = st.columns(2)
                with t_col1:
                    chart_panel("Tactic distribution", "Share of detected techniques per ATT&CK tactic.")
                    st.altair_chart(tactic_donut(tech_df), use_container_width=True)
                with t_col2:
                    chart_panel("Techniques per tactic", "How many detections map to each tactic.")
                    st.altair_chart(tactic_bar_chart(tech_df), use_container_width=True)

        with tab4:
            if not has_sequence:
                st.info("No attack sequence to chart.")
            else:
                a_col1, a_col2 = st.columns([3, 2])
                with a_col1:
                    chart_panel("Kill-chain path", "Rows follow the ATT&CK kill chain. Each dot is one attack step.")
                    st.altair_chart(kill_chain_matrix(seq_df), use_container_width=True)
                with a_col2:
                    chart_panel("Strength per step", "Colored by strength level.")
                    st.altair_chart(step_strength_chart(seq_df), use_container_width=True)

    # ---------- Techniques ----------
    st.divider()
    st.markdown('<div class="section-title">🎯 Detected Techniques</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">Ranked by strength, highest first.</div>', unsafe_allow_html=True)

    if not has_techniques:
        st.info("No techniques were detected.")
    else:
        ordered_results = sorted(
            results,
            key=lambda r: tech_df.loc[
                tech_df["ID"] == str(r.get("technique_id", "?")), "Strength"
            ].max() if False else 0,
        )
        for index, row in tech_df.iterrows():
            match = next(
                (r for r in results if str(r.get("technique_id", "?")) == row["ID"]
                 and str(r.get("technique_name", "Unknown")) == row["Technique"]),
                None,
            )
            if match is not None:
                render_technique_card(match, index, row["Strength"])

    # ---------- Attack sequence ----------
    st.divider()
    st.markdown('<div class="section-title">🔗 Attack Sequence</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-sub">Reconstructed progression of the adversary across the kill chain.</div>',
        unsafe_allow_html=True,
    )

    if has_sequence:
        for index, (step, strength) in enumerate(zip(sequence, seq_df["Strength"].tolist())):
            render_sequence_step(step, index, strength)
    else:
        st.info("No attack sequence was generated.")

    # ---------- Feedback ----------
    st.divider()
    st.markdown('<div class="section-title">👨‍💻 Analyst Feedback</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-sub">Your review helps evaluate the model and guides future retraining.</div>',
        unsafe_allow_html=True,
    )

    if results:
        feedback_options = {
            f"{r.get('technique_id')} — {r.get('technique_name')}": r.get("technique_id")
            for r in results
        }
        selected = st.selectbox("Select a technique to review", list(feedback_options.keys()))
        selected_id = feedback_options[selected]

        fb1, fb2 = st.columns(2)
        with fb1:
            if st.button("✅  Correct", use_container_width=True):
                submit_feedback(analysis_id, selected_id, True)
        with fb2:
            if st.button("❌  Incorrect", use_container_width=True):
                submit_feedback(analysis_id, selected_id, False)


# ============================================================
# FOOTER
# ============================================================

st.divider()
st.markdown(
    '<div class="footer">MITRE ATT&amp;CK Technique Mapper • Context-aware hybrid ML system</div>',
    unsafe_allow_html=True,
)