"""
SIEM Dashboard
--------------
Run with: python3 dashboard.py
Then open: http://localhost:8050

Requires: pip install dash plotly pandas
"""

import sqlite3
import pandas as pd
from datetime import datetime, timedelta
from dash import Dash, dcc, html, Input, Output, callback_context
import plotly.graph_objects as go
import plotly.express as px

DB = "siem.db"

# ─── Color palette ───────────────────────────
C = {
    "bg":        "#0B0E14",
    "surface":   "#111520",
    "border":    "#1E2535",
    "border2":   "#2A3348",
    "text":      "#CDD6F4",
    "muted":     "#6C7A96",
    "accent":    "#7EB8F7",
    "green":     "#A6E3A1",
    "yellow":    "#F9E2AF",
    "red":       "#F38BA8",
    "orange":    "#FAB387",
    "purple":    "#CBA6F7",
    "teal":      "#94E2D5",
}

TAG_COLORS = {
    "failed_login":     C["red"],
    "invalid_user":     C["orange"],
    "successful_login": C["green"],
    "session_opened":   C["teal"],
    "session_closed":   C["muted"],
    "sudo":             C["yellow"],
    "cron":             C["purple"],
    "connection_closed":C["muted"],
    "disconnected":     C["muted"],
    "normal":           C["border2"],
}

PLOT_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="'JetBrains Mono', 'Fira Code', monospace", color=C["muted"], size=11),
    margin=dict(l=12, r=12, t=32, b=12),
    xaxis=dict(gridcolor=C["border"], showline=False, zeroline=False, tickfont=dict(size=10)),
    yaxis=dict(gridcolor=C["border"], showline=False, zeroline=False, tickfont=dict(size=10)),
    legend=dict(bgcolor="rgba(0,0,0,0)", borderwidth=0, font=dict(size=10)),
    hoverlabel=dict(bgcolor=C["surface"], bordercolor=C["border2"], font_color=C["text"]),
)

# ─── Data fetchers ────────────────────────────

def get_logs(hours=24):
    conn = sqlite3.connect(DB)
    try:
        df = pd.read_sql(
            f"SELECT * FROM logs ORDER BY id DESC LIMIT 5000",
            conn, parse_dates=["timestamp"]
        )
    except Exception:
        df = pd.DataFrame(columns=["id","timestamp","host","program","message","tag","src_ip"])
    conn.close()
    if not df.empty:
        cutoff = pd.Timestamp.now() - pd.Timedelta(hours=hours)
        df = df[df["timestamp"] > cutoff]
    return df

def get_alerts():
    conn = sqlite3.connect(DB)
    try:
        df = pd.read_sql("SELECT * FROM alerts ORDER BY id DESC LIMIT 50", conn, parse_dates=["timestamp"])
    except Exception:
        df = pd.DataFrame(columns=["id","timestamp","alert_type","detail","sent_via"])
    conn.close()
    return df

# ─── Reusable card wrapper ────────────────────

def card(children, style=None):
    base = {
        "background": C["surface"],
        "border": f"1px solid {C['border']}",
        "borderRadius": "8px",
        "padding": "16px 20px",
    }
    if style:
        base.update(style)
    return html.Div(children, style=base)

def kpi_card(label, value, color=C["text"], sub=None):
    return card([
        html.Div(label, style={"fontSize": "10px", "letterSpacing": "0.1em",
                               "textTransform": "uppercase", "color": C["muted"], "marginBottom": "6px"}),
        html.Div(str(value), style={"fontSize": "32px", "fontWeight": "700",
                                    "color": color, "fontFamily": "'JetBrains Mono', monospace",
                                    "lineHeight": "1"}),
        html.Div(sub or "", style={"fontSize": "10px", "color": C["muted"], "marginTop": "4px"}),
    ], style={"flex": "1", "minWidth": "130px"})

def section_header(title, icon=""):
    return html.Div([
        html.Span(icon + " " if icon else "", style={"marginRight": "6px"}),
        html.Span(title),
    ], style={"fontSize": "11px", "letterSpacing": "0.08em", "textTransform": "uppercase",
              "color": C["muted"], "marginBottom": "10px", "fontWeight": "600"})

# ─── App layout ───────────────────────────────

app = Dash(__name__, title="SIEM Dashboard")

app.index_string = '''
<!DOCTYPE html>
<html>
<head>
  {%metas%}
  <title>{%title%}</title>
  {%favicon%}
  {%css%}
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html, body { background: #0B0E14; color: #CDD6F4; font-family: "JetBrains Mono", monospace; }
    ::-webkit-scrollbar { width: 4px; }
    ::-webkit-scrollbar-track { background: #0B0E14; }
    ::-webkit-scrollbar-thumb { background: #1E2535; border-radius: 4px; }
    .dash-graph .modebar { display: none !important; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
    .live-dot { width:6px;height:6px;border-radius:50%;background:#A6E3A1;
                display:inline-block;margin-right:6px;animation:pulse 2s infinite; }
    .alert-row:nth-child(even) { background: rgba(30,37,53,0.4); }
  </style>
</head>
<body>{%app_entry%}<footer>{%config%}{%scripts%}{%renderer%}</footer></body>
</html>
'''

app.layout = html.Div([

    dcc.Interval(id="tick", interval=5000),

    # ── Top bar ──────────────────────────────
    html.Div([
        html.Div([
            html.Span(className="live-dot"),
            html.Span("SIEM", style={"fontFamily": "'Syne', sans-serif", "fontWeight": "800",
                                     "fontSize": "18px", "color": C["text"], "letterSpacing": "0.05em"}),
            html.Span(" // Security Dashboard",
                      style={"fontSize": "12px", "color": C["muted"], "marginLeft": "8px"}),
        ], style={"display": "flex", "alignItems": "center"}),
        html.Div(id="clock", style={"fontSize": "11px", "color": C["muted"], "fontFamily": "'JetBrains Mono', monospace"}),
    ], style={
        "display": "flex", "justifyContent": "space-between", "alignItems": "center",
        "padding": "14px 24px", "borderBottom": f"1px solid {C['border']}",
        "background": C["surface"], "position": "sticky", "top": "0", "zIndex": "100",
    }),

    # ── Main content ─────────────────────────
    html.Div([

        # ── KPI row ──
        html.Div(id="kpi-row", style={"display": "flex", "gap": "12px", "flexWrap": "wrap", "marginBottom": "16px"}),

        # ── Row 2: timeline + tag breakdown ──
        html.Div([
            card([
                section_header("Events over time", "◈"),
                dcc.Graph(id="timeline-chart", config={"displayModeBar": False},
                          style={"height": "220px"}),
            ], style={"flex": "2", "minWidth": "300px"}),

            card([
                section_header("Event types", "◈"),
                dcc.Graph(id="tag-chart", config={"displayModeBar": False},
                          style={"height": "220px"}),
            ], style={"flex": "1", "minWidth": "220px"}),
        ], style={"display": "flex", "gap": "12px", "marginBottom": "16px", "flexWrap": "wrap"}),

        # ── Row 3: top IPs + alerts ──
        html.Div([
            card([
                section_header("Top source IPs", "◈"),
                dcc.Graph(id="ip-chart", config={"displayModeBar": False},
                          style={"height": "200px"}),
            ], style={"flex": "1", "minWidth": "240px"}),

            card([
                section_header("Alert feed", "⚡"),
                html.Div(id="alert-feed", style={"overflowY": "auto", "maxHeight": "200px",
                                                  "fontSize": "11px"}),
            ], style={"flex": "1", "minWidth": "240px"}),
        ], style={"display": "flex", "gap": "12px", "marginBottom": "16px", "flexWrap": "wrap"}),

        # ── Row 4: live log tail ──
        card([
            section_header("Live log tail — last 50 events", "▸"),
            html.Div(id="log-tail", style={
                "fontFamily": "'JetBrains Mono', monospace", "fontSize": "11px",
                "overflowY": "auto", "maxHeight": "240px", "lineHeight": "1.8",
            }),
        ]),

    ], style={"padding": "20px 24px", "maxWidth": "1400px", "margin": "0 auto"}),

], style={"minHeight": "100vh", "background": C["bg"]})

# ─── Callbacks ────────────────────────────────

@app.callback(
    Output("clock", "children"),
    Output("kpi-row", "children"),
    Output("timeline-chart", "figure"),
    Output("tag-chart", "figure"),
    Output("ip-chart", "figure"),
    Output("alert-feed", "children"),
    Output("log-tail", "children"),
    Input("tick", "n_intervals"),
)
def refresh(_):
    df = get_logs(24)
    alerts_df = get_alerts()
    now = datetime.now()

    # ── Clock ──
    clock = now.strftime("%Y-%m-%d  %H:%M:%S")

    # ── KPIs ──
    total = len(df)
    failed = len(df[df.tag == "failed_login"]) if not df.empty else 0
    success = len(df[df.tag == "successful_login"]) if not df.empty else 0
    alert_count = len(alerts_df)
    unique_ips = df["src_ip"].nunique() if not df.empty and "src_ip" in df.columns else 0

    last_alert_str = ""
    if not alerts_df.empty:
        last = alerts_df.iloc[0]
        last_alert_str = last["alert_type"].replace("_", " ")

    kpis = [
        kpi_card("Total events / 24h", total, C["text"]),
        kpi_card("Failed logins", failed, C["red"] if failed > 0 else C["text"],
                 sub="brute force indicator"),
        kpi_card("Successful logins", success, C["green"]),
        kpi_card("Unique IPs", unique_ips, C["accent"]),
        kpi_card("Alerts fired", alert_count, C["yellow"] if alert_count > 0 else C["text"],
                 sub=last_alert_str),
    ]

    # ── Timeline chart ──
    if df.empty:
        timeline_fig = go.Figure(layout={**PLOT_LAYOUT, "title": {"text": "no data", "font": {"color": C["muted"]}}})
    else:
        df["minute"] = df["timestamp"].dt.floor("5min")
        top_tags = df["tag"].value_counts().head(5).index.tolist()
        tdf = df[df["tag"].isin(top_tags)].groupby(["minute", "tag"]).size().reset_index(name="count")
        timeline_fig = go.Figure()
        for tag in top_tags:
            sub = tdf[tdf.tag == tag]
            timeline_fig.add_trace(go.Scatter(
                x=sub["minute"], y=sub["count"], name=tag,
                line=dict(color=TAG_COLORS.get(tag, C["muted"]), width=1.5),
                fill="tozeroy", fillcolor="rgba(126,184,247,0.08)",
                mode="lines",
            ))
        timeline_fig.update_layout(**PLOT_LAYOUT, showlegend=True)

    # ── Tag donut ──
    if df.empty:
        tag_fig = go.Figure(layout={**PLOT_LAYOUT})
    else:
        tag_counts = df["tag"].value_counts().reset_index()
        tag_counts.columns = ["tag", "count"]
        tag_fig = go.Figure(go.Pie(
            labels=tag_counts["tag"],
            values=tag_counts["count"],
            hole=0.6,
            marker_colors=[TAG_COLORS.get(t, C["muted"]) for t in tag_counts["tag"]],
            textinfo="none",
            hovertemplate="<b>%{label}</b><br>%{value} events<extra></extra>",
        ))
        tag_fig.update_layout(
            **PLOT_LAYOUT,
            showlegend=True
        )

    # ── Top IPs ──
    if df.empty or "src_ip" not in df.columns:
        ip_fig = go.Figure(layout={**PLOT_LAYOUT})
    else:
        ip_df = df[df["src_ip"] != ""].groupby("src_ip").size().reset_index(name="count")
        ip_df = ip_df.sort_values("count", ascending=True).tail(8)
        ip_fig = go.Figure(go.Bar(
            x=ip_df["count"], y=ip_df["src_ip"],
            orientation="h",
            marker=dict(
                color=ip_df["count"],
                colorscale=[[0, C["border2"]], [0.5, C["accent"]], [1, C["red"]]],
            ),
            text=ip_df["count"], textposition="auto",
            hovertemplate="<b>%{y}</b><br>%{x} events<extra></extra>",
        ))
        ip_fig.update_layout(
                **PLOT_LAYOUT
        )

    # ── Alert feed ──
    if alerts_df.empty:
        alert_items = [html.Div("No alerts fired yet.",
                                style={"color": C["muted"], "padding": "8px 0"})]
    else:
        alert_items = []
        for _, row in alerts_df.iterrows():
            ts = row["timestamp"].strftime("%H:%M:%S") if hasattr(row["timestamp"], "strftime") else str(row["timestamp"])[:19]
            alert_items.append(html.Div([
                html.Span(ts, style={"color": C["muted"], "marginRight": "10px", "minWidth": "65px", "display": "inline-block"}),
                html.Span("⚡ ", style={"color": C["yellow"]}),
                html.Span(row["alert_type"].replace("_", " "), style={"color": C["yellow"], "marginRight": "8px"}),
                html.Span(row["detail"], style={"color": C["muted"]}),
            ], className="alert-row", style={"padding": "4px 0", "borderBottom": f"1px solid {C['border']}"}))

    # ── Log tail ──
    if df.empty:
        log_rows = [html.Div("Waiting for log events...", style={"color": C["muted"]})]
    else:
        recent = df.sort_values("timestamp", ascending=False).head(50)
        log_rows = []
        for _, row in recent.iterrows():
            ts = row["timestamp"].strftime("%H:%M:%S") if hasattr(row["timestamp"], "strftime") else str(row["timestamp"])[11:19]
            tag = row.get("tag", "normal")
            color = TAG_COLORS.get(tag, C["muted"])
            log_rows.append(html.Div([
                html.Span(ts, style={"color": C["muted"], "marginRight": "12px",
                                     "minWidth": "65px", "display": "inline-block"}),
                html.Span(f"[{tag}]", style={"color": color, "marginRight": "10px",
                                              "minWidth": "150px", "display": "inline-block"}),
                html.Span(row.get("message", "")[:90], style={"color": C["text"]}),
            ], style={"padding": "2px 0", "borderBottom": f"1px solid {C['border']}20",
                      "whiteSpace": "nowrap", "overflow": "hidden", "textOverflow": "ellipsis"}))
    return clock, kpis, timeline_fig, tag_fig, ip_fig, alert_items, log_rows


if __name__ == "__main__":
    print("[SIEM Dashboard] Starting at http://localhost:8050")
    app.run(debug=False, host="127.0.0.1", port=8050)
