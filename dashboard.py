import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output
import pandas as pd
import plotly.graph_objs as go
import os

app = dash.Dash(__name__)

app.layout = html.Div(style={
    "backgroundColor": "#f5f6fa",
    "minHeight": "100vh",
    "padding": "30px",
    "fontFamily": "Arial, sans-serif"
}, children=[

    html.Div([
        html.H1("DNS Exfiltration Monitor",
                style={"margin": "0", "fontSize": "24px", "color": "#2d3436", "fontWeight": "600"}),
        html.P("Monitoring live DNS traffic for tunneling and C2 exfiltration indicators",
               style={"margin": "4px 0 0 0", "color": "#636e72", "fontSize": "14px"})
    ], style={"marginBottom": "24px", "borderBottom": "2px solid #dfe6e9", "paddingBottom": "16px"}),

    html.Div(id="stats-row", style={"display": "flex", "gap": "16px", "marginBottom": "24px"}),

    html.Div([
        html.H3("Entropy Score Timeline",
                style={"margin": "0 0 12px 0", "fontSize": "15px", "color": "#2d3436", "fontWeight": "600"}),
        dcc.Graph(id="entropy-graph")
    ], style={"backgroundColor": "white", "padding": "20px", "borderRadius": "6px",
              "marginBottom": "20px", "boxShadow": "0 1px 3px rgba(0,0,0,0.08)"}),

    html.Div([
        html.H3("Alert Log (Most Recent First)",
                style={"margin": "0 0 12px 0", "fontSize": "15px", "color": "#2d3436", "fontWeight": "600"}),
        html.Div(id="alert-table")
    ], style={"backgroundColor": "white", "padding": "20px", "borderRadius": "6px",
              "boxShadow": "0 1px 3px rgba(0,0,0,0.08)"}),

    dcc.Interval(id="refresh", interval=3000, n_intervals=0)
])

def load_alerts():
    if not os.path.exists("alerts.log") or os.path.getsize("alerts.log") == 0:
        return pd.DataFrame(columns=["time", "rule", "src_ip", "domain", "subdomain", "entropy", "severity"])
    rows = []
    with open("alerts.log", "r") as f:
        for line in f:
            parts = line.strip().split(" | ")
            if len(parts) >= 6:
                rows.append({
                    "time": parts[0],
                    "rule": parts[1],
                    "src_ip": parts[2],
                    "domain": parts[3],
                    "subdomain": parts[4],
                    "entropy": float(parts[5].replace("entropy=", "")),
                    "severity": parts[6].replace("severity=", "").strip() if len(parts) > 6 else "N/A"
                })
    df = pd.DataFrame(rows)
    df = df.sort_values(by="time", ascending=False).reset_index(drop=True)
    return df

@app.callback(
    [Output("entropy-graph", "figure"),
     Output("alert-table", "children"),
     Output("stats-row", "children")],
    Input("refresh", "n_intervals")
)
def update(n):
    df = load_alerts()

    total = len(df)
    high_ent = len(df[df["rule"].str.contains("HIGH ENTROPY", na=False)]) if total > 0 else 0
    high_freq = len(df[df["rule"].str.contains("HIGH FREQUENCY", na=False)]) if total > 0 else 0

    def stat_card(label, value, color, bg):
        return html.Div([
            html.H2(str(value), style={"color": color, "margin": "0", "fontSize": "32px", "fontWeight": "700"}),
            html.P(label, style={"color": "#636e72", "margin": "4px 0 0 0", "fontSize": "13px"})
        ], style={"backgroundColor": bg, "padding": "16px 28px", "borderRadius": "6px",
                  "textAlign": "center", "borderLeft": f"4px solid {color}",
                  "boxShadow": "0 1px 3px rgba(0,0,0,0.08)", "minWidth": "140px"})

    stats = [
        stat_card("Total Alerts", total, "#0984e3", "white"),
        stat_card("High Entropy", high_ent, "#d63031", "#fff5f5"),
        stat_card("High Frequency", high_freq, "#e17055", "#fff9f5"),
    ]

    if total > 0:
        plot_df = df.sort_values(by="time", ascending=True)
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=plot_df["time"], y=plot_df["entropy"],
            mode="markers+lines",
            marker=dict(color=plot_df["entropy"], colorscale="Reds", size=8, showscale=True),
            line=dict(color="#b2bec3"),
            text=plot_df["domain"],
            hovertemplate="<b>%{text}</b><br>Entropy: %{y:.2f}<br>Time: %{x}"
        ))
        fig.add_hline(y=3.8, line_dash="dash", line_color="#d63031",
                      annotation_text="Threshold (3.8)", annotation_font_color="#d63031")
        fig.update_layout(
            paper_bgcolor="white", plot_bgcolor="#f5f6fa",
            font=dict(color="#2d3436"),
            xaxis=dict(gridcolor="#dfe6e9", title="Time"),
            yaxis=dict(gridcolor="#dfe6e9", title="Entropy Score"),
            margin=dict(l=40, r=40, t=20, b=40)
        )
    else:
        fig = go.Figure()
        fig.update_layout(
            paper_bgcolor="white", plot_bgcolor="#f5f6fa",
            annotations=[dict(text="No alerts yet",
                            showarrow=False, font=dict(size=14, color="#b2bec3"))]
        )

    if total > 0:
        table = dash_table.DataTable(
            data=df.to_dict("records"),
            columns=[{"name": c.upper(), "id": c} for c in df.columns],
            page_size=20,
            page_action="native",
            style_table={"overflowX": "auto"},
            style_cell={"backgroundColor": "white", "color": "#2d3436",
                       "border": "1px solid #dfe6e9", "padding": "10px",
                       "fontSize": "13px", "textAlign": "left"},
            style_header={"backgroundColor": "#f5f6fa", "color": "#2d3436",
                         "fontWeight": "600", "border": "1px solid #dfe6e9"},
            style_data_conditional=[
                {"if": {"filter_query": '{severity} = "CRITICAL"'},
                 "color": "#d63031", "fontWeight": "500"},
                {"if": {"filter_query": '{severity} = "MEDIUM"'},
                 "color": "#e17055", "fontWeight": "500"},
            ]
        )
    else:
        table = html.P("No alerts logged yet.", style={"color": "#b2bec3"})

    return fig, table, stats

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=8050)
