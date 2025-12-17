import json
import base64
from pathlib import Path
from collections import Counter

import pandas as pd
import matplotlib.pyplot as plt
from jinja2 import Template

DATA_PATH = "../analysis/data.json"
OUT_DIR = Path("report_out")
ASSETS_DIR = OUT_DIR / "assets"
DETAILS_DIR = OUT_DIR / "details"
OUT_DIR.mkdir(exist_ok=True)
ASSETS_DIR.mkdir(exist_ok=True)
DETAILS_DIR.mkdir(exist_ok=True)

def safe_b64_preview(s: str | None, max_bytes: int = 64) -> str:
    """Try to decode base64 and return a short hex preview. Falls back to truncated string."""
    if not s:
        return ""
    try:
        raw = base64.b64decode(s, validate=False)
        raw = raw[:max_bytes]
        return raw.hex()
    except Exception:
        # not valid b64, return truncated original
        return (s[:120] + "…") if len(s) > 120 else s

def load_records(path: str):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Accept either: [ {...}, {...} ] OR { "records": [ ... ] } OR { ...single... }
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in ("records", "attacks", "items", "results", "data"):
            if k in data and isinstance(data[k], list):
                return data[k]
        # if it's a single record dict
        if "problematic_input" in data and "failure_cause" in data:
            return [data]
    raise ValueError("Unsupported JSON format. Expected a list of records (or a dict containing one).")

records = load_records(DATA_PATH)

# --- Flatten to DataFrame (keep observations as list) ---
df = pd.json_normalize(records)

# Normalize missing columns (so template doesn't break)
for col in ["problematic_input", "problematic_field", "failure_cause", "explanation", "response_received", "response_b64", "observations"]:
    if col not in df.columns:
        df[col] = None

# Ensure observations is list
def to_list(x):
    if x is None or (isinstance(x, float) and pd.isna(x)):
        return []
    if isinstance(x, list):
        return x
    return [str(x)]

df["observations"] = df["observations"].apply(to_list)

# Add convenience previews
df["input_preview_hex"] = df["problematic_input"].apply(lambda s: safe_b64_preview(s, max_bytes=48))
df["response_preview_hex"] = df["response_b64"].apply(lambda s: safe_b64_preview(s, max_bytes=48))

# Create stable IDs for detail pages
df["row_id"] = [f"R{i:05d}" for i in range(len(df))]
df["details_file"] = df["row_id"].apply(lambda rid: f"details/{rid}.html")

# --- KPIs ---
total = len(df)
responses_true = int(df["response_received"].fillna(False).astype(bool).sum())
responses_false = total - responses_true

failure_counts = df["failure_cause"].fillna("Unknown").value_counts().to_dict()

# observations counts (tag frequency across all records)
obs_counter = Counter()
for lst in df["observations"].tolist():
    obs_counter.update([str(x) for x in lst])
obs_top = obs_counter.most_common(15)

# --- Charts (static PNG) ---
def save_bar_chart(series_or_dict, title, xlabel, ylabel, outpath: Path, top_n: int | None = None):
    if isinstance(series_or_dict, dict):
        items = sorted(series_or_dict.items(), key=lambda kv: kv[1], reverse=True)
        if top_n:
            items = items[:top_n]
        labels = [k for k, _ in items]
        values = [v for _, v in items]
    else:
        vc = series_or_dict.value_counts()
        if top_n:
            vc = vc.head(top_n)
        labels = vc.index.astype(str).tolist()
        values = vc.values.tolist()

    if not labels:
        return None

    plt.figure()
    plt.bar(labels, values)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(outpath, dpi=200)
    plt.close()
    return outpath

chart_failure = save_bar_chart(
    df["failure_cause"].fillna("Unknown"),
    "Failures by Cause",
    "failure_cause",
    "count",
    ASSETS_DIR / "failures_by_cause.png",
    top_n=12
)

chart_response = save_bar_chart(
    {"response_received=true": responses_true, "response_received=false": responses_false},
    "Response Received",
    "response_received",
    "count",
    ASSETS_DIR / "response_received.png"
)

chart_obs = None
if obs_top:
    chart_obs = save_bar_chart(
        dict(obs_top),
        "Top Observations",
        "observation",
        "count",
        ASSETS_DIR / "top_observations.png",
        top_n=15
    )

# --- Build details pages ---
details_tpl = Template(r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Record {{ row_id }}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 32px; background:#f6f6f6; }
    a { color: #0b57d0; text-decoration: none; }
    .card { background:white; border-radius:12px; padding:16px; margin-bottom: 12px; box-shadow:0 2px 8px rgba(0,0,0,0.06); }
    code, pre { background:#fafafa; padding:10px; border-radius:10px; display:block; overflow:auto; }
    .k { color:#666; font-size: 12px; margin-bottom: 4px; }
    .v { font-size: 16px; font-weight: 600; }
    ul { margin: 8px 0 0 18px; }
  </style>
</head>
<body>
  <div class="card">
    <div style="display:flex; justify-content:space-between; align-items:center;">
      <h2 style="margin:0;">Record {{ row_id }}</h2>
      <a href="../report.html">← Back to report</a>
    </div>
  </div>

  <div class="card">
    <div class="k">problematic_field</div>
    <div class="v">{{ problematic_field }}</div>
  </div>

  <div class="card">
    <div class="k">failure_cause</div>
    <div class="v">{{ failure_cause }}</div>
  </div>

  <div class="card">
    <div class="k">response_received</div>
    <div class="v">{{ response_received }}</div>
  </div>

  <div class="card">
    <div class="k">explanation</div>
    <div>{{ explanation }}</div>
  </div>

  <div class="card">
    <div class="k">observations</div>
    {% if observations and observations|length > 0 %}
      <ul>
        {% for x in observations %}
          <li>{{ x }}</li>
        {% endfor %}
      </ul>
    {% else %}
      <div>—</div>
    {% endif %}
  </div>

  <div class="card">
    <div class="k">problematic_input (preview hex)</div>
    <code>{{ input_preview_hex }}</code>
  </div>

  <div class="card">
    <div class="k">response_b64 (preview hex)</div>
    <code>{{ response_preview_hex }}</code>
  </div>

</body>
</html>
""")

for _, row in df.iterrows():
    html = details_tpl.render(
        row_id=row["row_id"],
        problematic_field=row.get("problematic_field", ""),
        failure_cause=row.get("failure_cause", ""),
        explanation=row.get("explanation", ""),
        response_received=bool(row.get("response_received", False)),
        observations=row.get("observations", []),
        input_preview_hex=row.get("input_preview_hex", ""),
        response_preview_hex=row.get("response_preview_hex", ""),
    )
    outpath = OUT_DIR / row["details_file"]
    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_text(html, encoding="utf-8")

# --- Main report HTML ---
main_tpl = Template(r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Fuzzer Static Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 32px; background:#f6f6f6; }
    h1 { text-align:center; margin-bottom: 18px; }
    .grid { display:grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 16px; }
    .card { background:white; border-radius:12px; padding:14px; box-shadow:0 2px 8px rgba(0,0,0,0.06); }
    .k { color:#666; font-size: 12px; }
    .v { font-size: 26px; font-weight: 800; }
    img { max-width: 100%; height: auto; border-radius: 10px; }
    table { width:100%; border-collapse: collapse; background:white; border-radius:12px; overflow:hidden; }
    th, td { padding: 8px 10px; border-bottom: 1px solid #eee; font-size: 13px; vertical-align: top; }
    th { background: #fafafa; text-align:left; }
    a { color:#0b57d0; text-decoration:none; }
    .muted { color:#888; font-size: 12px; }
    .section { margin-bottom: 14px; }
  </style>
</head>
<body>
  <h1>📄 Fuzzer Static Report</h1>

  <div class="grid">
    <div class="card"><div class="k">Total records</div><div class="v">{{ total }}</div></div>
    <div class="card"><div class="k">response_received = true</div><div class="v">{{ responses_true }}</div></div>
    <div class="card"><div class="k">response_received = false</div><div class="v">{{ responses_false }}</div></div>
    <div class="card"><div class="k">Distinct failure causes</div><div class="v">{{ distinct_causes }}</div></div>
  </div>

  <div class="section card">
    <div class="k">Failure cause breakdown</div>
    <div class="muted">
      {% for k, v in failure_counts.items() %}
        <span><b>{{ k }}</b>: {{ v }}</span>{% if not loop.last %} · {% endif %}
      {% endfor %}
    </div>
  </div>

  <div class="section" style="display:grid; grid-template-columns: 1fr 1fr; gap: 12px;">
    {% if chart_failure %}
    <div class="card">
      <h3 style="margin-top:0;">Failures by Cause</h3>
      <img src="{{ chart_failure }}" alt="Failures by Cause">
    </div>
    {% endif %}

    {% if chart_response %}
    <div class="card">
      <h3 style="margin-top:0;">Response Received</h3>
      <img src="{{ chart_response }}" alt="Response Received">
    </div>
    {% endif %}
  </div>

  {% if chart_obs %}
  <div class="section card">
    <h3 style="margin-top:0;">Top Observations</h3>
    <img src="{{ chart_obs }}" alt="Top Observations">
  </div>
  {% endif %}

  <div class="section card">
    <h3 style="margin-top:0;">Results Table</h3>
    <div class="muted">Click a Record ID to open details.</div>
    {{ table_html | safe }}
  </div>

</body>
</html>
""")

# Build a clean table (select columns + add details link)
table_df = df[[
    "row_id",
    "details_file",         
    "problematic_field",
    "failure_cause",
    "response_received",
    "explanation",
    "input_preview_hex",
]].copy()

# Render row_id as link to details
table_df["row_id"] = table_df.apply(lambda r: f'<a href="{r["details_file"]}">{r["row_id"]}</a>', axis=1)

table_html = table_df.to_html(index=False, escape=False)

report_html = main_tpl.render(
    total=total,
    responses_true=responses_true,
    responses_false=responses_false,
    distinct_causes=len(failure_counts),
    failure_counts=failure_counts,
    chart_failure=str(chart_failure.relative_to(OUT_DIR)).replace("\\", "/") if chart_failure else None,
    chart_response=str(chart_response.relative_to(OUT_DIR)).replace("\\", "/") if chart_response else None,
    chart_obs=str(chart_obs.relative_to(OUT_DIR)).replace("\\", "/") if chart_obs else None,
    table_html=table_html
)

(OUT_DIR / "report.html").write_text(report_html, encoding="utf-8")
print(f"✅ Created: {OUT_DIR / 'report.html'}")
print(f"📁 Details: {DETAILS_DIR}")
print(f"🖼 Assets:  {ASSETS_DIR}")
