"""Render the assembled report as JSON, Markdown and a standalone RTL HTML page."""
import html
import json
from collections import Counter

SEV_HE = {"critical": "קריטי", "high": "גבוה", "medium": "בינוני", "low": "נמוך", "info": "מידע"}
VER_HE = {"confirmed": "אומת", "partially_confirmed": "אומת חלקית", "unconfirmed": "לא אומת",
          "false": "הופרך", "not_verified": "לא נבדק"}
SEV_COLOR = {"critical": "#b42318", "high": "#c4320a", "medium": "#b54708", "low": "#027a48", "info": "#475467"}


def to_markdown(r):
    c = Counter(i["severity"] for i in r["items"])
    out = ['<div dir="rtl">', "",
           f"# דוח ממצאי סייבר בתחום AI", "",
           f"**תקופה:** {r['since']} – {r['until']}  ",
           f"**ממצאים:** {len(r['items'])} "
           + " | ".join(f"{SEV_HE[s]}: {c[s]}" for s in SEV_HE if c[s]), "",
           "## תקציר מנהלים", "", r["executive_summary"], "",
           "## מגמות מרכזיות", ""]
    out += [f"- {t}" for t in r["key_trends"]]
    out += ["", "## טבלת ממצאים", "",
            "| # | חומרה | כותרת | קטגוריה | אימות | תאריך |", "|---|---|---|---|---|---|"]
    for n, i in enumerate(r["items"], 1):
        out.append(f"| {n} | {SEV_HE.get(i['severity'], i['severity'])} | {i['title']} | {i['category']} "
                   f"| {VER_HE.get(i['verification'], i['verification'])} | {i['published']} |")
    out += ["", "## פירוט ממצאים", ""]
    for n, i in enumerate(r["items"], 1):
        out += [f"### {n}. {i['title']}", "",
                f"- **חומרה:** {SEV_HE.get(i['severity'], i['severity'])}",
                f"- **מושפעים:** {i['affected']}",
                f"- **אימות:** {VER_HE.get(i['verification'], i['verification'])}", "",
                i["summary"], "", f"**המלצה:** {i['recommendation']}", "", "**מקורות:**"]
        out += [f"- <{s}>" for s in i["sources"]]
        out.append("")
    out += ["## המלצות", ""] + [f"- {x}" for x in r["recommendations"]]
    out += ["", "## פריטים פתוחים", ""] + [f"- [ ] {x}" for x in r["open_items"]]
    out += ["", "## נספח: סוכנים שהופעלו", "", "| סוכן | מודל | סטטוס | ממצאים |", "|---|---|---|---|"]
    out += [f"| {a['agent']} | {a['model']} | {a['status']} | {a['findings']} |" for a in r["agents"]]
    out += ["", f"_מנהל: {r['models']['orchestrator']} · סורקים: {r['models']['scanner']} · "
            f"מאמת: {r['models']['verifier']}_", "", "</div>", ""]
    return "\n".join(out)


def to_html(r):
    e = html.escape
    c = Counter(i["severity"] for i in r["items"])

    def badge(s):
        return f'<span class="b" style="background:{SEV_COLOR.get(s, "#475467")}">{e(SEV_HE.get(s, s))}</span>'

    rows = "".join(
        f"<tr><td>{n}</td><td>{badge(i['severity'])}</td><td><a href='#f{n}'>{e(i['title'])}</a></td>"
        f"<td>{e(i['category'])}</td><td>{e(VER_HE.get(i['verification'], i['verification']))}</td>"
        f"<td>{e(i['published'])}</td></tr>" for n, i in enumerate(r["items"], 1))
    cards = "".join(
        f"<article id='f{n}'><h3>{n}. {e(i['title'])} {badge(i['severity'])}</h3>"
        f"<p class='m'>מושפעים: {e(i['affected'])} · אימות: {e(VER_HE.get(i['verification'], i['verification']))}"
        f" · {e(i['published'])}</p><p>{e(i['summary'])}</p>"
        f"<p><strong>המלצה:</strong> {e(i['recommendation'])}</p><ul class='src'>"
        + "".join(f"<li><a dir='ltr' href='{e(s)}' rel='noopener'>{e(s)}</a></li>" for s in i["sources"])
        + "</ul></article>" for n, i in enumerate(r["items"], 1))
    stats = "".join(f"<div class='s'><b>{c[s]}</b>{badge(s)}</div>" for s in SEV_HE if c[s])
    li = lambda xs: "".join(f"<li>{e(x)}</li>" for x in xs)
    agents = "".join(f"<tr><td>{e(a['agent'])}</td><td>{e(a['model'])}</td><td>{e(str(a['status']))}</td>"
                     f"<td>{a['findings']}</td></tr>" for a in r["agents"])
    return f"""<!doctype html><html lang="he" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>דוח סייבר AI</title>
<style>
:root{{--bg:#fff;--fg:#101828;--mut:#475467;--line:#e4e7ec;--card:#f9fafb}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0c111d;--fg:#f5f5f6;--mut:#94969c;--line:#1f242f;--card:#161b26}}}}
body{{background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,"Segoe UI",Arial,sans-serif;margin:0;padding:24px 16px}}
main{{max-width:960px;margin:auto}} h1{{margin:0 0 4px}} .m{{color:var(--mut);font-size:14px}}
table{{width:100%;border-collapse:collapse;font-size:14px}} td,th{{border-bottom:1px solid var(--line);padding:8px;text-align:right}}
.wrap{{overflow-x:auto}} .b{{color:#fff;border-radius:6px;padding:1px 8px;font-size:12px;white-space:nowrap}}
.stats{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}} .s{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 14px;display:flex;gap:8px;align-items:center}}
article{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:4px 16px;margin:12px 0}}
.src{{font-size:13px;word-break:break-all}} a{{color:#2e90fa}}
</style></head><body><main>
<h1>דוח ממצאי סייבר בתחום AI</h1><p class="m">תקופה: {e(r['since'])} – {e(r['until'])} · {len(r['items'])} ממצאים</p>
<div class="stats">{stats}</div>
<h2>תקציר מנהלים</h2><p>{e(r['executive_summary'])}</p>
<h2>מגמות מרכזיות</h2><ul>{li(r['key_trends'])}</ul>
<h2>טבלת ממצאים</h2><div class="wrap"><table><tr><th>#</th><th>חומרה</th><th>כותרת</th><th>קטגוריה</th><th>אימות</th><th>תאריך</th></tr>{rows}</table></div>
<h2>פירוט ממצאים</h2>{cards}
<h2>המלצות</h2><ul>{li(r['recommendations'])}</ul>
<h2>פריטים פתוחים</h2><ul>{li(r['open_items'])}</ul>
<h2>נספח: סוכנים שהופעלו</h2><div class="wrap"><table><tr><th>סוכן</th><th>מודל</th><th>סטטוס</th><th>ממצאים</th></tr>{agents}</table></div>
</main></body></html>"""


def write_all(r, base_path):
    with open(base_path + ".json", "w", encoding="utf-8") as f:
        json.dump(r, f, ensure_ascii=False, indent=2)
    with open(base_path + ".md", "w", encoding="utf-8") as f:
        f.write(to_markdown(r))
    with open(base_path + ".html", "w", encoding="utf-8") as f:
        f.write(to_html(r))
    return [base_path + ext for ext in (".json", ".md", ".html")]
