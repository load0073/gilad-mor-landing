<div dir="rtl">

# מערכת סוכנים – סריקת ממצאי סייבר בתחום AI

מערכת רב-סוכנית: מודל גבוה מנהל, סוכנים במודלים נמוכים מבצעים, והפלט הוא דוח מסודר בעברית.

## ארכיטקטורה

| תפקיד | מודל | מה עושה |
|---|---|---|
| מנהל (Orchestrator) | `claude-opus-5-5` | מפרק את המשימה, מפעיל סוכנים במקביל, מאחד כפילויות, קובע חומרה, כותב את הדוח |
| סורקים (Scanners) | `claude-haiku-5-5` | חיפוש ברשת לפי תחום, רישום כל ממצא עם מקור ותאריך |
| מאמת (Verifier) | `claude-sonnet-5-5` | בדיקה צולבת של ממצאים קריטיים/גבוהים ותיקון חומרה |

</div>

```
Opus (manager)
 ├─ dispatch_scanners ──► Haiku ×N in parallel (web_search) ──► record_finding
 ├─ verify_findings ────► Sonnet (web_search + web_fetch)   ──► record_verdict
 └─ submit_report ──────► report JSON / Markdown / HTML (RTL)
```

<div dir="rtl">

**תחומי סריקה ברירת מחדל:** CVE בכלי AI · Prompt injection ותקיפות סוכנים/MCP · שרשרת אספקה (מודלים/חבילות זדוניות) · שחקני איום שמשתמשים ב-AI · דליפות ואירועים אצל ספקי AI · הנחיות ורגולציה (CISA, NCSC, ENISA, מערך הסייבר הלאומי, NIST, OWASP).

**בקרות איכות:**
- מקורות בדוח נלקחים רק מרישומי הסוכנים – המנהל לא יכול להמציא קישור; פריט ללא מקור נמחק.
- מגבלות על מספר תורות, סוכנים מקבילים וחיפושים לכל סוכן (שליטה בעלות).
- טיפול ב-`refusal`, ו-fallback אוטומטי בצד השרת עבור Opus/Sonnet.

## הרצה

</div>

```bash
cd ai-cyber-agents && pip install -r requirements.txt
```

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

```bash
python run.py --days 14
```

<div dir="rtl">

הפלט נשמר ב-`reports/ai-cyber-report-YYYY-MM-DD.{json,md,html}`.
דגלים: `--days` חלון זמן · `--out` תיקיית פלט · `--domain "..."` (ניתן לחזור) להחלפת תחומי הסריקה.

בדיקה אופליין (ללא עלות API):

</div>

```bash
python tests/test_pipeline.py
```

<div dir="rtl">

## הרצה אוטומטית (GitHub Actions)

הקובץ `.github/workflows/ai-cyber-scan.yml` מריץ סריקה שבועית (ראשון 05:17 UTC) או ידנית מלשונית Actions, ומעלה את הדוח כ-Artifact להורדה.
דרישה: להוסיף `ANTHROPIC_API_KEY` תחת Settings → Secrets and variables → Actions.

## התאמות

כל ההגדרות ב-`agents/config.py`: מודלים, רמות effort, מספר סוכנים מקבילים, מגבלות חיפוש ותחומי סריקה.

</div>
