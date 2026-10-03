# 🛡️ phish-classifier

[![CI](https://github.com/Hamzamn19/phish-classifier/actions/workflows/ci.yml/badge.svg)](https://github.com/Hamzamn19/phish-classifier/actions/workflows/ci.yml)

**Local, offline phishing classification for `.mbox` archives with a single strong Ollama model.**

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-39%20passed-brightgreen)](#-testing)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Offline](https://img.shields.io/badge/100%25-offline-orange)](#-privacy--offline)

> Your email never leaves your machine. No cloud APIs, no telemetry — everything runs on your own GPU through a local [Ollama](https://ollama.com) server.

**Author:** hamzah sheikh alashrah

---

## ✨ Highlights

- **Single strong model** — one model, one load, zero model-hopping: the whitelist answers instantly and only suspicious emails reach the GPU. Measured **0.38 s per decision** on an RTX 3060.
- **Spoof-safe whitelist** — 859 trusted domains (curated + official [Rspamd DMARC list](https://github.com/rspamd/maps)) skipped instantly with **exact / subdomain matching** — not substring matching (see [Security](#-security-challenges--mitigations)).
- **Smart head-and-tail truncation** — long emails keep their first *and* last 350 characters, so verdicts/subjects at the tail are never lost.
- **Robust MIME parsing** — invalid charsets (e.g. `tr-ascii`) and one broken message never abort a run.
- **Google Takeout ready** — reads `.mbox` directly, exports Excel-friendly `utf-8-sig` CSV.
- **Offline-first** — the whitelist ships *inside* the package; no network access is required at runtime (except your local Ollama).

## 🏗 Architecture

```
[ Email .mbox ] ──> [ Exact/Subdomain Whitelist ] ──(Safe)──> ✅ Skip (0.001s)
                               │
                          (Suspicious)
                               ▼
                    [ clef-flash-4k / nimble ] ──> 🎣 Phishing / ⚠️ Spam
```

## 🚀 Quick start

### 1. Prerequisites

- Python **3.9+**
- [Ollama](https://ollama.com) **≥ 0.35.1** with the model pulled:
  ```bash
  ollama pull clef-flash-4k   # the deciding model (or any model via --strong)
  ```
- A GPU with ~11 GB free VRAM (tested on RTX 3060 12 GB).

> **Tip:** `/v1/systemone` ignores per-request `num_ctx`. Bake it into a Modelfile variant
> (`FROM clef-flash` + `PARAMETER num_ctx 4096`) so the model fits your VRAM.

### 2. Install

```bash
git clone https://github.com/Hamzamn19/phish-classifier.git
cd phish-classifier
pip install -e .          # or: pip install .  (with the shipped whitelist)
```

### 3. Scan

```bash
# Typer CLI (recommended)
phish-scan ~/Takeout/Mail/Inbox.mbox 1000 --last --csv results.csv

# Classic entry point (unchanged, still supported)
python email_scanner.py ~/Takeout/Mail/Inbox.mbox 1000 --last

# Pick a different deciding model
phish-scan inbox.mbox 500 --strong nimble-4k

# Verbose per-email decisions
phish-scan inbox.mbox 20 --last -v
```

| Option | Meaning |
|--------|---------|
| `--last` | scan the newest N emails instead of the first N |
| `--strong / -s` | override the deciding model (default `clef-flash-4k`) |
| `--csv PATH` | output path (default `scan_results.csv`, `utf-8-sig`) |
| `-v / --verbose` | print per-email decisions and whitelist hits |

## 📊 Benchmarks (RTX 3060 12 GB, 19,108-email mailbox)

| Scenario | Result |
|----------|--------|
| Whitelist coverage (exact/subdomain) | **62.0 %** of the mailbox skipped, **0.4 s total** |
| Strong-model decision cost | **≈ 0.38 s / email** |
| Full scan (direct strong model, 19,108 emails) | **57 min**, 0 errors, VRAM peak 10.9 GB |
| 1,000-email single-pass test | **56.6 s** — Safe 917 / Spam 61 / Phishing 22, 91 % whitelist skip |

> On the same 1,000-email sample the previous two-stage design flagged only 20
> (the fast model wrongly accepted obvious spam as `Safe`). The single strong
> model catches **83** — 4× more — for +6 s.

> Timings depend on your GPU and how much of your mailbox the whitelist matches.

## 🔒 Security challenges & mitigations

**Challenge — substring whitelist matching (`domain in sender`).**
The original matcher trusted any sender whose raw string *contained* a
whitelisted domain. An attacker who buys `mermaidcha-rt.com` (contains
`rt.com`) or `buy-cheap-apple.com` (contains `apple.com`) would silently
bypass every model and be marked `Safe`.

**Mitigation — exact / subdomain matching.**
`phish_classifier.whitelist` extracts the real domain after `@` and
requires either an exact match or a dot-boundary subdomain:

```python
sender_domain == entry or sender_domain.endswith("." + entry)
```

Verified by 11 spoofing regression tests (`tests/test_whitelist.py`) —
all blocked, while legitimate senders (`mail.youtube.com`,
`accounts.google.com`, …) still match.

Two more hardening measures are built in:

- **Per-message loader guard** — a single unparseable message is skipped with a warning instead of aborting the run (a real bug that once stopped a scan at 8,092 / 19,108).
- **Unknown-charset fallback** — `payload.decode("tr-ascii")` now falls back to UTF-8 instead of raising `LookupError`.

## 🗂 Project layout

```
phish_classifier/
├── whitelist.py   # spoof-safe exact/subdomain whitelist + shipped Rspamd list
├── extract.py     # MIME/mbox extraction, HTML cleaning, smart head&tail cut
├── scanner.py     # Ollama client, whitelist -> strong model, CSV export, summary
├── cli.py         # `phish-scan` Typer command
└── whitelist_rspamd.txt   # official Rspamd DMARC whitelist (ships offline)
email_scanner.py   # backward-compatible classic entry point
tests/             # 39 pytest tests (whitelist security + extraction)
```

## 🧪 Testing

```bash
pip install -e ".[dev]"
pytest            # 39 passed
```

The suite covers the **security-critical** paths only: whitelist spoofing
resistance, charset robustness, smart truncation and mbox loading. Model
inference is intentionally not tested (non-deterministic).

## 🔐 Privacy & offline

- No telemetry, no cloud calls: only `POST http://localhost:11434/...`.
- Your mailbox, scan results and logs are ignored by `.gitignore`
  (`*.mbox`, `*.zip`, `Takeout/`, `*.csv`, `scan_*.log`, `*.vram`).
- The whitelist file ships with the package — zero downloads at runtime.

## 📄 License

[MIT](LICENSE) © 2026 **hamzah sheikh alashrah**

---
---

# 🛡️ phish-classifier (العربية)

**تصنيف محلي وبدون إنترنت لرسائل التصيد في ملفات `.mbox` عبر نموذج Ollama قوي واحد.**

> بريدك لا يغادر جهازك أبداً — لا سحابة، لا اتصال خارجي، كل شيء يعمل على كرتك الرسومي محلياً.

**المؤلف:** hamzah sheikh alashrah

## ✨ المميزات

- **نموذج قوي واحد:** نموذج واحد يُحمَّل مرة واحدة فقط — القائمة البيضاء تجيب فوراً والمشبوه فقط يصل إلى كرت الرسوم — **0.38 ثانية لكل قرار** على RTX 3060.
- **قائمة بيضاء آمنة ضد التزوير:** 859 نطاقاً موثوقاً (قائمة مُنسّقة + قائمة [Rspamd الرسمية](https://github.com/rspamd/maps)) تتخطّى فوراً بمطابقة **تامة أو فرعية** — وليست مطابقة جزئية (انظر قسم الأمان).
- **قص ذكي (Head & Tail):** الرسائل الطويلة تحتفظ بأول 350 وآخر 350 حرفاً — الحُكم والموضوع في النهاية لا يضيعان.
- **قراءة MIME متينة:** ترميزات معطوبة (`tr-ascii`) أو رسالة واحدة تالفة لا توقف المسح أبداً.
- **جاهز لـ Google Takeout:** يقرأ `.mbox` مباشرة ويصدّر CSV بترميز `utf-8-sig` (متوافق مع Excel والعربي).

## 🚀 البدء السريع

```bash
# 1) المتطلبات: Python 3.9+ و Ollama >= 0.35.1 مع النموذج
ollama pull clef-flash-4k

# 2) التثبيت
git clone https://github.com/Hamzamn19/phish-classifier.git
cd phish-classifier
pip install -e .

# 3) الفحص
phish-scan ~/Takeout/Mail/Inbox.mbox 1000 --last --csv results.csv
# أو بالأمر الكلاسيكي القديم (يعمل كما هو):
python email_scanner.py ~/Takeout/Mail/Inbox.mbox 1000 --last
```

> **مهم:** واجهة `/v1/systemone` تتجاهل `num_ctx` في الطلب — اخبزه داخل Modelfile
> (`PARAMETER num_ctx 4096`) ليناسب ذاكرتك الرسومية.

## 📊 نتائج قياس الأداء (RTX 3060 12GB — صندوق 19,108 رسالة)

| السيناريو | النتيجة |
|-----------|---------|
| تغطية القائمة البيضاء | **62%** تتخطّى في **0.4 ثانية** |
| تكلفة قرار النموذج القوي | **≈ 0.38 ثانية/إيميل** |
| مسح كامل (19,108) | **57 دقيقة** — صفر أخطاء — VRAM ذروته 10.9GB |
| اختبار تمريرة واحدة على 1000 | **56.6 ثانية** — Safe 917 / Spam 61 / Phishing 22 |

> على نفس العيّنة، تصميم التسلسل المرحلي القديم كان يرصد 20 فقط (النموذج
> السريع كان يقبل إيميلات تصيد واضحة كـ`Safe`) — النموذج القوي الواحد يرصد
> **83** (أي ~4× أكثر) بتكلفة +6 ثوانٍ فقط.

## 🔒 التحديات الأمنية والحلول

**الثغرة — المطابقة الجزئية (`domain in sender`):** كانت القائمة البيضاء تثق بأي مرسل **يحتوي** نصه النطاق الموثوق. مهاجم يشتري `mermaidcha-rt.com` (تحتوي `rt.com`) يتجاوز كل النماذج ويُعلَّم Safe.

**الحل — مطابقة تامة/فرعية:** استخراج النطاق بعد `@` ثم:

```python
sender_domain == entry or sender_domain.endswith("." + entry)
```

مُثبت بـ **11 اختبار تزوير** في `tests/test_whitelist.py` — كلها محجوبة، والمرسلون الشرعيون (`mail.youtube.com`, `accounts.google.com`) تبقى مطابقة.

**تدابير إضافية:** حارس تحميل لكل رسالة (رسالة تالفة واحدة لا توقف المسح) + رجوع تلقائي لـ UTF-8 عند ترميز مجهول.

## 🧪 الاختبارات

```bash
pip install -e ".[dev]"
pytest            # 39 passed
```

الاختبارات تغطي **المسارات الحرجة أمنياً** فقط: مقاومة التزوير، متانة الترميز، القص الذكي، وتحميل mbox — دون اختبار النماذج (غير حتمية).

## 📄 الترخيص

[MIT](LICENSE) © 2026 **hamzah sheikh alashrah**
