#!/usr/bin/env python3
"""Merge scan_results_clef.csv vs scan_results_v6_last1000_backup.csv
and answer the 3 analysis questions (FP / missing Spam / Head&Tail effect).
"""
import re
import mailbox
import pandas as pd

CLEF = "scan_results_clef.csv"
NIMBLE = "scan_results_v6_last1000_backup.csv"
MBOX = ("Takeout/Mail/جميع رسائل البريد بما في ذلك الرسائل غير المرغوب "
        "فيها والمهملات.mbox")
WHITELIST = ("youtube.com", "linkedin.com", "accountprotection.microsoft.com")

# ---------------------------------------------------------------- load+merge
clef = pd.read_csv(CLEF, encoding="utf-8-sig")
nimble = pd.read_csv(NIMBLE, encoding="utf-8-sig")

assert len(clef) == len(nimble), "row count differs"
# alignment check (both files were written in identical scan order)
aligned = ((clef["Subject"].fillna("") == nimble["Subject"].fillna("")).all()
           and (clef["Sender"].fillna("") == nimble["Sender"].fillna("")).all())
print(f"alignment (row-by-row identical): {aligned}  rows={len(clef)}")

df = pd.DataFrame({
    "sender": clef["Sender"],
    "subject": clef["Subject"],
    "nimble": nimble["Final_Decision"],
    "clef": clef["Final_Decision"],
    "nimble_model": nimble["Model_Used"],
    "clef_model": clef["Model_Used"],
    "nimble_prob": pd.to_numeric(nimble["Probability_Score"], errors="coerce"),
    "clef_prob": pd.to_numeric(clef["Probability_Score"], errors="coerce"),
})

def domain_of(s: str) -> str:
    m = re.search(r"<([^>]+)>", str(s))
    addr = m.group(1) if m else str(s)
    return addr.split("@")[-1].strip().lower() or "?"

df["domain"] = df["sender"].map(domain_of)
df["wl"] = df["domain"].map(lambda d: any(w in d for w in WHITELIST))

# --------------------------------------------- rebuild full text lengths (mbox)
from email_scanner import EmailScanner          # reuse exact same extraction
scanner = EmailScanner()
mb = mailbox.mbox(MBOX)
start = len(mb) - len(df)
lengths = []
for i in range(start, len(mb)):
    p = scanner.extract_email_parts(mb[i])
    full = f"Subject: {p['subject']}\n\n{p['body']}"
    lengths.append(len(full))
df["full_len"] = lengths
df["truncated"] = df["full_len"] > 700           # gets \n...[مقطوع]...\n marker
print(f"text lengths: mean={df['full_len'].mean():.0f}  "
      f"max={df['full_len'].max()}  >700 chars (marker): "
      f"{df['truncated'].sum()/len(df):.0%}\n")

pd.set_option("display.width", 200)
pd.set_option("display.max_colwidth", 70)

# ============================================================ Q1: FALSE PHISH
q1 = df[(df.clef == "Phishing") & (df.nimble == "Safe")]
print("=" * 78)
print(f"Q1) FALSE PHISHING (Clef=Phishing, Nimble=Safe): {len(q1)} emails")
print("=" * 78)
by_dom = (q1.groupby("domain").size().sort_values(ascending=False)
          .rename("count").to_frame())
by_dom["in_whitelist?"] = [
    "YES" if any(w in d for w in WHITELIST) else "-" for d in by_dom.index]
by_dom["sample_subject"] = [
    q1[q1.domain == d].iloc[0]["subject"][:55] for d in by_dom.index]
print(by_dom.to_string())
print("\n-- full sender groups --")
for snd, g in q1.groupby("sender"):
    print(f"  {len(g):3}x  {snd[:70]}")
print(f"\n  of these, truncated(>700ch): {q1.truncated.sum()}/{len(q1)}")
print(f"  low-confidence (clef_prob<0.80): "
      f"{(q1.clef_prob < 0.80).sum()}/{len(q1)}")

# ============================================================== Q2: LOST SPAM
q2 = df[(df.nimble == "Spam") & (df.clef == "Safe")]
print("\n" + "=" * 78)
print(f"Q2) NIMBLE=Spam -> CLEF=Safe: {len(q2)} emails "
      f"(nimble total Spam={int((df.nimble=='Spam').sum())}, "
      f"clef total Spam={int((df.clef=='Spam').sum())})")
print("=" * 78)
sample = q2.sample(n=min(10, len(q2)), random_state=42)
for _, r in sample.iterrows():
    print(f"  | {r.sender[:45]:45} | {str(r.subject)[:58]}")
    print(f"  |     nimble={r.nimble_prob:.2f} clef={r.clef_prob:.2f} "
          f"len={r.full_len} trunc={r.truncated}")
print("\n-- sender domains involved --")
print(q2.groupby("domain").size().sort_values(ascending=False).to_string())

# ================================================= Q3: HEAD & TAIL TRUNCATION
print("\n" + "=" * 78)
print("Q3) HEAD & TAIL effect (emails actually decided by clef-flash)")
print("=" * 78)
qc = df[df.clef_model == "clef-flash-4k"].copy()
stats = qc.groupby("truncated").agg(
    n=("clef", "size"),
    mean_prob=("clef_prob", "mean"),
    med_prob=("clef_prob", "median"),
    safe_pct=("clef", lambda s: (s == "Safe").mean() * 100),
    spam_pct=("clef", lambda s: (s == "Spam").mean() * 100),
    phish_pct=("clef", lambda s: (s == "Phishing").mean() * 100),
)
stats.index = ["short (<=700, no marker)", "LONG (>700, marker)"]
print(stats.round(1).to_string())

# same emails under nimble (both models judged them) for a fair split
both = qc[qc.nimble_model == "nimble-4k"]
print(f"\n(subset both models judged: {len(both)})")
st2 = both.groupby("truncated").agg(
    n=("clef", "size"),
    clef_phish=("clef", lambda s: (s == "Phishing").mean() * 100),
    nimble_phish=("nimble", lambda s: (s == "Phishing").mean() * 100),
    clef_mean=("clef_prob", "mean"),
    nimble_mean=("nimble_prob", "mean"),
)
st2.index = ["short", "LONG"]
print(st2.round(1).to_string())

print("\n-- suspicious score patterns --")
flag = qc[qc.clef != "Safe"]
print(f"clef flags on LONG emails: "
      f"{(flag.truncated).sum()}/{len(flag)} of its flags")
border = flag[flag.clef_prob < 0.70]
print(f"borderline flags (prob<0.70) - marker confusion suspects: "
      f"{len(border)}")
for _, r in border.iterrows():
    print(f"  {r.clef_prob:.3f} {r.clef:9} trunc={str(r.truncated):5} "
          f"len={r.full_len:5} | {r.sender[:38]} | {str(r.subject)[:45]}")

print("\n-- length vs clef suspicion (flagged only) --")
print(qc.groupby(["truncated", "clef"])["clef_prob"].mean().round(3).to_string())

# correlation between length and flag probability among clef-decided
import numpy as np
qc["flagged"] = (qc.clef != "Safe").astype(int)
r = np.corrcoef(qc.full_len, qc.flagged)[0, 1]
print(f"\nPearson r(full_len, flagged) = {r:.3f}  "
      f"(n={len(qc)} clef-decided)")
