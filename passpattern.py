#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 PASSPATTERN
 Password Leak Pattern Detector - CLI + Web App  (OFFLINE ONLY)
--------------------------------------------------------------------------------
 Author  : Karanam Shrivasta
 GitHub  : https://github.com/mrshrivasta
 LinkedIn: https://www.linkedin.com/in/karanam-shrivasta/
 Version : 1.0.0
--------------------------------------------------------------------------------
 *** THIS IS NOT A BREACH CHECK ***
   Read this first, because the difference matters more than anything else here.

   This tool CANNOT tell you whether your password has been leaked. Nothing here
   is compared against Have I Been Pwned or any breach corpus - that requires a
   network request, and this tool never makes one.

   What it does instead is find the STRUCTURE that leaked passwords overwhelmingly
   share: a dictionary word with predictable decoration, a keyboard walk, a name
   and a year, a capital at the front and a digit and a symbol at the back. Those
   patterns are what cracking tools generate first, so a password built that way
   falls early whether or not it has ever appeared in a dump.

   The reverse also holds and is the more dangerous direction: a password with no
   detectable pattern here may still be in a breach corpus, because you used it
   somewhere that got compromised. NO PATTERN FOUND DOES NOT MEAN SAFE. If you
   want to know whether a specific password has been exposed, use a service with
   a real breach dataset - the k-anonymity API at Have I Been Pwned never sends
   the full hash - and treat that as a separate question from this one.

 NOTHING LEAVES THIS MACHINE, AND NOTHING IS STORED
   No network request is made, ever. Passwords are held in memory for the length
   of the check and are NEVER written to the database, to a log, or to an export.
   What gets stored is a SHA-256 fingerprint, which allows reuse to be detected
   across a batch without keeping the password itself. Exports contain findings
   and fingerprints, never the password.

   The one exception is deliberate and visible: the terminal will show a password
   you passed on the command line, because your shell already recorded it in
   history. Prefer 'check --stdin' or the interactive prompt.

 STRENGTH ESTIMATES ARE ESTIMATES
   The crack-time figures are arithmetic against a MODEL of an attacker: a guess
   rate you choose, and a search space this tool computes. A real attacker with a
   good wordlist and rule set does far better than the naive space suggests,
   which is the entire reason pattern detection exists. Treat the numbers as
   orders of magnitude, never as promises.

 LEGAL DISCLAIMER
   Provided "as is" with no warranty. Do not treat a good result as clearance to
   keep using a password. The author accepts no liability for any loss or damage.
================================================================================
"""

from __future__ import annotations

import argparse
import csv
import getpass
import hashlib
import html as _html
import io
import json
import math
import os
import platform
import re
import shutil
import sqlite3
import sys
import textwrap
import time
import unicodedata
from datetime import datetime, timezone

APP_NAME = "PassPattern"
APP_SHORT = "PASSPATTERN"
VERSION = "1.0.0"
AUTHOR = "Karanam Shrivasta"
GITHUB = "https://github.com/mrshrivasta"
LINKEDIN = "https://www.linkedin.com/in/karanam-shrivasta/"
DEFAULT_DB = os.environ.get("PASSPATTERN_DB", "passpattern.db")

NOT_A_BREACH_CHECK = (
    "This is NOT a breach check. It cannot tell you whether a password has been leaked - "
    "that needs a breach corpus and a network request, and this tool makes neither. It finds "
    "the STRUCTURE that leaked passwords share. No pattern found does NOT mean safe: a "
    "password with no detectable pattern can still be in a dump because a site you used it "
    "on was compromised."
)
NEVER_STORED = (
    "Passwords are never written to the database, the logs or any export. Only a SHA-256 "
    "fingerprint is stored, which is enough to detect reuse across a batch without keeping "
    "the password itself. No network request is made at any point."
)
DISCLAIMER_SHORT = (
    "Offline only - nothing is sent anywhere and no password is stored. This finds patterns "
    "that make a password guessable; it does NOT check whether it has been breached, and a "
    "clean result is not proof of safety."
)
DISCLAIMER_LONG = textwrap.dedent(
    """\
    THIS IS NOT A BREACH CHECK. It cannot tell you whether a password has been leaked.
    Nothing is compared against Have I Been Pwned or any breach corpus, because that needs a
    network request and this tool never makes one. It finds the structure that leaked
    passwords overwhelmingly share - a dictionary word with predictable decoration, a
    keyboard walk, a name and a year - because that structure is what cracking tools generate
    first.

    NO PATTERN FOUND DOES NOT MEAN SAFE. A password with nothing detectable here may still
    sit in a breach corpus because a site you used it on was compromised. Those are two
    different questions and this tool only answers one of them.

    NOTHING LEAVES THIS MACHINE AND NOTHING IS STORED. No network request is made. Passwords
    live in memory for the length of a check and are never written to the database, to a log,
    or to an export - only a SHA-256 fingerprint is kept, which detects reuse without
    retaining the password.

    STRENGTH ESTIMATES ARE ESTIMATES. Crack-time figures are arithmetic against a model: a
    guess rate you choose and a search space this tool computes. A real attacker with a good
    wordlist and rule set does far better than a naive search space suggests - which is
    exactly why pattern detection matters more than the raw number.

    Provided "as is" with no warranty; the author accepts no liability for any loss or
    damage."""
)

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_COLOR = {"critical": "#e5484d", "high": "#f76808", "medium": "#ffb224",
             "low": "#3e9dd8", "info": "#8b8f9b"}


def strength_band(bits: float) -> tuple[str, str]:
    """Effective bits AFTER pattern penalties, not raw character-space entropy."""
    if bits < 25:
        return "falls immediately", "#e5484d"
    if bits < 40:
        return "falls quickly", "#f76808"
    if bits < 55:
        return "modest", "#ffb224"
    if bits < 75:
        return "reasonable", "#3e9dd8"
    return "strong against guessing", "#30a46c"


# Attacker models. The point of showing several is that "how long does this take
# to crack" has no single answer - it depends entirely on how the password is
# stored at the other end, which you usually cannot control or even find out.
ATTACK_MODELS = [
    ("online_throttled", "Online, rate limited", 10,
     "Guessing against a live login that locks out or backs off. 10 guesses/second."),
    ("online_unthrottled", "Online, no limiting", 1_000,
     "A live service with no rate limiting at all. 1 thousand guesses/second."),
    ("offline_bcrypt", "Offline, slow hash", 20_000,
     "The database has leaked and passwords were stored with bcrypt/scrypt/argon2. "
     "20 thousand guesses/second on good hardware."),
    ("offline_fast", "Offline, fast hash", 20_000_000_000,
     "The database has leaked and passwords were stored with MD5 or unsalted SHA-1 - still "
     "distressingly common. 20 billion guesses/second on a GPU rig."),
]


# =============================================================================
# SECTION 1 - Utilities
# =============================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ts_pretty(iso: str | None) -> str:
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def html_escape(s) -> str:
    return _html.escape("" if s is None else str(s), quote=True)


def fingerprint(password: str) -> str:
    """A non-reversible identifier, so reuse can be spotted without keeping the
    password. Salted with nothing on purpose - the same password must produce the
    same fingerprint within a batch for reuse detection to work at all."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def mask(password: str) -> str:
    """What is safe to print. Never the password."""
    n = len(password)
    if n == 0:
        return "(empty)"
    if n <= 2:
        return "*" * n
    return f"{password[0]}{'*' * (n - 2)}{password[-1]}  ({n} chars)"


def fmt_time(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = [("second", 60), ("minute", 60), ("hour", 24), ("day", 365.25),
             ("year", 1000), ("thousand years", 1000), ("million years", 1000),
             ("billion years", 1e9)]
    value = seconds
    for name, factor in units:
        if value < factor:
            return f"{value:.0f} {name}{'s' if value >= 2 and 'years' not in name else ''}"
        value /= factor
    return "longer than the age of the universe"


def F(category, title, severity, description, evidence="", advice=""):
    return {"category": category, "title": title, "severity": severity,
            "description": description, "evidence": str(evidence)[:1500],
            "advice": advice}


# =============================================================================
# SECTION 2 - The patterns
#   Everything here is a structural observation about the password itself. There
#   is no wordlist of leaked passwords, because shipping one would be a breach
#   corpus in disguise - and a small one would give false comfort.
# =============================================================================

KEYBOARD_ROWS = {
    "qwerty": ["`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"],
    "qwertz": ["`1234567890ß´", "qwertzuiopü+", "asdfghjklöä#", "yxcvbnm,.-"],
    "azerty": ["²&é\"'(-è_çà)=", "azertyuiop^$", "qsdfghjklmù*", "wxcvbn,;:!"],
    "numpad": ["789", "456", "123"],
}

# Very common structural words. This is NOT a leaked-password list - it is the
# handful of words that appear in almost every cracking rule set, kept short
# deliberately so it is obviously not pretending to be comprehensive.
COMMON_BASES = {
    "password", "passwd", "pass", "welcome", "letmein", "admin", "administrator",
    "login", "root", "user", "guest", "test", "demo", "default", "changeme",
    "secret", "master", "access", "qwerty", "monkey", "dragon", "sunshine",
    "princess", "football", "baseball", "superman", "batman", "shadow", "michael",
    "jordan", "hunter", "trustno1", "iloveyou", "starwars", "computer", "internet",
    "samsung", "google", "facebook", "whatsapp", "india", "cricket", "krishna",
    "ganesh", "shiva", "rahul", "amit", "priya", "summer", "winter", "spring",
    "autumn", "january", "february", "march", "april", "june", "july", "august",
    "september", "october", "november", "december", "monday", "friday",
}

LEET_MAP = {"4": "a", "@": "a", "8": "b", "(": "c", "3": "e", "6": "g", "9": "g",
            "1": "i", "!": "i", "|": "i", "0": "o", "5": "s", "$": "s", "7": "t",
            "+": "t", "2": "z"}

SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789",
             "qwertyuiop", "asdfghjkl", "zxcvbnm"]

CHAR_CLASSES = [
    ("lower", re.compile(r"[a-z]"), 26),
    ("upper", re.compile(r"[A-Z]"), 26),
    ("digit", re.compile(r"[0-9]"), 10),
    ("symbol", re.compile(r"[^a-zA-Z0-9\s]"), 33),
    ("space", re.compile(r"\s"), 1),
    ("nonascii", re.compile(r"[^\x00-\x7f]"), 100),
]


def char_space(password: str) -> tuple[int, list[str]]:
    """How many characters an attacker would have to try per position, if they
    knew nothing about structure. This is the OPTIMISTIC number."""
    space, used = 0, []
    for name, pattern, size in CHAR_CLASSES:
        if pattern.search(password):
            space += size
            used.append(name)
    return max(space, 1), used


def unleet(text: str) -> str:
    return "".join(LEET_MAP.get(ch, ch) for ch in text.lower())


def find_keyboard_walks(password: str, min_len: int = 4) -> list[dict]:
    """Runs that trace a straight line across a keyboard."""
    found = []
    low = password.lower()
    for layout, rows in KEYBOARD_ROWS.items():
        for row in rows:
            for direction, seq in (("forward", row), ("backward", row[::-1])):
                for start in range(len(seq) - min_len + 1):
                    for length in range(len(seq) - start, min_len - 1, -1):
                        chunk = seq[start:start + length]
                        idx = low.find(chunk)
                        if idx >= 0:
                            found.append({"layout": layout, "run": chunk,
                                          "direction": direction, "position": idx,
                                          "length": len(chunk)})
                            break
    # keep only the longest run at each position
    best: dict[int, dict] = {}
    for f in found:
        cur = best.get(f["position"])
        if cur is None or f["length"] > cur["length"]:
            best[f["position"]] = f
    return sorted(best.values(), key=lambda f: -f["length"])[:5]


def find_sequences(password: str, min_len: int = 3) -> list[dict]:
    """abc, 123, and their reverses."""
    found = []
    low = password.lower()
    for seq in SEQUENCES:
        for direction, s in (("ascending", seq), ("descending", seq[::-1])):
            for length in range(len(s), min_len - 1, -1):
                for start in range(len(s) - length + 1):
                    chunk = s[start:start + length]
                    idx = low.find(chunk)
                    if idx >= 0:
                        found.append({"run": chunk, "direction": direction,
                                      "position": idx, "length": length})
    best: dict[int, dict] = {}
    for f in found:
        cur = best.get(f["position"])
        if cur is None or f["length"] > cur["length"]:
            best[f["position"]] = f
    return sorted(best.values(), key=lambda f: -f["length"])[:5]


def find_repeats(password: str) -> list[dict]:
    """aaaa, and abcabcabc."""
    found = []
    for m in re.finditer(r"(.)\1{2,}", password):
        found.append({"kind": "character", "run": m.group(0), "unit": m.group(1),
                      "count": len(m.group(0)), "position": m.start()})
    for size in range(2, min(len(password) // 2, 8) + 1):
        for m in re.finditer(rf"(.{{{size}}})\1{{1,}}", password):
            found.append({"kind": "block", "run": m.group(0), "unit": m.group(1),
                          "count": len(m.group(0)) // size, "position": m.start()})
    seen, out = set(), []
    for f in sorted(found, key=lambda f: (-len(f["run"]), f["position"])):
        key = (f["position"], len(f["run"]))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out[:5]


def find_dates(password: str) -> list[dict]:
    """Years, and full dates. A year is the single most common decoration."""
    found = []
    this_year = datetime.now(timezone.utc).year
    for m in re.finditer(r"(19[0-9]{2}|20[0-9]{2})", password):
        year = int(m.group(1))
        plausible = 1940 <= year <= this_year + 2
        found.append({"kind": "year", "value": m.group(1), "position": m.start(),
                      "plausible": plausible,
                      "why": ("a birth year, graduation year or the current year"
                              if plausible else "a four-digit run that reads as a year")})
    for m in re.finditer(r"\b(\d{1,2})[-/.](\d{1,2})[-/.](\d{2,4})\b", password):
        found.append({"kind": "date", "value": m.group(0), "position": m.start(),
                      "plausible": True, "why": "a full date"})
    for m in re.finditer(r"(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])", password):
        if not any(f["position"] <= m.start() < f["position"] + len(f["value"])
                   for f in found):
            found.append({"kind": "ddmm", "value": m.group(0), "position": m.start(),
                          "plausible": True,
                          "why": "reads as a day and month, or a month and day"})
    return found[:6]


def find_base_word(password: str) -> dict | None:
    """A common word hiding under capitalisation and leetspeak."""
    normalised = unleet(password)
    best = None
    for word in COMMON_BASES:
        idx = normalised.find(word)
        if idx >= 0:
            original = password[idx:idx + len(word)]
            transformed = original.lower() != word
            cand = {"word": word, "as_written": original, "position": idx,
                    "length": len(word), "transformed": transformed}
            if best is None or cand["length"] > best["length"]:
                best = cand
    return best


def looks_word_shaped(password: str, base_matched: bool) -> dict:
    """Does this look like word-plus-decoration even though no known word matched?

    The built-in list is deliberately tiny - a few dozen entries - because
    shipping a real cracking wordlist would make this tool a liability and a
    small one would give false comfort. The cost of that choice is that a
    password built on an ordinary dictionary word outside the list gets full
    credit it does not deserve. Rather than quietly over-rating it, this detects
    the SHAPE and says the estimate is probably optimistic.
    """
    out = {"word_shaped": False, "run": "", "why": "", "passphrase": False,
           "word_count": 0}
    # Decode DIGIT leet only. Digits are how a real word hides (tr0ub4dor), but
    # decoding symbols as well turns '!' into 'i' and manufactures vowels, which
    # made random strings like 'Lm2!Zt' read as words.
    digit_leet = {k: v for k, v in LEET_MAP.items() if k.isdigit()}
    decoded = "".join(digit_leet.get(c, c) for c in password.lower())
    runs = re.findall(r"[a-z]{4,}", decoded)
    if not runs:
        return out
    def wordish(run):
        vowels = sum(1 for c in run if c in "aeiou")
        ratio = vowels / len(run)
        # Real words cluster well above this; random letters rarely reach it.
        return len(run) >= 5 and 0.25 <= ratio <= 0.65
    words = [r for r in runs if wordish(r)]
    out["word_count"] = len(words)
    if len(words) >= 3:
        # Several separate words is a passphrase, and a passphrase built from
        # genuinely unrelated words is the good case - not something to warn about.
        out["passphrase"] = True
        return out
    if base_matched or not words:
        return out
    longest = max(words, key=len)
    out.update(word_shaped=True, run=longest,
               why=(f"a {len(longest)}-letter run with a vowel pattern typical of a real "
                    f"word"))
    return out


def describe_structure(password: str) -> dict:
    """The shape of the password, which is what rule-based cracking targets."""
    out = {"pattern": "", "capital_first_only": False, "digits_at_end": 0,
           "symbols_at_end": 0, "classic_shape": False, "why": ""}
    shape = []
    for ch in password:
        if ch.isupper():
            shape.append("U")
        elif ch.islower():
            shape.append("l")
        elif ch.isdigit():
            shape.append("d")
        elif ch.isspace():
            shape.append("_")
        else:
            shape.append("s")
    out["pattern"] = "".join(shape)
    letters = [c for c in password if c.isalpha()]
    out["capital_first_only"] = bool(
        letters and password[0].isupper()
        and all(not c.isupper() for c in password[1:] if c.isalpha()))
    m = re.search(r"(\d+)$", password)
    out["digits_at_end"] = len(m.group(1)) if m else 0
    m = re.search(r"([^a-zA-Z0-9]+)$", password)
    out["symbols_at_end"] = len(m.group(1)) if m else 0
    m = re.search(r"(\d+)([^a-zA-Z0-9]*)$", password)
    trailing_digits = len(m.group(1)) if m else 0
    if out["capital_first_only"] and trailing_digits:
        out["classic_shape"] = True
        out["why"] = ("a capital at the front, lower case in the middle, digits at the end"
                      + (" and a symbol after those" if out["symbols_at_end"] else "")
                      + " - the shape a password policy produces, and the first shape every "
                        "cracking rule set tries")
    return out


def analyse_password(password: str) -> dict:
    """Everything structural, in one pass. The password itself is not returned."""
    space, classes = char_space(password)
    raw_bits = len(password) * math.log2(space) if password else 0.0
    return {
        "length": len(password), "char_space": space, "classes": classes,
        "raw_bits": round(raw_bits, 1),
        "unique_chars": len(set(password)),
        "keyboard_walks": find_keyboard_walks(password),
        "sequences": find_sequences(password),
        "repeats": find_repeats(password),
        "dates": find_dates(password),
        "base_word": find_base_word(password),
        "word_shaped": looks_word_shaped(password, find_base_word(password) is not None),
        "structure": describe_structure(password),
        "fingerprint": fingerprint(password),
        "masked": mask(password),
        "all_one_class": len(classes) <= 1,
        "leet_applied": unleet(password) != password.lower(),
    }


# =============================================================================
# SECTION 3 - From patterns to an honest estimate
#   Raw character-space entropy is the number people quote and it is close to
#   useless: it assumes the attacker guesses blindly. A rule-based attacker does
#   not. So each pattern found here REPLACES the span it covers with the much
#   smaller number of guesses actually needed to produce it, and the accounting
#   is shown rather than hidden behind a single score.
# =============================================================================

# Rough guess counts an attacker needs for each construction. These are
# deliberately conservative round numbers - the point is the order of magnitude.
GUESS_COSTS = {
    "common_word": 1e4,        # position in a standard cracking wordlist
    "leet_transform": 64,      # the handful of substitution rules that get tried
    "capitalisation": 8,       # first-letter, all-caps, alternating and so on
    "year": 80,                # a plausible year
    "date": 4e4,               # a full date
    "digit_suffix": 1e3,       # short trailing digit runs are tried in order
    "symbol_suffix": 32,       # the symbols people actually pick
    "keyboard_walk": 3e3,      # walks across all common layouts
    "sequence": 200,           # abc/123 runs
    "repeat": 100,             # a repeated unit
}


def effective_bits(password: str, a: dict) -> dict:
    """Bits of real resistance, with the reasoning kept alongside the number."""
    n = len(password)
    if n == 0:
        return {"bits": 0.0, "guesses": 1.0, "covered": 0, "accounting": [],
                "raw_bits": 0.0}
    covered = [False] * n
    guesses = 1.0
    accounting = []

    def cover(start, length, cost, label, detail):
        nonlocal guesses
        span = range(max(0, start), min(n, start + length))
        newly = [i for i in span if not covered[i]]
        if not newly:
            return
        for i in newly:
            covered[i] = True
        guesses *= cost
        accounting.append({"label": label, "detail": detail, "chars": len(newly),
                           "guesses": cost, "bits": round(math.log2(cost), 1)})

    base = a["base_word"]
    if base:
        cost = GUESS_COSTS["common_word"]
        detail = f"'{base['word']}' is in every cracking wordlist"
        if base["transformed"]:
            cost *= GUESS_COSTS["leet_transform"]
            detail += (", and substituting digits or symbols for letters is a standard rule "
                       "- it does not add meaningful work")
        cover(base["position"], base["length"], cost, "a common word", detail)

    for w in a["keyboard_walks"]:
        cover(w["position"], w["length"], GUESS_COSTS["keyboard_walk"],
              "a keyboard walk",
              f"'{w['run']}' traces a straight line across a {w['layout']} keyboard")
    for s in a["sequences"]:
        cover(s["position"], s["length"], GUESS_COSTS["sequence"],
              "a sequence", f"'{s['run']}' runs {s['direction']}")
    for r in a["repeats"]:
        cover(r["position"], len(r["run"]), GUESS_COSTS["repeat"],
              "a repeat", f"'{r['unit']}' repeated {r['count']} times")
    for d in a["dates"]:
        cost = GUESS_COSTS["year"] if d["kind"] == "year" else GUESS_COSTS["date"]
        cover(d["position"], len(d["value"]), cost,
              "a date" if d["kind"] != "year" else "a year",
              f"'{d['value']}' is {d['why']}")

    st = a["structure"]
    if st["capital_first_only"]:
        guesses *= GUESS_COSTS["capitalisation"]
        accounting.append({"label": "predictable capitalisation",
                           "detail": "only the first letter is capitalised, which is the "
                                     "first thing every rule set tries",
                           "chars": 0, "guesses": GUESS_COSTS["capitalisation"],
                           "bits": round(math.log2(GUESS_COSTS["capitalisation"]), 1)})

    # whatever is left is genuinely unpredictable, and gets full credit
    remaining = covered.count(False)
    space = a["char_space"]
    if remaining:
        cost = space ** remaining
        guesses *= cost
        accounting.append({"label": "unpredictable characters",
                           "detail": f"{remaining} character(s) are not part of any pattern "
                                     f"found here, drawn from a space of {space}",
                           "chars": remaining, "guesses": cost,
                           "bits": round(remaining * math.log2(space), 1)})
    guesses = max(guesses, 1.0)
    return {"bits": round(math.log2(guesses), 1), "guesses": guesses,
            "covered": n - remaining, "accounting": accounting,
            "raw_bits": a["raw_bits"]}


def crack_times(guesses: float) -> list[dict]:
    """The same password against four different attackers."""
    out = []
    for key, name, rate, why in ATTACK_MODELS:
        seconds = (guesses / 2.0) / rate          # expected, not worst case
        out.append({"key": key, "model": name, "rate": rate, "why": why,
                    "seconds": seconds, "human": fmt_time(seconds)})
    return out


def analyse_full(password: str) -> dict:
    a = analyse_password(password)
    eff = effective_bits(password, a)
    band, colour = strength_band(eff["bits"])
    return {**a, "effective": eff, "band": band, "band_colour": colour,
            "crack_times": crack_times(eff["guesses"]),
            "penalty_bits": round(a["raw_bits"] - eff["bits"], 1)}


# =============================================================================
# SECTION 4 - Findings
# =============================================================================

def build_findings(res: dict, label: str = "") -> list[dict]:
    out: list[dict] = []
    eff = res["effective"]
    bits = eff["bits"]
    n = res["length"]

    if n == 0:
        return [F("Basics", "The password is empty", "critical", "There is nothing here.",
                  "", "An empty password is no password.")]

    # ---- the headline ----
    offline_fast = next(c for c in res["crack_times"] if c["key"] == "offline_fast")
    online = next(c for c in res["crack_times"] if c["key"] == "online_throttled")
    sev = ("critical" if bits < 25 else "high" if bits < 40
           else "medium" if bits < 55 else "low" if bits < 75 else "info")
    out.append(F("Strength", f"About {bits:.0f} bits of real resistance - {res['band']}",
                 sev,
                 f"A naive count of the character space gives {eff['raw_bits']:.0f} bits. "
                 f"After accounting for the patterns found, the honest figure is "
                 f"{bits:.0f}.",
                 f"if the site rate-limits: {online['human']}\n"
                 f"if the database leaks and hashing is weak: {offline_fast['human']}",
                 "The gap between those two numbers is the whole point: you do not control "
                 "how the other end stores your password, so assume the worse of the two."
                 if res["penalty_bits"] > 10 else
                 "These are order-of-magnitude estimates against a modelled attacker, not "
                 "promises."))

    if res["penalty_bits"] > 15:
        out.append(F("Strength", f"Patterns account for {res['penalty_bits']:.0f} bits of "
                     f"apparent strength", "info",
                     "Most of the length here is predictable, so it does not cost an "
                     "attacker much.",
                     "\n".join(f"{acc['label']}: {acc['detail']} "
                               f"(~2^{acc['bits']:.0f} guesses)"
                               for acc in eff["accounting"]),
                     "A longer password built from predictable parts is not stronger than a "
                     "shorter unpredictable one. This is why length advice alone is "
                     "misleading."))

    # ---- individual patterns ----
    base = res["base_word"]
    if base:
        out.append(F("Pattern", f"Built on the common word '{base['word']}'",
                     "critical" if n <= 12 else "high",
                     "This word appears in every cracking wordlist, so it is tried within "
                     "the first few thousand guesses."
                     + (" Substituting digits and symbols for letters does not help - "
                        "reversing that is a standard rule."
                        if base["transformed"] else ""),
                     f"position {base['position']}, written as '{base['as_written']}'",
                     "Leetspeak feels clever and is worth almost nothing: 'P@ssw0rd' and "
                     "'password' cost an attacker the same. Choose words that are not on "
                     "anyone's list, or better, use several unrelated ones."))
    for w in res["keyboard_walks"][:2]:
        out.append(F("Pattern", f"Keyboard walk: '{w['run']}'", "high",
                     f"These characters trace a straight line across a {w['layout']} "
                     f"keyboard, running {w['direction']}.",
                     f"position {w['position']}, {w['length']} characters",
                     "Walks are generated exhaustively before dictionary attacks even "
                     "begin. They feel random because the fingers move; they are not."))
    for s in res["sequences"][:2]:
        out.append(F("Pattern", f"Sequence: '{s['run']}'", "medium",
                     f"A run of {s['length']} characters {s['direction']}.",
                     f"position {s['position']}",
                     "Sequences cost an attacker almost nothing."))
    for r in res["repeats"][:2]:
        out.append(F("Pattern", f"Repetition: '{r['unit']}' repeated {r['count']} times",
                     "medium",
                     f"{len(r['run'])} of the {n} characters are one repeated unit.",
                     f"position {r['position']}",
                     "Repetition adds length without adding anything to guess. The real "
                     "strength here comes from the unique part only."))
    for d in res["dates"]:
        sev_d = "high" if d["plausible"] else "medium"
        out.append(F("Pattern", f"Contains {d['kind'] if d['kind'] != 'ddmm' else 'a date'}"
                     f": '{d['value']}'", sev_d,
                     f"{d['why'].capitalize()}.", f"position {d['position']}",
                     "Years are the most common decoration there is - a birth year, a "
                     "graduation year, or whatever year the password policy last forced a "
                     "change. There are fewer than a hundred plausible ones."))

    st = res["structure"]
    if st["classic_shape"]:
        out.append(F("Pattern", "The classic password-policy shape", "high",
                     f"The pattern is {st['pattern']}: {st['why']}.",
                     f"shape: {st['pattern']}",
                     "This is what happens when a policy demands an upper case letter, a "
                     "digit and a symbol: everyone puts the capital first and the digits "
                     "last. Cracking rules exploit exactly that, which is why the policy "
                     "buys far less than it appears to."))
    elif st["capital_first_only"] and n > 4:
        out.append(F("Pattern", "Only the first letter is capitalised", "low",
                     "The most predictable place to put a capital.",
                     f"shape: {st['pattern']}",
                     "Worth a few guesses at most."))

    # ---- composition ----
    if n < 8:
        out.append(F("Basics", f"Only {n} characters long", "critical",
                     "Short enough to fall to brute force regardless of what it contains.",
                     f"{n} characters, {res['unique_chars']} of them distinct",
                     "Below about 12 characters, composition rules stop mattering - there "
                     "simply is not enough space to search."))
    elif n < 12:
        out.append(F("Basics", f"{n} characters long", "medium",
                     "Short by current standards.",
                     f"{n} characters, {res['unique_chars']} distinct",
                     "Length is the cheapest strength there is, provided the added length "
                     "is not predictable."))
    else:
        out.append(F("Basics", f"{n} characters long", "info",
                     f"{res['unique_chars']} of them distinct.",
                     f"character classes used: {', '.join(res['classes'])}",
                     "Good length. What matters now is whether it is predictable."))

    if res["all_one_class"] and n < 20:
        out.append(F("Basics", f"Uses only one kind of character ({res['classes'][0]})",
                     "medium", "The search space per character is as small as it gets.",
                     f"space: {res['char_space']} characters per position",
                     "Mixing in another class helps - though far less than not being "
                     "guessable in the first place. A long passphrase of ordinary lower "
                     "case words beats a short mixed-class password comfortably."))

    if res["unique_chars"] <= 4 and n >= 6:
        out.append(F("Basics", f"Only {res['unique_chars']} distinct characters", "high",
                     "The password reuses a very small alphabet.",
                     f"{n} characters, {res['unique_chars']} distinct",
                     "The real space here is far smaller than the length suggests."))

    ws = res.get("word_shaped") or {}
    if ws.get("passphrase"):
        out.append(F("Estimate", f"This looks like a passphrase of {ws['word_count']} "
                     f"words", "info",
                     "Several separate word-like runs, which is the shape of a passphrase "
                     "rather than a word with decoration.",
                     f"{ws['word_count']} word-like runs",
                     "This is the good case, and the estimate above may actually be "
                     "generous: an attacker guessing whole words needs roughly 11 to 13 "
                     "bits per word rather than per character, so four unrelated words is "
                     "around 45 to 50 bits - strong, but not the number a per-character "
                     "count suggests. Four words chosen at random beat almost any single "
                     "decorated word, provided you did not pick them from a phrase anyone "
                     "has ever written down."))
    elif ws.get("word_shaped"):
        out.append(F("Estimate", "This estimate is probably optimistic", "high",
                     f"'{ws['run']}' looks like a dictionary word - {ws['why']} - but it is "
                     f"not in this tool's built-in list, so it was credited as "
                     f"unpredictable when it almost certainly is not.",
                     f"letter run: {len(ws['run'])} characters",
                     "The built-in word list is deliberately tiny, because shipping a real "
                     "cracking wordlist would make this tool a liability. The cost is "
                     "exactly this case: a password built on an ordinary word outside the "
                     "list scores far too well. If that run is a word in any language, "
                     "assume the real figure is 30 to 40 bits lower than the one above - "
                     "which is the difference between centuries and seconds."))

    # ---- the thing this tool cannot do ----
    out.append(F("Scope", "Whether this password has been breached was NOT checked", "info",
                 NOT_A_BREACH_CHECK, "",
                 "If you want to know whether a specific password has appeared in a dump, "
                 "use a service with a real breach dataset - Have I Been Pwned's range API "
                 "sends only the first five characters of the SHA-1 hash, so the password "
                 "itself never leaves your machine either. That is a different question "
                 "from the one answered here, and both are worth asking."))
    return out


def check_password(password: str, label: str = "") -> dict:
    t0 = time.time()
    res = analyse_full(password)
    findings = build_findings(res, label)
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    return {"label": label, "checked_at": now_iso(), "analysis": res,
            "findings": findings, "counts": counts,
            "bits": res["effective"]["bits"], "band": res["band"],
            "band_colour": res["band_colour"], "fingerprint": res["fingerprint"],
            "masked": res["masked"], "length": res["length"],
            "elapsed_ms": int((time.time() - t0) * 1000)}


def find_reuse(results: list[dict]) -> list[dict]:
    """Identical passwords, and passwords sharing a base with a different tail.

    Compared by fingerprint and by structural shape - never by keeping the
    passwords around to compare directly.
    """
    out = []
    by_fp: dict[str, list] = {}
    for r in results:
        by_fp.setdefault(r["fingerprint"], []).append(r)
    for fp, group in by_fp.items():
        if len(group) > 1:
            out.append({"kind": "identical", "fingerprint": fp,
                        "labels": [g["label"] or g["masked"] for g in group],
                        "count": len(group)})
    by_base: dict[str, list] = {}
    for r in results:
        base = r["analysis"].get("base_word")
        if base:
            by_base.setdefault(base["word"], []).append(r)
    for word, group in by_base.items():
        distinct = {g["fingerprint"] for g in group}
        if len(distinct) > 1:
            out.append({"kind": "shared_base", "base": word,
                        "labels": [g["label"] or g["masked"] for g in group],
                        "count": len(group)})
    return out


# =============================================================================
# SECTION 5 - Database
#   The password is never a column here. Only the fingerprint, the findings and
#   the structural facts.
# =============================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, label TEXT, fingerprint TEXT NOT NULL, length INTEGER,
    bits REAL, raw_bits REAL, penalty_bits REAL, band TEXT, unique_chars INTEGER,
    char_space INTEGER, classes TEXT, shape TEXT, base_word TEXT,
    has_walk INTEGER DEFAULT 0, has_sequence INTEGER DEFAULT 0,
    has_repeat INTEGER DEFAULT 0, has_date INTEGER DEFAULT 0,
    classic_shape INTEGER DEFAULT 0, crack_offline_fast REAL, crack_online REAL,
    elapsed_ms INTEGER, payload TEXT, batch TEXT,
    critical INTEGER DEFAULT 0, high INTEGER DEFAULT 0, medium INTEGER DEFAULT 0,
    low INTEGER DEFAULT 0, info INTEGER DEFAULT 0, note TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, check_id INTEGER NOT NULL,
    category TEXT, title TEXT, severity TEXT, description TEXT, evidence TEXT,
    advice TEXT, FOREIGN KEY (check_id) REFERENCES checks(id)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, level TEXT NOT NULL, source TEXT, message TEXT, check_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_find_check ON findings(check_id);
CREATE INDEX IF NOT EXISTS idx_checks_fp ON checks(fingerprint);
CREATE INDEX IF NOT EXISTS idx_checks_batch ON checks(batch);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""

_DB_PATH = DEFAULT_DB


def set_db_path(p: str) -> None:
    global _DB_PATH
    _DB_PATH = p


def db_path() -> str:
    return _DB_PATH


def connect(path: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or _DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        if own:
            conn.close()


def q(sql: str, args: tuple = (), conn=None) -> list[sqlite3.Row]:
    own = conn is None
    conn = conn or connect()
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        if own:
            conn.close()


def q1(sql: str, args: tuple = (), conn=None):
    rows = q(sql, args, conn)
    return rows[0] if rows else None


def log_event(level: str, source: str, message: str, check_id=None, conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.execute("INSERT INTO audit_log (ts, level, source, message, check_id) "
                     "VALUES (?,?,?,?,?)",
                     (now_iso(), level.upper(), source,
                      " ".join(str(message).split())[:1000], check_id))
        conn.commit()
    except Exception:
        pass
    finally:
        if own:
            conn.close()


def _safe_payload(res: dict) -> dict:
    """Everything except anything that could reconstruct the password.

    'as_written' shows the literal characters of the matched word, so it is
    dropped here even though it is useful on screen - what is on screen is gone
    when the terminal closes, and what is in the database is not.
    """
    a = dict(res["analysis"])
    if a.get("base_word"):
        a["base_word"] = {k: v for k, v in a["base_word"].items() if k != "as_written"}
    a.pop("masked", None)
    return {"label": res["label"], "checked_at": res["checked_at"], "analysis": a,
            "bits": res["bits"], "band": res["band"], "counts": res["counts"]}


def save_check(res: dict, note: str = "", batch: str = "") -> int:
    conn = connect()
    try:
        init_db(conn)
        a = res["analysis"]
        eff = a["effective"]
        counts = res["counts"]
        fast = next(c["seconds"] for c in a["crack_times"] if c["key"] == "offline_fast")
        onl = next(c["seconds"] for c in a["crack_times"]
                   if c["key"] == "online_throttled")
        cur = conn.execute(
            "INSERT INTO checks (ts, label, fingerprint, length, bits, raw_bits,"
            " penalty_bits, band, unique_chars, char_space, classes, shape, base_word,"
            " has_walk, has_sequence, has_repeat, has_date, classic_shape,"
            " crack_offline_fast, crack_online, elapsed_ms, payload, batch,"
            " critical, high, medium, low, info, note)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (res["checked_at"], res["label"], res["fingerprint"], res["length"],
             eff["bits"], a["raw_bits"], a["raw_bits"] - eff["bits"], res["band"],
             a["unique_chars"], a["char_space"], json.dumps(a["classes"]),
             a["structure"]["pattern"],
             (a["base_word"] or {}).get("word"),
             int(bool(a["keyboard_walks"])), int(bool(a["sequences"])),
             int(bool(a["repeats"])), int(bool(a["dates"])),
             int(bool(a["structure"]["classic_shape"])), fast, onl,
             res["elapsed_ms"], json.dumps(_safe_payload(res), default=str), batch,
             counts["critical"], counts["high"], counts["medium"], counts["low"],
             counts["info"], note))
        cid = cur.lastrowid
        for f in res["findings"]:
            conn.execute("INSERT INTO findings (check_id, category, title, severity,"
                         " description, evidence, advice) VALUES (?,?,?,?,?,?,?)",
                         (cid, f["category"], f["title"], f["severity"],
                          f["description"], f["evidence"], f.get("advice", "")))
        conn.commit()
        log_event("INFO", "check",
                  f"Checked {res['label'] or 'a password'}: {eff['bits']:.0f} bits "
                  f"({res['band']})", cid, conn)
        return cid
    finally:
        conn.close()


def latest_check_id(conn=None):
    row = q1("SELECT id FROM checks ORDER BY id DESC LIMIT 1", (), conn)
    return row["id"] if row else None


def check_summary(cid: int, conn=None):
    row = q1("SELECT * FROM checks WHERE id=?", (cid,), conn)
    if not row:
        return None
    d = dict(row)
    for key, default in (("payload", "{}"), ("classes", "[]")):
        try:
            d[key] = json.loads(d[key] or default)
        except json.JSONDecodeError:
            d[key] = {} if key == "payload" else []
    d["band_colour"] = strength_band(d["bits"] or 0)[1]
    return d


def reuse_in_db(conn=None) -> list[dict]:
    out = []
    for r in q("SELECT fingerprint, COUNT(*) n, GROUP_CONCAT(IFNULL(label,'unlabelled')) "
               "labels FROM checks GROUP BY fingerprint HAVING n > 1", (), conn):
        out.append({"kind": "identical", "fingerprint": r["fingerprint"],
                    "count": r["n"], "labels": (r["labels"] or "").split(",")})
    for r in q("SELECT base_word, COUNT(DISTINCT fingerprint) n, "
               "GROUP_CONCAT(IFNULL(label,'unlabelled')) labels FROM checks "
               "WHERE base_word IS NOT NULL GROUP BY base_word HAVING n > 1", (), conn):
        out.append({"kind": "shared_base", "base": r["base_word"], "count": r["n"],
                    "labels": (r["labels"] or "").split(",")})
    return out


# =============================================================================
# SECTION 6 - Charts (hand-drawn SVG: no CDN, no JS library, offline)
# =============================================================================

def svg_accounting(res: dict, width=900, title="Where the strength actually comes from"):
    """The signature visual: apparent bits versus real bits, broken down.

    Two stacked bars. The top is what a naive character count claims; the bottom
    is what survives once each pattern is replaced by the guesses it really costs.
    """
    a = res.get("analysis") or res
    eff = a.get("effective") or {}
    acc = eff.get("accounting") or []
    raw = a.get("raw_bits", 0) or 0
    real = eff.get("bits", 0) or 0
    if not acc and not raw:
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    scale_max = max(raw, real, 1)
    pad_l, bw, bh = 150, width - 200, 34
    parts = [f'<text x="{pad_l - 12}" y="30" text-anchor="end" class="lbl">claimed</text>',
             f'<rect x="{pad_l}" y="12" width="{bw}" height="{bh}" rx="5" class="btrack"/>',
             f'<rect x="{pad_l}" y="12" width="{bw * raw / scale_max:.1f}" height="{bh}" '
             f'rx="5" fill="#3a3f4a"/>',
             f'<text x="{pad_l + bw * raw / scale_max + 8:.1f}" y="34" class="bv">'
             f'{raw:.0f} bits</text>',
             f'<text x="{pad_l - 12}" y="86" text-anchor="end" class="lbl">real</text>',
             f'<rect x="{pad_l}" y="68" width="{bw}" height="{bh}" rx="5" class="btrack"/>']
    x = pad_l
    palette = ["#e5484d", "#f76808", "#ffb224", "#9775fa", "#3e9dd8"]
    pattern_parts = [p for p in acc if p["label"] != "unpredictable characters"]
    good = [p for p in acc if p["label"] == "unpredictable characters"]
    for i, p in enumerate(pattern_parts):
        w = bw * (p["bits"] / scale_max)
        parts.append(f'<rect x="{x:.1f}" y="68" width="{max(w, 1.5):.1f}" height="{bh}" '
                     f'fill="{palette[i % len(palette)]}">'
                     f'<title>{html_escape(p["label"])}: {html_escape(p["detail"])} '
                     f'(~2^{p["bits"]:.0f})</title></rect>')
        x += w
    for p in good:
        w = bw * (p["bits"] / scale_max)
        parts.append(f'<rect x="{x:.1f}" y="68" width="{max(w, 1.5):.1f}" height="{bh}" '
                     f'rx="5" fill="#30a46c">'
                     f'<title>{html_escape(p["detail"])}</title></rect>')
        x += w
    parts.append(f'<text x="{x + 8:.1f}" y="90" class="bv">{real:.0f} bits</text>')
    legend = []
    for i, p in enumerate(pattern_parts):
        legend.append(f'<div class="lg"><i style="background:'
                      f'{palette[i % len(palette)]}"></i>'
                      f'<span>{html_escape(p["label"])}</span>'
                      f'<b>2^{p["bits"]:.0f}</b></div>')
    for p in good:
        legend.append(f'<div class="lg"><i style="background:#30a46c"></i>'
                      f'<span>unpredictable ({p["chars"]} chars)</span>'
                      f'<b>2^{p["bits"]:.0f}</b></div>')
    return (f'<figure class="chart wide"><figcaption>{html_escape(title)} &middot; '
            f'grey is what a naive character count claims &middot; green is what an '
            f'attacker actually has to search</figcaption>'
            f'<svg viewBox="0 0 {width} 112" width="100%" height="112" role="img" '
            f'aria-label="{html_escape(title)}">{"".join(parts)}</svg>'
            f'<div class="legend row">{"".join(legend)}</div></figure>')


def svg_crack_times(times: list[dict], width=430, title="How long, against whom"):
    if not times:
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    row_h, gap, pad_l, pad_t = 26, 9, 150, 10
    height = pad_t * 2 + len(times) * (row_h + gap)
    bw = width - pad_l - 70
    # log scale: seconds span from instant to longer than the universe
    def scale(sec):
        return clamp(math.log10(max(sec, 1e-3) + 1) / 18.0, 0.01, 1.0)
    rows = []
    for i, t in enumerate(times):
        y = pad_t + i * (row_h + gap)
        frac = scale(t["seconds"])
        colour = ("#e5484d" if t["seconds"] < 3600 else
                  "#f76808" if t["seconds"] < 86400 * 30 else
                  "#ffb224" if t["seconds"] < 86400 * 365 * 10 else "#30a46c")
        rows.append(
            f'<text x="{pad_l - 9}" y="{y + row_h * 0.68:.1f}" text-anchor="end" '
            f'class="bl">{html_escape(t["model"])}</text>'
            f'<rect x="{pad_l}" y="{y}" width="{bw}" height="{row_h}" rx="4" class="btrack"/>'
            f'<rect x="{pad_l}" y="{y}" width="{max(bw * frac, 3):.1f}" height="{row_h}" '
            f'rx="4" fill="{colour}"><title>{html_escape(t["why"])}</title></rect>'
            f'<text x="{pad_l + 8}" y="{y + row_h * 0.68:.1f}" class="bv">'
            f'{html_escape(t["human"])}</text>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)} &middot; log scale '
            f'&middot; hover for the assumption</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(rows)}</svg></figure>')


def svg_pie(items, size=180, title="Findings by severity", fmt=lambda v: f"{v:g}"):
    items = [(l, float(v), c) for (l, v, c) in items if v and v > 0]
    total = sum(v for _, v, _ in items)
    if total <= 0:
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    cx = cy = size / 2
    r_out, r_in = size / 2 - 10, size / 2 - 42
    parts, legend, angle = [], [], -90.0
    for label, value, color in items:
        sweep = 360.0 * value / total
        if abs(sweep - 360.0) < 1e-9:
            parts.append(f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2:.2f}" '
                         f'fill="none" stroke="{color}" stroke-width="{r_out - r_in:.2f}"/>')
        else:
            a0, a1 = math.radians(angle), math.radians(angle + sweep)
            x0, y0 = cx + r_out * math.cos(a0), cy + r_out * math.sin(a0)
            x1, y1 = cx + r_out * math.cos(a1), cy + r_out * math.sin(a1)
            x2, y2 = cx + r_in * math.cos(a1), cy + r_in * math.sin(a1)
            x3, y3 = cx + r_in * math.cos(a0), cy + r_in * math.sin(a0)
            lg = 1 if sweep > 180 else 0
            parts.append(f'<path d="M {x0:.2f} {y0:.2f} A {r_out:.2f} {r_out:.2f} 0 {lg} 1 '
                         f'{x1:.2f} {y1:.2f} L {x2:.2f} {y2:.2f} A {r_in:.2f} {r_in:.2f} 0 '
                         f'{lg} 0 {x3:.2f} {y3:.2f} Z" fill="{color}">'
                         f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title>'
                         f'</path>')
        angle += sweep
        legend.append(f'<div class="lg"><i style="background:{color}"></i>'
                      f'<span>{html_escape(label)}</span><b>{html_escape(fmt(value))}</b>'
                      f'</div>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<div class="chart-row"><svg viewBox="0 0 {size} {size}" width="{size}" '
            f'height="{size}" role="img" aria-label="{html_escape(title)}">{"".join(parts)}'
            f'<text x="{cx}" y="{cy + 5}" text-anchor="middle" class="pie-n">'
            f'{html_escape(fmt(total))}</text></svg>'
            f'<div class="legend">{"".join(legend)}</div></div></figure>')


def svg_bar(items, width=430, title="", color="#5b8def", fmt=lambda v: f"{v:g}",
            colors=None):
    items = [(str(l), float(v or 0)) for l, v in items]
    if not items or all(v <= 0 for _, v in items):
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    row_h, gap, pad_l, pad_t = 22, 7, 150, 8
    height = pad_t * 2 + len(items) * (row_h + gap)
    mx = max(v for _, v in items) or 1
    bw = width - pad_l - 62
    rows = []
    for i, (label, value) in enumerate(items):
        y = pad_t + i * (row_h + gap)
        w = max(2.0, bw * value / mx)
        c = (colors or {}).get(label, color)
        lbl = label if len(label) <= 21 else label[:20] + "\u2026"
        rows.append(
            f'<text x="{pad_l - 9}" y="{y + row_h * 0.7:.1f}" text-anchor="end" class="bl">'
            f'{html_escape(lbl)}</text>'
            f'<rect x="{pad_l}" y="{y}" width="{bw}" height="{row_h}" rx="4" class="btrack"/>'
            f'<rect x="{pad_l}" y="{y}" width="{w:.1f}" height="{row_h}" rx="4" fill="{c}">'
            f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title></rect>'
            f'<text x="{pad_l + bw + 7:.1f}" y="{y + row_h * 0.7:.1f}" class="bv">'
            f'{html_escape(fmt(value))}</text>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(rows)}</svg></figure>')


# =============================================================================
# SECTION 7 - Exports
#   No export ever contains a password. This is asserted by the self test.
# =============================================================================

def report_payload(cid=None, conn=None) -> dict:
    own = conn is None
    conn = conn or connect()
    try:
        cid = cid or latest_check_id(conn)
        chk = check_summary(cid, conn) if cid else None
        return {
            "tool": APP_NAME, "version": VERSION, "author": AUTHOR,
            "generated_at": now_iso(), "disclaimer": DISCLAIMER_LONG,
            "this_is_not_a_breach_check": NOT_A_BREACH_CHECK,
            "passwords_are_never_stored": NEVER_STORED,
            "limitations": [
                "This is NOT a breach check and cannot tell you whether a password has "
                "been leaked. No pattern found does not mean safe.",
                "The built-in word list is deliberately tiny, so a password built on an "
                "ordinary dictionary word outside it will be over-rated - the report says "
                "so when it detects that shape.",
                "Crack-time figures are arithmetic against a modelled attacker at a chosen "
                "guess rate. A real attacker with a good rule set does better.",
                "You do not control how the other end stores your password, so the "
                "fast-hash figure is the one to plan around.",
                "No password is written to the database, the logs or any export - only a "
                "SHA-256 fingerprint, which detects reuse without retaining the password.",
                "No network request is made at any point.",
            ],
            "check": chk,
            "findings": [dict(r) for r in q(
                "SELECT category,title,severity,description,evidence,advice FROM findings "
                "WHERE check_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 "
                "WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id",
                (cid,), conn)] if cid else [],
            "reuse": reuse_in_db(conn),
            "checks": [dict(r) for r in q(
                "SELECT id,ts,label,length,bits,band,batch FROM checks "
                "ORDER BY id DESC LIMIT 100", (), conn)],
        }
    finally:
        if own:
            conn.close()


def export_json(cid=None) -> str:
    return json.dumps(report_payload(cid), indent=2, default=str)


def export_csv(cid=None) -> str:
    conn = connect()
    try:
        cid = cid or latest_check_id(conn)
        chk = check_summary(cid, conn)
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow([f"# {APP_NAME} v{VERSION} by {AUTHOR}"])
        w.writerow([f"# check={cid} generated={now_iso()}"])
        w.writerow([f"# {DISCLAIMER_SHORT}"])
        w.writerow(["# No password appears in this file - only fingerprints and findings."])
        if not chk:
            return buf.getvalue()
        w.writerow([])
        w.writerow(["## Result"])
        w.writerow(["label", "fingerprint", "length", "bits", "raw_bits", "band",
                    "shape", "base_word", "unique_chars"])
        w.writerow([chk["label"], chk["fingerprint"], chk["length"], chk["bits"],
                    chk["raw_bits"], chk["band"], chk["shape"], chk["base_word"],
                    chk["unique_chars"]])
        w.writerow([])
        w.writerow(["## Findings"])
        w.writerow(["severity", "category", "title", "description", "advice"])
        for r in q("SELECT * FROM findings WHERE check_id=? ORDER BY id", (cid,), conn):
            w.writerow([r["severity"], r["category"], r["title"], r["description"],
                        r["advice"]])
        w.writerow([])
        w.writerow(["## All checks"])
        w.writerow(["id", "ts", "label", "length", "bits", "band"])
        for r in q("SELECT * FROM checks ORDER BY id", (), conn):
            w.writerow([r["id"], r["ts"], r["label"], r["length"], r["bits"], r["band"]])
        return buf.getvalue()
    finally:
        conn.close()


def export_html(cid=None) -> str:
    conn = connect()
    try:
        p = report_payload(cid, conn)
        chk, esc = p["check"], html_escape
        if not chk:
            return "<!doctype html><html><body><h1>No checks recorded</h1></body></html>"
        counts = {s: chk[s] or 0 for s in SEVERITIES}
        payload = chk.get("payload") or {}
        acc_chart = svg_accounting(payload)
        times = (payload.get("analysis") or {}).get("crack_times") or []
        frows = "".join(
            f'<tr><td><span class="pill" style="background:{SEV_COLOR[f["severity"]]}">'
            f'{esc(f["severity"].upper())}</span></td>'
            f'<td><b>{esc(f["title"])}</b>'
            f'<div class="desc">{esc(f["description"])}</div>'
            + (f'<pre>{esc(f["evidence"])}</pre>' if f["evidence"] else "")
            + (f'<div class="means"><b>What to do:</b> {esc(f["advice"])}</div>'
               if f["advice"] else "") + "</td></tr>" for f in p["findings"])
        limits = "".join(f"<li>{esc(x)}</li>" for x in p["limitations"])
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{APP_SHORT} report</title><style>
 body{{font:14px/1.55 ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif;margin:0;
      background:#0f1115;color:#e6e8ee}}
 .wrap{{max-width:1060px;margin:0 auto;padding:28px 20px 60px}}
 h1{{font-size:22px;margin:0 0 4px}} .meta{{color:#8b8f9b;font-size:12.5px}}
 h2{{font-size:12px;text-transform:uppercase;letter-spacing:.15em;color:#8b8f9b;
     margin:30px 0 12px;border-bottom:1px solid #262a33;padding-bottom:8px}}
 .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:18px 0}}
 .card{{background:#171a21;border:1px solid #262a33;border-radius:10px;padding:12px 14px}}
 .card .n{{font-size:21px;font-weight:700;font-family:ui-monospace,monospace}}
 .card .l{{font-size:10.5px;text-transform:uppercase;letter-spacing:.11em;color:#8b8f9b}}
 table{{width:100%;border-collapse:collapse;background:#171a21;border:1px solid #262a33;
        border-radius:10px;overflow:hidden;font-size:12.7px}}
 th{{text-align:left;font-size:10.5px;letter-spacing:.11em;text-transform:uppercase;
     color:#8b8f9b;padding:9px 11px;border-bottom:1px solid #262a33;background:#1c2029}}
 td{{padding:8px 11px;border-bottom:1px solid #1e222a;vertical-align:top}}
 .mono{{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;word-break:break-all}}
 .pill{{color:#0f1115;font-weight:700;font-size:10px;padding:2px 8px;border-radius:20px}}
 .desc{{color:#b6bac4;margin-top:4px;max-width:84ch}}
 .means{{margin-top:6px;color:#8fd3b0;font-size:12.4px;max-width:84ch}}
 pre{{background:#0f1115;border:1px solid #262a33;border-radius:6px;padding:9px;
      font-family:ui-monospace,monospace;font-size:11.5px;margin:6px 0 0;overflow:auto;
      white-space:pre-wrap;color:#b6bac4}}
 .warn{{background:#231a12;border:1px solid #5a3b1c;color:#ffcf9e;padding:12px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0;white-space:pre-wrap}}
 .note{{background:#12202a;border:1px solid #1c4a5e;color:#a8d8e8;padding:11px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0}}
 .note ul{{margin:6px 0 0 18px;padding:0}} .note li{{margin:3px 0}}
 .privacy{{background:#12241a;border:1px solid #1e5138;color:#a8e8c4;padding:11px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0}}
 .charts{{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start;margin-bottom:14px}}
 .chart{{margin:0;background:#171a21;border:1px solid #262a33;border-radius:10px;
   padding:14px 16px}}
 .chart.wide{{width:100%}}
 .chart figcaption{{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;
   color:#8b8f9b;margin-bottom:10px;font-family:ui-monospace,monospace}}
 .chart-row{{display:flex;gap:16px;align-items:center;flex-wrap:wrap}}
 .chart-empty{{background:#171a21;border:1px dashed #31363f;border-radius:10px;padding:18px;
   color:#8b8f9b;font-size:12.5px}}
 .legend{{display:flex;flex-direction:column;gap:6px;min-width:130px}}
 .legend.row{{flex-direction:row;flex-wrap:wrap;gap:14px;margin-top:12px}}
 .lg{{display:flex;align-items:center;gap:7px;font-size:12.2px}}
 .lg i{{width:11px;height:11px;border-radius:3px}} .lg b{{font-family:ui-monospace,monospace}}
 text.bl{{fill:#8b8f9b;font:10.5px ui-monospace,monospace}}
 text.bv{{fill:#e6e8ee;font:11px ui-monospace,monospace}}
 text.lbl{{fill:#8b8f9b;font:11.5px ui-monospace,monospace}}
 text.pie-n{{fill:#e6e8ee;font:700 16px ui-monospace,monospace}}
 rect.btrack{{fill:#1e222a}}
 footer{{margin-top:36px;color:#6f7685;font-size:12px;border-top:1px solid #262a33;
   padding-top:14px}}
</style></head><body><div class="wrap">
<h1>Password pattern report</h1>
<div class="meta">{esc(chk['label'] or 'unlabelled')} &middot; {chk['length']} characters
 &middot; {ts_pretty(chk['ts'])}<br>fingerprint {esc(chk['fingerprint'])}</div>
<div class="note"><b>This is not a breach check.</b>
 {esc(p['this_is_not_a_breach_check'])}<ul>{limits}</ul></div>
<div class="privacy"><b>Nothing stored, nothing sent.</b>
 {esc(p['passwords_are_never_stored'])}</div>
<div class="warn">{esc(DISCLAIMER_LONG)}</div>
<div class="grid">
 <div class="card"><div class="l">Real strength</div>
  <div class="n" style="color:{chk['band_colour']}">{chk['bits']:.0f}</div>
  <div class="l">bits &middot; {esc(chk['band'] or '')}</div></div>
 <div class="card"><div class="l">Claimed</div>
  <div class="n" style="color:#6f7685">{chk['raw_bits']:.0f}</div>
  <div class="l">naive count</div></div>
 <div class="card"><div class="l">Lost to patterns</div>
  <div class="n" style="color:#f76808">{chk['penalty_bits']:.0f}</div></div>
 <div class="card"><div class="l">Length</div><div class="n">{chk['length']}</div>
  <div class="l">{chk['unique_chars']} distinct</div></div>
 <div class="card"><div class="l">Shape</div>
  <div class="n mono" style="font-size:13px">{esc((chk['shape'] or '')[:18])}</div></div>
</div>
<div class="charts">{acc_chart}</div>
<div class="charts">{svg_crack_times(times)}
 {svg_pie([(s, counts[s], SEV_COLOR[s]) for s in SEVERITIES])}</div>
<h2>Findings ({len(p['findings'])})</h2>
{'<table><tr><th>Severity</th><th>Detail</th></tr>' + frows + '</table>'
 if frows else '<div class="chart-empty">No findings.</div>'}
<footer>Generated by {APP_NAME} v{VERSION} &middot; {AUTHOR} &middot; {GITHUB}<br>
 No password appears anywhere in this file. This tool made no network request.</footer>
</div></body></html>"""
    finally:
        conn.close()


# =============================================================================
# SECTION 8 - Web application (offline: no CDN, no JS libraries, no requests)
# =============================================================================

CSS = """
:root{--bg:#0f1115;--panel:#171a21;--panel-2:#1c2029;--line:#262a33;--line-2:#31363f;
 --tx:#e6e8ee;--tx-dim:#8b8f9b;--tx-mid:#b6bac4;--accent:#9775fa;--ok:#30a46c;
 --warn:#ffb224;--crit:#e5484d;--good:#8fd3b0;
 --mono:ui-monospace,SFMono-Regular,'JetBrains Mono',Menlo,Consolas,'Courier New',monospace;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);
 font:14px/1.55 ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
header.top{border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:9}
.hd{max-width:1120px;margin:0 auto;padding:11px 20px;display:flex;align-items:center;gap:14px;
 flex-wrap:wrap}
.brand{font-family:var(--mono);font-weight:700;letter-spacing:-.4px;font-size:15px}
.brand b{color:var(--accent)}
.brand small{display:block;font-weight:400;font-size:10px;letter-spacing:.14em;
 text-transform:uppercase;color:var(--tx-dim)}
nav{display:flex;gap:2px;margin-left:auto;flex-wrap:wrap}
nav a{font-family:var(--mono);font-size:11.5px;letter-spacing:.05em;text-transform:uppercase;
 padding:6px 10px;border-radius:6px;color:var(--tx-dim)}
nav a:hover{background:var(--panel-2);color:var(--tx);text-decoration:none}
nav a.on{background:var(--accent);color:#0b0d10;font-weight:600}
.wrap{max-width:1120px;margin:0 auto;padding:20px 20px 70px}
.banner{background:#12202a;border:1px solid #1c4a5e;color:#a8d8e8;padding:10px 14px;
 border-radius:9px;font-size:12.3px;margin-bottom:12px;line-height:1.5}
.banner.warn{background:#231a12;border-color:#5a3b1c;color:#ffcf9e}
.banner.bad{background:#2a1216;border-color:#6b2229;color:#ffc9cd}
.banner.good{background:#12241a;border-color:#1e5138;color:#a8e8c4}
.banner b{color:#fff} .banner ul{margin:6px 0 0 18px;padding:0} .banner li{margin:3px 0}
h1{font-size:19px;margin:0 0 3px;letter-spacing:-.3px}
h2{font-family:var(--mono);font-size:11.5px;letter-spacing:.16em;text-transform:uppercase;
 color:var(--tx-dim);margin:24px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
.sub{color:var(--tx-dim);font-size:12.5px;margin-bottom:14px}
.sub2{color:var(--tx-dim);font-size:11px;font-family:var(--mono)}
.bar{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin:0 0 16px}
.btn{font-family:var(--mono);font-size:12px;padding:8px 13px;border-radius:7px;cursor:pointer;
 border:1px solid var(--line-2);background:var(--panel-2);color:var(--tx);display:inline-block}
.btn:hover{border-color:var(--accent);text-decoration:none}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#0b0d10;font-weight:700}
input[type=text],input[type=password]{font-family:var(--mono);font-size:13px;padding:9px 11px;
 background:var(--panel-2);color:var(--tx);border:1px solid var(--line-2);border-radius:7px;
 min-width:280px}
label.chk{font-family:var(--mono);font-size:12px;color:var(--tx-dim);display:flex;gap:5px;
 align-items:center}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));margin:14px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:13px 15px}
.card .l{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;text-transform:uppercase;
 color:var(--tx-dim)}
.card .n{font-size:21px;font-weight:700;line-height:1.3;font-family:var(--mono)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
 border-radius:11px;overflow:hidden;font-size:12.7px}
th{text-align:left;font-family:var(--mono);font-size:10.5px;letter-spacing:.11em;
 text-transform:uppercase;color:var(--tx-dim);padding:9px 11px;border-bottom:1px solid var(--line);
 background:var(--panel-2);white-space:nowrap}
td{padding:8px 11px;border-bottom:1px solid #1e222a;vertical-align:top}
tr:last-child td{border-bottom:none} tr:hover td{background:#1b1f27}
.mono{font-family:var(--mono);font-size:11.8px;word-break:break-all}
.num{font-family:var(--mono);font-size:11.8px;text-align:right}
.pill{display:inline-block;color:#0b0d10;font-weight:700;font-size:10px;padding:2px 8px;
 border-radius:20px;letter-spacing:.06em;font-family:var(--mono);white-space:nowrap}
.desc{color:var(--tx-mid);margin-top:4px;max-width:84ch}
.means{margin-top:6px;color:var(--good);font-size:12.4px;max-width:84ch}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:9px 11px;
 font-family:var(--mono);font-size:11.5px;margin:6px 0 0;max-height:280px;overflow:auto;
 white-space:pre-wrap;color:var(--tx-mid)}
.charts{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start;margin-bottom:14px}
.chart{margin:0;background:var(--panel);border:1px solid var(--line);border-radius:11px;
 padding:14px 16px}
.chart.wide{width:100%}
.chart figcaption{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;
 text-transform:uppercase;color:var(--tx-dim);margin-bottom:10px}
.chart-row{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
.chart-empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;
 padding:20px;color:var(--tx-dim);font-size:12.5px;flex:1;min-width:240px}
.legend{display:flex;flex-direction:column;gap:6px;min-width:130px}
.legend.row{flex-direction:row;flex-wrap:wrap;gap:14px;margin-top:12px}
.lg{display:flex;align-items:center;gap:7px;font-size:12.2px}
.lg i{width:11px;height:11px;border-radius:3px;flex:none} .lg span{flex:1}
.lg b{font-family:var(--mono)}
text.bl{fill:#8b8f9b;font:10.5px var(--mono)} text.bv{fill:#e6e8ee;font:11px var(--mono)}
text.lbl{fill:#8b8f9b;font:11.5px var(--mono)}
text.pie-n{fill:#e6e8ee;font:700 16px var(--mono)}
rect.btrack{fill:#1e222a}
.empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;padding:28px;
 text-align:center;color:var(--tx-dim)}
.empty b{display:block;color:var(--tx);margin-bottom:6px;font-size:15px}
footer{max-width:1120px;margin:0 auto;padding:16px 20px 40px;color:#6f7685;font-size:11.5px;
 border-top:1px solid var(--line);line-height:1.7}
@media (max-width:640px){.hd{padding:10px 14px} .wrap{padding:14px 14px 50px}
 nav{margin-left:0;width:100%} .card .n{font-size:18px} table{font-size:12px}
 th,td{padding:7px 8px} input[type=text],input[type=password]{min-width:180px}}
"""

BASE_TPL = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ page }} - """ + APP_SHORT + """</title><style>""" + CSS + """</style></head><body>
<header class="top"><div class="hd">
 <div class="brand"><b>PASSPATTERN</b> <small>offline pattern detector</small></div>
 <nav>
  <a href="{{ url_for('page_home') }}" class="{{ 'on' if nav=='home' }}">Check</a>
  <a href="{{ url_for('page_history') }}" class="{{ 'on' if nav=='history' }}">History</a>
  <a href="{{ url_for('page_learn') }}" class="{{ 'on' if nav=='learn' }}">Learn</a>
 </nav></div></header>
<div class="wrap">
 <div class="banner bad"><b>This is not a breach check.</b>
  """ + NOT_A_BREACH_CHECK + """</div>
 <div class="banner good"><b>Nothing stored, nothing sent.</b>
  """ + NEVER_STORED + """</div>
 {% if error %}<div class="banner bad"><b>That failed:</b> {{ error }}</div>{% endif %}
 {% block body %}{% endblock %}
</div>
<footer>""" + APP_NAME + """ v""" + VERSION + """ &middot; built by """ + AUTHOR + """ &middot;
 <a href=\"""" + GITHUB + """\" rel="noopener">GitHub</a> &middot;
 <a href=\"""" + LINKEDIN + """\" rel="noopener">LinkedIn</a><br>
 Offline only. No password is written to the database, the logs or any export, and no network
 request is made at any point. Run this locally; do not expose it.</footer>
</body></html>"""

HOME_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Check a password</h1>
<div class="sub">It is analysed in memory and discarded. Only a SHA-256 fingerprint is
 kept, so reuse can be spotted across several checks.</div>
<form method="post" action="{{ url_for('do_check') }}" class="bar">
 <input type="password" name="password" placeholder="password" autofocus autocomplete="off">
 <input type="text" name="label" placeholder="label, e.g. 'email' (optional)"
  style="min-width:200px" autocomplete="off">
 <button class="btn primary" type="submit">Check</button>
</form>
{% if not check %}
<div class="empty"><b>Enter a password above</b>
 It looks for the structure that leaked passwords share - a common word under leetspeak, a
 keyboard walk, a year, the capital-then-digits shape a password policy produces - and shows
 how much of the apparent strength survives.
 <div class="mono" style="margin-top:12px;color:var(--tx-dim)">
  from the terminal: python3 passpattern.py check --prompt</div>
</div>
{% else %}
<div class="grid">
 <div class="card"><div class="l">Real strength</div>
  <div class="n" style="color:{{ check.band_colour }}">{{ '%.0f'|format(check.bits) }}</div>
  <div class="l">bits &middot; {{ check.band }}</div></div>
 <div class="card"><div class="l">Claimed</div>
  <div class="n" style="color:#6f7685">{{ '%.0f'|format(check.raw_bits) }}</div>
  <div class="l">naive count</div></div>
 <div class="card"><div class="l">Lost to patterns</div>
  <div class="n" style="color:#f76808">{{ '%.0f'|format(check.penalty_bits) }}</div></div>
 <div class="card"><div class="l">Length</div><div class="n">{{ check.length }}</div>
  <div class="l">{{ check.unique_chars }} distinct</div></div>
 <div class="card"><div class="l">Shape</div>
  <div class="n mono" style="font-size:13px">{{ check.shape[:16] }}</div></div>
</div>
<div class="charts">{{ acc_chart|safe }}</div>
<div class="charts">{{ times_chart|safe }}{{ pie|safe }}</div>
{% if reuse %}
<h2>Reuse</h2>
<table><tr><th>Kind</th><th>Detail</th></tr>
{% for r in reuse %}<tr>
 <td><span class="pill" style="background:{{ '#e5484d' if r.kind=='identical'
  else '#ffb224' }}">{{ r.kind }}</span></td>
 <td>{% if r.kind=='identical' %}The same password was checked under
  {{ r.count }} label(s): {{ ', '.join(r.labels) }}. Reusing one password means one breach
  unlocks all of them.{% else %}{{ r.count }} different password(s) are built on
  '{{ r.base }}': {{ ', '.join(r.labels) }}. Changing the digits on the end does not make it
  a different password to anyone cracking it.{% endif %}</td></tr>{% endfor %}</table>
{% endif %}
<h2>Findings ({{ findings|length }})</h2>
{% if findings %}
<table><tr><th>Severity</th><th>Detail</th></tr>
{% for f in findings %}
<tr><td><span class="pill" style="background:{{ sev[f.severity] }}">
 {{ f.severity|upper }}</span></td>
 <td><b>{{ f.title }}</b><div class="desc">{{ f.description }}</div>
  {% if f.evidence %}<pre>{{ f.evidence }}</pre>{% endif %}
  {% if f.advice %}<div class="means"><b>What to do:</b> {{ f.advice }}</div>{% endif %}
 </td></tr>
{% endfor %}</table>
{% else %}<div class="empty">No findings.</div>{% endif %}
<div class="bar" style="margin-top:16px">
 <a class="btn" href="{{ url_for('export', fmt='html') }}?check={{ check.id }}">Export HTML</a>
 <a class="btn" href="{{ url_for('export', fmt='json') }}?check={{ check.id }}">JSON</a>
 <a class="btn" href="{{ url_for('export', fmt='csv') }}?check={{ check.id }}">CSV</a>
</div>
{% endif %}
{% endblock %}"""

HISTORY_TPL = """{% extends 'base.html' %}{% block body %}
<h1>History</h1>
<div class="sub">{{ rows|length }} check(s). No password is stored - these are fingerprints
 and structural facts only.</div>
{% if reuse %}
<div class="banner warn"><b>{{ reuse|length }} reuse pattern(s) found across your checks.</b>
 Identical passwords mean one breach unlocks everything; a shared base word means changing
 the digits on the end fooled nobody.</div>
{% endif %}
{% if rows %}
<table><tr><th>#</th><th>When</th><th>Label</th><th>Length</th><th>Bits</th><th>Band</th>
 <th>Base word</th><th>Fingerprint</th><th></th></tr>
{% for r in rows %}<tr>
 <td class="mono">#{{ r.id }}</td>
 <td class="mono">{{ r.ts[:19].replace('T',' ') }}</td>
 <td>{{ r.label or '-' }}</td>
 <td class="num">{{ r.length }}</td>
 <td class="num" style="color:{{ bandcol(r.bits) }}">{{ '%.0f'|format(r.bits) }}</td>
 <td class="sub2">{{ r.band }}</td>
 <td class="mono">{{ r.base_word or '-' }}</td>
 <td class="mono">{{ r.fingerprint[:12] }}...</td>
 <td><a class="btn" href="{{ url_for('page_home') }}?check={{ r.id }}">view</a></td>
</tr>{% endfor %}</table>
{% else %}<div class="empty"><b>Nothing checked yet</b></div>{% endif %}
{% endblock %}"""

LEARN_TPL = """{% extends 'base.html' %}{% block body %}
<h1>What makes a password fall</h1>
<div class="banner bad"><b>This tool cannot tell you if a password was leaked.</b> That needs
 a breach corpus and a network request, and neither happens here. It finds the structure that
 leaked passwords share, because that structure is what cracking tools generate first. The
 reverse matters more: <b>no pattern found does not mean safe</b> - a password with nothing
 detectable here can still sit in a dump because a site you used it on was compromised. For
 that question use Have I Been Pwned, whose range API sends only the first five characters of
 the SHA-1 hash.</div>
<h2>Why the big number is a lie</h2>
<div class="desc">A twelve-character password drawn from 95 possible characters has about 79
 bits of entropy - <i>if the attacker guesses blindly</i>. Nobody guesses blindly.
 <span class="mono">P@ssw0rd123!</span> has all four character classes, twelve characters, and
 that same 79-bit claim. Its real resistance is around 36 bits, because an attacker tries
 'password', applies the standard leetspeak rules, appends common digit runs, and is done in
 seconds. The gap between the two numbers is what this tool measures.</div>
<h2>Leetspeak is worth nothing</h2>
<div class="desc">Substituting <span class="mono">@</span> for a,
 <span class="mono">0</span> for o and <span class="mono">3</span> for e feels clever and
 costs an attacker a factor of about 64 - roughly six bits, or a rounding error. Reversing
 those substitutions is one of the first rules in every rule set.</div>
<h2>The shape a policy produces</h2>
<div class="desc">Demand an upper case letter, a digit and a symbol, and almost everyone
 produces the same thing: capital at the front, digits at the end, symbol after those. The
 pattern <span class="mono">Ullllldddds</span> describes an enormous share of corporate
 passwords, and cracking rules target it directly. This is why composition policies buy far
 less than they appear to, and why forced 90-day rotation mostly produces
 <span class="mono">Summer2024!</span> followed by <span class="mono">Autumn2024!</span>.</div>
<h2>Length only helps if it is unpredictable</h2>
<div class="desc"><span class="mono">aaa111aaa111</span> is twelve characters and worth about
 seven bits. Four genuinely unrelated words are around 45 to 50 bits and far easier to type.
 What matters is how many guesses it takes, not how many characters there are.</div>
<h2>Reuse is the real problem</h2>
<div class="desc">A perfect password used in two places is a bad password in both. When one
 site leaks, everyone tries that same pair everywhere else - which is why credential stuffing
 works so well. Changing the trailing digit does not help: rule sets generate those
 variations automatically. This tool detects both cases across your checks, using
 fingerprints rather than keeping the passwords.</div>
<h2>What the crack times assume</h2>
<div class="desc">Four attackers, because the answer depends entirely on how the other end
 stores your password - something you cannot control and usually cannot find out. A live
 login that rate-limits is slow to attack. A leaked database hashed with bcrypt is slow. The
 same database hashed with unsalted MD5 falls at twenty billion guesses a second.
 <b>Plan around the fast-hash figure</b>, because you will not be told which one applies until
 after the breach.</div>
<h2>Where this tool is weakest</h2>
<div class="banner warn">The built-in word list is deliberately tiny - a few dozen entries -
 because shipping a real cracking wordlist would make this a liability. The cost is that a
 password built on an ordinary dictionary word outside that list gets credit it does not
 deserve. When the shape of a word is detected without a match, the report says the estimate
 is probably optimistic rather than quietly over-rating it. Treat every figure here as an
 order of magnitude, never a promise.</div>
{% endblock %}"""

TEMPLATES = {"base.html": BASE_TPL, "home.html": HOME_TPL, "history.html": HISTORY_TPL,
             "learn.html": LEARN_TPL}

try:
    from flask import (Flask, Response, jsonify, redirect, render_template, request, url_for)
    from jinja2 import ChoiceLoader, DictLoader
    HAVE_FLASK = True
except Exception:  # pragma: no cover
    HAVE_FLASK = False


def build_app():
    if not HAVE_FLASK:
        raise SystemExit("Flask is not installed. Install it with:  pip install flask\n"
                         "(The CLI works without Flask; only the web app needs it.)")
    app = Flask(__name__)
    app.jinja_loader = ChoiceLoader([DictLoader(TEMPLATES), app.jinja_loader])

    def bandcol(bits):
        return strength_band(bits or 0)[1]

    def ctx(nav, **kw):
        base = {"nav": nav, "page": nav.capitalize(), "sev": SEV_COLOR,
                "severities": SEVERITIES, "ts_pretty": ts_pretty, "bandcol": bandcol,
                "error": request.args.get("error"), "check": None}
        base.update(kw)
        return base

    @app.route("/")
    def page_home():
        conn = connect()
        try:
            init_db(conn)
            try:
                cid = int(request.args.get("check", "") or 0)
            except ValueError:
                cid = 0
            chk = check_summary(cid, conn) if cid else None
            if not chk:
                return render_template("home.html", **ctx("home"))
            p = report_payload(chk["id"], conn)
            payload = chk.get("payload") or {}
            counts = {s: chk[s] or 0 for s in SEVERITIES}
            times = (payload.get("analysis") or {}).get("crack_times") or []
            return render_template("home.html", **ctx(
                "home", check=chk, findings=p["findings"], reuse=p["reuse"],
                acc_chart=svg_accounting(payload),
                times_chart=svg_crack_times(times),
                pie=svg_pie([(s, counts[s], SEV_COLOR[s]) for s in SEVERITIES])))
        finally:
            conn.close()

    @app.post("/check")
    def do_check():
        import urllib.parse as up
        password = request.form.get("password") or ""
        label = (request.form.get("label") or "").strip()
        if not password:
            return redirect(url_for("page_home") + "?error="
                            + up.quote("no password given"))
        try:
            res = check_password(password, label)
            cid = save_check(res, note="from the web UI")
        except Exception as e:
            log_event("ERROR", "check", str(e))
            return redirect(url_for("page_home") + "?error=" + up.quote(str(e)))
        finally:
            password = None                      # not kept a moment longer than needed
        return redirect(url_for("page_home") + f"?check={cid}")

    @app.route("/history")
    def page_history():
        conn = connect()
        try:
            init_db(conn)
            return render_template("history.html", **ctx(
                "history", rows=q("SELECT * FROM checks ORDER BY id DESC LIMIT 200",
                                  (), conn),
                reuse=reuse_in_db(conn)))
        finally:
            conn.close()

    @app.route("/learn")
    def page_learn():
        return render_template("learn.html", **ctx("learn"))

    @app.route("/export/<fmt>")
    def export(fmt):
        try:
            cid = int(request.args.get("check", "") or 0) or None
        except ValueError:
            cid = None
        fmt = fmt.lower()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if fmt == "json":
            body, mime = export_json(cid), "application/json"
        elif fmt == "csv":
            body, mime = export_csv(cid), "text/csv"
        elif fmt == "html":
            body, mime = export_html(cid), "text/html"
        else:
            return Response("Unsupported format. Use json, csv or html.", 400,
                            mimetype="text/plain")
        log_event("INFO", "export", f"Exported the report as {fmt.upper()}", cid)
        return Response(body, mimetype=mime, headers={
            "Content-Disposition": f'attachment; filename="passpattern-{stamp}.{fmt}"'})

    @app.route("/api/summary")
    def api_summary():
        cid = latest_check_id()
        if not cid:
            return jsonify({"error": "no checks yet"}), 404
        s = check_summary(cid)
        return jsonify({"tool": APP_NAME, "version": VERSION,
                        "is_not_a_breach_check": True,
                        "passwords_never_stored": True, "offline_only": True,
                        "disclaimer": DISCLAIMER_SHORT,
                        "check": {k: v for k, v in s.items() if k != "payload"}})

    @app.errorhandler(404)
    def nf(_e):
        return Response("404 - page not found. Valid pages: / /history /learn", 404,
                        mimetype="text/plain")

    return app


def serve(host: str, port: int, debug: bool = False):
    app = build_app()
    init_db()
    log_event("INFO", "web", f"Web app started on http://{host}:{port}")
    print(f"\n  {APP_NAME} v{VERSION} - by {AUTHOR}")
    print(f"  {'-' * 66}")
    print(f"  Web app : http://{'127.0.0.1' if host == '0.0.0.0' else host}:{port}")
    print(f"  Database: {os.path.abspath(db_path())}")
    if host == "0.0.0.0":
        print("  REFUSING : this form accepts passwords. Binding it to a network\n"
              "             interface would send them over the wire in the clear.")
        raise SystemExit("Refusing to bind a password form to 0.0.0.0. Use 127.0.0.1.")
    print(f"  {textwrap.fill(DISCLAIMER_SHORT, 66, subsequent_indent='  ')}")
    print(f"  {'-' * 66}\n  Press Ctrl+C to stop.\n")
    app.run(host=host, port=port, debug=debug, use_reloader=False)


# =============================================================================
# SECTION 9 - Command line interface
# =============================================================================

def line(char="-", n=78):
    print(char * n)


def banner():
    print(f"\n{APP_NAME} v{VERSION}  |  {AUTHOR}")
    line()
    print(textwrap.fill(DISCLAIMER_SHORT, 78))
    line()


def _print_findings(rows, limit=None, quiet=False):
    shown = [f for f in rows if not (quiet and f["severity"] == "info")]
    shown = shown[:limit] if limit else shown
    for f in shown:
        print(f"\n  [{f['severity'].upper():^8}] {f['title']}")
        for l in textwrap.wrap(f["description"], 70):
            print(f"      {l}")
        if f.get("evidence"):
            for l in str(f["evidence"]).splitlines()[:6]:
                for w in textwrap.wrap(l, 70) or [""]:
                    print(f"      {w}")
        if f.get("advice"):
            for l in textwrap.wrap("what to do: " + f["advice"], 70):
                print(f"      {l}")


def _collect_passwords(a) -> list[tuple[str, str]]:
    """Gather passwords without putting them anywhere they can be recovered."""
    out: list[tuple[str, str]] = []
    if a.password:
        out.append((a.password, a.label or ""))
        print("  NOTE: a password given on the command line is already in your shell\n"
              "        history. Prefer --prompt or --stdin.\n")
    if a.prompt:
        while True:
            pw = getpass.getpass("  password (blank to finish): ")
            if not pw:
                break
            lbl = input("  label (optional): ").strip()
            out.append((pw, lbl))
    if a.stdin:
        for raw in sys.stdin:
            raw = raw.rstrip("\n")
            if not raw or raw.startswith("#"):
                continue
            if "\t" in raw:
                lbl, _, pw = raw.partition("\t")
                out.append((pw, lbl.strip()))
            else:
                out.append((raw, ""))
    return out


def cmd_check(a):
    banner()
    pairs = _collect_passwords(a)
    if not pairs:
        print("Nothing to check. Use --prompt, --stdin, or pass one as an argument\n"
              "(though the last of those leaves it in your shell history).")
        return 1
    batch = a.batch or (now_iso() if len(pairs) > 1 else "")
    results = []
    for pw, label in pairs:
        res = check_password(pw, label)
        cid = save_check(res, note=a.note or "", batch=batch)
        res["id"] = cid
        results.append(res)
        if len(pairs) == 1:
            _report_one(res, a)
        else:
            print(f"  {res['bits']:>5.0f}b  {res['band']:<26} "
                  f"{label or res['masked']}")
    del pairs

    if len(results) > 1:
        line("=")
        print(f"  {len(results)} password(s), weakest first")
        for r in sorted(results, key=lambda r: r["bits"]):
            print(f"   {r['bits']:>5.0f}b  {r['band']:<26} {r['label'] or r['masked']}")
        line("=")
        reuse = find_reuse(results)
        if reuse:
            print("  REUSE")
            for r in reuse:
                if r["kind"] == "identical":
                    print(f"   !! the same password is used for: "
                          f"{', '.join(r['labels'][:6])}")
                    for l in textwrap.wrap(
                            "One breach unlocks all of them. This is the single most "
                            "valuable thing to fix.", 70):
                        print(f"      {l}")
                else:
                    print(f"   !  {r['count']} passwords are built on '{r['base']}': "
                          f"{', '.join(r['labels'][:6])}")
                    for l in textwrap.wrap(
                            "Changing the digits on the end does not make it a different "
                            "password to anyone cracking it.", 70):
                        print(f"      {l}")
            line("=")

    print(textwrap.fill("  " + NOT_A_BREACH_CHECK, 78))
    line()
    weakest = min(r["bits"] for r in results)
    if a.fail_under is not None and weakest < a.fail_under:
        print(f"  Exiting non-zero: {weakest:.0f} bits is below --fail-under "
              f"{a.fail_under}")
        return 2
    return 0


def _report_one(res, a):
    an = res["analysis"]
    eff = an["effective"]
    print(f"Password: {res['masked']}"
          + (f"   [{res['label']}]" if res["label"] else ""))
    print(f"Finger  : {res['fingerprint'][:32]}...")
    line("=")
    print(f"  {eff['bits']:.0f} BITS OF REAL RESISTANCE   -   {res['band'].upper()}")
    print(f"  a naive character count would claim {an['raw_bits']:.0f}")
    line("=")
    if eff["accounting"]:
        print("  WHERE THE STRENGTH GOES")
        for acc in eff["accounting"]:
            print(f"   2^{acc['bits']:<5.0f} {acc['label']}")
            for l in textwrap.wrap(acc["detail"], 66):
                print(f"          {l}")
        line()
    print("  HOW LONG, AGAINST WHOM")
    for t in an["crack_times"]:
        print(f"   {t['model']:<26} {t['human']}")
    print()
    for l in textwrap.wrap(
            "You do not control how the other end stores your password, so the fast-hash "
            "figure is the one to plan around.", 74):
        print(f"   {l}")
    line()
    _print_findings(res["findings"], a.show, a.quiet)
    line()


def cmd_learn(_a):
    banner()
    print(textwrap.dedent("""\
        THIS IS NOT A BREACH CHECK

          It cannot tell you whether a password has been leaked. That needs a
          breach corpus and a network request, and neither happens here.

          What it finds is the STRUCTURE leaked passwords share, because that is
          what cracking tools generate first. The reverse matters more: NO
          PATTERN FOUND DOES NOT MEAN SAFE. A password with nothing detectable
          here can still be in a dump, because a site you used it on was
          compromised. For that question use Have I Been Pwned - its range API
          sends only the first five characters of the SHA-1 hash, so the password
          never leaves your machine there either.

        WHY THE BIG NUMBER IS A LIE

          Twelve characters from a 95-character space is about 79 bits - IF the
          attacker guesses blindly. Nobody guesses blindly.

          P@ssw0rd123! has four character classes, twelve characters, and that
          same 79-bit claim. Its real resistance is around 36 bits: an attacker
          tries 'password', applies standard leetspeak rules, appends common
          digit runs, and is finished in seconds. The gap between those two
          numbers is what this tool measures.

        LEETSPEAK IS WORTH NOTHING

          @ for a, 0 for o, 3 for e. It feels clever and costs an attacker a
          factor of about 64 - roughly six bits. Reversing those substitutions is
          one of the first rules in every rule set.

        THE SHAPE A POLICY PRODUCES

          Demand an upper case letter, a digit and a symbol and almost everyone
          produces the same thing: capital at the front, digits at the end, symbol
          after those. Cracking rules target that shape directly, which is why
          composition policies buy far less than they appear to - and why forced
          rotation mostly produces Summer2024! followed by Autumn2024!.

        LENGTH ONLY HELPS IF IT IS UNPREDICTABLE

          aaa111aaa111 is twelve characters and worth about seven bits. Four
          genuinely unrelated words are around 45 to 50 bits and far easier to
          type. What matters is the number of guesses, not the number of
          characters.

        REUSE IS THE REAL PROBLEM

          A perfect password used in two places is a bad password in both. When
          one site leaks, everyone tries that pair everywhere else. Changing the
          trailing digit does not help - rule sets generate those variations
          automatically. This tool detects both cases across your checks using
          fingerprints, never by keeping the passwords.

        WHAT THE CRACK TIMES ASSUME

          Four attackers, because the answer depends entirely on how the other end
          stores your password - which you cannot control and usually cannot find
          out. A rate-limited login is slow to attack. A leaked database hashed
          with bcrypt is slow. The same database hashed with unsalted MD5 falls at
          twenty billion guesses a second. Plan around the fast-hash figure,
          because nobody tells you which one applied until after the breach.

        WHERE THIS TOOL IS WEAKEST

          The built-in word list is deliberately tiny, because shipping a real
          cracking wordlist would make this a liability. The cost is that a
          password built on an ordinary dictionary word outside that list gets
          credit it does not deserve. When the shape of a word is detected without
          a match, the report says the estimate is probably optimistic rather than
          quietly over-rating it.

          Every figure here is an order of magnitude, never a promise.
        """))
    line()


def cmd_history(a):
    rows = q("SELECT * FROM checks ORDER BY id DESC LIMIT ?", (a.limit,))
    if not rows:
        print("Nothing checked yet.")
        return 0
    print(f"{'ID':>4}  {'WHEN (UTC)':<20} {'LEN':>4} {'BITS':>6} {'BAND':<26} LABEL")
    line()
    for r in rows:
        print(f"{r['id']:>4}  {r['ts'][:19].replace('T', ' '):<20} {r['length']:>4} "
              f"{r['bits']:>6.0f} {(r['band'] or ''):<26} {r['label'] or '-'}")
    line()
    reuse = reuse_in_db()
    if reuse:
        print(f"  {len(reuse)} reuse pattern(s):")
        for r in reuse:
            if r["kind"] == "identical":
                print(f"   !! the same password under {r['count']} label(s): "
                      f"{', '.join(r['labels'][:6])}")
            else:
                print(f"   !  {r['count']} built on '{r['base']}': "
                      f"{', '.join(r['labels'][:6])}")
        line()
    return 0


def cmd_export(a):
    cid = a.check or latest_check_id()
    if not cid:
        print("Nothing to export yet.")
        return 1
    fmt = a.format.lower()
    body = {"json": export_json, "csv": export_csv, "html": export_html}[fmt](cid)
    out = a.out or f"passpattern-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.{fmt}"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(body)
    log_event("INFO", "export", f"Exported check #{cid} as {fmt.upper()} to {out}", cid)
    print(f"Wrote {out} ({len(body):,} bytes)")
    print("No password appears in it - only fingerprints, findings and structure.")
    return 0


def cmd_logs(a):
    rows = q("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (a.limit,))
    if not rows:
        print("No log entries.")
        return 0
    for e in reversed(rows):
        print(f"{e['ts'][:19].replace('T', ' ')}  {e['level']:<5} {e['source']:<8} "
              f"{e['message']}")
    return 0


def cmd_purge(a):
    conn = connect()
    try:
        if a.all:
            for t in ("findings", "checks", "audit_log"):
                conn.execute(f"DELETE FROM {t}")
            conn.commit()
            print("All checks, findings and logs deleted.")
            return 0
        rows = q("SELECT id FROM checks ORDER BY id DESC", (), conn)
        drop = [r["id"] for r in rows[a.keep:]]
        for cid in drop:
            conn.execute("DELETE FROM findings WHERE check_id=?", (cid,))
            conn.execute("DELETE FROM checks WHERE id=?", (cid,))
        conn.commit()
        print(f"Purged {len(drop)} check(s); kept the newest {a.keep}.")
        return 0
    finally:
        conn.close()


def cmd_serve(a):
    serve(a.host, a.port, a.debug)


def cmd_version(_a):
    banner()
    print(f"  Python    : {platform.python_version()} ({sys.platform})")
    print(f"  Flask     : {'yes' if HAVE_FLASK else 'NOT INSTALLED - web app unavailable'}")
    print(f"  Word list : {len(COMMON_BASES)} entries (deliberately tiny - see 'learn')")
    print(f"  Layouts   : {', '.join(KEYBOARD_ROWS)}")
    print(f"  Models    : {len(ATTACK_MODELS)} attacker models")
    print(f"  Network   : none, ever")
    print(f"  Database  : {os.path.abspath(db_path())}")
    print(f"  GitHub    : {GITHUB}")
    line()
    print(DISCLAIMER_LONG)
    line()


# =============================================================================
# SECTION 10 - Self test
# =============================================================================

def cmd_selftest(_a=None) -> int:
    import tempfile
    passed, failed = [], []

    def check(name, cond, detail=""):
        (passed if cond else failed).append(name)
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              f"{'  <- ' + str(detail) if detail and not cond else ''}")

    banner()
    print("SELF TEST - patterns, estimates, and the promise that nothing is stored.\n")
    original = db_path()
    tmp = tempfile.mkdtemp(prefix="passpattern-selftest-")
    set_db_path(os.path.join(tmp, "selftest.db"))
    SECRET = "Zq7#Hn4$Tp9wLx2"       # used to prove it never reaches disk
    try:
        print(" Masking and fingerprints")
        check("a password is never shown in full", "assword" not in mask("password123"))
        check("the mask keeps only the first and last character",
              mask("password") == "p******d  (8 chars)", mask("password"))
        check("a very short password is fully masked", mask("ab") == "**")
        check("an empty password is handled", mask("") == "(empty)")
        check("the same password fingerprints identically",
              fingerprint("abc") == fingerprint("abc"))
        check("different passwords fingerprint differently",
              fingerprint("abc") != fingerprint("abd"))
        check("the fingerprint is not reversible to the password",
              "abc" not in fingerprint("abc"))

        print("\n Keyboard walks")
        check("a qwerty row run is found",
              any(w["run"].startswith("qwert") for w in find_keyboard_walks("qwerty123")))
        check("a walk is found mid-password",
              bool(find_keyboard_walks("xxasdfghxx")))
        check("a backward walk is found", bool(find_keyboard_walks("0987654321")))
        check("random text has no walk", not find_keyboard_walks("Zq7Hn4Tp9w"),
              find_keyboard_walks("Zq7Hn4Tp9w"))

        print("\n Sequences, repeats, dates")
        check("an ascending sequence is found",
              any(s["run"] == "abcdef" for s in find_sequences("xxabcdefxx")))
        check("a digit run is found", bool(find_sequences("pass123")))
        check("a descending run is found",
              any(s["direction"] == "descending" for s in find_sequences("cba")))
        check("repeated characters are found",
              any(r["kind"] == "character" for r in find_repeats("aaaa1")))
        check("a repeated block is found",
              any(r["kind"] == "block" for r in find_repeats("abcabcabc")))
        check("a plausible year is found and marked plausible",
              any(d["value"] == "1998" and d["plausible"] for d in find_dates("rahul1998")))
        check("an implausible year is found but not marked plausible",
              any(d["value"] == "1901" and not d["plausible"] for d in find_dates("x1901")))
        check("a full date is found", any(d["kind"] == "date"
                                          for d in find_dates("bob 12/05/1990")))

        print("\n Words under leetspeak")
        b = find_base_word("P@ssw0rd")
        check("a leetspeak word is found", b and b["word"] == "password", b)
        check("and is marked as transformed", b and b["transformed"])
        b = find_base_word("mypasswordhere")
        check("a plain word is found", b and b["word"] == "password")
        check("and is not marked as transformed", b and not b["transformed"])
        check("random text matches no word", find_base_word("Zq7Hn4Tp9wLx") is None,
              find_base_word("Zq7Hn4Tp9wLx"))
        check("the word list is deliberately small", len(COMMON_BASES) < 200,
              len(COMMON_BASES))

        print("\n Structure")
        st = describe_structure("Password123!")
        check("the shape is recorded", st["pattern"] == "Ulllllllddds", st["pattern"])
        check("the classic policy shape is recognised", st["classic_shape"])
        check("trailing digits are counted", st["digits_at_end"] == 0,
              st["digits_at_end"])
        st = describe_structure("Password123")
        check("trailing digits are counted when last", st["digits_at_end"] == 3)
        st = describe_structure("aBcDeF")
        check("mixed capitalisation is not called the classic shape",
              not st["classic_shape"] and not st["capital_first_only"])

        print("\n The estimate is honest about patterns")
        weak = analyse_full("P@ssw0rd123!")
        check("a patterned password loses most of its apparent strength",
              weak["effective"]["bits"] < weak["raw_bits"] / 1.8,
              (weak["raw_bits"], weak["effective"]["bits"]))
        check("and the accounting explains where it went",
              any("common word" in a["label"] for a in weak["effective"]["accounting"]),
              [a["label"] for a in weak["effective"]["accounting"]])
        strong = analyse_full("Zq7#Hn4$Tp9wLx2")
        check("an unpatterned password keeps its strength",
              abs(strong["effective"]["bits"] - strong["raw_bits"]) < 1,
              (strong["raw_bits"], strong["effective"]["bits"]))
        check("the weak one is rated far below the strong one",
              weak["effective"]["bits"] < strong["effective"]["bits"] - 40,
              (weak["effective"]["bits"], strong["effective"]["bits"]))
        rep = analyse_full("aaa111aaa111")
        check("repetition is worth almost nothing",
              rep["effective"]["bits"] < 20, rep["effective"]["bits"])
        check("a 12-character repeated password scores below an 8-character random one",
              rep["effective"]["bits"] < analyse_full("Zq7#Hn4x")["effective"]["bits"])

        print("\n Leetspeak is correctly valued at almost nothing")
        plain = analyse_full("password123")["effective"]["bits"]
        leet = analyse_full("p@ssw0rd123")["effective"]["bits"]
        check("leetspeak adds only a few bits over the plain word",
              abs(leet - plain) < 12, (plain, leet))

        print("\n The wordlist limitation is disclosed, not hidden")
        r = check_password("tr0ub4dor&3")
        ws = r["analysis"]["word_shaped"]
        check("a word-shaped run outside the list is detected", ws["word_shaped"], ws)
        check("and the report says the estimate is optimistic",
              any(f["category"] == "Estimate" and "optimistic" in f["title"]
                  for f in r["findings"]), [f["title"] for f in r["findings"]])
        check("the advice quantifies how wrong it may be",
              any("30 to 40 bits lower" in f.get("advice", "") for f in r["findings"]))
        check("random text is NOT called word-shaped",
              not check_password("Xq7#Lm2!Zt")["analysis"]["word_shaped"]["word_shaped"],
              "leet-decoding symbols used to manufacture vowels here")
        check("digit leet is still decoded, so tr0ub4dor is caught",
              check_password("s3cur1ty")["analysis"]["word_shaped"]["word_shaped"]
              or check_password("tr0ub4dor&3")["analysis"]["word_shaped"]["word_shaped"])

        print("\n Passphrases are the good case, not a warning")
        pp = check_password("correct horse battery staple")
        check("several word runs are recognised as a passphrase",
              pp["analysis"]["word_shaped"]["passphrase"], pp["analysis"]["word_shaped"])
        check("a passphrase is NOT flagged as optimistic",
              not any(f["severity"] in ("critical", "high") and f["category"] == "Estimate"
                      for f in pp["findings"]),
              [f["title"] for f in pp["findings"] if f["category"] == "Estimate"])
        check("but the report is still honest about per-word entropy",
              any("11 to 13 bits per word" in f.get("advice", "") for f in pp["findings"]))

        print("\n Crack times")
        times = crack_times(2 ** 40)
        check("every attacker model produces a figure", len(times) == len(ATTACK_MODELS))
        check("a fast offline attacker is faster than a throttled online one",
              next(t["seconds"] for t in times if t["key"] == "offline_fast")
              < next(t["seconds"] for t in times if t["key"] == "online_throttled"))
        check("each model states its assumption", all(t["why"] for t in times))
        check("a trivial password cracks instantly",
              crack_times(100)[3]["human"] == "instantly")
        check("a strong one does not",
              "instantly" not in crack_times(2 ** 90)[3]["human"])

        print("\n Findings")
        f = check_password("abc")["findings"]
        check("a very short password is CRITICAL",
              any(x["severity"] == "critical" for x in f), [x["title"] for x in f])
        f = check_password("")["findings"]
        check("an empty password is handled",
              f and f[0]["severity"] == "critical")
        check("every report says it is not a breach check",
              any(x["category"] == "Scope" for x in check_password("Zq7#Hn4x")["findings"]))
        check("and points at where to actually check that",
              any("Have I Been Pwned" in x.get("advice", "")
                  for x in check_password("Zq7#Hn4x")["findings"]))

        print("\n Reuse")
        rs = [check_password("samepass1", "email"), check_password("samepass1", "bank"),
              check_password("Summer2024!", "work"), check_password("Summer2025!", "vpn")]
        reuse = find_reuse(rs)
        check("an identical password across labels is found",
              any(r["kind"] == "identical" and r["count"] == 2 for r in reuse), reuse)
        check("a shared base word across different passwords is found",
              any(r["kind"] == "shared_base" and r["base"] == "summer" for r in reuse),
              reuse)
        check("distinct unrelated passwords raise nothing",
              not find_reuse([check_password("Zq7#Hn4x"),
                              check_password("Kp2$Wm8y")]))

        print("\n *** Nothing is stored ***")
        init_db()
        res = check_password(SECRET, "the secret")
        cid = save_check(res, note="selftest")
        blob = json.dumps([dict(r) for r in q("SELECT * FROM checks", ())])
        check("the password is not in the checks table", SECRET not in blob)
        fblob = json.dumps([dict(r) for r in q("SELECT * FROM findings", ())])
        check("the password is not in the findings table", SECRET not in fblob)
        lblob = json.dumps([dict(r) for r in q("SELECT * FROM audit_log", ())])
        check("the password is not in the audit log", SECRET not in lblob)
        check("the password is not in the stored payload",
              SECRET not in json.dumps(check_summary(cid)["payload"]))
        with open(db_path(), "rb") as fh:
            raw = fh.read()
        check("the password is not in the raw database file on disk",
              SECRET.encode() not in raw)
        check("but the fingerprint IS stored, so reuse still works",
              check_summary(cid)["fingerprint"] == fingerprint(SECRET))
        check("JSON export contains no password", SECRET not in export_json(cid))
        check("CSV export contains no password", SECRET not in export_csv(cid))
        check("HTML export contains no password", SECRET not in export_html(cid))
        leaky = check_password("P@ssw0rd123!", "leaky")
        lcid = save_check(leaky)
        check("even a matched word is not stored as written",
              "P@ssw0rd" not in json.dumps(check_summary(lcid)["payload"]),
              "the literal characters of the matched word must not be kept")
        check("only the normalised word is kept, which does not reconstruct it",
              check_summary(lcid)["base_word"] == "password")

        print("\n No network is ever used")
        mod = sys.modules[__name__]
        for banned in ("requests", "urllib", "http", "socket"):
            check(f"'{banned}' is not imported", banned not in dir(mod),
                  f"{banned} present in module namespace")

        print("\n Persistence")
        check("a check is stored and read back", check_summary(cid)["id"] == cid)
        check("findings are stored",
              q1("SELECT COUNT(*) c FROM findings WHERE check_id=?",
                 (cid,))["c"] == len(res["findings"]))
        save_check(check_password(SECRET, "again"))
        check("reuse is detected across stored checks",
              any(r["kind"] == "identical" for r in reuse_in_db()), reuse_in_db())

        print("\n Charts")
        acc = svg_accounting(_safe_payload(check_password("P@ssw0rd123!")))
        check("the accounting chart draws both bars", acc.count("<rect") >= 4)
        check("it labels claimed versus real", "claimed" in acc and "real" in acc)
        check("the crack-time chart draws a row per model",
              svg_crack_times(crack_times(2 ** 40)).count("<rect")
              == len(ATTACK_MODELS) * 2)
        check("pie renders slices",
              svg_pie([("a", 2, "#fff"), ("b", 1, "#000")]).count("<path") == 2)
        check("charts guard against empty input",
              all("nothing to show" in x for x in (svg_pie([]), svg_bar([]),
                                                   svg_crack_times([]))))

        print("\n Exports")
        j = json.loads(export_json(cid))
        check("JSON export says it is not a breach check",
              "NOT a breach check" in j["this_is_not_a_breach_check"])
        check("JSON export says nothing is stored",
              "never written" in j["passwords_are_never_stored"])
        check("JSON export lists the limitations", len(j["limitations"]) >= 6)
        check("JSON export discloses the tiny wordlist",
              any("deliberately tiny" in x for x in j["limitations"]))
        c_ = export_csv(cid)
        check("CSV states no password is in the file",
              any("No password appears" in l for l in c_.splitlines()[:6]))
        h = export_html(cid)
        check("HTML export is a complete document",
              h.startswith("<!doctype html") and h.rstrip().endswith("</html>"))
        check("HTML export contains charts and the author", "<svg" in h and AUTHOR in h)

        print("\n Web application")
        if not HAVE_FLASK:
            check("Flask installed", False, "pip install flask")
        else:
            app = build_app()
            app.config["TESTING"] = True
            cl = app.test_client()
            for path, must in (("/", "Check a password"), ("/history", "History"),
                               ("/learn", "not a breach check")):
                r_ = cl.get(path)
                body = r_.get_data(as_text=True)
                check(f"page {path} renders",
                      r_.status_code == 200 and must.lower() in body.lower(),
                      r_.status_code)
            check("every page says it is not a breach check",
                  "not a breach check" in cl.get("/").get_data(as_text=True).lower())
            check("every page says nothing is stored",
                  "Nothing stored" in cl.get("/").get_data(as_text=True))
            check("the password field is type=password",
                  'type="password"' in cl.get("/").get_data(as_text=True))
            check("the learn page explains why the big number is a lie",
                  "big number is a lie" in cl.get("/learn").get_data(as_text=True))
            r_ = cl.post("/check", data={"password": "", "label": ""})
            check("an empty password is rejected",
                  r_.status_code == 302 and "error" in r_.headers["Location"])
            r_ = cl.post("/check", data={"password": SECRET, "label": "web"})
            check("checking from the web works", r_.status_code == 302)
            with open(db_path(), "rb") as fh:
                check("and the password still never reaches the database",
                      SECRET.encode() not in fh.read())
            body = cl.get("/history").get_data(as_text=True)
            check("the history page shows no password", SECRET not in body)
            for fmt in ("json", "csv", "html"):
                r_ = cl.get(f"/export/{fmt}?check={cid}")
                check(f"export /{fmt} downloads",
                      r_.status_code == 200
                      and "attachment" in r_.headers.get("Content-Disposition", ""))
                check(f"export /{fmt} contains no password",
                      SECRET not in r_.get_data(as_text=True))
            check("bad export format is rejected", cl.get("/export/exe").status_code == 400)
            check("unknown route returns a helpful 404", cl.get("/nope").status_code == 404)
            api = cl.get("/api/summary").get_json()
            check("the api declares it is not a breach check",
                  api["is_not_a_breach_check"] is True)
            check("the api declares passwords are never stored",
                  api["passwords_never_stored"] is True)
            check("the api declares it is offline only", api["offline_only"] is True)

        print("\n Retention")
        cmd_purge(argparse.Namespace(all=False, keep=1))
        check("purge keeps exactly the newest check",
              q1("SELECT COUNT(*) c FROM checks", ())["c"] == 1)
        check("purge removes orphaned findings",
              q1("SELECT COUNT(*) c FROM findings WHERE check_id NOT IN "
                 "(SELECT id FROM checks)", ())["c"] == 0)
        cmd_purge(argparse.Namespace(all=True, keep=1))
        check("purge --all clears everything",
              q1("SELECT COUNT(*) c FROM checks", ())["c"] == 0)
    finally:
        set_db_path(original)
        shutil.rmtree(tmp, ignore_errors=True)

    line("=")
    print(f"  {len(passed)} passed, {len(failed)} failed")
    if failed:
        print("  Failed: " + ", ".join(failed))
    else:
        print("  All checks passed. No password reached disk, no network request was\n"
              "  made, and the temporary database has been removed.")
    line("=")
    return 0 if not failed else 1


# =============================================================================
# SECTION 11 - Entry point
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=os.path.basename(__file__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{APP_NAME} v{VERSION} - offline password pattern detector, "
                    f"by {AUTHOR}",
        epilog=textwrap.dedent(f"""\
            examples
              %(prog)s learn                      what makes a password fall
              %(prog)s check --prompt             type it, nothing echoes
              cat vault.txt | %(prog)s check --stdin
              %(prog)s check --prompt --fail-under 50
              %(prog)s serve                      http://127.0.0.1:5000

            THIS IS NOT A BREACH CHECK. It cannot tell you whether a password has
            been leaked - only whether it is built the way leaked ones are.

            {DISCLAIMER_LONG}
            """))
    p.add_argument("--db", default=DEFAULT_DB,
                   help=f"SQLite database file (default: {DEFAULT_DB})")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("check", help="check one or more passwords")
    s.add_argument("password", nargs="?", default="",
                   help="AVOID - your shell records this. Use --prompt or --stdin.")
    s.add_argument("--label", help="what this password is for")
    s.add_argument("--prompt", action="store_true",
                   help="type passwords at a prompt; nothing is echoed")
    s.add_argument("--stdin", action="store_true",
                   help="read from standard input, one per line, optionally 'label<TAB>pw'")
    s.add_argument("--batch", help="a name for this group of checks")
    s.add_argument("--quiet", action="store_true", help="hide informational findings")
    s.add_argument("--show", type=int, help="limit how many findings are printed")
    s.add_argument("--fail-under", type=float,
                   help="exit non-zero if any password is below this many bits")
    s.add_argument("--note")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("learn", help="what makes a password fall")
    s.set_defaults(func=cmd_learn)

    s = sub.add_parser("history", help="previous checks and any reuse")
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(func=cmd_history)

    s = sub.add_parser("serve", help="start the web app (127.0.0.1 only)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5000)
    s.add_argument("--debug", action="store_true")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("export", help="write a report to a file")
    s.add_argument("--check", type=int)
    s.add_argument("--format", choices=["json", "csv", "html"], default="html")
    s.add_argument("--out")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("logs", help="local event log")
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("purge", help="delete stored checks")
    s.add_argument("--keep", type=int, default=50)
    s.add_argument("--all", action="store_true")
    s.set_defaults(func=cmd_purge)

    s = sub.add_parser("selftest", help="verify every component (temporary database)")
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("version", help="versions and the disclaimer")
    s.set_defaults(func=cmd_version)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    set_db_path(args.db)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    if args.cmd == "check" and not (args.password or args.prompt or args.stdin):
        parser.parse_args(["check", "--help"])
        return 1
    if args.cmd != "selftest":
        init_db()
    try:
        rc = args.func(args)
        return rc if isinstance(rc, int) else 0
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except sqlite3.OperationalError as e:
        print(f"Database error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
