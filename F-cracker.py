#pip install requests beautifulsoup4 pyfiglet
import os
import sys
import subprocess
import webbrowser
import time
import re
import csv
import io
import difflib
import shutil
import logging
import requests
from tempfile import mkdtemp
from datetime import timedelta
from pathlib import Path
from bs4 import BeautifulSoup
import pyfiglet

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# ANSI Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
GRAY = "\033[90m"
RESET = "\033[0m"

def print_banner():
    banner = pyfiglet.figlet_format("F.Cracker", font="slant")
    print(f"{GREEN}{banner}{RESET}")
    print(f"{CYAN}Made By Fathi Eltantawy{RESET}")
    print(f"{GRAY}{'='*50}{RESET}")

# Color codes (ANSI)
GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
BLUE = "\033[94m"; CYAN = "\033[96m"; GRAY = "\033[90m"; RESET = "\033[0m"

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(message)s")

def search_default_passwords(service_name, max_results=10, cache_days=7):
    """
    Intelligent multi-source default password searcher.
    Enhanced design + colored output table.
    Sources:
      - datarecovery.com
      - default-password.info
      - cirt.net
      - SecLists (cached CSV fallback)
    """
    start_time = time.time()
    service_q = (service_name or "").strip().lower()
    if not service_q:
        print(f"{YELLOW}[-] No service name provided.{RESET}")
        return []

    print(f"\n{BLUE}[+] Searching default passwords for: {CYAN}{service_name}{RESET}")
    print(f"{GRAY}{'='*90}{RESET}")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept-Language": "en-US,en;q=0.9",
    }

    matches = []

    def is_match(field, query):
        """Fuzzy & keyword-based match."""
        if not field:
            return False
        s = field.lower()
        if query in s:
            return True
        if difflib.SequenceMatcher(None, query, s).ratio() > 0.7:
            return True
        return False

    def add_match(src, svc, usr, pwd, extra=None):
        """Add result safely."""
        matches.append({
            "source": src,
            "service": svc or "-",
            "user": usr or "-",
            "pass": pwd or "-",
            "extra": extra or []
        })

    def parse_html_table(url, src_name):
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code != 200:
                return
            soup = BeautifulSoup(r.text, "html.parser")
            rows = soup.find_all("tr")
            for row in rows:
                cols = [c.get_text(strip=True) for c in row.find_all(["td","th"])]
                if len(cols) >= 3:
                    svc, usr, pwd = cols[:3]
                    if is_match(svc, service_q) or is_match(" ".join(cols), service_q):
                        add_match(src_name, svc, usr, pwd, cols[3:])
        except Exception as e:
            logger.debug(f"{src_name} failed: {e}")

    # 1️⃣ DataRecovery.com
    parse_html_table("https://datarecovery.com/rd/default-passwords/", "DataRecovery")

    # 2️⃣ Default-Password.info
    if not matches:
        parse_html_table("https://default-password.info/", "Default-Password.info")

    # 3️⃣ CIRT.net
    if not matches:
        parse_html_table("https://cirt.net/passwords", "CIRT.net")

    # 4️⃣ SecLists fallback
    if not matches:
        try:
            cache_dir = Path.home() / ".cache" / "fcracker"
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache_file = cache_dir / "default-passwords.csv"
            refresh = True
            if cache_file.exists() and time.time() - cache_file.stat().st_mtime < cache_days * 86400:
                refresh = False

            csv_text = None
            if refresh:
                url = ("https://raw.githubusercontent.com/"
                       "danielmiessler/SecLists/master/Passwords/Default-Credentials/default-passwords.csv")
                r = requests.get(url, headers=headers, timeout=15)
                if r.status_code == 200 and r.text:
                    csv_text = r.text
                    cache_file.write_text(csv_text, encoding="utf-8")
                    logger.info(f"{GRAY}[Cache Updated]{RESET} {cache_file}")
            else:
                csv_text = cache_file.read_text(encoding="utf-8")

            if csv_text:
                reader = csv.reader(io.StringIO(csv_text))
                for row in reader:
                    if not row:
                        continue
                    svc = row[0] if len(row) > 0 else ""
                    usr = row[1] if len(row) > 1 else ""
                    pwd = row[2] if len(row) > 2 else ""
                    extra = row[3:] if len(row) > 3 else []
                    if is_match(svc, service_q) or any(is_match(x, service_q) for x in [usr, pwd] + extra):
                        add_match("SecLists", svc, usr, pwd, extra)
        except Exception as e:
            logger.debug(f"SecLists fallback failed: {e}")

    # Deduplicate & sort
    seen = set()
    deduped = []
    for m in matches:
        key = (m["service"].lower(), m["user"], m["pass"])
        if key not in seen:
            seen.add(key)
            deduped.append(m)
    matches = sorted(deduped, key=lambda x: x["source"])

    elapsed = time.time() - start_time

    # 🎨 Output section
    if matches:
        print(f"{GREEN}[✓] Found {len(matches)} possible default credentials (showing top {max_results}){RESET}")
        print(f"{GRAY}{'-'*90}{RESET}")
        print(f"{CYAN}{'Source':<20} {'Service':<25} {'Username':<20} {'Password':<20}{RESET}")
        print(f"{GRAY}{'-'*90}{RESET}")
        for m in matches[:max_results]:
            src = m["source"]
            svc = m["service"][:24]
            usr = m["user"][:19]
            pwd = m["pass"][:19]
            icon = "🔍" if src == "SecLists" else "🌐"
            print(f"{icon} {src:<18} {svc:<25} {usr:<20} {pwd:<20}")
        print(f"{GRAY}{'-'*90}{RESET}")
        print(f"{BLUE}[*] Search completed in {elapsed:.2f}s{RESET}\n")
    else:
        print(f"{YELLOW}[-] No default credentials found for '{service_name}'.{RESET}")
        print(f"{BLUE}[*] Completed in {elapsed:.2f}s{RESET}\n")

    return matches

def detect_hash_with_hashid(hash_str):
    """Detect hash type using hashid"""
    candidates = []
    hc_cmd = shutil.which("hashid")
    use_module = False
    if not hc_cmd:
        hc_cmd = sys.executable
        use_module = True
    
    if hc_cmd:
        try:
            if use_module:
                proc = subprocess.run([hc_cmd, "-m", "hashid", hash_str], 
                                    capture_output=True, text=True, check=False)
            else:
                proc = subprocess.run([hc_cmd, hash_str], 
                                    capture_output=True, text=True, check=False)
            
            out = (proc.stdout or "") + "\n" + (proc.stderr or "")
            # Skip analysis lines and just get hash types
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                # Skip the "Analyzing" line
                if "analyzing" in line.lower():
                    continue
                # Skip lines with [+], [!], etc. prefixes
                if line.startswith("["):
                    line = line[3:].strip()  # Remove [+] or [!] prefix
                
                if "hashcat" in line.lower():
                    m = re.search(r"(\d{1,5})", line)
                    if m:
                        mode = m.group(1)
                        desc = line.strip()
                        candidates.append((mode, desc))
                else:
                    name = line.strip()
                    if len(name) <= 60 and any(ch.isalpha() for ch in name):
                        candidates.append((None, name))
            
            seen = set()
            dedup = []
            for m, d in candidates:
                key = f"{m}:{d}"
                if key not in seen:
                    seen.add(key)
                    dedup.append((m, d))
            return dedup
        except Exception:
            return []
    return []
import subprocess, shlex, re, difflib, shutil, sys

def extract_modes_from_hashcat(search_term):
    """
    Smarter Hashcat mode finder.
    - Accepts: mode number, hash name (even with typos), regex (/…/), aliases (ntlmv2, bcrypt, …), or a raw hash sample.
    - Always returns a mode number (string) or prompts to refine; never dead-ends with "no match".
    - If multiple good matches: shows a ranked list (up to 30) and lets user pick by index or enter a mode directly.

    Interactivity:
      * Press Enter on prompts to retry with a new search term.
      * Type a valid hashcat mode (e.g., 0, 1000, 5600) at any prompt to select it immediately.
    """

    # --- graceful color fallback (if your color constants don't exist) ---
    globals_dict = globals()
    GREEN = globals_dict.get("GREEN", "")
    RED   = globals_dict.get("RED", "")
    YELLOW= globals_dict.get("YELLOW","")
    BLUE  = globals_dict.get("BLUE","")
    CYAN  = globals_dict.get("CYAN","")
    GRAY  = globals_dict.get("GRAY","")
    RESET = globals_dict.get("RESET","")

    def _run(cmd):
        return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)

    def _hashcat_exists():
        return shutil.which("hashcat") is not None

    def _load_help():
        """
        Load and parse 'hashcat -hh' output once.
        Return: list of dicts: [{"mode":"0", "name":"MD5", "line":"  0 | MD5 | Raw Hash"}, ...]
        """
        if not _hashcat_exists():
            raise RuntimeError("hashcat not found in PATH. Install or add to PATH.")

        out = _run("hashcat -hh")
        modes = []
        # Robust regex: "  1000 | NTLM | ..." or "  3200 | bcrypt(...) | ..."
        rx = re.compile(r'^\s*([0-9]{1,6})\s*\|\s*([^\|]+?)(?:\s*\|\s*.*)?$')
        for line in out.splitlines():
            m = rx.match(line)
            if m:
                mode = m.group(1).strip()
                name = m.group(2).strip()
                modes.append({"mode": mode, "name": name, "line": line.rstrip()})
        if not modes:
            # Fallback parser: try to catch looser formats
            rx2 = re.compile(r'^\s*([0-9]{1,6})\s*\|\s*(.+)$')
            for line in out.splitlines():
                m = rx2.match(line)
                if m:
                    modes.append({"mode": m.group(1).strip(),
                                  "name": m.group(2).strip(),
                                  "line": line.rstrip()})
        if not modes:
            raise RuntimeError("Could not parse hash modes from 'hashcat -h'.")
        return modes

    # Common alias & synonym expansions (lowercase keys)
    ALIASES = {
        "ntlm": ["ntlm", "microsoft nt hash", "windows ntlm"],
        "ntlmv2": ["netntlmv2", "ntlmv2", "ms-chapv2 ntlmv2"],
        "netntlm": ["netntlm", "mschap", "ms-chap"],
        "netntlmv2": ["netntlmv2", "ms-chapv2", "mschapv2"],
        "lm": ["lm", "lanman"],
        "md5": ["md5"],
        "sha1": ["sha1", "sha-1"],
        "sha256": ["sha256", "sha-256"],
        "sha512": ["sha512", "sha-512"],
        "bcrypt": ["bcrypt", "blowfish"],
        "scrypt": ["scrypt"],
        "argon2": ["argon2", "argon2id", "argon2i", "argon2d"],
        "mysql": ["mysql", "mysql323", "mysql41"],
        "mssql": ["mssql", "microsoft sql"],
        "oracle": ["oracle"],
        "postgres": ["postgres", "postgresql"],
        "wpa": ["wpa", "wpapsk", "hccapx", "pmkid"],
        "wpa2": ["wpa2", "wpa", "wpapsk"],
        "krb": ["kerberos", "krb", "asrep", "tgs", "tgt", "kerberoast"],
        "zip": ["zip", "pkzip"],
        "rar": ["rar"],
        "7z": ["7z", "7zip"],
        "pdf": ["pdf", "adobe"],
        "office": ["office", "msoffice", "xlsx", "docx", "pptx"],
        "bitlocker": ["bitlocker", "bek", "fvek"],
        "des": ["des", "unix des"],
        "sha512crypt": ["sha512crypt", "$6$"],
        "sha256crypt": ["sha256crypt", "$5$"],
        "md5crypt": ["md5crypt", "$1$"],
        "apr1": ["apr1", "apache md5", "$apr1$"],
        "ssha": ["ssha", "salted sha1"],
        "djangosha1": ["django (sha1)", "django-sha1"],
        "phpass": ["phpass", "wordpress", "joomla", "phpbb"],
        "aws": ["aws", "rds", "iam", "cisco"],
        "android": ["android", "scrypt", "keystore"],
        "ethereum": ["ethereum", "geth", "mist"],
    }

    # Heuristic guess by raw hash appearance (length/charset)
    # Maps length -> likely names substrings (lowercase)
    HEUR_LEN = {
        32:  ["md5", "ntlm", "descrypt"],      # 32 hex (md5/NT hash) – ambiguity handled by name scoring
        40:  ["sha1"],
        48:  ["sha1(salt)","ssha"],            # some salted forms
        56:  ["sha224"],
        64:  ["sha256", "sha256crypt"],
        96:  ["sha384"],
        128: ["sha512", "sha512crypt"],
    }

    # Looks like hex?
    HEX_RE = re.compile(r'^[0-9a-fA-F]+$')

    def _tokenize(s):
        return re.findall(r'[A-Za-z0-9\$\-]+', s.lower())

    def _expand_aliases(term):
        # If the search term exactly matches a known alias key, return its expansions too
        ex = set([term])
        for k, vals in ALIASES.items():
            if term == k or term in vals:
                ex.update([k])
                ex.update(vals)
        return list(ex)

    def _guess_by_hash(raw):
        """If input looks like a hash, propose likely families."""
        raw = raw.strip()
        hints = set()
        # detect hex and length
        if HEX_RE.match(raw):
            hints.update(HEUR_LEN.get(len(raw), []))
        # common markers
        if raw.startswith("$1$"):
            hints.add("md5crypt")
        if raw.startswith("$5$"):
            hints.add("sha256crypt")
        if raw.startswith("$6$"):
            hints.add("sha512crypt")
        if raw.startswith("$2a$") or raw.startswith("$2b$") or raw.startswith("$2y$"):
            hints.add("bcrypt")
        if raw.startswith("$krb5") or "krb" in raw.lower():
            hints.add("kerberos")
        if ":$23$" in raw or raw.lower().startswith("pbkdf2"):
            hints.add("pbkdf2")
        if raw.lower().startswith("$ml$") or "argon2" in raw.lower():
            hints.add("argon2")
        if raw.count(":") >= 3 and "netntlm" in raw.lower():
            hints.add("netntlm")
            hints.add("netntlmv2")
        return list(hints)

    def _score(term, item, extra_terms):
        """
        Produce a composite score for how well 'item' (mode entry) matches 'term' & extra terms.
        item: {"mode","name","line"}
        """
        name = item["name"].lower()
        line = item["line"].lower()
        # base: partial/substring
        score = 0.0
        if term in name or term in line:
            score += 50
        # difflib similarity
        score += 100 * difflib.SequenceMatcher(None, term, name).ratio()
        # token coverage (all extra terms present)
        for t in extra_terms:
            if t in name or t in line:
                score += 15
        return score

    def _rank(modes, query):
        """
        Rank modes by a flexible query:
          - If numeric and exists -> return exact at top.
          - If /regex/ -> regex filter.
          - Else -> fuzzy/aliases/scoring + hash-sample guesses
        """
        query = (query or "").strip()
        # direct numeric mode?
        if query.isdigit():
            # exact mode first if exists
            exact = [m for m in modes if m["mode"] == query]
            if exact:
                return exact + [m for m in modes if m["mode"] != query]

        # regex search like /sha.*256/i
        if len(query) >= 2 and query.startswith("/") and query.endswith("/"):
            pat = query[1:-1]
            try:
                rx = re.compile(pat, re.IGNORECASE)
                hits = [m for m in modes if rx.search(m["line"]) or rx.search(m["name"])]
                if hits:
                    return hits
            except re.error:
                pass  # fall through to fuzzy

        base = query.lower().strip('"').strip("'")
        tokens = _tokenize(base)
        extra = set(tokens)
        # alias expansion on single-token queries
        if len(tokens) == 1:
            extra.update(_expand_aliases(tokens[0]))

        # hash sample heuristic hints
        raw_hints = _guess_by_hash(query)
        extra.update(raw_hints)

        # If nothing to go by, just return everything (later narrowed by user)
        if not base and not extra:
            return modes

        # score everything, keep positives
        scored = []
        for m in modes:
            s = 0.0
            # core term score
            if base:
                s += _score(base, m, extra_terms=[])
            # bonus from extra terms (aliases, hints)
            if extra:
                s += sum(_score(t, m, extra_terms=[]) * 0.25 for t in extra if t != base)
            # tiny bonus if every token appears
            if all((t in m["name"].lower() or t in m["line"].lower()) for t in tokens):
                s += 20
            if s > 0:
                scored.append((s, m))

        if scored:
            scored.sort(key=lambda x: x[0], reverse=True)
            return [m for _, m in scored]

        # last resort: fuzzy by difflib against names
        names = [m["name"] for m in modes]
        close = difflib.get_close_matches(base, names, n=30, cutoff=0.0)
        if close:
            lookup = {m["name"]: m for m in modes}
            return [lookup[n] for n in close if n in lookup]

        # truly nothing? Return all (the caller will paginate and ask)
        return modes

    # ---------- main interactive loop ----------
    try:
        modes = _load_help()
    except Exception as e:
        print(f"{RED}[-] Error getting modes: {e}{RESET}")
        # As an ultimate fallback: ask user to type a mode number
        return input(f"{YELLOW}[?] Enter mode number manually: {RESET}").strip()

    # loop that guarantees we never end with "no match"
    current_query = (search_term or "").strip()
    while True:
        ranked = _rank(modes, current_query)
        # cap view but keep full for validation
        show = ranked[:30]

        print(f"\n{BLUE}[+] Top {len(show)} match(es) for '{current_query or 'ALL'}':{RESET}")
        print(f"{GRAY}{'='*85}{RESET}")

        # pretty print with truncated line context
        for i, m in enumerate(show, 1):
            mode = m["mode"]
            name = m["name"]
            print(f"{GREEN}{i:2d}.{RESET} {CYAN}Mode {mode:5s}{RESET} | {name}")

        if len(ranked) > 30:
            print(f"{YELLOW}[!] Showing first 30 of {len(ranked)} matches. Refine the search to narrow down.{RESET}")

        print(f"{GRAY}{'='*85}{RESET}")

        # Prompt selection
        choice = input(f"\n{GREEN}[?]{RESET} Enter selection number (1-{min(len(show),30)}), a mode number, or new search term: ").strip()

        # Empty -> ask new term
        if not choice:
            current_query = input(f"{CYAN}[?] Enter new search term (or /regex/ or paste hash sample): {RESET}").strip()
            continue

        # If user typed a valid mode number directly and it exists -> accept
        if choice.isdigit():
            # First check if it's a list index
            idx = int(choice)
            if 1 <= idx <= len(show):
                picked = show[idx - 1]
                print(f"{GREEN}[✓] Selected: Mode {picked['mode']} - {picked['name']}{RESET}")
                return picked["mode"]
            # Else check if it's an actual mode id anywhere
            if any(m["mode"] == choice for m in modes):
                picked = next(m for m in modes if m["mode"] == choice)
                print(f"{GREEN}[✓] Selected: Mode {picked['mode']} - {picked['name']}{RESET}")
                return picked["mode"]
            # Not index, not mode -> treat as new query
            current_query = choice
            continue

        # If looks like /regex/
        if len(choice) >= 2 and choice.startswith("/") and choice.endswith("/"):
            current_query = choice
            continue

        # Otherwise treat as new search term (could be alias, typo, or raw hash sample)
        current_query = choice


def split_wordlist(wordlist_path, lines_per_file=1_000_000):
    temp_dir = mkdtemp()
    print(f"{BLUE}[+] Splitting wordlist into {lines_per_file}-line chunks...{RESET}")
    split_files = []
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = []
        index = 0
        for i, line in enumerate(f):
            lines.append(line)
            if (i + 1) % lines_per_file == 0:
                split_path = os.path.join(temp_dir, f"chunk_{index}.txt")
                with open(split_path, 'w') as chunk:
                    chunk.writelines(lines)
                split_files.append(split_path)
                lines = []
                index += 1
        if lines:
            split_path = os.path.join(temp_dir, f"chunk_{index}.txt")
            with open(split_path, 'w') as chunk:
                chunk.writelines(lines)
            split_files.append(split_path)
    print(f"{GREEN}[✓] Wordlist split into {len(split_files)} parts.{RESET}")
    return split_files

def list_rules():
    path = "/usr/share/hashcat/rules"
    if not os.path.exists(path):
        print(f"{RED}[-] Hashcat rules directory not found!{RESET}")
        return []
    
    rules = [r for r in os.listdir(path) if r.endswith(".rule")]
    for i, rule in enumerate(rules, 1):
        print(f"{i}. {rule}")
    return rules

def try_crack(mode, hash_value, wordlist, rules):
    cmd = [
        "hashcat", "-a", "0", "-m", mode, hash_value, wordlist,
        "--force", "--logfile-disable" , "-w", "4", "-O","--status", "--status-timer=10"
    ]
    for rule in rules:
        cmd.extend(["-r", f"/usr/share/hashcat/rules/{rule}"])

    try:
        print(f"\n{CYAN}[*] Trying with full wordlist: {wordlist}{RESET}")
        result = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if result.returncode == 139:
            return "FAIL"
        if result.returncode == 0:
            # Check if cracked
            show_cmd = [
                "hashcat", "-m", mode, "--show", hash_value
            ]
            show_result = subprocess.run(
                show_cmd, text=True, capture_output=True
            )
            output = show_result.stdout.strip()
            if output:
                print(f"{GREEN}[✓] Hash cracked! Result:{RESET}\n{CYAN}{output}{RESET}")
                return "SUCCESS"
            else:
                print(f"{YELLOW}[*] Hashcat finished but no result found.{RESET}")
                return "FAIL"
        return "FAIL"
    
    except subprocess.CalledProcessError as e:
        print(f"{RED}[-] Cracking failed: {e}{RESET}")
        return "FAIL"

def crack_chunks(mode, hash_value, chunks, rules):
    start_time = time.time()
    total_chunks = len(chunks)
    cracked = False

    for i, chunk in enumerate(chunks):
        chunk_start = time.time()
        print(f"{YELLOW}[+] Processing chunk {i+1}/{total_chunks}: {os.path.basename(chunk)}{RESET}")
        
        for rule in rules:
            rule_start = time.time()
            cmd = [
                "hashcat", "-a", "0", "-m", mode, hash_value, chunk,   
                "-r", f"/usr/share/hashcat/rules/{rule}",
                "--force", "--session", f"session_{i}_{rule}",
                "--segment-size=1", "--logfile-disable" "-w", "4", "-O","--status", "--status-timer=10"
            ]
            try:
                subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                # Check if cracked after each run
                show_cmd = [
                    "hashcat", "-m", mode, "--show", hash_value
                ]
                show_result = subprocess.run(
                    show_cmd, text=True, capture_output=True
                )
                output = show_result.stdout.strip()
                if output:
                    print(f"{GREEN}[✓] Hash cracked! Result:{RESET}\n{CYAN}{output}{RESET}")
                    cracked = True
                    break
            except subprocess.CalledProcessError:
                pass
        print(f"{BLUE}[•] Progress: {i+1}/{total_chunks} chunks{RESET}")
        if cracked:
            break

    if cracked:
        print(f"{GREEN}[✓] Cracking finished: SUCCESS{RESET}")
    else:
        print(f"{YELLOW}[-] Cracking finished: FAILED{RESET}")

def main():
    print_banner()
    start_time = time.time()
    
    # New feature: Default password search
    print(f"\n{CYAN}[?] What would you like to do?{RESET}")
    print(f"{CYAN}  1. Crack a hash{RESET}")
    print(f"{CYAN}  2. Search default passwords{RESET}")
    choice = input(f"{GREEN}[?] Enter choice (1/2): {RESET}").strip()
    
    if choice == "2":
        service = input(f"{CYAN}[?] Enter service/technology name: {RESET}").strip()
        search_default_passwords(service)
        return
    
    # Original hash cracking workflow
    hash_input = input(f"\n{CYAN}[?] Enter Path To File or Hash: {RESET}").strip()
    if os.path.isfile(hash_input):
        hash_value = hash_input
        # Try to detect hash type from first hash in file
        with open(hash_input, 'r') as f:
            first_hash = f.readline().strip()
    else:
        first_hash = hash_input
        temp_dir = mkdtemp()
        hash_value = os.path.join(temp_dir, "hash.txt")
        with open(hash_value, 'w') as f:
            f.write(hash_input)
        print(f"{GREEN}[+] Hash saved to temporary file: {hash_value}{RESET}")

    # Try automatic detection with hashid
    print(f"\n{BLUE}[+] Attempting automatic hash detection...{RESET}")
    detected = detect_hash_with_hashid(first_hash)
    if detected:
        print(f"{GREEN}[✓] Possible hash types detected:{RESET}")
        for i, (mode, desc) in enumerate(detected[:10], 1):
            if mode:
                print(f"{CYAN}  {i}. [Hashcat Mode {mode}] {desc}{RESET}")
            else:
                print(f"{CYAN}  {i}. {desc}{RESET}")
    
    know_hash_type = input(f"\n{CYAN}[?] Do you know the hash type? (y/n): {RESET}").strip().lower()
    if know_hash_type != "y":
        print(f"{YELLOW}[!] Opening hash identifier tool in browser...{RESET}")
        webbrowser.open("https://hashes.com/en/tools/hash_identifier")
        hash_name = input(f"{CYAN}[?] After identifying, enter hash name (e.g., ntlm, sha1, md5): {RESET}").strip()
    else:
        hash_name = input(f"{CYAN}[?] Enter the hash name or keyword (e.g., ntlm, sha1, md5): {RESET}").strip()

    mode = extract_modes_from_hashcat(hash_name)
    
    if not mode:
        print(f"{RED}[-] No valid mode selected. Exiting.{RESET}")
        return

    wordlist = input(f"\n{CYAN}[?] Enter path to wordlist: {RESET}").strip()
    if not os.path.isfile(wordlist):
        print(f"{RED}[-] Wordlist not found.{RESET}")
        return

    wordlist_size = os.path.getsize(wordlist)
    print(f"{BLUE}[+] Wordlist size: {wordlist_size/(1024*1024):.2f} MB{RESET}")
    
    use_rules = input(f"{CYAN}[?] Use rules? (y/n): {RESET}").strip().lower()
    rules = []
    if use_rules == 'y':
        print(f"\n{BLUE}[+] Available rules:{RESET}")
        all_rules = list_rules()
        if all_rules:
            selected = input(f"\n{CYAN}[?] Select rule numbers (comma separated): {RESET}")
            nums = [int(i.strip()) for i in selected.split(',') if i.strip().isdigit()]
            rules = [all_rules[n - 1] for n in nums if 0 < n <= len(all_rules)]
            print(f"{GREEN}[+] Selected rules: {', '.join(rules)}{RESET}")
        else:
            print(f"{YELLOW}[-] No rules available. Proceeding without rules.{RESET}")

    print(f"\n{CYAN}[+] Starting cracking process...{RESET}")
    crack_start = time.time()

    # Force split and chunked processing if more than one rule is selected
    if len(rules) > 1:
        print(f"{YELLOW}[!] More than one rule selected, forcing chunked processing!{RESET}")
        chunks = split_wordlist(wordlist)
        crack_chunks(mode, hash_value, chunks, rules)
        result = None
    else:
        result = try_crack(mode, hash_value, wordlist, rules)
        if result == "MEMORY":
            print(f"{RED}[-] Memory error detected. Switching to chunked processing...{RESET}")
            chunks = split_wordlist(wordlist)
            crack_chunks(mode, hash_value, chunks, rules)

    if result == "SUCCESS":
        print(f"{GREEN}[✓] Successfully cracked hash!{RESET}")
    else:
        print(f"{YELLOW}[-] Cracking attempt finished{RESET}")

    total_time = time.time() - start_time
    crack_time = time.time() - crack_start
    print(f"\n{GREEN}[+] Operation completed.{RESET}")
    print(f"{CYAN}    Total runtime: {timedelta(seconds=int(total_time))}{RESET}")
    print(f"{CYAN}    Active cracking time: {timedelta(seconds=int(crack_time))}{RESET}")
    print(f"{YELLOW}    Use 'hashcat -m {mode} --show {hash_value}' to view results{RESET}")

if __name__ == "__main__":
    main()