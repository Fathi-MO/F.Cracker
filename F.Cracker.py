import os
import subprocess
import webbrowser
import time
from tempfile import mkdtemp
from datetime import timedelta
import pyfiglet

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
    print(f"{CYAN}made by Fathi Eltantawy{RESET}")
    print(f"{GRAY}{'='*50}{RESET}")

def extract_modes_from_hashcat(search_term):
    try:
        output = subprocess.check_output("hashcat -h", shell=True, text=True)
        print(f"\n{BLUE}[+] Top matching modes in hashcat:{RESET}")
        matched = []
        for line in output.splitlines():
            if search_term.lower() in line.lower():
                parts = line.strip().split("|")
                if parts and parts[0].strip().isdigit():
                    mode = parts[0].strip()
                    matched.append((mode, line.strip()))
        if not matched:
            print(f"{YELLOW}[-] No match found.{RESET}")
            return input(f"{YELLOW}[?] Enter mode manually: {RESET}").strip()
        for i, (mode, line) in enumerate(matched[:5], 1):
            print(f"{CYAN}   {line.strip()}{RESET}")
        return input(f"\n{GREEN}[?] Enter the MODE number from above: {RESET}").strip()
    except Exception as e:
        print(f"{RED}[-] Error getting modes: {e}{RESET}")
        return input(f"{YELLOW}[?] Enter mode manually: {RESET}").strip()

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
        "--force", "--logfile-disable"
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
                "--segment-size=1", "--logfile-disable"
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
    
    hash_input = input(f"{CYAN}[?] Enter hash or path to file: {RESET}").strip()
    if os.path.isfile(hash_input):
        hash_value = hash_input
    else:
        temp_dir = mkdtemp()
        hash_value = os.path.join(temp_dir, "hash.txt")
        with open(hash_value, 'w') as f:
            f.write(hash_input)
        print(f"{GREEN}[+] Hash saved to temporary file: {hash_value}{RESET}")

    know_hash_type = input(f"\n{CYAN}[?] Do you know the hash type? (y/n): {RESET}").strip().lower()
    if know_hash_type != "y":
        print(f"{YELLOW}[!] Opening hash identifier tool in browser...{RESET}")
        webbrowser.open("https://hashes.com/en/tools/hash_identifier")
        hash_name = input(f"{CYAN}[?] After identifying, enter hash name (e.g., ntlm, sha1): {RESET}").strip()
    else:
        hash_name = input(f"{CYAN}[?] Enter the hash name (e.g., ntlm, sha1): {RESET}").strip()

    mode = extract_modes_from_hashcat(hash_name)

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
        result = None  # No need to run try_crack
    else:
        result = try_crack(mode, hash_value, wordlist, rules)
        if result == "MEMORY":
            print(f"{RED}[-] Memory error detected. Switching to chunked processing...{RESET}")
            chunks = split_wordlist(wordlist)
            crack_chunks(mode, hash_value, chunks, rules)

    if result == "SUCCESS":
        print(f"{GREEN}[✓] Successfully cracked hash!{RESET}")
    else:
        print(f"{YELLOW}[-] Cracking attempt failed{RESET}")

    total_time = time.time() - start_time
    crack_time = time.time() - crack_start
    print(f"\n{GREEN}[+] Operation completed.{RESET}")
    print(f"{CYAN}    Total runtime: {timedelta(seconds=int(total_time))}{RESET}")
    print(f"{CYAN}    Active cracking time: {timedelta(seconds=int(crack_time))}{RESET}")
    print(f"{YELLOW}    Use 'hashcat -m {mode} --show {hash_value}' to view results{RESET}")

if __name__ == "__main__":
    main()
