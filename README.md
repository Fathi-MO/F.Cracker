# F.Cracker
Hash Crack Tool
✅ 1. Interactive Hash Mode Identification

    Normal Hashcat: You must know the hash mode (-m) or search through a large hashcat -h output manually.

    F.Cracker: Accepts a hash name like ntlm, sha1, md5, then filters and shows top 50 matching modes to choose from quickly.

    ✅ Saves time and reduces error in mode selection.

✅ 2. Auto-opening Web Hash Identifier

    If you don't know the hash type, the script opens the hashes.com hash identifier for you.

    ✅ Helps beginners or even experienced users who forget some hash formats.

✅ 3. Handles Long Wordlists Automatically

    Normal Hashcat: Will crash or throw GPU memory error on massive wordlists.

    F.Cracker: Detects memory error and automatically splits the wordlist into chunks (1M lines each) and tries again chunk-by-chunk.

    ✅ Automatically adapts to GPU limits, reducing crashes and wasted time.

✅ 4. Session Tracking with Chunks + Rules

    Applies hashcat sessions (--session) for each chunk and rule, enabling better tracking and even resuming.

    You can review logs or performance for each chunk separately.

    ✅ Professional-grade wordlist management.

✅ 5. Rule Selection Interface

    Lists all .rule files from /usr/share/hashcat/rules and lets you select multiple by number.

    ✅ No need to remember rule filenames, and avoids typos.

✅ 6. Color-coded Output and Progress Tracking

    Uses ANSI colors for clean, readable terminal output.

    Shows:

        Time per chunk

        Estimated time remaining (ETA)

        Total runtime

        Cracking runtime

    ✅ Looks clean, helps you track progress like a pro
    ✅ 7. Temporary File Handling

    Automatically saves hashes into a temp file if you input raw hash text.

    ✅ Makes hashcat commands compatible without manually creating files.
    ✅ 8. Clear Success/Failure Handling

    Detects if cracking was successful (returncode == 0)

    Automatically suggests running:

    hashcat -m <mode> --show <file>

    ✅ Tells you exactly what to do next.

    🔹 Efficient Memory Management with Smart Wordlist Chunking

Unlike regular Hashcat usage, where applying multiple rules on large wordlists can quickly exceed RAM and disk capacity (causing crashes or severe slowdowns), F.Cracker implements an intelligent chunking mechanism:

    The wordlist is automatically split into manageable chunks (e.g., 1 million lines per file).

    After processing each chunk, it's deleted from disk to free up space and minimize memory pressure.

    This allows massive wordlists and multiple rule combinations to be used efficiently—even on systems with limited RAM or storage.

    ✅ This design unleashes the full power of Hashcat without being constrained by hardware limits, making F.Cracker highly scalable and stable for large-scale cracking jobs.
