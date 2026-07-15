r"""
clean_bundle.py
------------------------------------------------------------------------------
SentinalFlow AI -- GitHub Upload Bundle Creator
Run this script from inside your main 'Sentinalflow AI' folder.

What it does:
  1. Creates a clean folder: Documents\Sentinelflow_GitHub_Ready\
  2. Copies all main Python/CSV files into the root of that folder.
  3. Copies the sentinel_artefacts\ folder in full.
  4. Copies the dashboard\ folder -- but completely skips node_modules\.

Run:
  python clean_bundle.py

After it finishes, drag EVERYTHING inside
  C:\Users\<you>\Documents\Sentinelflow_GitHub_Ready\
straight onto GitHub's upload page.
------------------------------------------------------------------------------
"""

import os
import shutil
import sys
from pathlib import Path

# Force UTF-8 output so the script works on Windows cp1252 consoles
# without needing the -X utf8 flag.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# -----------------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------------

# Source: the folder this script lives in (your main Sentinalflow AI folder)
SOURCE_DIR = Path(__file__).resolve().parent

# Destination: a brand-new folder in your Documents directory
DEST_DIR = Path.home() / "Documents" / "Sentinelflow_GitHub_Ready"

# Individual files to copy into the bundle root
ROOT_FILES = [
    "main.py",
    "train.py",
    "mock_generator.py",
    "run_demo.py",
    "smoke_test.py",
    "clean_bundle.py",        # include this script itself for reference
    "banking_telemetry_dataset.csv",
]

# Entire folders to copy (with optional skip-list per folder)
FOLDER_COPIES = [
    {
        "src"  : "sentinel_artefacts",
        "skip" : [],                      # copy everything inside
    },
    {
        "src"  : "dashboard",
        "skip" : ["node_modules"],        # skip node_modules -- this is the key step
    },
]

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def print_header():
    print()
    print("=" * 62)
    print("  SentinalFlow AI -- GitHub Upload Bundle Creator")
    print("=" * 62)
    print(f"  Source : {SOURCE_DIR}")
    print(f"  Dest   : {DEST_DIR}")
    print("=" * 62)
    print()


def confirm_overwrite(dest: Path) -> bool:
    """If the destination already exists, ask before nuking it."""
    if not dest.exists():
        return True
    print(f"  [WARN] Destination folder already exists:")
    print(f"         {dest}")
    answer = input("  Overwrite it completely? [y/N]: ").strip().lower()
    return answer == "y"


def copy_file(src: Path, dest: Path):
    """Copy a single file, creating parent dirs as needed."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)


def copy_folder_excluding(src: Path, dest: Path, skip_names: list[str]):
    """
    Recursively copy `src` -> `dest`, skipping any directory whose
    name appears in `skip_names` (case-insensitive on Windows).

    Uses shutil.copytree with an ignore function -- the cleanest approach.
    """
    skip_lower = {s.lower() for s in skip_names}

    def _ignore(directory, contents):
        ignored = set()
        for item in contents:
            if item.lower() in skip_lower:
                ignored.add(item)
        return ignored

    shutil.copytree(
        src,
        dest,
        ignore        = _ignore,
        dirs_exist_ok = False,   # dest must not exist yet (we control this)
        copy_function = shutil.copy2,
    )


def count_files(folder: Path) -> int:
    return sum(1 for _ in folder.rglob("*") if _.is_file())


# -----------------------------------------------------------------------------
# Main routine
# -----------------------------------------------------------------------------

def main():
    print_header()

    # -- Safety check: must be run from the correct source directory ----------
    if not (SOURCE_DIR / "main.py").exists():
        print("  [ERROR] Could not find main.py in the current directory.")
        print("          Make sure you run this script from inside your")
        print("          'Sentinalflow AI' project folder.")
        sys.exit(1)

    # -- Confirm overwrite if destination already exists ----------------------
    if not confirm_overwrite(DEST_DIR):
        print("  Aborted -- no files were changed.")
        sys.exit(0)

    # -- Wipe destination if it already exists --------------------------------
    if DEST_DIR.exists():
        print(f"  Removing old destination folder...")
        shutil.rmtree(DEST_DIR)

    DEST_DIR.mkdir(parents=True, exist_ok=True)
    print(f"  Created: {DEST_DIR}\n")

    # -- Step 1: Copy individual root files -----------------------------------
    print("  [1/3] Copying root files...")
    copied_files   = 0
    skipped_files  = 0

    for filename in ROOT_FILES:
        src_path  = SOURCE_DIR / filename
        dest_path = DEST_DIR   / filename

        if src_path.exists():
            copy_file(src_path, dest_path)
            size_kb = src_path.stat().st_size / 1024
            print(f"        OK  {filename:<42} ({size_kb:,.1f} KB)")
            copied_files += 1
        else:
            print(f"        --  {filename:<42} (not found, skipped)")
            skipped_files += 1

    print(f"\n        {copied_files} file(s) copied, {skipped_files} not found.\n")

    # -- Step 2 & 3: Copy folders ---------------------------------------------
    print("  [2/3] Copying folders...")

    for idx, entry in enumerate(FOLDER_COPIES, start=1):
        src_name   = entry["src"]
        skip_names = entry["skip"]
        src_path   = SOURCE_DIR / src_name
        dest_path  = DEST_DIR   / src_name

        if not src_path.exists():
            print(f"        --  {src_name}\\  (not found, skipped)")
            continue

        skip_label = f"  [skipping: {', '.join(skip_names)}]" if skip_names else ""
        print(f"        Copying  {src_name}\\{skip_label}")

        try:
            copy_folder_excluding(src_path, dest_path, skip_names)
            n = count_files(dest_path)
            print(f"        OK  {src_name}\\  ->  {n:,} file(s) copied")
        except Exception as exc:
            print(f"        [ERROR] Failed to copy {src_name}\\: {exc}")
            sys.exit(1)

    # -- Step 3: Write a .gitignore so node_modules stays excluded on Git -----
    print()
    print("  [3/3] Writing .gitignore...")
    gitignore_path = DEST_DIR / ".gitignore"
    gitignore_content = """\
# Python
__pycache__/
*.py[cod]
*.pyo
*.pyd
.Python
*.egg-info/
dist/
build/
.env
*.log

# Node / Dashboard
dashboard/node_modules/
dashboard/.cache/
dashboard/dist/
dashboard/.vite/

# ML artefacts (large binaries - commit if needed)
# sentinel_artefacts/*.pkl
# sentinel_artefacts/*.joblib

# OS noise
.DS_Store
Thumbs.db
desktop.ini
"""
    gitignore_path.write_text(gitignore_content, encoding="utf-8")
    print(f"        OK  .gitignore written")

    # ── Final summary ─────────────────────────────────────────────────────────
    total_files = count_files(DEST_DIR)
    total_size  = sum(
        f.stat().st_size for f in DEST_DIR.rglob("*") if f.is_file()
    )
    total_size_mb = total_size / (1024 * 1024)

    print()
    print("=" * 62)
    print("  BUNDLE COMPLETE")
    print("=" * 62)
    print(f"  Location  : {DEST_DIR}")
    print(f"  Files     : {total_files:,}")
    print(f"  Total size: {total_size_mb:.2f} MB")
    print()
    print("  Next steps:")
    print("  1. Open GitHub in your browser -> your repo -> 'Add file'")
    print("     -> 'Upload files'")
    print("  2. Open File Explorer and navigate to:")
    print(f"     {DEST_DIR}")
    print("  3. Select ALL files and folders inside it (Ctrl+A)")
    print("     and drag them onto the GitHub upload page.")
    print()
    print("  NOTE: node_modules was NOT included. GitHub will")
    print("  reconstruct it from package.json via 'npm install'.")
    print("=" * 62)
    print()

    # ── Open the bundle folder in File Explorer automatically ─────────────────
    try:
        os.startfile(DEST_DIR)
        print("  File Explorer opened at your bundle folder.")
    except Exception:
        pass  # Non-Windows fallback — just skip


if __name__ == "__main__":
    main()
