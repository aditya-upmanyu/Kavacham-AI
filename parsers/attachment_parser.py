"""
parsers/attachment_parser.py
============================
Attachment security helpers: risky extension rules, spoofed double extensions
and MIME-type checks. Pure logic — no file execution ever happens.
"""

import os


# Extensions whose content is frequently weaponized (executables, scripts,
# active content, archives).
RISKY_EXTENSIONS = {
    ".exe", ".apk", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".scr", ".msi",
    ".docm", ".xlsm", ".jar", ".dll", ".com", ".pif", ".wsf", ".hta",
    ".lnk", ".iso", ".svg", ".swf", ".hta", ".mht", ".reg", ".msc",
    ".zip", ".rar", ".7z", ".cab", ".gz", ".bz2",
}

# Executable / script classes (highest severity).
EXECUTABLE_EXTENSIONS = {
    ".exe", ".apk", ".jar", ".dll", ".com", ".pif", ".msi", ".scr", ".iso"
}

# Script & active-content classes (high severity).
SCRIPT_EXTENSIONS = {
    ".js", ".vbs", ".ps1", ".bat", ".cmd", ".wsf", ".hta", ".lnk", ".reg",
    ".msc", ".svg", ".swf",
}

# Macro-enabled Office documents (documented macro risk).
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt"}

# Compressed formats (can hide payloads inside).
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".cab", ".gz", ".bz2", ".tar"}

# Safe-ish extensions that attackers append beside a payload (double ext).
SAFE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt", ".docx", ".xlsx",
    ".pptx", ".csv", ".mp4", ".mp3", ".mov", ".wav",
}


def analyze_attachment_extension(filename: str) -> dict:
    """
    Evaluate a filename for risky extensions, including double-extension
    spoofing (e.g. `invoice.pdf.exe`).

    Returns { extension, risk (none|low|medium|high|critical),
              risky, reason, matched_class }.
    """
    name = (filename or "").strip()
    low = name.lower()
    if not low:
        return {"extension": "", "risk": "none", "risky": False, "reason": "", "matched_class": ""}

    # Multi-dot extension detection — last two labels
    base_ext = os.path.splitext(low)[1]
    dotted = low.rsplit(".", 1)
    second_ext = os.path.splitext(dotted[0])[1] if len(dotted) > 1 and dotted[0] else ""

    risk = "none"
    reason = ""
    matched_class = ""

    for ext in (base_ext, second_ext):
        if ext in EXECUTABLE_EXTENSIONS:
            risk = "critical"
            matched_class = "executable"
            reason = f"File carries an executable extension ({ext}) which can contain malicious code"
            break
        if ext in SCRIPT_EXTENSIONS:
            risk = "high"
            matched_class = "script"
            reason = f"File carries a script/active-content extension ({ext}) that can run code"
            break
        if ext in MACRO_EXTENSIONS:
            risk = "medium"
            matched_class = "macro"
            reason = f"File uses a macro-capable format ({ext}) which may contain embedded macro payloads"
            break
        if ext in ARCHIVE_EXTENSIONS:
            risk = "medium"
            matched_class = "archive"
            reason = f"File is an archive ({ext}) that can hide payloads inside"
            break

    # Double-extension spoofing: safe-looking last ext + risky earlier ext
    if base_ext in SAFE_EXTENSIONS and second_ext in RISKY_EXTENSIONS:
        risk = "critical"
        matched_class = "double_extension"
        reason = (
            f"Possible double-extension spoofing: filename ends in {base_ext} "
            f"but contains hidden {second_ext} payload"
        )

    return {
        "extension": base_ext,
        "risk": risk,
        "risky": risk in ("medium", "high", "critical"),
        "reason": reason,
        "matched_class": matched_class,
    }