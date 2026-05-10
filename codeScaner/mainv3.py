import sqlite3
import re
import requests
import json
from dataclasses import dataclass


@dataclass
class PipelineConfig:
    file_path: str
    language: str
    model: str
    llm_url: str
    high_confidence: re.Pattern
    ambiguous_keys: re.Pattern
    safe_values: re.Pattern
    sql_injection: re.Pattern
    direct_reference: re.Pattern # file path access safeguard


def main():
    FILE_PATH = "test.py" # to be inputted by the user
    # TODO add safeguard for all language
    config = PipelineConfig(
        file_path=FILE_PATH,
        language=get_lang(FILE_PATH),
        model="qwen2.5-coder:3b",
        llm_url="http://127.0.0.1:11434/api/generate",
        high_confidence=re.compile(
            r'('
            r'password|passwd|pwd|secret|secret_key|client_secret'
            r'|api_key|apikey|api_secret'
            r'|token|access_token|refresh_token|auth_token|bearer_token'
            r'|private_key|signing_key'
            r'|db_password|db_pass|db_uri|connection_string|conn_str|dsn'
            r'|mongo_uri|postgres_url|mysql_url'
            r'|aws_access_key|aws_secret_key|aws_bucket'
            r'|azure_key|azure_secret|azure_connection'
            r'|gcp_key|google_api_key|firebase_key'
            r'|stripe_key|stripe_secret|twilio_token|twilio_sid'
            r'|sendgrid_key|mailgun_key|github_token|gitlab_token'
            r'|slack_token|slack_webhook|jwt_secret|oauth_secret'
            r'|passphrase|encryption_key|ssh_key|rsa_key|pem'
            r')\s*=\s*[\'"][^\'"]+[\'"]',
            re.IGNORECASE
        ),
        ambiguous_keys=re.compile(
            r'(host|hostname|ip_address|url|base_url|endpoint|localhost_url'
            r'|port|server|domain|ftp_host|smtp_host|smtp_server'
            r'|db_url|db_name|db_user|username|login|cert|ssl_cert|tls_cert|salt)'
            r'\s*=\s*[\'"]([^\'"]+)[\'"]',
            re.IGNORECASE
        ),
        safe_values=re.compile(
            r'^('
            r'localhost|127\.0\.0\.1|0\.0\.0\.0'
            r'|http://localhost.*|https://localhost.*'
            r'|your_.*|<.*>|\$\{.*\}|%.*%'
            r'|example\.com|test|dev|staging'
            r'|true|false|none|null|undefined'
            r'|\d{1,5}'
            r')$',
            re.IGNORECASE
        ),
        sql_injection=re.compile(
            r'('
            r'(execute|executemany|raw|query)\s*\(\s*[\'"].*?\+.*?[\'"]'
            r'|(execute|executemany|raw|query)\s*\(\s*f[\'"].*?\{.*?\}.*?[\'"]'
            r'|(execute|executemany|raw|query)\s*\(\s*[\'"].*?%.*?[\'"\s]*%'
            r'|(execute|executemany|raw|query)\s*\([\s\S]*?\+[\s\S]*?\)'  
            r')\s*',
            re.IGNORECASE | re.DOTALL 
        ),
        direct_reference=re.compile(
            r'('
            r'open\s*\(\s*(request|req|input|args|params|data|query)'
            r'|open\s*\(\s*f[\'"].*\{.*(request|req|input|args|params|data|query).*\}.*[\'"]'
            r'|os\.(path\.(join|abspath|open)|getcwd)\s*\(.*\b(request|req|input|args|params|data|query)\b'
            r'|send_file\s*\(.*\b(request|req|input|args|params|data|query)\b'
            r'|send_from_directory\s*\(.*\b(request|req|input|args|params|data|query)\b'
            r'|filename\s*=\s*(request|req)\.(args|form|json|data|params)\b'
            r')',
            re.IGNORECASE
        )
    )

    conn = set_up_database()
    run_devsecops_pipeline(config, conn)


def get_lang(file):
    dot_index = file.rfind(".")
    file_extension = file[dot_index:] if dot_index != -1 else ""

    valid_extensions = {
        ".py": "Python", ".pyw": "Python (Windows GUI)", ".pyi": "Python (type hints)",
        ".java": "Java",
        ".js": "JavaScript", ".mjs": "JavaScript (ES Modules)", ".cjs": "JavaScript (CommonJS)",
        ".ts": "TypeScript", ".tsx": "TypeScript (React)",
        ".c": "C", ".h": "C / C Header", ".cpp": "C++", ".cc": "C++",
        ".cxx": "C++", ".hpp": "C++ Header",
        ".cs": "C#", ".go": "Go", ".rs": "Rust", ".php": "PHP",
        ".rb": "Ruby", ".swift": "Swift", ".kt": "Kotlin", ".kts": "Kotlin Script",
        ".dart": "Dart", ".r": "R", ".R": "R",
        ".sh": "Shell Script", ".bash": "Bash Script", ".zsh": "Zsh Script",
        ".bat": "Windows Batch", ".cmd": "Windows Command Script",
        ".sql": "SQL", ".html": "HTML", ".htm": "HTML", ".css": "CSS",
        ".json": "JSON", ".yaml": "YAML", ".yml": "YAML",
        ".xml": "XML", ".toml": "TOML", ".ini": "INI Config",
        ".scala": "Scala", ".clj": "Clojure", ".hs": "Haskell", ".elm": "Elm",
        ".lua": "Lua", ".pl": "Perl", ".jl": "Julia", ".m": "MATLAB / Objective-C",
    }

    return valid_extensions.get(file_extension, "Invalid or Unknown format")


def set_up_database():
    connection = sqlite3.connect("D:\\philsca\\databases\\codeScanner.db")
    cursor = connection.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT,
            line_number INTEGER,
            vulnerability_type TEXT,
            original_code TEXT,
            suggested_fix TEXT,
            status TEXT DEFAULT 'OPEN'
        )
    ''')

    connection.commit()
    return connection


def scan_file(config: PipelineConfig):
    findings = []

    with open(config.file_path, "r") as file:
        lines = file.readlines()
        full_content = "".join(lines)  

        for line_number, line in enumerate(lines, start=1):
            stripped = line.strip()

            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Tier 1: Hardcoded secrets — single line is enough
            if config.high_confidence.search(line):
                findings.append({
                    "file_path": config.file_path,
                    "line_number": line_number,
                    "type": "Hardcoded Secret",
                    "confidence": "HIGH",
                    "code": stripped
                })
                continue

            # Tier 2: Ambiguous secrets — single line is enough
            match = config.ambiguous_keys.search(line)
            if match:
                value = match.group(2)
                if not config.safe_values.match(value):
                    findings.append({
                        "file_path": config.file_path,
                        "line_number": line_number,
                        "type": "Possible Hardcoded Secret",
                        "confidence": "LOW",
                        "code": stripped
                    })
                continue

            # Tier 3: SQL Injection — check multi-line blocks starting at this line
            # Grab a window of 5 lines starting from current line
            line_window = "".join(lines[line_number - 1 : line_number + 4])
            if config.sql_injection.search(line_window):
                # Collect the full block as the code snippet
                block = line_window.strip()
                findings.append({
                    "file_path": config.file_path,
                    "line_number": line_number,
                    "type": "SQL Injection",
                    "confidence": "HIGH",
                    "code": block
                })
                continue

            # Tier 4: Insecure Direct Object Reference — same windowed approach
            if config.direct_reference.search(line_window):
                block = line_window.strip()
                findings.append({
                    "file_path": config.file_path,
                    "line_number": line_number,
                    "type": "Insecure Direct Object Reference",
                    "confidence": "HIGH",
                    "code": block
                })

    return findings


# ai consultation part (used local llm for this project)
def ask_ai_recommendation(vulnerable_code, vulnerability_type, config: PipelineConfig):
    # parameters can also be improved further
    if vulnerability_type == "Hardcoded Secret":
        specific_instruction = (
            "Use environment variables (e.g., os.environ) instead of hardcoding.\n\n"
            "Example:\n"
            "Input:  DB_PASS = \"hunter2\"\n"
            "Output: DB_PASS = os.getenv('DB_PASS')\n"
        )
    elif vulnerability_type == "SQL Injection":
        specific_instruction = (
            "Use parameterized queries instead of string formatting or concatenation.\n\n"
            "Example:\n"
            "Input:  cursor.execute(\"SELECT * FROM users WHERE name = \" + name)\n"
            "Output: cursor.execute(\"SELECT * FROM users WHERE name = ?\", (name,))\n\n"
            "Example:\n"
            "Input:  query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\"\n"
            "Output: query = (\"SELECT * FROM users WHERE id = ?\", (user_id,))\n\n"  
            "Example:\n"
            "Input:  cursor.execute(f\"DELETE FROM users WHERE id = {user_id}\")\n"
            "Output: cursor.execute(\"DELETE FROM users WHERE id = ?\", (user_id,))\n"
        )

    elif vulnerability_type == "Insecure Direct Object Reference":
        specific_instruction = (
            "Use an indirect reference map instead of passing user input directly.\n\n"
            "Example:\n"
            "Input:  open(request.args.get('file'))\n"
            "Output: open(FILE_MAP.get(request.args.get('id')))\n\n"
            "Example:\n"
            "Input:  return send_from_directory('/var/www', request.args.get('path'))\n"
            "Output: return send_from_directory(SAFE_DIR, FILE_MAP.get(request.args.get('id')))\n\n"  # covers Test 9
            "Example:\n"
            "Input:  send_file(request.args.get('path'))\n"
            "Output: send_file(FILE_MAP.get(request.args.get('id')))\n"
        )
    else:
        specific_instruction = "Apply standard secure coding practices to fix the vulnerability.\n"

    data = {
        "model": config.model,
        "prompt": (
            f"You are an expert DevSecOps engineer the following {config.language} code contains {vulnerability_type} vulnerability.\n"
            f"given these examples: {specific_instruction}\n"
            f"rewrite the code and return ONLY the single fixed line, no imports, no explanations:\n"
            f"Input:  {vulnerable_code}\n"
            f"Output:"
        ),
        "stream": True,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "repeat_penalty": 1.1,
            "num_ctx": 512
        }
    }

    response = requests.post(config.llm_url, json=data, stream=True)
    response.raise_for_status()

    full_response = ""
    for line in response.iter_lines():
        if not line:
            continue
        try:
            chunk = json.loads(line.decode())
            full_response += chunk.get("response", "")
            if chunk.get("done"):
                break
        except json.JSONDecodeError:
            continue

    cleaned = re.sub(r"```(?:\w+)?\n?|```", "", full_response).strip()
    cleaned = cleaned.splitlines()[0].strip()

    return cleaned


# TODO
def run_devsecops_pipeline(config: PipelineConfig, conn):
    print(f"[*] Scanning {config.file_path} for vulnerabilities...")

    vulnerabilities = scan_file(config)

    if not vulnerabilities:
        print("[+] No vulnerabilities found.")
        return

    cursor = conn.cursor()

    for vuln in vulnerabilities:
        tag = f"[{vuln['confidence']}]"
        print(f"[!] {tag} Found '{vuln['type']}' in {vuln['file_path']} on line {vuln['line_number']}")
        print(f"    Original: {vuln['code']}")

        if vuln['confidence'] == "LOW":
            print("    [~] Low confidence — skipping AI fix, logging as warning.\n")
            cursor.execute('''
                INSERT INTO vulnerabilities
                (file_path, line_number, vulnerability_type, original_code, suggested_fix, status)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (vuln['file_path'], vuln['line_number'], vuln['type'], vuln['code'], "REVIEW MANUALLY", "WARNING"))
            continue

        print("    [*] Asking AI for remediation...")
        secure_code = ask_ai_recommendation(vuln['code'], vuln['type'], config)
        print(f"    [+] AI Fix: {secure_code}\n")

        cursor.execute('''
            INSERT INTO vulnerabilities
            (file_path, line_number, vulnerability_type, original_code, suggested_fix)
            VALUES (?, ?, ?, ?, ?)
        ''', (vuln['file_path'], vuln['line_number'], vuln['type'], vuln['code'], secure_code))

    conn.commit()
    print("[*] Scan complete. Results saved to database.")


if __name__ == "__main__":
    main()
