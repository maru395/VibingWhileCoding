import sqlite3
import re
import requests
import json

from click import Parameter

def main():
    # TODO
    # parameters
    LOCALHOST_URL = "http://127.0.0.1:11434/api/generate"
    FILE_PATH = "test.py"
    LANGUAGE = get_lang(FILE_PATH)
    MODEL = "gemma:2b"
    HARDCODED_PATTERNS = re.compile(r'(password|secret|api_key|token)\s*=\s*[\'"][^\'"]+[\'"]', re.IGNORECASE) # checks for passwords, api_keys etc
    
    set_up_database()
    run_devsecops_pipeline(FILE_PATH, LANGUAGE, LOCALHOST_URL, MODEL)


def get_lang(file):
    file_extension = file.split(".")[0]
    valid_extensions = {
        # Python
        ".py": "Python", ".pyw": "Python (Windows GUI)",".pyi": "Python (type hints)",
        # Java
        ".java": "Java",
        # JavaScript / Web
        ".js": "JavaScript",".mjs": "JavaScript (ES Modules)",".cjs": "JavaScript (CommonJS)",".ts": "TypeScript",".tsx": "TypeScript (React)",
        # C / C++
        ".c": "C",".h": "C / C Header",".cpp": "C++",".cc": "C++",".cxx": "C++",".hpp": "C++ Header",
        # C#
        ".cs": "C#",
        # Go
        ".go": "Go",
        # Rust
        ".rs": "Rust",
        # PHP
        ".php": "PHP",
        # Ruby
        ".rb": "Ruby",
        # Swift
        ".swift": "Swift",
        # Kotlin / Android
        ".kt": "Kotlin",".kts": "Kotlin Script",
        # Dart / Flutter
        ".dart": "Dart",
        # R
        ".r": "R",".R": "R",
        # Shell / Scripts
        ".sh": "Shell Script",".bash": "Bash Script",".zsh": "Zsh Script",".bat": "Windows Batch",".cmd": "Windows Command Script",
        # Database
        ".sql": "SQL",
        # Web
        ".html": "HTML",".htm": "HTML",".css": "CSS",
        # Data / Config
        ".json": "JSON",".yaml": "YAML",".yml": "YAML",".xml": "XML",".toml": "TOML",".ini": "INI Config",
        # Functional / JVM languages
        ".scala": "Scala",".clj": "Clojure",".hs": "Haskell",".elm": "Elm",
        # Others
        ".lua": "Lua",".pl": "Perl",".jl": "Julia",".m": "MATLAB / Objective-C",
    }
    if file_extension in valid_extensions:
        return valid_extensions[file_extension]
    else:
        return "Invalid or Unknown format"


def set_up_database():
    connection = sqlite3.connect("D:\\philsca\\databases\\codeScanner.db")
    cursor = connection.cursor() # enables data manipulation one at a time
    
    # initializes table values
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT,
            line_number INTEGER,
            type_of_vulnerability TEXT,
            original_code TEXT,
            suggested_fix TEXT,
            status TEXT DEFAULT 'OPEN'
        )
    ''')
    
    connection.commit()
    return connection


# engine to check the code inputted
def scan_file(file_path, hard_coded_parameters):
    findings = []
    
    with open(file_path, "r") as file:
        lines = lines.readlines()
        
        for line_number, line in enumerate(lines, start=1):
            # catch for hard coded secret parameters set 
            if hard_coded_parameters.find(line):
                findings.append({
                    "file_path" : file_path,
                    "line_number" : line_number,
                    "type" : "hard coded secret",
                    "code" : line.strip()
                })
    
    return findings


# ai consultation part (used local llm for this project)
def ask_ai_recommendation(vulnerable_code, language, url, model):
    data = {
    "model": model,
        "prompt": f"""
            You are an expert DevSecOps engineer. 
            The following {language} code contains a security vulnerability (Hardcoded Secret):
            
            `{vulnerable_code}`
            
            Rewrite this single line of code to be secure. Use environment variables (os.environ) instead of hardcoding. 
            Return ONLY the exact line of fixed code, no explanations, no markdown formatting.
            """,
        "stream": True,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "repeat_penalty": 1.1,
            "num_ctx": 512
        }
    }

    response = requests.post(url, json=data, stream=True)
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

    # Strip markdown fences (opening + closing) and extra whitespace
    cleaned = re.sub(r"```(?:python)?\n?|```", "", full_response).strip()
    # Take only the first line in case the model over-generates
    cleaned = cleaned.splitlines()[0].strip()

    return cleaned


# TODO
def run_devsecops_pipeline(target_file, language, url, model):
    print(f"[*] Scanning {target_file} for vulnerabilities...")
    
    # 1. Scan the code
    vulnerabilities = scan_file(target_file)
        
    cursor = conn.cursor()
    
    # 2. Process findings
    for vuln in vulnerabilities:
        print(f"[!] Found {vuln['type']} in {vuln['file']} on line {vuln['line_num']}")
        print(f"    Original: {vuln['code']}")
        
        # 3. Get AI Fix
        print("    [*] Asking AI for remediation...")
        secure_code = get_ai_remediation(vuln['code'], language, url, model)
        print(f"    [+] AI Fix : {secure_code}\n")
        
        # 4. Log to Database
        cursor.execute('''
            INSERT INTO vulnerabilities 
            (file_path, line_number, vulnerability_type, original_code, suggested_fix)
            VALUES (?, ?, ?, ?, ?)
        ''', (vuln['file'], vuln['line_num'], vuln['type'], vuln['code'], secure_code))
        
    conn.commit()
    print("[*] Scan complete. Results saved to database.")


if __name__ == __name__:
    main()
