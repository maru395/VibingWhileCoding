import re
from main import PipelineConfig, ask_ai_recommendation, get_lang

# Minimal config just for testing
config = PipelineConfig(
    file_path="test.py",
    language="Python",
    model="qwen2.5-coder:3b",
    llm_url="http://127.0.0.1:11434/api/generate",
    high_confidence=re.compile(r''),
    ambiguous_keys=re.compile(r''),
    safe_values=re.compile(r''),
    sql_injection=re.compile(r''),
    direct_reference=re.compile(r'')
)

# --- Test Cases ---
test_cases = [
    # --- HARDCODED SECRETS ---
    {
        "type": "Hardcoded Secret",
        "code": 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
    },
    {
        "type": "Hardcoded Secret",
        "code": 'connection_string = "postgresql://admin:P@ssw0rd123!@localhost:5432/mydb"',
    },
    {
        "type": "Hardcoded Secret",
        "code": 'auth_header = {"Authorization": "Bearer 1a2b3c4d5e6f7g8h9i0j"}',
    },
    {
        "type": "Hardcoded Secret",
        "code": 'stripe_webhook_signing_secret = "whsec_06d8816f0076a084..."',
    },

    # --- SQL INJECTION ---
    {
        "type": "SQL Injection",
        "code": 'db.execute(f"UPDATE profiles SET bio = \'{user_bio}\' WHERE user_id = {uid}")',
    },
    {
        "type": "SQL Injection",
        "code": 'query = "SELECT * FROM products WHERE category = \'" + request.form["cat"] + "\'"',
    },
    {
        "type": "SQL Injection",
        "code": 'results = User.objects.raw("SELECT * FROM users WHERE name LIKE %s" % search_term)',
    },
    {
        "type": "SQL Injection",
        "code": 'cursor.execute("DELETE FROM logs WHERE level = " + params["level"])',
    },

    # --- INSECURE DIRECT OBJECT REFERENCE / PATH TRAVERSAL ---
    {
        "type": "Insecure Direct Object Reference",
        "code": 'return send_from_directory("/var/www/data", request.args.get("path"))',
    },
    {
        "type": "Insecure Direct Object Reference",
        "code": 'with open(f"./uploads/{req.json[\"user_id\"]}/config.json") as f:',
    },
    {
        "type": "Insecure Direct Object Reference",
        "code": 'image_data = open("assets/" + request.params["img_name"], "rb").read()',
    },
    {
        "type": "Insecure Direct Object Reference",
        "code": 'file_to_delete = os.path.join(UPLOADS_DIR, request.values.get("file_id"))\nos.remove(file_to_delete)',
    },
]

# --- Run Tests ---
for i, test in enumerate(test_cases, start=1):
    print(f"\n{'='*50}")
    print(f"Test {i}: {test['type']}")
    print(f"Input:  {test['code']}")

    result = ask_ai_recommendation(test['code'], test['type'], config)

    print(f"Output: {result}")
    print(f"{'='*50}")
