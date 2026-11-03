"""
remediation_kb.py - Curated, deterministic security guidance keyed by Bandit test ID.

Why this exists: a 1.5B-parameter model cannot be trusted to write secure fixes.
Explanations, impact statements, recommendations and code examples for known
Bandit tests are written here by hand, reviewed by a human, and never change
between runs. The LLM only adds a short plain-English explanation on top.

Categories (we never call anything a "confirmed" vulnerability, because Bandit
cannot know where data really comes from):
    informational            - a pattern worth knowing about, not a problem by itself
    warning                  - may or may not be a problem, depends on context
    potential_vulnerability  - exploitable IF attacker-controlled data reaches it
"""

CATEGORY_LABELS = {
    "informational": "Informational: a code pattern worth knowing about, not a vulnerability by itself",
    "warning": "Security warning: whether this is a real problem depends on context",
    "potential_vulnerability": (
        "Potential vulnerability: may be exploitable if attacker-controlled data reaches this code"
    ),
}


def _entry(category, explanation, impact, recommendation, fixed_code="", notes=None):
    return {
        "category": category,
        "explanation": explanation,
        "impact": impact,
        "recommendation": recommendation,
        "fixed_code": fixed_code,
        "notes": notes or [],
    }


# ---------------------------------------------------------------- shared text
_DISPATCH_EXAMPLE = '''\
def show_version():
    return "1.0"

def show_status():
    return "ok"

# Only the actions listed here can ever run.
ALLOWED_ACTIONS = {
    "version": show_version,
    "status": show_status,
}

def run_action(action_name):
    handler = ALLOWED_ACTIONS.get(action_name)
    if handler is None:
        raise ValueError("Unsupported action")
    return handler()'''

_SHELL_FIX = '''\
import subprocess

# Fixed allow-list: the caller picks a NAME, never the command text.
ALLOWED_COMMANDS = {
    "python_version": ["python", "--version"],
    "pip_list": ["python", "-m", "pip", "list"],
}

def execute_command(name):
    argv = ALLOWED_COMMANDS.get(name)
    if argv is None:
        raise ValueError("Command not allowed")
    return subprocess.run(
        argv,              # a list of separate arguments
        shell=False,       # no shell interpretation
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )'''

_SHELL_EXPLANATION = (
    "A command is started through the system shell (cmd.exe on Windows, /bin/sh on "
    "Linux/macOS). The shell treats characters such as ; & | and $( ) as instructions, "
    "not as plain text."
)
_SHELL_IMPACT = (
    "If any part of the command can be influenced by user input or other untrusted data, "
    "an attacker may be able to add their own commands (OS command injection). If the "
    "command is a fixed string that you wrote yourself, the risk is much lower, but the "
    "pattern is still discouraged."
)
_SHELL_RECOMMENDATION = (
    "Do not just swap `subprocess.call` for `subprocess.check_output` or `subprocess.run`: "
    "those still use the shell if `shell=True` is kept. A real fix has four parts: "
    "(1) remove `shell=True`; (2) pass the command as a LIST of separate arguments; "
    "(3) validate or allow-list anything that comes from outside the program; "
    "(4) set a timeout. If you truly need shell features, do them in Python instead."
)

_SECRET_FIX = '''\
import os

password = os.environ.get("APP_PASSWORD")
if not password:
    raise RuntimeError("APP_PASSWORD environment variable is not set")'''

_XML_ENTRY = _entry(
    "warning",
    "Python's built-in XML parsers can be abused with specially crafted XML "
    "(for example entity-expansion attacks) when they process data you do not control.",
    "Parsing untrusted XML with these parsers can use huge amounts of memory or CPU, and "
    "depending on the parser and version may expose local files.",
    "If the XML can come from outside your program, parse it with the `defusedxml` package "
    "(pip install defusedxml). If the XML is always your own trusted data, this is low risk.",
    "import defusedxml.ElementTree as ET\n\ntree = ET.fromstring(xml_text)",
)

_IMPORT_ENTRY = _entry(
    "informational",
    "Bandit flags the import of a module that is often misused. Importing a module is "
    "not a vulnerability.",
    "None by itself. Risk depends on how the module is used elsewhere in the code.",
    "Review how this module is used in the project and look at any other findings that "
    "involve it.",
)

# ------------------------------------------------------------------ the data
KNOWLEDGE_BASE = {
    "B101": _entry(
        "warning",
        "`assert` statements are removed when Python runs with the -O flag, so a check "
        "written with assert can silently disappear in production.",
        "If assert guards authentication, authorization or input validation, that guard "
        "may not run. In test code this finding is usually harmless.",
        "Keep assert for tests and internal sanity checks. For anything security-relevant, "
        "raise an explicit exception.",
        'if not user.is_admin:\n    raise PermissionError("Administrator access required")',
    ),
    "B102": _entry(
        "potential_vulnerability",
        "`exec()` runs a string as Python code.",
        "If any part of that string can be influenced by an outside party, they may be able "
        "to run their own code inside your program. If the string is a constant you wrote, "
        "the risk is much lower.",
        "Avoid exec(). Use ordinary functions, an allow-list of actions, or a data format "
        "such as JSON instead of generating code.",
        _DISPATCH_EXAMPLE,
    ),
    "B103": _entry(
        "warning",
        "A file or folder is given permissions that are very open (for example world-writable).",
        "Other users on the same machine may be able to read or modify the file.",
        "Give files the minimum permissions they need. Owner-only read/write is a good default.",
        "import os\n\nos.chmod(path, 0o600)  # owner can read/write, nobody else",
    ),
    "B104": _entry(
        "warning",
        "The program binds a network socket to all interfaces (0.0.0.0), making it reachable "
        "from other machines.",
        "A service meant for local use only may become reachable from the network.",
        "Bind to 127.0.0.1 for local-only services. If network access is intended, make sure "
        "authentication and a firewall protect it.",
        'server.bind(("127.0.0.1", 8080))',
    ),
    "B105": _entry(
        "warning",
        "A string that looks like a password, token or key is written directly in the source code.",
        "Anyone who can read the code (repository, shared ZIP, leaked backup) can read the "
        "secret. If the value is only a placeholder or test value, this may be a false positive.",
        "Load secrets at run time from environment variables or a secret manager. If this was "
        "a real secret, treat it as exposed: change it, and remove it from version-control history.",
        _SECRET_FIX,
        ["Bandit judges only by variable name and value shape. Confirm whether the value is a real secret."],
    ),
    "B106": None,  # filled below (same guidance as B105)
    "B107": None,
    "B108": _entry(
        "warning",
        "A fixed path in a shared temporary folder (such as /tmp) is used.",
        "Another local user could pre-create or replace that path, tricking the program into "
        "reading or overwriting the wrong file.",
        "Let Python create a unique, private temporary file or folder.",
        'import tempfile\n\nwith tempfile.NamedTemporaryFile("w", delete=False, suffix=".tmp") as tmp:\n'
        '    tmp.write("data")\n    temp_path = tmp.name',
    ),
    "B110": _entry(
        "informational",
        "An exception is caught and silently ignored (`try ... except: pass`).",
        "Errors, including security-relevant ones, can go unnoticed, which makes debugging and "
        "incident investigation harder.",
        "Catch the specific exception you expect and log it, or handle it deliberately.",
        'import logging\n\ntry:\n    do_work()\nexcept ValueError:\n    logging.exception("do_work failed")',
    ),
    "B112": _entry(
        "informational",
        "An exception is caught and the loop silently continues (`except: continue`).",
        "Failures are hidden, which can mask problems or attacks.",
        "Catch specific exceptions and log them.",
        'import logging\n\nfor item in items:\n    try:\n        process(item)\n    except ValueError:\n'
        '        logging.warning("Skipping bad item", exc_info=True)\n        continue',
    ),
    "B113": _entry(
        "warning",
        "An HTTP request is made without a timeout.",
        "If the remote server never answers, the program can hang forever, which can be abused "
        "for denial of service.",
        "Always pass a timeout to network requests.",
        "import requests\n\nresponse = requests.get(url, timeout=10)",
    ),
    "B201": _entry(
        "potential_vulnerability",
        "A Flask app is started with debug=True.",
        "Flask's debugger can let someone who reaches it run Python code on the server, and it "
        "exposes source code and internals in error pages.",
        "Never enable debug mode on a server reachable by others. Control it with configuration "
        "so it is off by default.",
        'import os\n\ndebug_mode = os.environ.get("FLASK_DEBUG") == "1"  # off unless explicitly enabled\n'
        "app.run(debug=debug_mode)",
    ),
    "B202": _entry(
        "potential_vulnerability",
        "`tarfile.extractall()` is used without checking the archive members.",
        "A malicious archive can contain paths like ../../file that write outside the target folder.",
        "Use the `filter=\"data\"` argument (Python 3.12+, and recent security releases of older "
        "versions), or validate every member path yourself.",
        'import tarfile\n\nwith tarfile.open("archive.tar") as tar:\n    tar.extractall(path="output_dir", filter="data")',
    ),
    "B301": _entry(
        "potential_vulnerability",
        "`pickle` can run code while loading data.",
        "Loading a pickle that an attacker can influence can run arbitrary code. Pickle that you "
        "created and stored where only you can modify it is much lower risk.",
        "Never unpickle data from untrusted sources. Use a data-only format such as JSON.",
        'import json\n\nwith open("data.json", "r", encoding="utf-8") as f:\n    data = json.load(f)',
    ),
    "B302": _entry(
        "potential_vulnerability",
        "`marshal` is not designed to be safe with untrusted data.",
        "Loading crafted marshal data can crash the interpreter or behave unpredictably.",
        "Use JSON or another data-only format for anything that crosses a trust boundary.",
        'import json\n\ndata = json.loads(text)',
    ),
    "B303": None,  # filled below (same guidance as B324)
    "B306": _entry(
        "warning",
        "`tempfile.mktemp()` returns a file name without creating the file.",
        "Between choosing the name and using it, another process can create that path first (a race condition).",
        "Use `mkstemp()` or `NamedTemporaryFile()`, which create the file safely.",
        'import os\nimport tempfile\n\nfd, temp_path = tempfile.mkstemp()\nos.close(fd)',
    ),
    "B308": _entry(
        "potential_vulnerability",
        "`mark_safe` tells Django not to escape a value when it is shown in HTML.",
        "If the value contains user input, an attacker may inject JavaScript into the page "
        "(cross-site scripting).",
        "Do not mark user-controlled data as safe. Use `format_html`, which escapes the values you insert.",
        'from django.utils.html import format_html\n\nhtml = format_html("<b>{}</b>", user_value)',
    ),
    "B310": _entry(
        "warning",
        "`urlopen` accepts many URL schemes, including file://, not only http(s).",
        "If the URL comes from a user, they may make the program read local files or contact "
        "internal services (server-side request forgery).",
        "Check the scheme, and ideally the host, against an allow-list before opening the URL, and set a timeout.",
        'from urllib.parse import urlparse\nfrom urllib.request import urlopen\n\n'
        'if urlparse(url).scheme not in ("http", "https"):\n    raise ValueError("Only http(s) URLs are allowed")\n'
        'with urlopen(url, timeout=10) as response:\n    data = response.read()',
        ["For user-supplied URLs also allow-list the host names; checking the scheme alone does not prevent SSRF."],
    ),
    "B311": _entry(
        "informational",
        "`random` is a predictable pseudo-random generator.",
        "It is fine for games and simulations, but unsafe for passwords, tokens or keys because "
        "outputs can be predicted.",
        "Use the `secrets` module for anything security-related.",
        "import secrets\n\ntoken = secrets.token_urlsafe(32)",
    ),
    "B321": _entry(
        "warning",
        "FTP sends data, including passwords, without encryption.",
        "Anyone on the network path can read or modify the transfer.",
        "Use SFTP/SCP, or `ftplib.FTP_TLS` if you must use FTP.",
        "from ftplib import FTP_TLS\n\nftp = FTP_TLS(host)\nftp.login(user, password)\nftp.prot_p()",
    ),
    "B323": _entry(
        "warning",
        "SSL certificate verification is disabled for this context.",
        "The program can be tricked into talking to an impostor server (man-in-the-middle).",
        "Use the default secure context, which verifies certificates.",
        "import ssl\n\ncontext = ssl.create_default_context()",
    ),
    "B324": _entry(
        "warning",
        "A weak hash algorithm (MD5 or SHA-1) is used.",
        "These hashes are broken for security purposes (collisions can be created). Using them "
        "to hash passwords or verify integrity against an attacker is unsafe. Using them only as a "
        "non-security checksum or cache key is generally fine.",
        "Use SHA-256 or stronger for integrity. For PASSWORDS use a slow, salted algorithm "
        "(hashlib.scrypt, or the bcrypt/argon2 packages), never a plain hash.",
        "import hashlib\n\ndigest = hashlib.sha256(data).hexdigest()",
    ),
    "B501": _entry(
        "potential_vulnerability",
        "HTTPS certificate verification is turned off (verify=False).",
        "The connection can be intercepted or modified by an attacker on the network "
        "(man-in-the-middle), even though it appears to use HTTPS.",
        "Remove verify=False. If you use a private certificate authority, point `verify` at its "
        "certificate file instead of disabling the check.",
        'import requests\n\n# verify=True is the default\nresponse = requests.get(url, timeout=10)\n'
        '# private CA: requests.get(url, timeout=10, verify="/path/to/ca.pem")',
    ),
    "B506": _entry(
        "potential_vulnerability",
        "`yaml.load()` can construct arbitrary Python objects from YAML.",
        "Loading untrusted YAML this way can lead to code execution.",
        "Use `yaml.safe_load()`, which only builds simple data types.",
        "import yaml\n\ndata = yaml.safe_load(text)",
    ),
    "B507": _entry(
        "potential_vulnerability",
        "SSH host key verification is disabled.",
        "The program may connect to an impostor server and send it credentials or data.",
        "Load known host keys and reject unknown hosts.",
        "import paramiko\n\nclient = paramiko.SSHClient()\nclient.load_system_host_keys()\n"
        "client.set_missing_host_key_policy(paramiko.RejectPolicy())",
    ),
    "B602": _entry(
        "potential_vulnerability", _SHELL_EXPLANATION, _SHELL_IMPACT,
        _SHELL_RECOMMENDATION, _SHELL_FIX,
    ),
    "B603": _entry(
        "warning",
        "A subprocess is started WITHOUT a shell. This is the safer form.",
        "Bandit flags it because the program or its arguments might come from untrusted data. "
        "If both are fixed or validated, this is usually acceptable.",
        "Make sure the program is fixed, arguments are passed as a list, and any value from "
        "outside is validated against an allow-list. Set a timeout.",
        "import subprocess\nimport sys\n\nresult = subprocess.run(\n    [sys.executable, \"--version\"],\n"
        "    check=True, capture_output=True, text=True, timeout=30,\n)",
    ),
    "B604": _entry(
        "potential_vulnerability", _SHELL_EXPLANATION, _SHELL_IMPACT,
        _SHELL_RECOMMENDATION, _SHELL_FIX,
    ),
    "B605": _entry(
        "potential_vulnerability",
        "A process is started through a shell (for example with `os.system`).",
        _SHELL_IMPACT, _SHELL_RECOMMENDATION, _SHELL_FIX,
    ),
    "B606": _entry(
        "warning",
        "A process is started without a shell using an os.exec*/os.spawn* function.",
        "Risk depends on whether the program path or arguments can be influenced by untrusted data.",
        "Prefer `subprocess.run` with an argument list, a fixed program, and validated arguments.",
        "",
    ),
    "B607": _entry(
        "warning",
        "A program is started using only its name (a partial path), so the system searches PATH for it.",
        "If an attacker can influence PATH or place a program earlier in it, a different program may run.",
        "Resolve and use a full path to the program.",
        "import shutil\nimport subprocess\n\ngit_path = shutil.which(\"git\")\nif git_path is None:\n"
        "    raise FileNotFoundError(\"git not found\")\nsubprocess.run([git_path, \"status\"], check=True, timeout=30)",
        ["A fixed absolute path in a trusted install location is safer than any PATH search."],
    ),
    "B608": _entry(
        "potential_vulnerability",
        "An SQL query is built by joining strings together.",
        "If any inserted value comes from a user, they may be able to change the meaning of the "
        "query (SQL injection) and read or alter data.",
        "Use parameterized queries: the database driver sends values separately from the SQL text.",
        'cursor.execute("SELECT * FROM users WHERE name = ?", (username,))',
        ["The placeholder style depends on the driver: ? for sqlite3, %s for psycopg2 and MySQL drivers.",
         "Table and column names cannot be parameters; allow-list them instead."],
    ),
    "B609": _entry(
        "warning",
        "A command is run with a wildcard (*), which the shell expands into file names.",
        "File names that look like command options can change what the command does (wildcard injection).",
        "Expand files in Python with `glob` and pass them as a list after `--`, without a shell.",
        "import glob\nimport subprocess\n\nfiles = glob.glob(\"*.txt\")\nsubprocess.run([\"tar\", \"-cf\", \"out.tar\", \"--\", *files], check=True, timeout=60)",
    ),
    "B610": _entry(
        "potential_vulnerability",
        "Django's `.extra()` is used and may include unescaped SQL.",
        "If user input reaches that SQL text, SQL injection is possible.",
        "Use the ORM's normal filters, or pass values separately as parameters.",
        'Model.objects.raw("SELECT * FROM app_model WHERE name = %s", [name])',
    ),
    "B611": _entry(
        "potential_vulnerability",
        "Django's `RawSQL` is used and may include unescaped SQL.",
        "If user input reaches that SQL text, SQL injection is possible.",
        "Pass values as parameters instead of formatting them into the SQL.",
        'RawSQL("SELECT id FROM app_model WHERE name = %s", [name])',
    ),
    "B701": _entry(
        "potential_vulnerability",
        "A Jinja2 environment is created without automatic HTML escaping.",
        "If user input is rendered into HTML templates, an attacker may inject JavaScript (cross-site scripting).",
        "Enable autoescaping.",
        "from jinja2 import Environment, select_autoescape\n\nenv = Environment(autoescape=select_autoescape())",
    ),
    "B702": _entry(
        "warning",
        "Mako templates do not escape HTML by default.",
        "User input rendered into HTML may allow cross-site scripting.",
        "Apply the `h` (HTML-escape) filter by default, or per expression with `${value | h}`.",
        "from mako.template import Template\n\ntemplate = Template(text, default_filters=[\"h\"])",
    ),
    "B703": None,  # filled below (same as B308)
}

# Entries that share guidance with another one.
KNOWLEDGE_BASE["B106"] = KNOWLEDGE_BASE["B105"]
KNOWLEDGE_BASE["B107"] = KNOWLEDGE_BASE["B105"]
KNOWLEDGE_BASE["B303"] = KNOWLEDGE_BASE["B324"]
KNOWLEDGE_BASE["B703"] = KNOWLEDGE_BASE["B308"]

KNOWLEDGE_BASE["B307"] = _entry(
    "potential_vulnerability",
    "`eval()` runs a string as a Python expression.",
    "If any part of that string can be influenced by an outside party, they may be able to run "
    "their own code inside your program. If the string is a constant you wrote, the risk is much "
    "lower. Bandit cannot tell which case this is.",
    "Decide what the code really needs. (1) If the input should only be a Python LITERAL (number, "
    "string, list, dict...), `ast.literal_eval()` is a reasonable replacement, but it ONLY parses "
    "literals: it cannot evaluate expressions or run commands, so it is not a drop-in fix for "
    "everything. (2) If the input names an action to perform, use an allow-list of actions "
    "(example below). (3) If you need arithmetic, use a dedicated expression parser. Do not try "
    "to 'clean' eval() input with filters; that is easy to bypass.",
    _DISPATCH_EXAMPLE,
)

KNOWLEDGE_BASE["B404"] = _entry(
    "informational",
    "The `subprocess` module lets a program start other programs. Bandit flags the import so "
    "you remember to review how it is used.",
    "None by itself. Risk comes from HOW subprocess is called (see findings such as B602 or B603).",
    "Review each subprocess call: avoid shell=True, pass arguments as a list, and validate anything "
    "that comes from outside. The import is not something to 'fix', and replacing `subprocess.call` "
    "with `subprocess.run` does not by itself make anything safer.",
)

for _xml_id in ("B313", "B314", "B315", "B316", "B317", "B318", "B319", "B320"):
    KNOWLEDGE_BASE[_xml_id] = _XML_ENTRY
for _import_id in ("B401", "B402", "B403", "B405", "B406", "B407", "B408", "B409",
                   "B410", "B411", "B412", "B413", "B415"):
    KNOWLEDGE_BASE[_import_id] = _IMPORT_ENTRY


def get_guidance(test_id: str, bandit_description: str = "",
                 severity: str = "", confidence: str = "") -> dict:
    """Return guidance for a Bandit test ID (a fresh dict, safe to modify)."""
    entry = KNOWLEDGE_BASE.get(test_id)

    if entry is None:
        guidance = {
            "curated": False,
            "category": "warning",
            "explanation": bandit_description or "Bandit reported this pattern.",
            "impact": "No curated guidance exists for this test ID, so the impact is not described here.",
            "recommendation": (
                "Open the Bandit documentation link for this test ID and decide based on how "
                "this code is actually used."
            ),
            "fixed_code": "",
            "notes": [],
        }
    else:
        guidance = dict(entry)
        guidance["curated"] = True
        guidance["notes"] = list(entry["notes"])

    guidance["category_label"] = CATEGORY_LABELS[guidance["category"]]

    # Context-aware notes derived from Bandit's own ratings.
    if test_id in ("B602", "B604") and severity == "LOW":
        guidance["notes"].append(
            "Bandit rated this LOW, which for shell=True usually means the command is a fixed string "
            "rather than a variable. Avoiding the shell is still the better practice."
        )
    if confidence == "LOW":
        guidance["notes"].append(
            "Bandit's confidence for this finding is LOW, so it has a higher chance of being a false positive."
        )
    return guidance
