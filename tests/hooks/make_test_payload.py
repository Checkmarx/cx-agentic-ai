"""Prints mock Copilot CLI PreToolUse stdin payloads for manual gate testing.
Usage:
    python tests/hooks/make_test_payload.py bootstrap   # bootstrap install → should ALLOW
    python tests/hooks/make_test_payload.py npm         # npm test → should DENY
    python tests/hooks/make_test_payload.py glob        # glob tool → should DENY
    python tests/hooks/make_test_payload.py create      # file create → should DENY
    python tests/hooks/make_test_payload.py auth        # cx auth login → DENY (below min) / ALLOW (ok cx)
"""
import json, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../plugins/copilot-devassist/hooks'))
import cx_check

BS = cx_check._bootstrap_script_path().replace('\\', '/')

PAYLOADS = {
    'bootstrap': {'name': 'powershell', 'args': {'command': 'bash "%s" install' % BS}},
    'npm':       {'name': 'powershell', 'args': {'command': 'npm test'}},
    'glob':      {'name': 'glob',       'args': {'pattern': '**/*.java'}},
    'create':    {'name': 'create',     'args': {'file_path': '/src/X.java', 'content': 'x=1'}},
    'auth':      {'name': 'powershell', 'args': {'command': 'cx auth login'}},
}

key = sys.argv[1] if len(sys.argv) > 1 else 'npm'
if key not in PAYLOADS:
    print('Unknown key. Choose: ' + ', '.join(PAYLOADS), file=sys.stderr)
    sys.exit(1)

p = PAYLOADS[key]
payload = {
    'sessionId': 'manual-test',
    'cwd': 'C:/workspace',
    'toolCalls': [{'id': 'toolu_test', 'name': p['name'], 'args': json.dumps(p['args'])}]
}
print(json.dumps(payload))
