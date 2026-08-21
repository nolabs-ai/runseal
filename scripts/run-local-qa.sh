#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="${RUNSEAL_QA_LAB:-$HOME/runseal-lab/project}"
HTTP_DIR="/tmp/runseal-api"
TLS_DIR="/tmp/runseal-tls"

PASS=0
FAIL=0
HTTP_PID=""
TLS_PID=""

log() { printf '\n==> %s\n' "$*"; }
pass() { printf 'PASS %s\n' "$*"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL %s\n' "$*"; FAIL=$((FAIL + 1)); }

cleanup() {
    [[ -n "${HTTP_PID}" ]] && kill "${HTTP_PID}" 2>/dev/null || true
    [[ -n "${TLS_PID}" ]] && kill "${TLS_PID}" 2>/dev/null || true
}
trap cleanup EXIT

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 2
    fi
}

print_landlock_abi() {
    python3 - <<'PY'
import ctypes
import os
import platform

if platform.system() != 'Linux':
    print('Landlock ABI: skipped (non-Linux host)')
    raise SystemExit(0)

SYS_landlock_create_ruleset = 444
LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
libc = ctypes.CDLL('libc.so.6', use_errno=True)
libc.syscall.restype = ctypes.c_long

try:
    abi = libc.syscall(
        SYS_landlock_create_ruleset,
        None,
        0,
        LANDLOCK_CREATE_RULESET_VERSION,
    )
except Exception as exc:
    print(f'Landlock ABI: unavailable ({exc})')
    raise SystemExit(0)

if abi < 0:
    err = ctypes.get_errno()
    if err == 38:
        print('Landlock ABI: unavailable (ENOSYS)')
    else:
        print(f'Landlock ABI: unavailable (errno={err} {os.strerror(err)})')
else:
    print(f'Landlock ABI version: {abi}')
PY
}

start_http_server() {
    mkdir -p "${HTTP_DIR}"
    rm -f "${HTTP_DIR}/last-request.txt"
    python3 - <<'PY' &
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

OUT = Path('/tmp/runseal-api/last-request.txt')

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.record()
        self.respond_ok()

    def do_POST(self):
        self.record()
        self.respond_ok()

    def respond_ok(self):
        body = b'ok\n'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = True

    def record(self):
        OUT.write_text(
            f'{self.command} {self.path}\n'
            f'Authorization: {self.headers.get("Authorization", "")}\n'
            f'Host: {self.headers.get("Host", "")}\n'
        )

    def log_message(self, format, *args):
        pass

HTTPServer(('127.0.0.1', 18080), Handler).serve_forever()
PY
    HTTP_PID=$!
    sleep 0.3
}

prepare_tls_certs() {
    mkdir -p "${TLS_DIR}"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${TLS_DIR}/ca-key.pem" \
        -out "${TLS_DIR}/ca.pem" \
        -days 1 \
        -subj '/CN=Runseal Test CA' \
        -addext 'basicConstraints=critical,CA:TRUE' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1

    openssl req -newkey rsa:2048 -nodes \
        -keyout "${TLS_DIR}/key.pem" \
        -out "${TLS_DIR}/server.csr" \
        -subj '/CN=api.runseal.test' \
        -addext 'subjectAltName=DNS:api.runseal.test' >/dev/null 2>&1

    cat > "${TLS_DIR}/server-ext.cnf" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:api.runseal.test
EOF

    openssl x509 -req \
        -in "${TLS_DIR}/server.csr" \
        -CA "${TLS_DIR}/ca.pem" \
        -CAkey "${TLS_DIR}/ca-key.pem" \
        -CAcreateserial \
        -out "${TLS_DIR}/cert.pem" \
        -days 1 \
        -extfile "${TLS_DIR}/server-ext.cnf" >/dev/null 2>&1
}

start_tls_server() {
    rm -f "${TLS_DIR}/last-request.txt"
    python3 - <<'PY' &
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import ssl

OUT = Path('/tmp/runseal-tls/last-request.txt')

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.record()
        self.respond_ok()

    def do_POST(self):
        self.record()
        self.respond_ok()

    def respond_ok(self):
        body = b'ok\n'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = True

    def record(self):
        OUT.write_text(
            f'{self.command} {self.path}\n'
            f'Authorization: {self.headers.get("Authorization", "")}\n'
            f'Host: {self.headers.get("Host", "")}\n'
        )

    def log_message(self, format, *args):
        pass

server = HTTPServer(('127.0.0.1', 18443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/tmp/runseal-tls/cert.pem', '/tmp/runseal-tls/key.pem')
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
    TLS_PID=$!
    sleep 0.3
}

setup_lab() {
    mkdir -p "${LAB}/dist"
    cd "${LAB}"
    printf 'allowed\n' > allowed.txt
    printf 'blocked\n' > blocked.txt
    rm -f new-file.txt dist/result.txt /tmp/runseal-example.html
}

require_cmd cargo
require_cmd curl
require_cmd nono
require_cmd openssl
require_cmd python3

if ! grep -q 'struct AccessInput' "${ROOT}/src/config.rs" || ! grep -q 'allow: Vec<String>' "${ROOT}/src/config.rs"; then
    cat >&2 <<'EOF'
Runseal source is missing `access` policy support required by this QA harness.
Update src/config.rs, src/profile.rs, and src/secrets.rs before running scripts/run-local-qa.sh.
EOF
    exit 2
fi

log "building runseal"
(cd "${ROOT}" && cargo clean -p runseal >/dev/null && cargo build --release >/dev/null)
RUNSEAL_BIN="${ROOT}/target/release/runseal"

log "versions"
nono --version
"${RUNSEAL_BIN}" --version
print_landlock_abi

setup_lab

log "filesystem and network scenarios"
if (cd "${LAB}" && RUNSEAL_RUN='printf "hello\n"' RUNSEAL_POLICY=$'fs:\n  read: ["."]\n  write: []\nnetwork:\n  mode: blocked\n' "${RUNSEAL_BIN}" run >/tmp/runseal-qa.out 2>&1) && grep -q '^hello$' /tmp/runseal-qa.out; then pass "basic command"; else cat /tmp/runseal-qa.out; fail "basic command"; fi

if (cd "${LAB}" && RUNSEAL_RUN="cat '${LAB}/allowed.txt'" RUNSEAL_POLICY=$'fs:\n  read: ["./allowed.txt"]\n  write: []\nnetwork:\n  mode: blocked\n' "${RUNSEAL_BIN}" run >/tmp/runseal-qa.out 2>&1) && grep -q '^allowed$' /tmp/runseal-qa.out; then pass "single file read allowed"; else cat /tmp/runseal-qa.out; fail "single file read allowed"; fi

if (cd "${LAB}" && RUNSEAL_RUN='cat blocked.txt' RUNSEAL_POLICY=$'fs:\n  read: ["./allowed.txt"]\n  write: []\nnetwork:\n  mode: blocked\n' "${RUNSEAL_BIN}" run >/tmp/runseal-qa.out 2>&1); then cat /tmp/runseal-qa.out; fail "read denied"; else pass "read denied"; fi

rm -f "${LAB}/new-file.txt"
if (cd "${LAB}" && RUNSEAL_RUN='echo nope > ./new-file.txt' RUNSEAL_POLICY=$'fs:\n  read: ["."]\n  write: []\nnetwork:\n  mode: blocked\n' "${RUNSEAL_BIN}" run >/tmp/runseal-qa.out 2>&1); then cat /tmp/runseal-qa.out; fail "write denied"; elif [[ ! -e "${LAB}/new-file.txt" ]]; then pass "write denied"; else fail "write denied"; fi

if (cd "${LAB}" && RUNSEAL_RUN='echo ok > ./dist/result.txt' RUNSEAL_POLICY=$'fs:\n  read: ["."]\n  write: ["./dist"]\nnetwork:\n  mode: blocked\n' "${RUNSEAL_BIN}" run >/tmp/runseal-qa.out 2>&1) && grep -q '^ok$' "${LAB}/dist/result.txt"; then pass "directory write allowed"; else cat /tmp/runseal-qa.out; fail "directory write allowed"; fi

if (cd "${LAB}" && RUNSEAL_RUN='curl -fsS https://example.com' RUNSEAL_POLICY=$'fs:\n  read: ["."]\n  write: []\nnetwork:\n  mode: blocked\n' "${RUNSEAL_BIN}" run >/tmp/runseal-qa.out 2>&1); then cat /tmp/runseal-qa.out; fail "network blocked"; else pass "network blocked"; fi

if (cd "${LAB}" && RUNSEAL_RUN='curl -fsS https://example.com >/tmp/runseal-example.html' RUNSEAL_POLICY=$'fs:\n  read: ["."]\n  write: ["/tmp"]\nnetwork:\n  mode: filtered\n  allow:\n    - example.com\n' "${RUNSEAL_BIN}" run >/tmp/runseal-qa.out 2>&1) && [[ -s /tmp/runseal-example.html ]]; then pass "network allowlist"; else cat /tmp/runseal-qa.out; fail "network allowlist"; fi

log "secret environment scenarios"
# The sandboxed command receives a phantom credential on the original env
# var (for SDK compatibility, see README.md), not an empty value -- assert
# the real secret never appears, matching the "http credential injection"
# check below.
if (cd "${LAB}" && API_TOKEN='real-secret-value' RUNSEAL_RUN='printf "API_TOKEN=<%s>\n" "$API_TOKEN"' RUNSEAL_POLICY=$'fs:\n  read: ["."]\n  write: []\nnetwork:\n  mode: filtered\naccess:\n  api:\n    secret: API_TOKEN\n    url: https://example.com\n    allow:\n      - GET /**\n' "${RUNSEAL_BIN}" run >/tmp/runseal-qa.out 2>&1) && ! grep -q 'API_TOKEN=<real-secret-value>' /tmp/runseal-qa.out; then pass "secret stripped from env"; else cat /tmp/runseal-qa.out; fail "secret stripped from env"; fi

log "HTTP credential injection and L7 scenarios"
start_http_server

if (cd "${LAB}" && API_TOKEN='real-secret-value' RUNSEAL_RUN='printf "API_TOKEN=<%s>\n" "$API_TOKEN"; curl -fsS -H "Authorization: Bearer ${API_TOKEN}" "${API_BASE_URL}/v1/allowed"' RUNSEAL_POLICY=$'fs:\n  read: ["."]\n  write: []\nnetwork:\n  mode: filtered\naccess:\n  api:\n    secret: API_TOKEN\n    url: http://127.0.0.1:18080\n    allow:\n      - GET /v1/allowed\n' "${RUNSEAL_BIN}" run >/tmp/runseal-qa.out 2>&1) && ! grep -q 'API_TOKEN=<real-secret-value>' /tmp/runseal-qa.out && grep -q 'Authorization: Bearer real-secret-value' "${HTTP_DIR}/last-request.txt"; then pass "http credential injection"; else cat /tmp/runseal-qa.out; [[ -f "${HTTP_DIR}/last-request.txt" ]] && cat "${HTTP_DIR}/last-request.txt"; fail "http credential injection"; fi

rm -f "${HTTP_DIR}/last-request.txt"
if (cd "${LAB}" && API_TOKEN='real-secret-value' RUNSEAL_RUN='curl -fsS -H "Authorization: Bearer ${API_TOKEN}" "${API_BASE_URL}/v1/denied"' RUNSEAL_POLICY=$'fs:\n  read: ["."]\n  write: []\nnetwork:\n  mode: filtered\naccess:\n  api:\n    secret: API_TOKEN\n    url: http://127.0.0.1:18080\n    allow:\n      - GET /v1/allowed\n' "${RUNSEAL_BIN}" run >/tmp/runseal-qa.out 2>&1); then cat /tmp/runseal-qa.out; fail "http l7 denied path"; elif [[ ! -e "${HTTP_DIR}/last-request.txt" ]]; then pass "http l7 denied path"; else cat "${HTTP_DIR}/last-request.txt"; fail "http l7 denied path"; fi

log "TLS credential injection scenario"
if ! grep -q 'api.runseal.test' /etc/hosts; then
    echo "127.0.0.1 api.runseal.test" | sudo tee -a /etc/hosts >/dev/null
fi
prepare_tls_certs
start_tls_server

rm -f "${TLS_DIR}/last-request.txt"
if (cd "${LAB}" && API_TOKEN='real-secret-value' RUNSEAL_RUN='printf "API_TOKEN=<%s>\n" "$API_TOKEN"; rc=0; curl -fsS -H "Authorization: Bearer ${API_TOKEN}" "${API_BASE_URL}/v1/allowed" || rc=$?; if [ "$rc" -ne 0 ] && [ "$rc" -ne 56 ]; then exit "$rc"; fi' RUNSEAL_POLICY=$'fs:\n  read: ["."]\n  write: []\nnetwork:\n  mode: filtered\naccess:\n  api:\n    secret: API_TOKEN\n    url: https://api.runseal.test:18443\n    tls_ca: /tmp/runseal-tls/ca.pem\n    allow:\n      - GET /v1/allowed\n' "${RUNSEAL_BIN}" run >/tmp/runseal-qa.out 2>&1) && ! grep -q 'API_TOKEN=<real-secret-value>' /tmp/runseal-qa.out && grep -q 'Authorization: Bearer real-secret-value' "${TLS_DIR}/last-request.txt"; then pass "tls credential injection"; else cat /tmp/runseal-qa.out; [[ -f "${TLS_DIR}/last-request.txt" ]] && cat "${TLS_DIR}/last-request.txt"; fail "tls credential injection"; fi

log "summary"
printf 'passed=%s failed=%s\n' "${PASS}" "${FAIL}"
if [[ "${FAIL}" -ne 0 ]]; then
    exit 1
fi
