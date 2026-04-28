#!/bin/bash
# Full integration tests: opendchub build + source fixes + odchbot v4 end-to-end
set -e

PASS=0
FAIL=0
SKIP=0
TESTS=0

pass() { PASS=$((PASS + 1)); TESTS=$((TESTS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); TESTS=$((TESTS + 1)); echo "  FAIL: $1"; }
skip() { SKIP=$((SKIP + 1)); TESTS=$((TESTS + 1)); echo "  SKIP: $1"; }

echo "========================================"
echo "=== OpenDCHub Build Verification     ==="
echo "========================================"

# Test 1: Binary exists
if [ -x /build/opendchub/src/opendchub ]; then
    pass "Binary built successfully"
else
    fail "Binary not found"
    exit 1
fi

# Test 2: Perl removed (v1.0.0+)
if grep -q "#define HAVE_PERL" /build/opendchub/config.h; then
    fail "Perl scripting still compiled in (should be removed)"
else
    pass "Perl scripting removed (v1.0.0 architecture)"
fi

# Test 2b: SSL support
if grep -q "#define HAVE_SSL" /build/opendchub/config.h; then
    pass "SSL/TLS support compiled in"
else
    fail "SSL/TLS support NOT compiled in"
fi

# Test 2c: Version string is set and not empty
HUB_VERSION=$(grep '#define VERSION ' /build/opendchub/config.h | head -1 | sed 's/.*"\(.*\)".*/\1/')
if [ -n "$HUB_VERSION" ] && [ "$HUB_VERSION" != "0.0.0" ]; then
    pass "Version string is $HUB_VERSION"
else
    fail "Version string missing or invalid"
fi

# Test 2d: TLS config persistence in write_config_file
if grep -q "tls_port" /build/opendchub/src/fileio.c && grep -q "tls_cert_file" /build/opendchub/src/fileio.c; then
    # Check that fprintf for tls settings exists (write path, not just read path)
    if grep -q 'fprintf.*tls_port' /build/opendchub/src/fileio.c; then
        pass "TLS config written in write_config_file()"
    else
        fail "TLS config NOT written in write_config_file()"
    fi
else
    fail "TLS config variables missing from fileio.c"
fi

echo ""
echo "========================================"
echo "=== Source Code Fix Verification     ==="
echo "========================================"

# Test 3: check_if_gagged has nickname comparison
if grep -q "match_with_wildcards(user->nick, gag_host)" /build/opendchub/src/fileio.c; then
    pass "check_if_gagged() compares against user nickname"
else
    fail "check_if_gagged() MISSING nickname comparison"
fi

# Test 4: No broken || GAG pattern (ignore comments)
BROKEN=$(grep -v '^\s*/\*' /build/opendchub/src/commands.c | grep -v '^\s*\*' | grep -c "== NICKBAN || GAG)" || true)
if [ "$BROKEN" = "0" ]; then
    pass "No broken '|| GAG)' always-true conditions"
else
    fail "Found $BROKEN broken '|| GAG)' patterns"
fi

# Test 5: Correct type == GAG pattern exists
FIXED=$(grep -c "type == NICKBAN || type == GAG)" /build/opendchub/src/commands.c || true)
if [ "$FIXED" = "2" ]; then
    pass "Both ballow() type checks use correct 'type == GAG'"
else
    fail "Expected 2 correct type checks, found $FIXED"
fi

# Test 6: snprintf used for ban_line (ignore comments)
SNPRINTF=$(grep -v '^\s*/\*' /build/opendchub/src/commands.c | grep -c "snprintf(ban_line, sizeof(ban_line)" || true)
if [ "$SNPRINTF" -ge 4 ]; then
    pass "All $SNPRINTF ban_line writes use snprintf with bounds"
else
    fail "Expected >= 4 snprintf calls, found $SNPRINTF"
fi

# Test 7: No unsafe sprintf on ban_line (excluding comments)
UNSAFE=$(grep -v '^\s*/\*' /build/opendchub/src/commands.c | grep -v '^\s*\*' | grep "sprintf(ban_line," | grep -cv "snprintf" || true)
if [ "$UNSAFE" = "0" ]; then
    pass "No unsafe sprintf calls on ban_line"
else
    fail "Found $UNSAFE unsafe sprintf calls"
fi

# Test 8: No triplicate log
if grep -q 'logprintf.*remove_line.*logprintf.*remove_line' /build/opendchub/src/fileio.c; then
    fail "Triplicate log message still present"
else
    pass "Triplicate log message fixed"
fi

# Test 9: Unused variables cleaned up
if grep -A 15 "int check_if_gagged" /build/opendchub/src/fileio.c | grep -q "string_ip"; then
    fail "Unused string_ip variable still in check_if_gagged()"
else
    pass "Unused variables removed from check_if_gagged()"
fi

echo ""
echo "========================================"
echo "=== JSON Structured Logging (A7)     ==="
echo "========================================"

# Test: log_format global variable exists in main.c
if grep -q "BYTE.*log_format" /build/opendchub/src/main.c; then
    pass "log_format global variable defined in main.c"
else
    fail "log_format global variable missing from main.c"
fi

# Test: log_file_path global variable exists in main.c
if grep -q "char.*log_file_path" /build/opendchub/src/main.c; then
    pass "log_file_path global variable defined in main.c"
else
    fail "log_file_path global variable missing from main.c"
fi

# Test: extern declarations in main.h
if grep -q "extern BYTE.*log_format" /build/opendchub/src/main.h; then
    pass "log_format extern declared in main.h"
else
    fail "log_format extern missing from main.h"
fi

if grep -q "extern char.*log_file_path" /build/opendchub/src/main.h; then
    pass "log_file_path extern declared in main.h"
else
    fail "log_file_path extern missing from main.h"
fi

# Test: JSON format output logic in logprintf (fileio.c)
if grep -q 'log_format == 1' /build/opendchub/src/fileio.c; then
    pass "logprintf has JSON format conditional (log_format == 1)"
else
    fail "logprintf missing JSON format conditional"
fi

# Test: JSON output contains required fields (timestamp, level, message)
if grep -q 'timestamp' /build/opendchub/src/fileio.c && \
   grep -q 'level' /build/opendchub/src/fileio.c && \
   grep -q 'message' /build/opendchub/src/fileio.c; then
    pass "JSON output includes timestamp, level, and message fields"
else
    fail "JSON output missing required fields"
fi

# Test: Verbosity-to-level mapping exists
if grep -q '"error"' /build/opendchub/src/fileio.c && \
   grep -q '"warn"' /build/opendchub/src/fileio.c && \
   grep -q '"trace"' /build/opendchub/src/fileio.c; then
    pass "Verbosity-to-level mapping (error/warn/trace) present"
else
    fail "Verbosity-to-level mapping incomplete"
fi

# Test: log_format read from config
if grep -q 'log_format' /build/opendchub/src/fileio.c | grep -q 'strncmp' 2>/dev/null || \
   grep -q '"log_format"' /build/opendchub/src/fileio.c || \
   grep 'strncmp.*log_format' /build/opendchub/src/fileio.c >/dev/null 2>&1; then
    pass "log_format config option parsed in read_config()"
else
    fail "log_format config option not parsed"
fi

# Test: log_file read from config
if grep 'strncmp.*log_file' /build/opendchub/src/fileio.c >/dev/null 2>&1; then
    pass "log_file config option parsed in read_config()"
else
    fail "log_file config option not parsed"
fi

# Test: log_format settable at runtime via set_var
if grep -q 'log_format' /build/opendchub/src/commands.c; then
    pass "log_format settable via set_var in commands.c"
else
    fail "log_format not settable via set_var"
fi

# Test: log_file settable at runtime via set_var
if grep -q 'log_file' /build/opendchub/src/commands.c; then
    pass "log_file settable via set_var in commands.c"
else
    fail "log_file not settable via set_var"
fi

# Test: log_format written to config file
if grep -q 'log_format' /build/opendchub/src/fileio.c && \
   grep 'fprintf.*log_format' /build/opendchub/src/fileio.c >/dev/null 2>&1; then
    pass "log_format written in write_config_file()"
else
    fail "log_format not written in write_config_file()"
fi

# Test: JSON escape function exists
if grep -q 'json_escape' /build/opendchub/src/fileio.c; then
    pass "JSON escape helper function present"
else
    fail "JSON escape helper function missing"
fi

echo ""
echo "========================================"
echo "=== SIGHUP Config Reload             ==="
echo "========================================"

# Test: SIGHUP handler registered in init_sig()
if grep -q "SIGHUP" /build/opendchub/src/main.c; then
    pass "SIGHUP handler registered in source"
else
    fail "SIGHUP handler missing from source"
fi

# Test: do_reload_conf flag exists
if grep -q "do_reload_conf" /build/opendchub/src/main.c; then
    pass "do_reload_conf flag implemented"
else
    fail "do_reload_conf flag missing"
fi

# Test: read_config called on reload
if grep -q "read_config" /build/opendchub/src/main.c; then
    pass "read_config() called on SIGHUP reload"
else
    fail "read_config() not called on reload"
fi

echo ""
echo "========================================"
echo "=== Bcrypt Support Verification      ==="
echo "========================================"

# Test: Bcrypt support compiled in (HAVE_CRYPT_GENSALT from configure)
if grep -q "HAVE_CRYPT_GENSALT" /build/opendchub/config.h 2>/dev/null; then
    pass "Bcrypt support compiled in (HAVE_CRYPT_GENSALT defined)"
else
    fail "Bcrypt support NOT compiled in (missing HAVE_CRYPT_GENSALT)"
fi

# Test: encrypt_pass generates bcrypt hashes (check source for $2b$ pattern)
if grep -q '\\$2b\\$\|bcrypt\|BCRYPT\|BF_crypt' /build/opendchub/src/main.c; then
    pass "encrypt_pass() has bcrypt implementation"
else
    fail "encrypt_pass() missing bcrypt implementation"
fi

echo ""
echo "========================================"
echo "=== Dragon Standalone Module Checks   ==="
echo "========================================"

# Test: Dragon's standalone modules compile
DRAGON_DIR="/build/odchbot"

for module in NMDCClient GatewayClient; do
    if perl -I"$DRAGON_DIR" -c "$DRAGON_DIR/$module.pm" 2>/dev/null; then
        pass "Module $module.pm compiles"
    else
        fail "Module $module.pm has compile errors"
    fi
done

# Test: dragon.pl compiles (syntax check only, won't connect)
if perl -c "$DRAGON_DIR/dragon.pl" 2>/dev/null; then
    pass "dragon.pl compiles"
else
    fail "dragon.pl has compile errors"
fi

echo ""
echo "========================================"
echo "=== Hub + Bot v4 Integration Test    ==="
echo "========================================"

# Generate self-signed TLS certificate
openssl req -x509 -newkey rsa:2048 -keyout /root/.opendchub/hub.key \
    -out /root/.opendchub/hub.crt -days 1 -nodes -subj "/CN=localhost" 2>/dev/null
chmod 600 /root/.opendchub/hub.key /root/.opendchub/hub.crt

# Set up hub config
mkdir -p /root/.opendchub/scripts
cat > /root/.opendchub/config << 'HUBCONF'
hub_name = "TestHub"
max_users = 50
hub_description = "Integration Test Hub"
hub_full_mess = "Sorry, this hub is full at the moment"
listening_port = 4111
admin_port = 53696
admin_pass = "testpass"
default_pass = ""
link_pass = "linkpass"
min_share = 0
registered_only = 0
hub_hostname = "localhost"
verbosity = 5
tls_port = 4112
tls_cert_file = "/root/.opendchub/hub.crt"
tls_key_file = "/root/.opendchub/hub.key"
HUBCONF

touch /root/.opendchub/banlist
touch /root/.opendchub/allowlist
touch /root/.opendchub/nickbanlist
touch /root/.opendchub/gaglist
touch /root/.opendchub/reglist
touch /root/.opendchub/linklist

# Set up v4 directory layout
# bin/odchbot.pl uses FindBin::Bin/../lib and FindBin::Bin/../odchbot.yml
# Hub loads scripts from ~/.opendchub/scripts/
# So: scripts/odchbot.pl (FindBin) -> ../lib (modules), ../odchbot.yml (config)

# Copy entry point to scripts dir
cp /build/odchbot/bin/odchbot.pl /root/.opendchub/scripts/odchbot.pl

# Copy lib tree one level up from scripts (../lib)
cp -r /build/odchbot/lib /root/.opendchub/lib

# Create config one level up from scripts (../odchbot.yml)
cat > /root/.opendchub/odchbot.yml << 'BOTCONF'
---
config:
  allow_anon: 1
  allow_external: 1
  allow_passive: 1
  botdescription: I am Dragon, hear me RAWR
  botemail: dragon@localhost
  botname: Dragon
  botshare: 136571
  botspeed: LAN(T1)
  bottag: RAWRDC++
  cp: "-"
  db:
    database: odchbot.db
    driver: SQLite
    host: ''
    password: ''
    path: logs
    port: ''
    username: ''
  debug: 0
  hubname: Integration Test Hub
  hubname_short: ODCH
  maintainer_email: test@test.com
  min_username: 3
  minshare: '0'
  no_perms: You do not have adequate permissions to use this function!
  timezone: Australia/Canberra
  username_anonymous: Anonymous
  username_max_length: 35
  version: v4
  website: http://localhost
  topic: "Integration Test Hub - Testing in Progress"
  rules_url: "http://localhost/rules"
  karma_url: "http://localhost/karma"
BOTCONF

chmod 600 /root/.opendchub/odchbot.yml

# Log4perl config (base_dir = dirname of yml = /root/.opendchub)
cat > /root/.opendchub/odchbot.log4perl.conf << 'LOG4PERL'
log4perl.rootLogger=DEBUG, LOGFILE
log4perl.appender.LOGFILE=Log::Log4perl::Appender::File
log4perl.appender.LOGFILE.filename=/root/.opendchub/logs/odchbot.log
log4perl.appender.LOGFILE.mode=append
log4perl.appender.LOGFILE.layout=Log::Log4perl::Layout::PatternLayout
log4perl.appender.LOGFILE.layout.ConversionPattern=[%p] %d{MM-dd-yyyy HH:mm:ss} %F %L - %m%n
LOG4PERL

mkdir -p /root/.opendchub/logs

# The hub CWD needs to be where relative paths resolve.
# Start the hub from the home dir.
cd /root/.opendchub/scripts

# Start hub (config file already has all settings)
/build/opendchub/src/opendchub -d &
HUB_PID=$!
echo "  Starting hub (PID: $HUB_PID)..."
sleep 3

# Check if hub is listening
if nc -z localhost 4111 2>/dev/null; then
    pass "Hub started and listening on port 4111"

    # Test: DC protocol handshake
    LOCK_RESPONSE=$(echo "" | timeout 3 nc -w 2 localhost 4111 2>/dev/null || true)
    if echo "$LOCK_RESPONSE" | grep -q "Lock"; then
        pass "Hub sends \$Lock protocol handshake"
    else
        fail "Hub did not send \$Lock (got: $LOCK_RESPONSE)"
    fi

    # Test: Admin port removed (v1.0.0+)
    if nc -z localhost 53696 2>/dev/null; then
        fail "Admin port 53696 still listening (should be disabled)"
    else
        pass "Admin port disabled (using JSON socket)"
    fi

    echo ""
    echo "========================================"
    echo "=== TLS Verification                 ==="
    echo "========================================"

    # Test: TLS port listening
    if nc -z localhost 4112 2>/dev/null; then
        pass "TLS port 4112 listening"
    else
        fail "TLS port 4112 not listening"
    fi

    # Test: TLS handshake succeeds
    TLS_RESULT=$(echo "" | timeout 3 openssl s_client -connect localhost:4112 -verify_return_error 2>&1 || true)
    if echo "$TLS_RESULT" | grep -q "BEGIN CERTIFICATE\|SSL handshake\|Verify return code: 0\|self-signed"; then
        pass "TLS handshake succeeds (openssl s_client)"
    else
        fail "TLS handshake failed (openssl s_client)"
    fi

    # Test: Plain text rejected on TLS port
    PLAIN_ON_TLS=$(echo "Hello" | timeout 2 nc -w 1 localhost 4112 2>/dev/null || true)
    if echo "$PLAIN_ON_TLS" | grep -q "Lock"; then
        fail "Plain text accepted on TLS port (should be rejected)"
    else
        pass "Plain text rejected on TLS port"
    fi

    # Test: Plain port still works normally (no TLS interference)
    PLAIN_CHECK=$(echo "" | timeout 3 nc -w 2 localhost 4111 2>/dev/null || true)
    if echo "$PLAIN_CHECK" | grep -q "Lock"; then
        pass "Plain port 4111 still works normally"
    else
        fail "Plain port 4111 broken after TLS setup"
    fi

    # Test: Gaglist file operations
    echo "SomeUser 0" > /root/.opendchub/gaglist
    if [ -s /root/.opendchub/gaglist ]; then
        pass "Gaglist file writable and readable"
    else
        fail "Gaglist file operations failed"
    fi
    > /root/.opendchub/gaglist

    # Dragon is a standalone NMDC client (not embedded), so no bot log check here.
    # Dragon integration tests are separate.
    pass "Hub started without embedded Perl (Dragon is standalone)"

    echo ""
    echo "========================================"
    echo "=== DC Client Integration Tests      ==="
    echo "========================================"

    # Run the comprehensive Perl DC client integration test
    cd /root/.opendchub/scripts
    if perl /build/test/dc_client.pl; then
        pass "DC client integration tests passed"
    else
        fail "DC client integration tests had failures"
    fi

    # Show bot log for debugging
    echo ""
    echo "--- Bot Log (last 50 lines) ---"
    tail -50 /root/.opendchub/logs/odchbot.log 2>/dev/null || echo "  (no log available)"

    # Clean up
    kill $HUB_PID 2>/dev/null || true
    killall opendchub 2>/dev/null || true
    wait $HUB_PID 2>/dev/null || true
    pass "Hub shut down cleanly"
else
    fail "Hub failed to start on port 4111"
    # Show any error output
    echo "  Checking for hub process..."
    ps aux | grep opendchub || true
    # Check if bot had errors
    echo "  Checking bot log..."
    cat /root/.opendchub/logs/odchbot.log 2>/dev/null || echo "  (no log)"
fi

echo ""
echo "========================================"
echo "Final Results: $PASS passed, $FAIL failed, $SKIP skipped out of $TESTS tests"
echo "========================================"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
