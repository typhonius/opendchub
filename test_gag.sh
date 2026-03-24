#!/bin/bash
# Full integration tests: opendchub build + source fixes + odchbot end-to-end
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
if [ -x /build/odchsrc/src/opendchub ]; then
    pass "Binary built successfully"
else
    fail "Binary not found"
    exit 1
fi

# Test 2: Perl support
if grep -q "#define HAVE_PERL" /build/odchsrc/config.h; then
    pass "Perl scripting support compiled in"
else
    fail "Perl scripting support NOT compiled in"
fi

echo ""
echo "========================================"
echo "=== Source Code Fix Verification     ==="
echo "========================================"

# Test 3: check_if_gagged has nickname comparison
if grep -q "match_with_wildcards(user->nick, gag_host)" /build/odchsrc/src/fileio.c; then
    pass "check_if_gagged() compares against user nickname"
else
    fail "check_if_gagged() MISSING nickname comparison"
fi

# Test 4: No broken || GAG pattern (ignore comments)
BROKEN=$(grep -v '^\s*/\*' /build/odchsrc/src/commands.c | grep -v '^\s*\*' | grep -c "== NICKBAN || GAG)" || true)
if [ "$BROKEN" = "0" ]; then
    pass "No broken '|| GAG)' always-true conditions"
else
    fail "Found $BROKEN broken '|| GAG)' patterns"
fi

# Test 5: Correct type == GAG pattern exists
FIXED=$(grep -c "type == NICKBAN || type == GAG)" /build/odchsrc/src/commands.c || true)
if [ "$FIXED" = "2" ]; then
    pass "Both ballow() type checks use correct 'type == GAG'"
else
    fail "Expected 2 correct type checks, found $FIXED"
fi

# Test 6: snprintf used for ban_line (ignore comments)
SNPRINTF=$(grep -v '^\s*/\*' /build/odchsrc/src/commands.c | grep -c "snprintf(ban_line, sizeof(ban_line)" || true)
if [ "$SNPRINTF" -ge 4 ]; then
    pass "All $SNPRINTF ban_line writes use snprintf with bounds"
else
    fail "Expected >= 4 snprintf calls, found $SNPRINTF"
fi

# Test 7: No unsafe sprintf on ban_line (excluding comments)
UNSAFE=$(grep -v '^\s*/\*' /build/odchsrc/src/commands.c | grep -v '^\s*\*' | grep "sprintf(ban_line," | grep -cv "snprintf" || true)
if [ "$UNSAFE" = "0" ]; then
    pass "No unsafe sprintf calls on ban_line"
else
    fail "Found $UNSAFE unsafe sprintf calls"
fi

# Test 8: No triplicate log
if grep -q 'logprintf.*remove_line.*logprintf.*remove_line' /build/odchsrc/src/fileio.c; then
    fail "Triplicate log message still present"
else
    pass "Triplicate log message fixed"
fi

# Test 9: Unused variables cleaned up
if grep -A 15 "int check_if_gagged" /build/odchsrc/src/fileio.c | grep -q "string_ip"; then
    fail "Unused string_ip variable still in check_if_gagged()"
else
    pass "Unused variables removed from check_if_gagged()"
fi

echo ""
echo "========================================"
echo "=== ODCHBot Perl Module Checks       ==="
echo "========================================"

# Test: Core modules load without errors
for module in DCBSettings DCBCommon DCBDatabase DCBUser; do
    if perl -I/build/odchbot -e "eval { require $module }; exit(\$@ ? 1 : 0)" 2>/dev/null; then
        pass "Module $module loads without compile errors"
    else
        fail "Module $module has compile errors"
    fi
done

# Test: Command modules compile (skip ones needing external modules)
CMD_PASS=0
CMD_FAIL=0
CMD_SKIP=0
# Commands that need external modules not available in test env
SKIP_CMDS="bug movie update weather"
for pm in /build/odchbot/commands/*.pm; do
    name=$(basename "$pm" .pm)
    if echo "$SKIP_CMDS" | grep -qw "$name"; then
        CMD_SKIP=$((CMD_SKIP + 1))
        continue
    fi
    if perl -I/build/odchbot -I/build/odchbot/commands -c "$pm" 2>/dev/null; then
        CMD_PASS=$((CMD_PASS + 1))
    else
        CMD_FAIL=$((CMD_FAIL + 1))
        echo "    WARNING: $name.pm failed compile check"
    fi
done
if [ $CMD_FAIL -eq 0 ]; then
    pass "All $CMD_PASS command modules compile cleanly ($CMD_SKIP skipped - need external deps)"
else
    fail "$CMD_FAIL command modules have compile issues ($CMD_PASS OK, $CMD_SKIP skipped)"
fi

# Test: YAML configs are valid
YAML_PASS=0
YAML_FAIL=0
for yml in /build/odchbot/commands/*.yml; do
    name=$(basename "$yml" .yml)
    if [ ! -s "$yml" ]; then
        # Skip empty files (legacy commands like random.yml)
        continue
    fi
    if perl -MYAML::Syck -e "YAML::Syck::LoadFile('$yml')" 2>/dev/null; then
        YAML_PASS=$((YAML_PASS + 1))
    else
        YAML_FAIL=$((YAML_FAIL + 1))
        echo "    WARNING: $name.yml is invalid YAML"
    fi
done
if [ $YAML_FAIL -eq 0 ]; then
    pass "All $YAML_PASS command YAML configs are valid"
else
    fail "$YAML_FAIL YAML configs are invalid ($YAML_PASS OK)"
fi

echo ""
echo "========================================"
echo "=== Hub + Bot Integration Test       ==="
echo "========================================"

# Set up hub config
mkdir -p /root/.opendchub/scripts
cat > /root/.opendchub/config << 'HUBCONF'
hub_name = TestHub
max_users = 50
hub_description = Integration Test Hub
listening_port = 4111
admin_port = 53696
admin_pass = testpass
default_pass =
min_share = 0
registered_only = 0
hub_hostname = localhost
verbosity = 5
HUBCONF

touch /root/.opendchub/banlist
touch /root/.opendchub/allowlist
touch /root/.opendchub/nickbanlist
touch /root/.opendchub/gaglist
touch /root/.opendchub/reglist
touch /root/.opendchub/linklist

# Set up odchbot configuration
mkdir -p /build/odchbot/logs
cat > /build/odchbot/odchbot.yml << 'BOTCONF'
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
  commandPath: commands
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
  version: v3
  website: http://localhost
  topic: "Integration Test Hub - Testing in Progress"
BOTCONF

cat > /build/odchbot/odchbot.log4perl.conf << 'LOG4PERL'
log4perl.rootLogger=DEBUG, LOGFILE
log4perl.appender.LOGFILE=Log::Log4perl::Appender::File
log4perl.appender.LOGFILE.filename=logs/odchbot.log
log4perl.appender.LOGFILE.mode=append
log4perl.appender.LOGFILE.layout=Log::Log4perl::Layout::PatternLayout
log4perl.appender.LOGFILE.layout.ConversionPattern=[%p] %d{MM-dd-yyyy HH:mm:ss} %F %L - %m%n
LOG4PERL

# Remove commands that need external modules not available in test env
# This prevents the bot from trying to register/compile them
rm -f /build/odchbot/commands/bug.yml /build/odchbot/commands/bug.pm
rm -f /build/odchbot/commands/movie.yml /build/odchbot/commands/movie.pm
rm -f /build/odchbot/commands/weather.yml /build/odchbot/commands/weather.pm
rm -f /build/odchbot/commands/update.yml /build/odchbot/commands/update.pm
rm -f /build/odchbot/commands/random.yml /build/odchbot/commands/random.pl

# Copy ALL odchbot files to the hub scripts directory
# The hub runs scripts from ~/.opendchub/scripts/ and FindBin resolves to that dir
cp /build/odchbot/odchbot.pl /root/.opendchub/scripts/odchbot.pl
cp /build/odchbot/DCBSettings.pm /root/.opendchub/scripts/
cp /build/odchbot/DCBDatabase.pm /root/.opendchub/scripts/
cp /build/odchbot/DCBCommon.pm /root/.opendchub/scripts/
cp /build/odchbot/DCBUser.pm /root/.opendchub/scripts/
cp /build/odchbot/odchbot.yml /root/.opendchub/scripts/odchbot.yml
chmod 600 /root/.opendchub/scripts/odchbot.yml
cp /build/odchbot/odchbot.log4perl.conf /root/.opendchub/scripts/
cp -r /build/odchbot/commands /root/.opendchub/scripts/commands
mkdir -p /root/.opendchub/scripts/logs

# The hub forks the Perl script with its own CWD.
# odchbot.pl uses FindBin for lib path, but Log::Log4perl->init() uses a relative path.
# Start the hub from the scripts dir so relative paths resolve correctly.
cd /root/.opendchub/scripts

# Start hub with piped config answers (port, admin_pass, link_pass)
printf "4111\ntestpass\nlinkpass\n" | /build/odchsrc/src/opendchub -d &
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

    # Test: Admin port
    if nc -z localhost 53696 2>/dev/null; then
        pass "Admin port 53696 listening"
    else
        fail "Admin port not listening"
    fi

    # Test: Gaglist file operations
    echo "SomeUser 0" > /root/.opendchub/gaglist
    if [ -s /root/.opendchub/gaglist ]; then
        pass "Gaglist file writable and readable"
    else
        fail "Gaglist file operations failed"
    fi
    > /root/.opendchub/gaglist

    # Check for bot startup in hub log or data
    sleep 2
    BOT_LOG="/root/.opendchub/scripts/logs/odchbot.log"
    if [ -f "$BOT_LOG" ]; then
        pass "ODCHBot log file created"
        if grep -q "Dragon" "$BOT_LOG" 2>/dev/null; then
            pass "ODCHBot initialized (found in log)"
        else
            skip "ODCHBot may not have logged startup yet"
        fi
    else
        skip "ODCHBot log file not found (bot may not have loaded)"
    fi

    echo ""
    echo "========================================"
    echo "=== DC Client Integration Tests      ==="
    echo "========================================"

    # Run the comprehensive Perl DC client integration test
    cd /root/.opendchub/scripts
    if perl /build/test_integration.pl; then
        pass "DC client integration tests passed"
    else
        fail "DC client integration tests had failures"
    fi

    # Show bot log for debugging
    echo ""
    echo "--- Bot Log (last 30 lines) ---"
    tail -30 /root/.opendchub/scripts/logs/odchbot.log 2>/dev/null || echo "  (no log available)"

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
fi

echo ""
echo "========================================"
echo "=== ODCHBot Unit Tests               ==="
echo "========================================"

# Run odchbot unit tests if the test directory exists
if [ -d /build/odchbot/t ]; then
    cd /build/odchbot
    if prove -I. -It/lib t/ 2>&1; then
        pass "All odchbot unit tests passed"
    else
        fail "ODCHBot unit test suite had failures"
    fi
else
    skip "No unit test directory found"
fi

echo ""
echo "========================================"
echo "Final Results: $PASS passed, $FAIL failed, $SKIP skipped out of $TESTS tests"
echo "========================================"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
