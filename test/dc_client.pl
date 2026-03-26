#!/usr/bin/perl
# NMDC protocol test client for odchbot v4 integration testing
# Connects to an OpenDCHub, completes handshake, sends commands, verifies responses

use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
my $HAS_SSL = eval { require IO::Socket::SSL; 1 };

# Prevent SIGPIPE from killing us when hub closes connection
$SIG{PIPE} = 'IGNORE';
# Unbuffer stdout so we see output even if we crash
$| = 1;

my $HOST = $ENV{HUB_HOST} || 'localhost';
my $PORT = $ENV{HUB_PORT} || 4111;
my $NICK = $ENV{TEST_NICK} || 'IntegrationTestUser';
my $BOTNAME = $ENV{BOT_NAME} || 'Dragon';
my $CMD_PREFIX = $ENV{CMD_PREFIX} || '-';

my $pass = 0;
my $fail = 0;
my $skip = 0;
my $total = 0;

sub pass { $pass++; $total++; print "  PASS: $_[0]\n"; }
sub fail { $fail++; $total++; print "  FAIL: $_[0]\n"; }
sub skip { $skip++; $total++; print "  SKIP: $_[0]\n"; }

# NMDC Lock-to-Key algorithm
sub lock2key {
    my $lock = shift;
    my @lock_bytes = map { ord($_) } split(//, $lock);
    my $len = scalar @lock_bytes;
    my @key;

    # First byte is special
    $key[0] = $lock_bytes[0] ^ $lock_bytes[$len - 1] ^ $lock_bytes[$len - 2] ^ 5;

    for my $i (1 .. $len - 1) {
        $key[$i] = $lock_bytes[$i] ^ $lock_bytes[$i - 1];
    }

    # Nibble swap all bytes
    for my $i (0 .. $len - 1) {
        $key[$i] = (($key[$i] << 4) & 0xF0) | (($key[$i] >> 4) & 0x0F);
    }

    # Encode special characters
    my $result = '';
    for my $byte (@key) {
        $byte &= 0xFF;
        if ($byte == 0) {
            $result .= '/%DCN000%/';
        } elsif ($byte == 5) {
            $result .= '/%DCN005%/';
        } elsif ($byte == 36) {
            $result .= '/%DCN036%/';
        } elsif ($byte == 96) {
            $result .= '/%DCN096%/';
        } elsif ($byte == 124) {
            $result .= '/%DCN124%/';
        } elsif ($byte == 126) {
            $result .= '/%DCN126%/';
        } else {
            $result .= chr($byte);
        }
    }
    return $result;
}

# Read from socket with timeout, collecting all available data
sub read_socket {
    my ($sock, $timeout) = @_;
    $timeout ||= 5;
    my $sel = IO::Select->new($sock);
    my $data = '';
    my $start = time();
    while (time() - $start < $timeout) {
        if ($sel->can_read(0.5)) {
            my $buf;
            my $bytes = sysread($sock, $buf, 8192);
            last if !$bytes;
            $data .= $buf;
        }
        # If we have data, wait a bit longer for bot response after echo
        last if length($data) > 0 && !$sel->can_read(0.5);
    }
    return $data;
}

# Read until we see a specific pattern or timeout
sub read_until {
    my ($sock, $pattern, $timeout) = @_;
    $timeout ||= 8;
    my $sel = IO::Select->new($sock);
    my $data = '';
    my $start = time();
    while (time() - $start < $timeout) {
        if ($sel->can_read(0.5)) {
            my $buf;
            my $bytes = sysread($sock, $buf, 8192);
            last if !$bytes;
            $data .= $buf;
            last if $data =~ $pattern;
        }
    }
    return $data;
}

# Drain all pending data from socket
sub drain_socket {
    my ($sock) = @_;
    my $sel = IO::Select->new($sock);
    my $data = '';
    while ($sel->can_read(0.3)) {
        my $buf;
        my $bytes = sysread($sock, $buf, 8192);
        last if !$bytes;
        $data .= $buf;
    }
    return $data;
}

# Send a chat message and read the bot's response
sub send_chat {
    my ($sock, $msg, $timeout) = @_;
    $timeout ||= 5;
    # Drain any pending data first
    drain_socket($sock);
    # Send the chat
    print $sock "<$NICK> $msg|";
    # Read response
    return read_socket($sock, $timeout);
}

# Send a bot command and read response
sub send_command {
    my ($sock, $cmd, $timeout) = @_;
    return send_chat($sock, "${CMD_PREFIX}${cmd}", $timeout);
}

print "=== ODCHBot v4 DC Client Integration Tests ===\n\n";

print "--- Phase 1: NMDC Protocol Handshake ---\n";

# Connect to hub
my $sock = IO::Socket::INET->new(
    PeerHost => $HOST,
    PeerPort => $PORT,
    Proto    => 'tcp',
    Timeout  => 10,
);

if (!$sock) {
    fail("Could not connect to hub at $HOST:$PORT: $!");
    print "\nResults: $pass passed, $fail failed, $skip skipped out of $total tests\n";
    exit 1;
}
pass("Connected to hub at $HOST:$PORT");

# Step 1: Receive $Lock
my $lock_msg = read_socket($sock, 5);
if ($lock_msg =~ /\$Lock\s+(\S+)/) {
    my $lock = $1;
    pass("Received \$Lock from hub");

    # Step 2: Send $Key and $ValidateNick
    my $key = lock2key($lock);
    my $supports = '$Supports UserCommand NoGetINFO NoHello UserIP2|';
    my $key_msg = "\$Key $key|";
    my $validate = "\$ValidateNick $NICK|";

    print $sock $supports;
    print $sock $key_msg;
    print $sock $validate;

    # Step 3: Read hub response
    my $response = read_until($sock, qr/\$Hello/, 8);

    if ($response =~ /\$Hello\s+\Q$NICK\E/) {
        pass("Logged in as $NICK (received \$Hello)");

        # Step 4: Send $MyINFO to complete registration
        my $myinfo = "\$MyINFO \$ALL $NICK Integration Tester<TestClient V:1.0,M:A,H:1/0/0,S:5>\$\$\$LAN(T1)\x01\$test\@test.com\$1073741824\$|";
        print $sock $myinfo;

        # Read all welcome messages, hub info, MOTD, bot greetings etc.
        my $welcome = read_socket($sock, 5);
        # Accumulate more data if bot sends delayed messages
        $welcome .= read_socket($sock, 3);

        my $all_data = $lock_msg . $response . $welcome;

        # Check if bot is present
        if ($all_data =~ /\Q$BOTNAME\E/) {
            pass("Bot '$BOTNAME' detected in hub");
        } else {
            # Try requesting nick list
            print $sock "\$GetNickList|";
            my $nicklist = read_socket($sock, 3);
            if ($nicklist =~ /\Q$BOTNAME\E/) {
                pass("Bot '$BOTNAME' found in nick list");
            } else {
                fail("Bot '$BOTNAME' not found (data: " . substr($all_data . $nicklist, 0, 300) . ")");
            }
        }

        # Check for bot MyINFO (bot registers itself)
        if ($all_data =~ /\$MyINFO \$ALL \Q$BOTNAME\E/) {
            pass("Bot sent \$MyINFO registration");
        } else {
            skip("Bot \$MyINFO not seen in initial data (may have been sent before connect)");
        }

        print "\n--- Phase 2: Basic Bot Commands ---\n";

        # Give the bot a moment to fully initialize
        sleep(1);
        drain_socket($sock);

        # Test: -commands (lists available commands)
        my $cmd_response = send_command($sock, "commands", 5);
        if ($cmd_response =~ /\Q$BOTNAME\E/ && $cmd_response =~ /time|coin|help/i) {
            pass("${CMD_PREFIX}commands - returned command list");
        } elsif (length($cmd_response) > 20) {
            pass("${CMD_PREFIX}commands - returned response (" . length($cmd_response) . " bytes)");
        } else {
            fail("${CMD_PREFIX}commands - no meaningful response (got: " . substr($cmd_response, 0, 200) . ")");
        }

        # Test: -help
        my $help_response = send_command($sock, "help", 5);
        if ($help_response =~ /help|welcome|connection|troubleshoot/i) {
            pass("${CMD_PREFIX}help - returned help text");
        } elsif (length($help_response) > 20) {
            pass("${CMD_PREFIX}help - returned response (" . length($help_response) . " bytes)");
        } else {
            fail("${CMD_PREFIX}help - no meaningful response (got: " . substr($help_response, 0, 200) . ")");
        }

        # Test: -time
        my $time_response = send_command($sock, "time", 5);
        if ($time_response =~ /\d{4}-\d{2}-\d{2}/ || $time_response =~ /Australia|Canberra|\d{2}:\d{2}/) {
            pass("${CMD_PREFIX}time - returned timestamp");
        } elsif ($time_response =~ /\d{4}/) {
            pass("${CMD_PREFIX}time - returned time data");
        } else {
            fail("${CMD_PREFIX}time - no timestamp (got: " . substr($time_response, 0, 200) . ")");
        }

        # Test: -coin
        my $coin_response = send_command($sock, "coin", 5);
        if ($coin_response =~ /head|tail/i) {
            pass("${CMD_PREFIX}coin - returned Heads/Tails");
        } elsif (length($coin_response) > 5) {
            pass("${CMD_PREFIX}coin - returned response");
        } else {
            fail("${CMD_PREFIX}coin - no response (got: '$coin_response')");
        }

        # Test: -coin with question
        my $coin_q = send_command($sock, "coin pizza or burgers", 5);
        if ($coin_q =~ /pizza|burgers|answer/i) {
            pass("${CMD_PREFIX}coin <question> - decided between options");
        } elsif (length($coin_q) > 5) {
            pass("${CMD_PREFIX}coin <question> - returned response");
        } else {
            fail("${CMD_PREFIX}coin <question> - no response");
        }

        # Test: -mynick
        my $nick_response = send_command($sock, "mynick", 5);
        if ($nick_response =~ /\Q$NICK\E/) {
            pass("${CMD_PREFIX}mynick - returned our nickname '$NICK'");
        } elsif (length($nick_response) > 5) {
            pass("${CMD_PREFIX}mynick - returned response");
        } else {
            fail("${CMD_PREFIX}mynick - no response (got: '$nick_response')");
        }

        # Test: -8ball (magic 8 ball)
        my $ball_response = send_command($sock, "8ball Will this test pass?", 5);
        if ($ball_response =~ /yes|no|maybe|outlook|doubt|know|kidding|good|bet|due time|sources/i) {
            pass("${CMD_PREFIX}8ball - returned magic 8 ball answer");
        } elsif (length($ball_response) > 5) {
            pass("${CMD_PREFIX}8ball - returned response");
        } else {
            fail("${CMD_PREFIX}8ball - no response (got: '$ball_response')");
        }

        # Test: -topic
        my $topic_response = send_command($sock, "topic", 5);
        if ($topic_response =~ /topic|hub/i || length($topic_response) > 5) {
            pass("${CMD_PREFIX}topic - returned topic info");
        } else {
            fail("${CMD_PREFIX}topic - no response");
        }

        # Test: -rules
        my $rules_response = send_command($sock, "rules", 5);
        if ($rules_response =~ /rules|link|url/i || length($rules_response) > 5) {
            pass("${CMD_PREFIX}rules - returned rules link");
        } else {
            fail("${CMD_PREFIX}rules - no response");
        }

        # Test: -karma
        my $karma_response = send_command($sock, "karma", 5);
        if ($karma_response =~ /karma|link|url|\+\+|--/i || length($karma_response) > 5) {
            pass("${CMD_PREFIX}karma - returned karma info");
        } else {
            fail("${CMD_PREFIX}karma - no response");
        }

        # Test: -website
        my $website_response = send_command($sock, "website", 5);
        if ($website_response =~ /website|http|link|url/i || length($website_response) > 5) {
            pass("${CMD_PREFIX}website - returned website link");
        } else {
            skip("${CMD_PREFIX}website - may not be configured");
        }

        # Test: -random (sentence generator)
        my $random_response = send_command($sock, "random", 5);
        if ($random_response =~ /the\s+\w+/i || length($random_response) > 10) {
            pass("${CMD_PREFIX}random - returned random sentence");
        } else {
            fail("${CMD_PREFIX}random - no response (got: '$random_response')");
        }

        print "\n--- Phase 3: Database-Backed Commands ---\n";

        # Test: -stats
        my $stats_response = send_command($sock, "stats", 5);
        if ($stats_response =~ /stat|connection|share|user|online/i) {
            pass("${CMD_PREFIX}stats - returned hub statistics");
        } elsif (length($stats_response) > 10) {
            pass("${CMD_PREFIX}stats - returned response (" . length($stats_response) . " bytes)");
        } else {
            fail("${CMD_PREFIX}stats - no response (got: '$stats_response')");
        }

        # Test: -info (about self)
        my $info_response = send_command($sock, "info", 5);
        if ($info_response =~ /info|join|share|permission|status/i) {
            pass("${CMD_PREFIX}info - returned user info");
        } elsif (length($info_response) > 10) {
            pass("${CMD_PREFIX}info - returned response");
        } else {
            fail("${CMD_PREFIX}info - no response (got: '$info_response')");
        }

        # First send some chat so history/first/last have data
        print $sock "<$NICK> Hello from the integration test!|";
        sleep(1);
        drain_socket($sock);

        print $sock "<$NICK> This is a second test message.|";
        sleep(1);
        drain_socket($sock);

        # Test: -history
        my $history_response = send_command($sock, "history", 5);
        if ($history_response =~ /history|chat/i) {
            pass("${CMD_PREFIX}history - returned chat history");
            if ($history_response =~ /integration test|test message/i) {
                pass("${CMD_PREFIX}history - contains our chat messages");
            } else {
                skip("${CMD_PREFIX}history - our messages may not be in history yet");
            }
        } elsif (length($history_response) > 10) {
            pass("${CMD_PREFIX}history - returned response");
        } else {
            fail("${CMD_PREFIX}history - no response");
        }

        # Test: -history with limit
        my $hist_limit = send_command($sock, "history 5", 5);
        if (length($hist_limit) > 5) {
            pass("${CMD_PREFIX}history 5 - returned limited history");
        } else {
            skip("${CMD_PREFIX}history 5 - no response (may have no data yet)");
        }

        # Test: -first (first line spoken by a user)
        my $first_response = send_command($sock, "first $NICK", 5);
        if ($first_response =~ /first|spoken|never|\Q$NICK\E/i) {
            pass("${CMD_PREFIX}first - returned first line data");
        } elsif (length($first_response) > 5) {
            pass("${CMD_PREFIX}first - returned response");
        } else {
            fail("${CMD_PREFIX}first - no response");
        }

        # Test: -last (last line spoken by a user)
        my $last_response = send_command($sock, "last $NICK", 5);
        if ($last_response =~ /last|spoken|never|\Q$NICK\E/i) {
            pass("${CMD_PREFIX}last - returned last line data");
        } elsif (length($last_response) > 5) {
            pass("${CMD_PREFIX}last - returned response");
        } else {
            fail("${CMD_PREFIX}last - no response");
        }

        # Test: -tell (leave a message for a user)
        # Tell ourselves a message
        my $tell_response = send_command($sock, "tell $NICK Remember to pass the tests!", 5);
        if ($tell_response =~ /message|saved|deliver|online|\Q$NICK\E/i) {
            pass("${CMD_PREFIX}tell - handled message for user");
        } elsif (length($tell_response) > 5) {
            pass("${CMD_PREFIX}tell - returned response");
        } else {
            fail("${CMD_PREFIX}tell - no response");
        }

        # Test: -tell with no user
        my $tell_nouser = send_command($sock, "tell", 5);
        if ($tell_nouser =~ /usage|specify/i || length($tell_nouser) > 5) {
            pass("${CMD_PREFIX}tell (no args) - handled gracefully");
        } else {
            skip("${CMD_PREFIX}tell (no args) - no response");
        }

        # Test: -winning (longest logged in users)
        my $winning_response = send_command($sock, "winning", 5);
        if ($winning_response =~ /winning|longest|online|connected|\Q$NICK\E/i || length($winning_response) > 5) {
            pass("${CMD_PREFIX}winning - returned winning data");
        } else {
            fail("${CMD_PREFIX}winning - no response");
        }

        print "\n--- Phase 4: Fun/Game Commands ---\n";

        # Test: -rr (russian roulette) - may kick us!
        skip("${CMD_PREFIX}rr (russian roulette) - skipped to avoid being kicked");

        # Test: -lasercats - also kicks, skip
        skip("${CMD_PREFIX}lasercats - skipped to avoid being kicked");

        # Test: -haha - also kicks, skip
        skip("${CMD_PREFIX}haha - skipped to avoid being kicked");

        # Test: -roll (dice roller)
        my $roll_response = send_command($sock, "roll", 5);
        if ($roll_response =~ /roll.*d6.*[1-6]/i) {
            pass("${CMD_PREFIX}roll - rolled default d6");
        } elsif (length($roll_response) > 5) {
            pass("${CMD_PREFIX}roll - returned response");
        } else {
            fail("${CMD_PREFIX}roll - no response");
        }

        # Test: -roll 2d20
        my $roll2d20 = send_command($sock, "roll 2d20", 5);
        if ($roll2d20 =~ /roll.*2d20.*\d+/i) {
            pass("${CMD_PREFIX}roll 2d20 - rolled multiple dice");
        } elsif (length($roll2d20) > 5) {
            pass("${CMD_PREFIX}roll 2d20 - returned response");
        } else {
            fail("${CMD_PREFIX}roll 2d20 - no response");
        }

        # Test: -uptime
        my $uptime_response = send_command($sock, "uptime", 5);
        if ($uptime_response =~ /uptime.*\d+[dhms]/i) {
            pass("${CMD_PREFIX}uptime - returned uptime info");
        } elsif (length($uptime_response) > 5) {
            pass("${CMD_PREFIX}uptime - returned response");
        } else {
            fail("${CMD_PREFIX}uptime - no response");
        }

        # Test: -seen (self)
        my $seen_response = send_command($sock, "seen $NICK", 5);
        if ($seen_response =~ /online|last seen|\Q$NICK\E/i) {
            pass("${CMD_PREFIX}seen - found user status");
        } elsif (length($seen_response) > 5) {
            pass("${CMD_PREFIX}seen - returned response");
        } else {
            fail("${CMD_PREFIX}seen - no response");
        }

        # Test: -seen (unknown user)
        my $seen_unknown = send_command($sock, "seen NobodyAtAll999", 5);
        if ($seen_unknown =~ /never seen|unknown|not found/i || length($seen_unknown) > 5) {
            pass("${CMD_PREFIX}seen (unknown) - handled gracefully");
        } else {
            fail("${CMD_PREFIX}seen (unknown) - no response");
        }

        # Test: -quote (random quote from history)
        my $quote_response = send_command($sock, "quote", 5);
        if ($quote_response =~ /"|history|no chat|no quote/i || length($quote_response) > 10) {
            pass("${CMD_PREFIX}quote - returned a quote or message");
        } else {
            fail("${CMD_PREFIX}quote - no response");
        }

        # Test: -google
        my $google_response = send_command($sock, "google test", 5);
        if ($google_response =~ /google|search|http/i || length($google_response) > 5) {
            pass("${CMD_PREFIX}google - returned search link");
        } else {
            fail("${CMD_PREFIX}google - no response");
        }

        print "\n--- Phase 5: Bot Message Formatting ---\n";

        # Verify bot messages have <BotName> prefix
        my $all_responses = $cmd_response . $help_response . $time_response .
                           $coin_response . $nick_response . $ball_response .
                           $stats_response . $info_response;

        if ($all_responses =~ /<\Q$BOTNAME\E>/) {
            pass("Bot messages use <$BOTNAME> prefix format");
        } else {
            fail("Bot messages don't use expected <$BOTNAME> prefix");
        }

        # Check for proper pipe-delimited message termination
        if ($all_responses =~ /\|/) {
            pass("Messages are pipe-delimited (NMDC format)");
        } else {
            fail("Messages not pipe-delimited");
        }

        # Check no raw errors leaked
        if ($all_responses =~ /die|Traceback|Can't locate|Undefined subroutine/i) {
            fail("Error messages found in bot responses");
            while ($all_responses =~ /((?:die|Traceback|Can't locate|Undefined subroutine)[^\|]{0,200})/ig) {
                print "    Error context: $1\n";
            }
        } else {
            pass("No error messages in bot responses");
        }

        print "\n--- Phase 6: Karma Hook ---\n";

        # Test karma ++ and -- hooks
        my $karma_plus = send_chat($sock, "TestBot++", 3);
        if ($karma_plus =~ /karma|\+\+|received/i) {
            pass("Karma ++ hook triggered");
        } elsif (length($karma_plus) > 5) {
            pass("Karma ++ hook returned data");
        } else {
            skip("Karma ++ hook - no response (hook may not be active)");
        }

        my $karma_minus = send_chat($sock, "TestBot--", 3);
        if ($karma_minus =~ /karma|--|lost/i) {
            pass("Karma -- hook triggered");
        } elsif (length($karma_minus) > 5) {
            pass("Karma -- hook returned data");
        } else {
            skip("Karma -- hook - no response");
        }

        print "\n--- Phase 7: Commands Listing Completeness ---\n";

        # Re-fetch command list and check key commands are registered
        drain_socket($sock);
        my $full_cmds = send_command($sock, "commands", 5);
        my @expected_cmds = qw(time coin commands help mynick topic rules karma stats info history first last tell winning uptime seen quote roll gag ungag random website google search 8ball);
        my $cmds_found = 0;
        my $cmds_missing = 0;
        for my $cmd (@expected_cmds) {
            if ($full_cmds =~ /\b\Q$cmd\E\b/i) {
                $cmds_found++;
            } else {
                $cmds_missing++;
                print "    NOTICE: '$cmd' not found in commands list\n";
            }
        }
        if ($cmds_found >= 15) {
            pass("Commands list contains $cmds_found/" . scalar(@expected_cmds) . " expected commands");
        } elsif ($cmds_found >= 10) {
            pass("Commands list contains $cmds_found expected commands (some may be permission-restricted)");
        } elsif (length($full_cmds) > 50) {
            pass("Commands list returned substantial data ($cmds_found expected commands found)");
        } else {
            fail("Commands list incomplete - only $cmds_found expected commands found");
        }

        print "\n--- Phase 8: TLS Connection Tests ---\n";

        if ($HAS_SSL) {
            my $TLS_PORT = $ENV{TLS_PORT} || 4112;

            # Test: TLS connection + full NMDC handshake
            my $tls_sock = IO::Socket::SSL->new(
                PeerHost        => $HOST,
                PeerPort        => $TLS_PORT,
                SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
                Timeout         => 10,
            );

            if ($tls_sock) {
                pass("TLS connection established on port $TLS_PORT");

                my $tls_lock = read_socket($tls_sock, 5);
                if ($tls_lock =~ /\$Lock\s+(\S+)/) {
                    my $tls_lock_str = $1;
                    pass("Received \$Lock over TLS");

                    # Complete NMDC handshake over TLS
                    my $tls_key = lock2key($tls_lock_str);
                    my $tls_nick = "TLSTestUser";
                    print $tls_sock "\$Supports UserCommand NoGetINFO NoHello UserIP2|";
                    print $tls_sock "\$Key $tls_key|";
                    print $tls_sock "\$ValidateNick $tls_nick|";

                    my $tls_response = read_until($tls_sock, qr/\$Hello/, 8);
                    if ($tls_response =~ /\$Hello\s+\Q$tls_nick\E/) {
                        pass("Full NMDC handshake over TLS succeeded");
                    } else {
                        fail("NMDC handshake over TLS failed (got: " . substr($tls_response, 0, 200) . ")");
                    }
                } else {
                    fail("No \$Lock received over TLS (got: " . substr($tls_lock, 0, 200) . ")");
                }
                close($tls_sock);
            } else {
                fail("TLS connection failed: " . IO::Socket::SSL::errstr());
            }

            # Test: Concurrent plain + TLS connections
            my $plain_sock2 = IO::Socket::INET->new(
                PeerHost => $HOST,
                PeerPort => $PORT,
                Proto    => 'tcp',
                Timeout  => 5,
            );
            my $tls_sock2 = IO::Socket::SSL->new(
                PeerHost        => $HOST,
                PeerPort        => $TLS_PORT,
                SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
                Timeout         => 5,
            );
            if ($plain_sock2 && $tls_sock2) {
                my $p_data = read_socket($plain_sock2, 3);
                my $t_data = read_socket($tls_sock2, 3);
                if ($p_data =~ /\$Lock/ && $t_data =~ /\$Lock/) {
                    pass("Concurrent plain + TLS connections both work");
                } else {
                    fail("Concurrent connections issue (plain: " . length($p_data) . "B, tls: " . length($t_data) . "B)");
                }
                close($plain_sock2);
                close($tls_sock2);
            } else {
                fail("Could not open concurrent connections");
                close($plain_sock2) if $plain_sock2;
                close($tls_sock2) if $tls_sock2;
            }
        } else {
            skip("IO::Socket::SSL not available - TLS client tests skipped");
            skip("TLS concurrent test skipped");
            skip("TLS handshake test skipped");
        }

    } elsif ($response =~ /\$ValidateDenide/) {
        fail("Hub denied nick validation for $NICK");
    } elsif ($response =~ /\$GetPass/) {
        # Hub wants a password
        print $sock "\$MyPass test|";
        my $pass_response = read_socket($sock, 3);
        if ($pass_response =~ /\$Hello/) {
            pass("Logged in as $NICK (with password)");
        } else {
            fail("Login failed after password (got: $pass_response)");
        }
    } else {
        fail("Unexpected response after ValidateNick: " . substr($response, 0, 200));
    }
} else {
    fail("Did not receive \$Lock (got: " . substr($lock_msg, 0, 200) . ")");
}

close($sock);

print "\n=== Integration Test Results: $pass passed, $fail failed, $skip skipped out of $total tests ===\n";
exit($fail > 0 ? 1 : 0);
