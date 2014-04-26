class Net::SOCKS;

method connect(:$host!, :$port!, :$proxy-server!, :$proxy-port = 1080, :$socket = IO::Socket::INET) {
    my $request = Buf.new(0x05, # version 5
                          0x01, # one auth method
                          0x00); # no authentication
    my $sock = $socket;
    unless $sock.defined {
        $sock = $sock.new(:host($proxy-server), :port($proxy-port));
    }

    $sock.write($request);
    my $r = $sock.read(2);
    unless $r[0] == 0x05 && $r[1] == 0x00 {
        fail "...";
    }

    my $request-type;
    my $request-data;
    if $host ~~ /^\d+\.\d+\.\d+\.\d+$/ {
        # ipv4
        $request-type = 0x01;
        $request-data = Buf.new($host.split('.'));
    } elsif $host ~~ /^...$/ {
        # ipv6
        $request-type = 0x01;
        $request-data = Buf.new(0..15);
    } else {
        # domain
        $request-type = 0x03;
        $request-data = Buf.new(0);
    }

    $request = Buf.new(0x05, # version 5
                       0x01, # establish a TCP connection
                       0x00, #reserved
                       $request-type # host type
                   ) ~ $request-data;
    $r = $sock.read(4);
    unless $r[0] == 0x05 && $r[1] == 0x00 && $r[2] == 0x00 {
        fail "...";
    }
    if $r[4] == 0x01 {
        $sock.read(4);
    } elsif $r[4] == 0x03 {
        my $len = $sock.read(1);
        $len = $len[0];
        $sock.read($len);
    } elsif $r[4] == 0x04 {
        $sock.read(16);
    } else {
        fail "...";
    }

    $sock.read(2);

    return $sock;
}
