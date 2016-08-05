use Test;
use HTTP::HPACK :internal;

# These tests are drawn from the examples section of the HPACK specification,
# located at https://tools.ietf.org/html/rfc7541#appendix-C

sub header($name, $value, $never-indexed = False) {
    HTTP::HPACK::Header.new(:$name, :$value, :$never-indexed)
}

# C.1.1.  Example 1: Encoding 10 Using a 5-Bit Prefix
{
    is-deeply encode-int(10, 5), Buf.new(0b00001010), 'encode 10 with 5-bit prefix';
    my int $offset = 0;
    is decode-int(Buf.new(0b11101010), 5, $offset), 10, 'decode 10 with 5-bit prefix';
    is $offset, 1, 'Consumed 1 byte';
}

# C.1.2.  Example 2: Encoding 1337 Using a 5-Bit Prefix
{
    is-deeply encode-int(1337, 5), Buf.new(0b00011111, 0b10011010, 0b00001010),
        'encode 1337 with 5-bit prefix';
    my int $offset = 0;
    is decode-int(Buf.new(0b11111111, 0b10011010, 0b00001010), 5, $offset), 1337,
        'decode 1337 with 5-bit prefix';
    is $offset, 3, 'Consumed 3 bytes';
}

# C.1.3.  Example 3: Encoding 42 Starting at an Octet Boundary
{
    is-deeply encode-int(42, 8), Buf.new(0b00101010), 'encode 42 with 8-bit prefix';
    my int $offset = 0;
    is decode-int(Buf.new(0b00101010), 8, $offset), 42, 'decode 42 with 8-bit prefix';
    is $offset, 1, 'Consumed 1 byte';
}

# C.2.1.  Literal Header Field with Indexing
is-deeply HTTP::HPACK::Decoder.new.decode-headers(
    Buf.new(0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65,
            0x79, 0x0d, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65,
            0x61, 0x64, 0x65, 0x72)),
    [ header('custom-key', 'custom-header') ],
    'decode custom-key: custom-header';

# C.2.2.  Literal Header Field without Indexing
is-deeply HTTP::HPACK::Decoder.new.decode-headers(
    Buf.new(0x04, 0x0c, 0x2f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x70,
            0x61, 0x74, 0x68)),
    [ header(':path', '/sample/path') ],
    'decode :path: /sample/path';

# C.2.3.  Literal Header Field Never Indexed
is-deeply HTTP::HPACK::Decoder.new.decode-headers(
    Buf.new(0x10, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x06,
            0x73, 0x65, 0x63, 0x72, 0x65, 0x74 )),
    [ header('password', 'secret', True) ],
    'decode password: secret';

# C.2.4.  Indexed Header Field
is-deeply HTTP::HPACK::Decoder.new.decode-headers(Buf.new(0x82)),
    [ header(':method', 'GET') ],
    'decode :method: GET';

# C.3.  Request Examples without Huffman Coding
{
    my $decoder = HTTP::HPACK::Decoder.new;
    is-deeply $decoder.decode-headers(
        Buf.new(0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78,
                0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d)),
        [ header(':method', 'GET'), header(':scheme', 'http'),
          header(':path', '/'), header(':authority', 'www.example.com') ],
        'decoded first request header example';
    is-deeply $decoder.decode-headers(
        Buf.new(0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61,
                0x63, 0x68, 0x65)),
        [ header(':method', 'GET'), header(':scheme', 'http'),
          header(':path', '/'), header(':authority', 'www.example.com'),
          header('cache-control', 'no-cache') ],
        'decoded second request header example';
    is-deeply $decoder.decode-headers(
        Buf.new(0x82, 0x87, 0x85, 0xbf, 0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f,
                0x6d, 0x2d, 0x6b, 0x65, 0x79, 0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f,
                0x6d, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65)),
        [ header(':method', 'GET'), header(':scheme', 'https'),
          header(':path', '/index.html'), header(':authority', 'www.example.com'),
          header('custom-key', 'custom-value') ],
        'decoded third request header example';
}

# C.4.  Request Examples with Huffman Coding
{
    my $decoder = HTTP::HPACK::Decoder.new;
    is-deeply $decoder.decode-headers(
        Buf.new(0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a,
                0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff)),
        [ header(':method', 'GET'), header(':scheme', 'http'),
          header(':path', '/'), header(':authority', 'www.example.com') ],
        'decoded first request header example (huffman coded)';
    is-deeply $decoder.decode-headers(
        Buf.new(0x82, 0x86, 0x84, 0xbe, 0x58, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c,
                0xbf)),
        [ header(':method', 'GET'), header(':scheme', 'http'),
          header(':path', '/'), header(':authority', 'www.example.com'),
          header('cache-control', 'no-cache') ],
        'decoded second request header example (huffman coded)';
    is-deeply $decoder.decode-headers(
        Buf.new(0x82, 0x87, 0x85, 0xbf, 0x40, 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b,
                0xa9, 0x7d, 0x7f, 0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8,
                0xb4, 0xbf)),
        [ header(':method', 'GET'), header(':scheme', 'https'),
          header(':path', '/index.html'), header(':authority', 'www.example.com'),
          header('custom-key', 'custom-value') ],
        'decoded third request header example (huffman coded)';
}

done-testing;
