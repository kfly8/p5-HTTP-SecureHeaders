use strict;
use warnings;
use Test::More;

use HTTP::SecureHeaders;
use Plack::Util;
use Plack::Response;

my $expected_headers = {
    'Content-Security-Policy'           => "default-src 'self' https:; font-src 'self' https: data:; img-src 'self' https: data:; object-src 'none'; script-src https:; style-src 'self' https: 'unsafe-inline'",
    'Strict-Transport-Security'         => 'max-age=631138519',
    'X-Content-Type-Options'            => 'nosniff',
    'X-Download-Options'                => 'noopen',
    'X-Frame-Options'                   => 'SAMEORIGIN',
    'X-Permitted-Cross-Domain-Policies' => 'none',
    'X-XSS-Protection'                  => '1; mode=block',
    'Referrer-Policy'                   => 'strict-origin-when-cross-origin',
};

my $lc_expected_headers = {
    map { lc $_ => $expected_headers->{$_} } keys %$expected_headers
};

subtest 'unknown headers' => sub {
    my $secure_headers = HTTP::SecureHeaders->new;

    subtest 'unblessed object' => sub {
        local $@;
        eval {
            $secure_headers->apply({});
        };
        like $@, qr/headers must be/;
    };

    subtest 'object not having set and exists methods' => sub {
        {
            package SomeHeaders;
            sub new { bless {}, $_[0] }
        }

        my $headers = SomeHeaders->new;

        local $@;
        eval {
            $secure_headers->apply($headers);
        };
        like $@, qr/unknown headers/;
    };

    subtest 'object not having set and exists methods' => sub {
        {
            package SomeHeaders2;
            sub new { bless {}, $_[0] }
            sub exists { }
        }
        my $headers = SomeHeaders2->new;

        local $@;
        eval {
            $secure_headers->apply($headers);
        };
        like $@, qr/unknown headers/;
    };
};

subtest 'default' => sub {
    my $secure_headers = HTTP::SecureHeaders->new;

    subtest 'Plack::Util::headers' => sub {
        my $data = [];
        my $headers = Plack::Util::headers($data);

        $secure_headers->apply($headers);
        is_deeply +{@$data}, $expected_headers;
    };

    subtest 'Plack::Response#headers' => sub {
        my $res = Plack::Response->new;

        $secure_headers->apply($res->headers);
        is_deeply +{ %{$res->headers} }, $lc_expected_headers;
    };
};

subtest 'set undef' => sub {
    my $secure_headers = HTTP::SecureHeaders->new(
        content_security_policy => undef,
    );

    subtest 'Plack::Util::headers' => sub {
        my $data = [];
        my $headers = Plack::Util::headers($data);

        $secure_headers->apply($headers);
        is_deeply +{@$data}, {
            %$expected_headers,
            'Content-Security-Policy' => undef,
        };
    };

    subtest 'Plack::Response#headers' => sub {
        my $res = Plack::Response->new;

        $secure_headers->apply($res->headers);

        is $res->header('Content-Security-Policy'), undef;

        my %expected = %$lc_expected_headers;
        delete $expected{'content-security-policy'};

        is_deeply +{ %{$res->headers} }, \%expected;
    };
};

subtest 'customized header' => sub {
    my $secure_headers = HTTP::SecureHeaders->new(
        content_security_policy => "default-src 'self' https:",
    );

    subtest 'Plack::Util::headers' => sub {
        my $data = [];
        my $headers = Plack::Util::headers($data);

        $secure_headers->apply($headers);

        is_deeply +{@$data}, {
            %$expected_headers,
            'Content-Security-Policy' => "default-src 'self' https:",
        };
    };

    subtest 'Plack::Response#headers' => sub {
        my $res = Plack::Response->new;

        $secure_headers->apply($res->headers);
        is_deeply +{ %{$res->headers} }, {
            %$lc_expected_headers,
            'content-security-policy' => "default-src 'self' https:",
        };
    };
};

subtest 'already set HTTP header' => sub {
    my $secure_headers = HTTP::SecureHeaders->new(
        'x_frame_options' => 'SAMEORIGIN',
    );

    subtest 'Plack::Util::headers' => sub {
        my $data = ['X-Frame-Options' => 'DENY'];
        my $headers = Plack::Util::headers($data);

        $secure_headers->apply($headers);

        is $headers->get('X-Frame-Options'), 'DENY';
        is_deeply +{@$data}, {
            %$expected_headers,
            'X-Frame-Options' => "DENY",
        };
    };

    subtest 'Plack::Response#headers' => sub {
        my $res = Plack::Response->new;
        $res->header('X-Frame-Options', 'DENY');

        $secure_headers->apply($res->headers);

        is $res->header('X-Frame-Options'), 'DENY';
        is_deeply +{ %{$res->headers} }, {
            %$lc_expected_headers,
            'x-frame-options' => "DENY",
        };
    };
};

done_testing;
