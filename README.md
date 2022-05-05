[![Actions Status](https://github.com/kfly8/p5-HTTP-SecureHeaders/actions/workflows/test.yml/badge.svg)](https://github.com/kfly8/p5-HTTP-SecureHeaders/actions)
# NAME

HTTP::SecureHeaders - manage security headers with many safe defaults

# SYNOPSIS

```perl
use HTTP::SecureHeaders;

my $headers = Plack::Util::headers([]);
$secure_headers->apply($headers);
```

Then it sets the following HTTP headers.

```
Content-Security-Policy
Strict-Transport-Security
X-Content-Type-Options
X-Download-Options
X-Frame-Options
X-Permitted-Cross-Domain-Policies
X-XSS-Protection
Referrer-Policy
```

# DESCRIPTION

HTTP::SecureHeaders manages HTTP headers to protect against XSS attacks, insecure connections, content type sniffing, etc.
NOTE: To protect against these attacks, sanitization of user input values and other protections are also required.

## DEFAULT HEADERS

By default, the following HTTP headers are set:

```
Content-Security-Policy: default-src 'self' https:; font-src 'self' https: data:; img-src 'self' https: data:; object-src 'none'; script-src https:; style-src 'self' https: 'unsafe-inline'
Strict-Transport-Security: max-age=631138519
X-Content-Type-Options: nosniff
X-Download-Options: noopen
X-Frame-Options: SAMEORIGIN
X-Permitted-Cross-Domain-Policies: none
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin,
```

This default value refers to the following sites [https://github.com/github/secure\_headers#default-values](https://github.com/github/secure_headers#default-values).

# METHODS

- `HTTP::SecureHeaders->new(%args)`

    Secure HTTP headers can be changed as follows:

    ```perl
    my $secure_headers = HTTP::SecureHeaders->new(
        content_security_policy           => "default-src 'self'",
        strict_transport_security         => 'max-age=631138519; includeSubDomains',
        x_content_type_options            => 'nosniff',
        x_download_options                => 'noopen',
        x_frame_options                   => 'DENY',
        x_permitted_cross_domain_policies => 'none',
        x_xss_protection                  => '1',
        referrer_policy                   => 'no-referrer',
    );
    ```

- `$self->apply($headers)`

    Apply the value of the secure header to the given header object.

# LICENSE

Copyright (C) kfly8.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

# AUTHOR

kfly8 <kfly@cpan.org>
