honeypot-pop3
=============

POP3 Honeypot

Features:
 * POP3 + POP3S

Dependencies:
 * Twisted
 * My site-packages(3) --> common-modules

Usage:
```bash
# Generate Config
python pop3.py -d config.xml
# Run
python pop3.py
```

TODO: 
 * interact with SMTP-honeypot
 
Contribution welcome.

FAQ
===
1) Generate SSL-Certificates

CA:
openssl genrsa -out ca.private.key 4096
openssl req -new -x509 -days 4096 -key ca.private.key -out ca.public.key

SRV:
openssl genrsa -out smtp.private.key 4096
openssl req -new -key smtp.private.key -out smtp.csr
openssl x509 -req -days 1024 -in smtp.csr -CA ca.public.key -CAkey ca.private.key -set_serial 01 -out smtp.public.key

SSL Check Connection
openssl s_client -quiet -connect 127.0.0.1:995

All rights reserved.
(c) 2014 by Alexander Bredo