# ktr

Highly asynchronous traceroute program written in Rust with ASN WHOIS and PeeringDB lookups. Hacked together mostly for [how-did-i-get-here.net](https://how-did-i-get-here.net/) :)

![](https://doggo.ninja/uQ6YKq.png)

Components:

- `ktr_lib`: main library code, handles traceroute, WHOIS lookups of ASNs, and PeeringDB SQLite support
- `ktr_agent`: daemon executable that allows use of the library over STDIN/STDOUT
