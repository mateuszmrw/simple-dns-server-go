# dns-client-go

## Project Overview

This project is a DNS server implementation in Golang based on the Rust implementation and guide here: [EmilHernvall - DNS Guide](https://github.com/EmilHernvall/dnsguide)
This DNS server is a simplified version, meant for educational purposes and not intended for production use. It allows users to understand and interact with DNS protocols directly.
The only dependency is the testify library.

## Usage

Ensure you have Golang installed on your machine. After cloning the repository run:

```bash
go run main.go
```

Open another terminal and query the DNS server using:

```bash
dig @127.0.0.1 -p 2053 <domain_name> <query_type>
```

## Supported Query Types
- NS
- A
- AAAA
- MX
- CNAME

## Disclaimer

This project is intended for educational purposes and should not be used as a production DNS server
