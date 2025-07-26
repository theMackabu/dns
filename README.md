DNS server written in Go.
example [config.toml](config.example.toml)

```bash
# build & run
go build -o dns-server cmd/dns-server/main.go
./dns-server --version
```

```bash
# testing
dig @localhost -p 53 google.com
dig @localhost -p 53 google.com AAAA
dig @localhost -p 53 google.com MX
```
