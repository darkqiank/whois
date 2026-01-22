mkdir -p build
CGO_ENABLED=0 go build -ldflags="-w -s" -o build/whois ./main/