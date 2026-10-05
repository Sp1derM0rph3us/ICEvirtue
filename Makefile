.PHONY: build test clean
build:
	mkdir -p bin
	go build -o bin/ICEvirtue .
	go build -o bin/ICEvirtue-worker ./cmd/worker
	go build -o bin/ICEvirtue-admin ./cmd/admin
test:
	go test ./...
clean:
	rm -f bin/ICEvirtue bin/ICEvirtue-worker bin/ICEvirtue-admin
