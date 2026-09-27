.PHONY: test build test-free-wings

test:
	go test ./...

test-free-wings:
	bash packaging/free/tests/refuse_unowned_servers.sh

build:
	mkdir -p dist
	go build -o dist/panel-api-test ./cmd/panel-api-test
