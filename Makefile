.PHONY: build
build:
	go build ./p11kit/...
	go build -o ./bin/example-p11-kit-server ./example/example-p11-kit-server

.PHONY: test
test:
	go test -v ./...

.PHONY: cover
cover:
	mkdir -p bin
	go test -v -coverprofile=./bin/coverage.out . || true
	go tool cover -html=./bin/coverage.out
