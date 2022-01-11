.PHONY: test
test:
	go test -v ./...

.PHONY: cover
cover:
	mkdir -p bin
	go test -v -coverprofile=./bin/coverage.out . || true
	go tool cover -html=./bin/coverage.out
