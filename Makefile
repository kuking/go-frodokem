all: clean build test bench coverage

clean:
	go clean -testcache -cache

build:
	go build

test:
	go test

bench:
	go test -run=Benchmark -bench=. -benchmem

coverage:
	go test -cover -coverprofile=coverage.out
	go tool cover -func=coverage.out

