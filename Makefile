all: clean build test bench coverage

clean:
	go clean -testcache -cache
	rm -f bin/soak_test bin/main

build:
	go build
	go build -o bin/soak_test main/soak.go
	go build -o bin/main main/main.go

test:
	go test

bench:
	go test -run=Benchmark -bench=. -benchmem

coverage:
	go test -cover -coverprofile=coverage.out
	go tool cover -func=coverage.out


