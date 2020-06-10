all: clean build test bench coverage

clean:
	go clean -testcache -cache
	rm -f bin/soak_test bin/demo

build:
	go build
	go build -o bin/soak_test	mains/soak/soak.go
	go build -o bin/demo		mains/demo/demo.go

test:
	go test

bench:
	go test -run=Benchmark -bench=. -benchmem

coverage:
	go test -cover -coverprofile=coverage.out
	go tool cover -func=coverage.out


