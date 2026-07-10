.PHONY: all up down test bench build clean

all: test bench

up:
	docker-compose up -d

down:
	docker-compose down

test:
	go test ./... -v -count=1 -race

bench:
	go test -bench=BenchmarkMiddlewares -benchmem -count=1 -timeout=60s | grep -v slowcall

bench-all:
	go test -bench=. -benchmem -count=1 -timeout=60s | grep -v slowcall

bench-real:
	docker-compose up -d
	BENCHMARK_REDIS_ADDR=localhost:6379 go test -bench=BenchmarkMiddlewares -benchmem -count=1 -timeout=60s
	docker-compose down

bench-full:
	docker-compose up -d
	BENCHMARK_REDIS_ADDR=localhost:6379 go test -bench=. -benchmem -count=1 -timeout=60s
	docker-compose down

build:
	go build ./...

clean:
	go clean -cache
	rm -f coverage.out

coverage:
	go test ./... -coverprofile=coverage.out -covermode=atomic
	go tool cover -html=coverage.out -o coverage.html
