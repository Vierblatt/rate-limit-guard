.PHONY: all up down test bench build clean

all: test bench

up:
	docker-compose up -d

down:
	docker-compose down

test:
	go test ./... -v -count=1 -race

bench:
	go test -bench=. -benchmem -count=3 -timeout=60s

build:
	go build ./...

clean:
	go clean -cache
	rm -f coverage.out

coverage:
	go test ./... -coverprofile=coverage.out -covermode=atomic
	go tool cover -html=coverage.out -o coverage.html
