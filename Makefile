.PHONY: build test cover lint vet check run docker clean

VERSION ?= dev

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/yandex-iap .

vet:
	go vet ./...

test:
	go test -race -count=1 ./...

cover:
	go test -race -count=1 -covermode=atomic -coverprofile=cover.out ./...
	go tool cover -func=cover.out | tail -n 1

lint:
	golangci-lint run ./...

# Everything CI runs, locally.
check: vet lint test

docker:
	docker build --build-arg VERSION=$(VERSION) -t yandex-iap:$(VERSION) .

clean:
	rm -rf bin cover.out
