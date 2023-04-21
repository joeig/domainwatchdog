GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOCOVER=$(GOCMD) tool cover
GOTEST=$(GOCMD) test
GOFMT=gofmt
BINARY_NAME=domainwatchdog
GOFILES=$(shell find . -type f -name '*.go' -not -path "./vendor/*")

.DEFAULT_GOAL := all
.PHONY: all build build-linux-amd64 coverage test check-fmt fmt clean

all: check-fmt test build

build:
	mkdir -p ./out
	$(GOBUILD) -o ./out/$(BINARY_NAME) -v ./cmd/$(BINARY_NAME)

build-linux-amd64:
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o ./out/$(BINARY_NAME)_linux_amd64 -v ./cmd/$(BINARY_NAME)

coverage:
	$(GOCOVER) -func=./out/coverage.out

test:
	mkdir -p ./out
	$(GOTEST) -v ./... -covermode=count -coverprofile=./out/coverage.out

check-fmt:
	$(GOFMT) -d ${GOFILES}

fmt:
	$(GOFMT) -w ${GOFILES}

clean:
	$(GOCLEAN)
	rm -rf ./out
