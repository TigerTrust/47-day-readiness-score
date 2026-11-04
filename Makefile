.PHONY: build test vet lint run install clean

BIN=bin/score

build:
	go build -o $(BIN) ./cmd/score

test:
	go test -race ./...

vet:
	go vet ./...

run: build
	$(BIN) example.com

install:
	go install ./cmd/score

clean:
	rm -rf bin
