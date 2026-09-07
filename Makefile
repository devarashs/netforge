BINARY := netforge
VERSION ?= dev

.PHONY: build install test vet fmt clean cross

build:
	go build -ldflags "-s -w" -o $(BINARY) .

install:
	go install .

vet:
	go vet ./...

fmt:
	gofmt -w .

test:
	go test ./...

clean:
	rm -f $(BINARY) $(BINARY)-*

# Cross-compile the most common targets into dist/
cross:
	mkdir -p dist
	GOOS=linux   GOARCH=amd64 go build -ldflags "-s -w" -o dist/$(BINARY)-linux-amd64 .
	GOOS=linux   GOARCH=arm64 go build -ldflags "-s -w" -o dist/$(BINARY)-linux-arm64 .
	GOOS=darwin  GOARCH=arm64 go build -ldflags "-s -w" -o dist/$(BINARY)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o dist/$(BINARY)-windows-amd64.exe .
