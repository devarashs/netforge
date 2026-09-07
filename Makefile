BINARY  := netforge
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build install test vet fmt clean cross

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

install:
	go install -trimpath -ldflags "$(LDFLAGS)" .

vet:
	go vet ./...

fmt:
	gofmt -w .

test:
	go test -race ./...

clean:
	rm -f $(BINARY) $(BINARY)-*
	rm -rf dist

# Cross-compile the release targets into dist/ (mirrors the CI release job).
cross:
	mkdir -p dist
	@for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
		os=$${t%/*}; arch=$${t#*/}; out=dist/$(BINARY)-$(VERSION)-$$os-$$arch; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		echo "-> $$out$$ext"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o $$out$$ext . ; \
	done
