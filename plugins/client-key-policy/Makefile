# Builds the client-key-policy CPA plugin as a native shared library.
# The release archive layout matches CPA's plugin store installer:
#   <id>_<version>_<goos>_<goarch>.zip containing <id>.<ext> at the zip root,
#   plus a checksums.txt (sha256sum format) next to the archives.

ID      := client-key-policy
VERSION ?= 0.1.0
GOOS    ?= $(shell go env GOOS)
GOARCH  ?= $(shell go env GOARCH)
DIST    ?= dist

ifeq ($(GOOS),darwin)
EXT := .dylib
else ifeq ($(GOOS),windows)
EXT := .dll
else
EXT := .so
endif

LIB := $(DIST)/$(GOOS)/$(GOARCH)/$(ID)$(EXT)
ZIP := $(DIST)/$(ID)_$(VERSION)_$(GOOS)_$(GOARCH).zip

.PHONY: build test package checksums clean

build: $(LIB)

$(LIB): $(wildcard *.go) ui/index.html go.mod
	mkdir -p $(dir $@)
	CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -buildmode=c-shared -ldflags "-s -w -X main.pluginVersion=$(VERSION)" -o $@ .
	rm -f $(basename $@).h

test:
	go vet ./...
	go test ./...

package: build
	cd $(dir $(LIB)) && rm -f $(abspath $(ZIP)) && zip -q $(abspath $(ZIP)) $(ID)$(EXT)

checksums:
	cd $(DIST) && sha256sum *.zip > checksums.txt

clean:
	rm -rf $(DIST)
