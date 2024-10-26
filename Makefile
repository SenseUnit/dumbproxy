PROGNAME = dumbproxy
OUTSUFFIX = bin/$(PROGNAME)
VERSION := $(shell git describe)
BUILDOPTS = -a -tags netgo -trimpath -asmflags -trimpath
LDFLAGS = -ldflags '-s -w -extldflags "-static" -X main.version=$(VERSION)'
LDFLAGS_NATIVE = -ldflags '-s -w -X main.version=$(VERSION)'

NDK_CC_ARM = $(abspath ../../ndk-toolchain-arm/bin/arm-linux-androideabi-gcc)
NDK_CC_ARM64 = $(abspath ../../ndk-toolchain-arm64/bin/aarch64-linux-android21-clang)

GO := go

src = $(wildcard *.go */*.go */*/*.go) go.mod go.sum

native: bin-native
all: bin-linux-amd64 bin-linux-386 bin-linux-arm bin-linux-arm64 \
	bin-freebsd-amd64 bin-freebsd-386 bin-freebsd-arm bin-freebsd-arm64 \
	bin-netbsd-amd64 bin-netbsd-386 bin-netbsd-arm bin-netbsd-arm64 \
	bin-openbsd-amd64 bin-openbsd-386 bin-openbsd-arm bin-openbsd-arm64 \
	bin-darwin-amd64 bin-darwin-arm64 \
	bin-windows-amd64 bin-windows-386 bin-windows-arm

allplus: all \
	bin-android-arm bin-android-arm64

bin-native: $(OUTSUFFIX)
bin-linux-amd64: $(OUTSUFFIX).linux-amd64
bin-linux-386: $(OUTSUFFIX).linux-386
bin-linux-arm: $(OUTSUFFIX).linux-arm
bin-linux-arm64: $(OUTSUFFIX).linux-arm64
bin-freebsd-amd64: $(OUTSUFFIX).freebsd-amd64
bin-freebsd-386: $(OUTSUFFIX).freebsd-386
bin-freebsd-arm: $(OUTSUFFIX).freebsd-arm
bin-freebsd-arm64: $(OUTSUFFIX).freebsd-arm64
bin-netbsd-amd64: $(OUTSUFFIX).netbsd-amd64
bin-netbsd-386: $(OUTSUFFIX).netbsd-386
bin-netbsd-arm: $(OUTSUFFIX).netbsd-arm
bin-netbsd-arm64: $(OUTSUFFIX).netbsd-arm64
bin-openbsd-amd64: $(OUTSUFFIX).openbsd-amd64
bin-openbsd-386: $(OUTSUFFIX).openbsd-386
bin-openbsd-arm: $(OUTSUFFIX).openbsd-arm
bin-openbsd-arm64: $(OUTSUFFIX).openbsd-arm64
bin-darwin-amd64: $(OUTSUFFIX).darwin-amd64
bin-darwin-arm64: $(OUTSUFFIX).darwin-arm64
bin-windows-amd64: $(OUTSUFFIX).windows-amd64.exe
bin-windows-386: $(OUTSUFFIX).windows-386.exe
bin-windows-arm: $(OUTSUFFIX).windows-arm.exe
bin-android-arm: $(OUTSUFFIX).android-arm
bin-android-arm64: $(OUTSUFFIX).android-arm64

$(OUTSUFFIX): $(src)
	$(GO) build $(LDFLAGS_NATIVE) -o $@

$(OUTSUFFIX).linux-amd64: $(src)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).linux-386: $(src)
	CGO_ENABLED=0 GOOS=linux GOARCH=386 $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).linux-arm: $(src)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).linux-arm64: $(src)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).freebsd-amd64: $(src)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).freebsd-386: $(src)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=386 $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).freebsd-arm: $(src)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=arm $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).freebsd-arm64: $(src)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=arm64 $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).netbsd-amd64: $(src)
	CGO_ENABLED=0 GOOS=netbsd GOARCH=amd64 $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).netbsd-386: $(src)
	CGO_ENABLED=0 GOOS=netbsd GOARCH=386 $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).netbsd-arm: $(src)
	CGO_ENABLED=0 GOOS=netbsd GOARCH=arm $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).netbsd-arm64: $(src)
	CGO_ENABLED=0 GOOS=netbsd GOARCH=arm64 $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).openbsd-amd64: $(src)
	CGO_ENABLED=0 GOOS=openbsd GOARCH=amd64 $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).openbsd-386: $(src)
	CGO_ENABLED=0 GOOS=openbsd GOARCH=386 $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).openbsd-arm: $(src)
	CGO_ENABLED=0 GOOS=openbsd GOARCH=arm $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).openbsd-arm64: $(src)
	CGO_ENABLED=0 GOOS=openbsd GOARCH=arm64 $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).darwin-amd64: $(src)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).darwin-arm64: $(src)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).windows-amd64.exe: $(src)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).windows-386.exe: $(src)
	CGO_ENABLED=0 GOOS=windows GOARCH=386 $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).windows-arm.exe: $(src)
	CGO_ENABLED=0 GOOS=windows GOARCH=arm GOARM=7 $(GO) build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).android-arm: $(src)
	CC=$(NDK_CC_ARM) CGO_ENABLED=1 GOOS=android GOARCH=arm GOARM=7 $(GO) build $(LDFLAGS_NATIVE) -o $@

$(OUTSUFFIX).android-arm64: $(src)
	CC=$(NDK_CC_ARM64) CGO_ENABLED=1 GOOS=android GOARCH=arm64 $(GO) build $(LDFLAGS_NATIVE) -o $@

clean:
	rm -f bin/*

fmt:
	$(GO) fmt ./...

run:
	$(GO) run $(LDFLAGS) .

install:
	$(GO) install $(LDFLAGS_NATIVE) .

.PHONY: clean all native fmt install \
	bin-native \
	bin-linux-amd64 \
	bin-linux-386 \
	bin-linux-arm \
	bin-linux-arm64 \
	bin-freebsd-amd64 \
	bin-freebsd-386 \
	bin-freebsd-arm \
	bin-freebsd-arm64 \
	bin-netbsd-amd64 \
	bin-netbsd-386 \
	bin-netbsd-arm \
	bin-netbsd-arm64 \
	bin-openbsd-amd64 \
	bin-openbsd-386 \
	bin-openbsd-arm \
	bin-openbsd-arm64 \
	bin-darwin-amd64 \
	bin-darwin-arm64 \
	bin-windows-amd64 \
	bin-windows-386 \
	bin-windows-arm \
	bin-android-arm \
	bin-android-arm64
