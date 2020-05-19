PROGNAME = dumbproxy
OUTSUFFIX = bin/$(PROGNAME)
BUILDOPTS = -a -tags netgo
LDFLAGS = -ldflags '-s -w -extldflags "-static"'

src = $(wildcard *.go)

native: bin-native
all: bin-linux-amd64 bin-linux-386 bin-linux-arm \
	bin-freebsd-amd64 bin-freebsd-386 bin-freebsd-arm \
	bin-darwin-amd64 \
	bin-windows-amd64 bin-windows-386

bin-native: $(OUTSUFFIX)
bin-linux-amd64: $(OUTSUFFIX).linux-amd64
bin-linux-386: $(OUTSUFFIX).linux-386
bin-linux-arm: $(OUTSUFFIX).linux-arm
bin-freebsd-amd64: $(OUTSUFFIX).freebsd-amd64
bin-freebsd-386: $(OUTSUFFIX).freebsd-386
bin-freebsd-arm: $(OUTSUFFIX).freebsd-arm
bin-darwin-amd64: $(OUTSUFFIX).darwin-amd64
bin-windows-amd64: $(OUTSUFFIX).windows-amd64.exe
bin-windows-386: $(OUTSUFFIX).windows-386.exe

$(OUTSUFFIX): $(src)
	CGO_ENABLED=0 go build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).linux-amd64: $(src)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).linux-386: $(src)
	CGO_ENABLED=0 GOOS=linux GOARCH=386 go build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).linux-arm: $(src)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm go build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).freebsd-amd64: $(src)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).freebsd-386: $(src)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=386 go build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).freebsd-arm: $(src)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=arm go build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).darwin-amd64: $(src)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).windows-amd64.exe: $(src)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(BUILDOPTS) $(LDFLAGS) -o $@

$(OUTSUFFIX).windows-386.exe: $(src)
	CGO_ENABLED=0 GOOS=windows GOARCH=386 go build $(BUILDOPTS) $(LDFLAGS) -o $@

clean:
	rm -f bin/*
