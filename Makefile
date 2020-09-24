APP=_bin/wireguard-daemon
SOURCES=$(wildcard wireguard-daemon/*.go)
SOURCES_NO_TESTS=$(filter-out $(wildcard wireguard-daemon/*_test.go),$(SOURCES))

.PHONY: build fmt lint check run test clean

build: $(APP)

$(APP): $(SOURCES_NO_TESTS)
	go build -o $(APP) $(SOURCES_NO_TESTS)

fmt: $(SOURCES)
	goimports -w -e -d $(SOURCES)

lint: $(SOURCES)
	golangci-lint run $(SOURCES)

check: $(SOURCES)
	! goimports -e -d $(SOURCES) | grep .
	$(MAKE) build lint test
	echo "Success"

run: $(APP)
	cd _bin && sudo ./wireguard-daemon

test: $(SOURCES)
	cd wireguard-daemon && go test

clean:
	rm -f $(APP)
