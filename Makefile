APP=_bin/wireguard-daemon
SOURCES=$(wildcard ./**/**/*.go)
SOURCES_NO_TESTS=$(filter-out $(wildcard ./**/*_test.go),$(SOURCES))

.PHONY: build fmt lint check run test clean

build: $(APP)

$(APP): $(SOURCES_NO_TESTS)
	go build -o $(APP) ./cmd/wireguard-daemon

fmt: $(SOURCES)
	goimports -w -e -d .

lint: $(SOURCES)
	golangci-lint run

check: $(SOURCES)
	! goimports -e -d . | grep .
	$(MAKE) build lint test
	echo "Success"

run: $(APP)
	sudo setcap cap_net_admin+ep $(APP)
	cd _bin && ./wireguard-daemon

test: $(SOURCES)
	go test ./internal/api

clean:
	rm -f $(APP)
