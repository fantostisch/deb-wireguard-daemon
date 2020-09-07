APP=_bin/wireguard-daemon
SOURCES=$(wildcard wireguard-daemon/*.go)

.PHONY: all fmt run clean

all: $(APP)

$(APP): $(SOURCES)
	go build -o $(APP) $(SOURCES)

fmt:
	gofmt -w -d $(SOURCES)

run: $(APP)
	cd _bin && sudo ./wireguard-daemon

clean:
	rm -f $(APP)
