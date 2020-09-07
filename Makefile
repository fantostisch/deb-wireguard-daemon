APP=wireguard-daemon
SOURCES=$(wildcard *.go)

.PHONY: all fmt clean

all: $(APP)

$(APP): $(SOURCES)
	go build -o $(APP) $(SOURCES)

fmt:
	gofmt -w -d $(SOURCES)

clean:
	rm -rf $(APP)
