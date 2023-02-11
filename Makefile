BINARY=certwatcher

all: build

build:
	go build -o $(BINARY) cmd/certwatcher/main.go

clean:
	go clean
	rm -f $(BINARY)

run:
	./$(BINARY)

.PHONY: all build clean run

install:
	@echo "[INFO] Moving the binary to /usr/bin/certwatcher"
	@cp cmd/certwatcher/certwatcher /usr/bin/certwatcher > /dev/null 2>&1
	@echo "[INFO] Certwatcher binary successfully installed at /usr/bin/certwatcher."
	@echo "[INFO] You can now run the certwatcher"