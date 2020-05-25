### -----------------------
# --- Building
### -----------------------

# first is default task when running "make" without args
build:
	@$(MAKE) go-format
	@$(MAKE) go-build
	@$(MAKE) go-lint

# useful to ensure that everything gets resetuped from scratch
all:
	@$(MAKE) clean
	@$(MAKE) init
	@$(MAKE) build
	@$(MAKE) info
	@$(MAKE) test

info:
	@go version

go-format:
	go fmt

go-build: 
	go build ./...

go-lint:
	golangci-lint run --fast

# https://github.com/golang/go/issues/24573
# w/o cache - see "go help testflag"
# use https://github.com/kyoh86/richgo to color
# note that these tests should not run verbose by default (e.g. use your IDE for this)
# TODO: add test shuffling/seeding when landed in go v1.15 (https://github.com/golang/go/issues/28592)
test:
	richgo test -cover -race -count=1 ./...

### -----------------------
# --- Initializing
### -----------------------

init:
	@$(MAKE) modules
	@$(MAKE) tools
	@$(MAKE) tidy
	@go version

# cache go modules (locally into .pkg)
modules:
	go mod download

# https://marcofranssen.nl/manage-go-tools-via-go-modules/
tools:
	cat tools.go | grep _ | awk -F'"' '{print $$2}' | xargs -tI % go install %

tidy:
	go mod tidy

### -----------------------
# --- Helpers
### -----------------------

clean:
	rm -rf tmp

### -----------------------
# --- Special targets
### -----------------------

# https://www.gnu.org/software/make/manual/html_node/Special-Targets.html
# https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html
# ignore matching file/make rule combinations in working-dir
.PHONY: test

# https://unix.stackexchange.com/questions/153763/dont-stop-makeing-if-a-command-fails-but-check-exit-status
# https://www.gnu.org/software/make/manual/html_node/One-Shell.html
# required to ensure make fails if one recipe fails (even on parallel jobs)
.ONESHELL:
SHELL = /bin/bash
.SHELLFLAGS = -ec
