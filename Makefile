ifeq ($(OS),Windows_NT)
EXEEXT := .exe
POSIX_SH ?= C:/Program Files/Git/usr/bin/sh.exe
SHELL := $(POSIX_SH)
else
EXEEXT :=
SHELL := /bin/sh
endif

GO ?= go
BIN_DIR ?= bin
OUT_DIR ?= .tmp/smoke
BIN := $(BIN_DIR)/procrustes$(EXEEXT)

.PHONY: help lint test build smoke run-checks clean

ifeq ($(OS),Windows_NT)
define MKDIR_P
powershell -NoProfile -Command "New-Item -ItemType Directory -Force '$(1)' | Out-Null"
endef

define RM_RF
powershell -NoProfile -Command "if (Test-Path '$(1)') { Remove-Item -Recurse -Force -LiteralPath '$(1)' }"
endef
else
define MKDIR_P
mkdir -p $(1)
endef

define RM_RF
rm -rf $(1)
endef
endif

help:
	@echo "Targets:"
	@echo "  lint        Check gofmt and run go vet"
	@echo "  test        Run unit, mutation, and deterministic-output tests"
	@echo "  build       Build the local Procrustes CLI"
	@echo "  smoke       Analyze the checked-in ready fixture"
	@echo "  run-checks  Run lint + test + build + smoke"
	@echo "  clean       Remove generated binaries and local output"

lint:
	@fmt_out="$$(gofmt -l $$(git ls-files -co --exclude-standard -- '*.go'))"; \
	if [ -n "$$fmt_out" ]; then \
		echo "gofmt required for:"; \
		echo "$$fmt_out"; \
		exit 1; \
	fi
	$(GO) vet ./...

test:
	$(GO) test ./...

build:
	$(call MKDIR_P,$(BIN_DIR))
	$(GO) build -trimpath -o $(BIN) ./cmd/procrustes

smoke: build
	$(BIN) analyze --source ready=testdata/ready --goal testdata/ready/goal.yaml --out-dir $(OUT_DIR) --fail-on-blocked

run-checks: lint test build smoke

clean:
	$(call RM_RF,$(BIN_DIR))
	$(call RM_RF,.tmp)
	$(call RM_RF,out)
