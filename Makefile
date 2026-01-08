# Top-level build helper for this workspace

PLATFORM ?= rk3588
AARCH64 ?= 1
BUILD_DIR ?= cbuild
INIT_BUILD ?= ../init-build.sh
NINJA ?= ninja

.PHONY: all clean configure build rebuild run

all: build

clean:
	@echo "Removing $(BUILD_DIR)"
	@rm -rf $(BUILD_DIR)

configure:
	@mkdir -p $(BUILD_DIR)
	@echo "Configuring PLATFORM=$(PLATFORM) AARCH64=$(AARCH64)"
	@cd $(BUILD_DIR) && $(INIT_BUILD) -DPLATFORM=$(PLATFORM) -DAARCH64=$(AARCH64) -DSel4testApp=hyperamp-server

build: configure
	@echo "Building in $(BUILD_DIR)"
	@$(NINJA) -C $(BUILD_DIR)

rebuild: clean all

run: build
	@echo "Build finished. Artifacts are in $(BUILD_DIR)."