.PHONY: all build clean test phase2 phase3

BUILD_DIR ?= build
CONFIG ?= Release

all: build

build:
	@mkdir -p "$(BUILD_DIR)"
	@cmake -S . -B "$(BUILD_DIR)" -DCMAKE_BUILD_TYPE="$(CONFIG)"
	@cmake --build "$(BUILD_DIR)" -- -j$$(nproc)

phase2: build
	@"$(BUILD_DIR)/cpp-cloudflared" --phase2

phase3: build
	@"$(BUILD_DIR)/cpp-cloudflared" --phase3

test: build
	@ctest --test-dir "$(BUILD_DIR)" --output-on-failure || true

clean:
	@rm -rf "$(BUILD_DIR)"


