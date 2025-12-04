.PHONY: rdebootstrap spec-id debian-tree debian-packages

.DEFAULT_GOAL := rdebootstrap

CARGO ?= cargo
PODMAN ?= podman
BUILD_DIR := $(CURDIR)/target/debian-build
SPEC_FILE := debian-build.toml
RDEBOOTSTRAP := ./target/release/rdebootstrap
SPEC_ID_FILE := $(BUILD_DIR)/.spec-id

rdebootstrap:
	@echo "Building rdebootstrap binary"
	$(CARGO) build --release

$(SPEC_ID_FILE): $(SPEC_FILE) rdebootstrap
	@mkdir -p "$(BUILD_DIR)"
	@$(RDEBOOTSTRAP) -m $(SPEC_FILE) show spec-hash > "$(SPEC_ID_FILE)"

spec-id: $(SPEC_ID_FILE)
	@cat "$(SPEC_ID_FILE)"

debian-tree: spec-id
	@SPEC_ID=$$(cat "$(SPEC_ID_FILE)"); \
	echo "Creating the target directory"; \
	mkdir -p "$(BUILD_DIR)/src" "$(BUILD_DIR)/target"; \
	if [ ! -d "$(BUILD_DIR)/$$SPEC_ID" ]; then \
		echo "Building the tree"; \
		$(RDEBOOTSTRAP) -m $(SPEC_FILE) build --path "$(BUILD_DIR)/$$SPEC_ID"; \
	fi

debian-packages: spec-id debian-tree
	@command -v $(PODMAN) >/dev/null 2>&1 || { echo "podman is required but not installed."; exit 1; }
	@SPEC_ID=$$(cat "$(SPEC_ID_FILE)"); \
	echo "Running the package builder"; \
	$(PODMAN) run --rm --systemd=always \
		--volume "$(BUILD_DIR):/root/build" \
		--volume "$(CURDIR):/root/build/src" \
		--volume "$(BUILD_DIR)/target:/root/build/src/target" \
		--workdir /root/build/src \
		--rootfs "$(BUILD_DIR)/$$SPEC_ID" \
		dpkg-buildpackage -us -uc -b
