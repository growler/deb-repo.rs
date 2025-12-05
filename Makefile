.PHONY: rdebootstrap spec-id debian-tree debian-packages

.DEFAULT_GOAL := rdebootstrap

CARGO ?= cargo
PODMAN ?= podman

DEBIAN_SPEC_FILE := debian-build.toml
DEBIAN_BUILD_DIR := $(CURDIR)/target/debian-build
DEBIAN_SPEC_ID_FILE := $(DEBIAN_BUILD_DIR)/.spec-id

UBUNTU_SPEC_FILE := ubuntu-build.toml
UBUNTU_BUILD_DIR := $(CURDIR)/target/ubuntu-build
UBUNTU_SPEC_ID_FILE := $(UBUNTU_BUILD_DIR)/.spec-id

RDEBOOTSTRAP := ./target/release/rdebootstrap

rdebootstrap:
	@echo "Building rdebootstrap binary"
	$(CARGO) build --release

$(DEBIAN_SPEC_ID_FILE): $(DEBIAN_SPEC_FILE) rdebootstrap
	@mkdir -p "$(DEBIAN_BUILD_DIR)"
	@$(RDEBOOTSTRAP) -m $(DEBIAN_SPEC_FILE) show spec-hash > "$(DEBIAN_SPEC_ID_FILE)"

$(UBUNTU_SPEC_ID_FILE): $(UBUNTU_SPEC_FILE) rdebootstrap
	@mkdir -p "$(UBUNTU_BUILD_DIR)"
	@$(RDEBOOTSTRAP) -m $(UBUNTU_SPEC_FILE) show spec-hash > "$(UBUNTU_SPEC_ID_FILE)"

debian-spec-id: $(DEBIAN_SPEC_ID_FILE)
	@cat "$(DEBIAN_SPEC_ID_FILE)"

ubuntu-spec-id: $(UBUNTU_SPEC_ID_FILE)
	@cat "$(UBUNTU_SPEC_ID_FILE)"

debian-tree: debian-spec-id
	@SPEC_ID=$$(cat "$(DEBIAN_SPEC_ID_FILE)"); \
	echo "Creating the target directory"; \
	mkdir -p "$(DEBIAN_BUILD_DIR)/src" "$(DEBIAN_BUILD_DIR)/target"; \
	if [ ! -d "$(DEBIAN_BUILD_DIR)/$$SPEC_ID" ]; then \
		echo "Building the tree"; \
		$(RDEBOOTSTRAP) -m $(DEBIAN_SPEC_FILE) build --path "$(DEBIAN_BUILD_DIR)/$$SPEC_ID"; \
	fi

ubuntu-tree: ubuntu-spec-id
	@SPEC_ID=$$(cat "$(UBUNTU_SPEC_ID_FILE)"); \
	echo "Creating the target directory"; \
	mkdir -p "$(UBUNTU_BUILD_DIR)/src" "$(UBUNTU_BUILD_DIR)/target"; \
	if [ ! -d "$(UBUNTU_BUILD_DIR)/$$SPEC_ID" ]; then \
		echo "Building the tree"; \
		$(RDEBOOTSTRAP) -m $(UBUNTU_SPEC_FILE) build --path "$(UBUNTU_BUILD_DIR)/$$SPEC_ID"; \
	fi

debian-packages: debian-spec-id debian-tree
	@command -v $(PODMAN) >/dev/null 2>&1 || { echo "podman is required but not installed."; exit 1; }
	@SPEC_ID=$$(cat "$(DEBIAN_SPEC_ID_FILE)"); \
	echo "Running the package builder"; \
	$(PODMAN) run --rm --systemd=always \
		--volume "$(DEBIAN_BUILD_DIR):/root/build" \
		--volume "$(CURDIR):/root/build/src" \
		--volume "$(DEBIAN_BUILD_DIR)/target:/root/build/src/target" \
		--workdir /root/build/src \
		--rootfs "$(DEBIAN_BUILD_DIR)/$$SPEC_ID" \
		dpkg-buildpackage -us -uc -b

ubuntu-packages: ubuntu-spec-id ubuntu-tree
	@command -v $(PODMAN) >/dev/null 2>&1 || { echo "podman is required but not installed."; exit 1; }
	@SPEC_ID=$$(cat "$(UBUNTU_SPEC_ID_FILE)"); \
	echo "Running the package builder"; \
	$(PODMAN) run --rm --systemd=always \
		--volume "$(UBUNTU_BUILD_DIR):/root/build" \
		--volume "$(CURDIR):/root/build/src" \
		--volume "$(UBUNTU_BUILD_DIR)/target:/root/build/src/target" \
		--workdir /root/build/src \
		--rootfs "$(UBUNTU_BUILD_DIR)/$$SPEC_ID" \
		dpkg-buildpackage -us -uc -b
