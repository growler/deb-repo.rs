.DEFAULT_GOAL := rdebootstrap

CARGO ?= cargo
PODMAN ?= podman
RDEBOOTSTRAP := $(CURDIR)/target/release/rdebootstrap

DISTROS := debian ubuntu

rdebootstrap:
	@echo "Building rdebootstrap binary"
	$(CARGO) build --release

.PHONY: rdebootstrap

define DISTRO_template

$(CURDIR)/target/$(1)-build:
	@mkdir -p "$$@" "$$@/src" "$$@/target"

$(CURDIR)/target/$(1)-build/.spec-id: $(CURDIR)/$(1)-build.toml $(CURDIR)/target/$(1)-build rdebootstrap
	@$(RDEBOOTSTRAP) -m "$$<" show spec-hash > "$$@"

$(1)-tree: $(CURDIR)/target/$(1)-build/.spec-id
	@TREE="$$(<D)/$$$$(cat "$$<")"; \
	echo "Creating the target directory"; \
	if [ ! -d "$$$$TREE" ]; then \
		echo "Building the tree"; \
		$(RDEBOOTSTRAP) -m $(CURDIR)/$(1)-build.toml build --path "$$$$TREE"; \
	fi

$(1)-packages: $(CURDIR)/target/$(1)-build/.spec-id $(1)-tree
	@command -v $(PODMAN) >/dev/null 2>&1 || { echo "podman is required but not installed."; exit 1; }
	@TREE="$$(<D)/$$$$(cat "$$<")"; \
	echo "Running the package builder"; \
	$(PODMAN) run --rm --systemd=always \
		--volume "$$(<D):/root/build" \
		--volume "$$(CURDIR):/root/build/src" \
		--volume "$$(<D)/target:/root/build/src/target" \
		--workdir /root/build/src \
		--rootfs "$$$$TREE:O" \
		dpkg-buildpackage -us -uc -b

.PHONY: $(1)-tree $(1)-packages
endef

$(foreach distro,$(DISTROS),$(eval $(call DISTRO_template,$(distro))))
