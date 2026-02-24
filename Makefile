.DEFAULT_GOAL := rdebootstrap

CARGO ?= cargo
PODMAN ?= podman
RDEBOOTSTRAP := $(CURDIR)/target/debug/rdebootstrap
DOWNLOADS ?= 10
MANPAGES_DIR := $(CURDIR)/target/man
DISTROS := debian ubuntu
debian_suffix := deb
ubuntu_suffix := ubuntu

version:
	@command -v dpkg-parsechangelog >/dev/null 2>&1 || { echo "dpkg-parsechangelog is required but not installed."; exit 1; }
	$(eval ver=$(shell bash -euo pipefail -c ' \
	full=$$(git describe --tags --match "v*" 2>/dev/null || true); \
	base=$$(echo "$$full" | sed -e "s%^v%%"); \
	debver=$$(dpkg-parsechangelog -SVersion); \
	if [ "$$base" = "$$debver" ]; then \
		ver="$$debver"; \
	elif [ -z "$$full" ]; then \
		ver="$$debver~pre$$(date +%s)+$$(git rev-parse --short HEAD)"; \
		[[ -z "$$(git status --porcelain)" ]] || ver="$$ver+untracked"; \
	else \
		tag=$$(git describe --tags --match "v*" --abbrev=0); \
		suffix=$${full#$$tag-}; \
		ver="$$debver~pre$$suffix"; \
		[[ -z "$$(git status --porcelain)" ]] || ver="$$ver+$$(date +%s)+untracked"; \
	fi; \
	echo $$ver \
	'))
	@echo "Debian version: ${ver}"

manpages:
	@echo "Generating binary manpages" ;\
	$(CARGO) xtask build-man

rdebootstrap:
	@echo "Building rdebootstrap binary" ;\
	$(CARGO) build -p rdebootstrap --release

$(RDEBOOTSTRAP):
	@$(CARGO) build -p rdebootstrap

.PHONY: $(RDEBOOTSTRAP) rdebootstrap packages

define DISTRO_template

$(CURDIR)/target/$(1)-tree/.spec-id: $(CURDIR)/$(1)-build.toml $(RDEBOOTSTRAP)
	@mkdir -p $$(@D) && $(RDEBOOTSTRAP) -m "$$<" show spec-hash > "$$@"

$(1)-tree: $(CURDIR)/target/$(1)-tree/.spec-id
	@command -v $(PODMAN) >/dev/null 2>&1 || { echo "podman is required but not installed."; exit 1; }
	@TREE="$$(<D)/$$$$(cat "$$<")"; \
	echo "Creating the target directory"; \
	if [ ! -d "$$$$TREE" ]; then \
		echo "Building the tree"; \
		podman unshare $(RDEBOOTSTRAP) -n $(DOWNLOADS) -m $(CURDIR)/$(1)-build.toml build --path "$$$$TREE"; \
		podman unshare chown -R "0:0" "$$$$TREE"; \
	fi

$(1)-packages: $(CURDIR)/target/$(1)-tree/.spec-id $(1)-tree version manpages
	@command -v $(PODMAN) >/dev/null 2>&1 || { echo "podman is required but not installed."; exit 1; }
	@command -v dpkg-parsechangelog >/dev/null 2>&1 || { echo "dpkg-parsechangelog is required but not installed."; exit 1; }
	@TREE="$$(<D)/$$$$(cat "$$<")"; \
	echo "Running the package builder"; \
	dist=$$$$(dpkg-parsechangelog -SDistribution); \
	maint=$$$$(dpkg-parsechangelog -SMaintainer); \
	version="$$(ver)+$($(1)_suffix)1"; \
	if [ "$$$$dist" = "UNRELEASED" ]; then \
		dch_mode=update; \
	else \
		dch_mode=new; \
		dch_message="$(1) package build"; \
	fi; \
	cp debian/changelog debian/orig-changelog; \
	trap 'mv debian/orig-changelog debian/changelog || true' EXIT; \
	$(PODMAN) run --rm --systemd=always \
		--volume "$$(CURDIR)/target:/root/build" \
		--volume "$$(CURDIR):/root/build/src" \
		--workdir /root/build/src \
		--env CARGO_HOME=/root/build/cargo-home \
		--env DCH_MODE="$$$$dch_mode" \
		--env DCH_DIST="$$$$dist" \
		--env DCH_NEW_VERSION="$$$$version" \
		--env DCH_MESSAGE="$$$$dch_message" \
		--env DEBEMAIL="$$$$maint" \
		--rootfs "$$$$TREE:O" \
		/bin/sh -ec ' \
			case "$$$$DCH_MODE" in \
				update) \
					dch -b -m -v "$$$$DCH_NEW_VERSION" -D UNRELEASED "" ;; \
				new) \
					dch -m -v "$$$$DCH_NEW_VERSION" -D "$$$$DCH_DIST" "$$$$DCH_MESSAGE" ;; \
				*) \
					echo "Unknown DCH_MODE=$$$$DCH_MODE" >&2; \
					exit 1 ;; \
			esac; \
			dpkg-buildpackage --no-sign -B -tc'

packages: $(1)-packages

.PHONY: $(1)-tree $(1)-packages
endef

$(foreach distro,$(DISTROS),$(eval $(call DISTRO_template,$(distro))))
