.DEFAULT_GOAL := rdebootstrap

CARGO ?= cargo
PODMAN ?= podman
RDEBOOTSTRAP := $(CURDIR)/target/debug/rdebootstrap
DOWNLOADS ?= 10

DISTROS := debian ubuntu
debian_suffix := deb
ubuntu_suffix := ubuntu

version:
	$(eval ver=$(shell bash -euo pipefail -c ' \
	ver=$$(git describe --tags --match "v*" | sed -e "s%^v%%"); \
	ref_type="$${GITHUB_REF_TYPE:-}"; \
	ref_name="$${GITHUB_REF_NAME:-}"; \
	if ! { \
		[[ "$$ref_type" == "branch" && "$$ref_name" == "develop" ]] || \
		{ [[ "$$ver" =~ ^[0-9]+[0-9\.]+$$ ]] && ! [[ "$$ref_type" == "tag" && "$$ref_name" =~ ^testing ]]; }; \
	}; then \
		ver="$$ver+$${GITHUB_RUN_ID:-$$(date +%s)}"; \
	fi; \
	[[ -z "$$(git status --porcelain)" ]] || ver="$$ver+untracked"; \
	echo $$ver \
	'))
	@bash -euo pipefail -c ' \
	ref_type="$${GITHUB_REF_TYPE:-}"; \
	ref_name="$${GITHUB_REF_NAME:-}"; \
	ver="$(ver)"; \
	if { [[ "$$ref_type" != "tag" ]] || ! [[ "$$ref_name" =~ ^debian/ ]]; } && \
		[[ "$$ver" =~ ^[0-9]+[0-9\.]+$$ ]]; then \
			echo "Building release version with non-release pipeline. This pipeline should have been skipped."; \
			exit 1; \
	fi \
	'
	@echo "Debian version: ${ver}"

rdebootstrap:
	@echo "Building rdebootstrap binary" ;\
	$(CARGO) build -p rdebootstrap --release

$(RDEBOOTSTRAP):
	@$(CARGO) build -p rdebootstrap

.PHONY: $(RDEBOOTSTRAP) rdebootstrap packages

define DISTRO_template

$(CURDIR)/target/$(1)-build:
	@mkdir -p "$$@" "$$@/src" "$$@/target"

$(CURDIR)/target/$(1)-build/.spec-id: $(CURDIR)/$(1)-build.toml $(CURDIR)/target/$(1)-build $(RDEBOOTSTRAP)
	@$(RDEBOOTSTRAP) -m "$$<" show spec-hash > "$$@"

$(1)-tree: $(CURDIR)/target/$(1)-build/.spec-id
	@command -v $(PODMAN) >/dev/null 2>&1 || { echo "podman is required but not installed."; exit 1; }
	@TREE="$$(<D)/$$$$(cat "$$<")"; \
	echo "Creating the target directory"; \
	if [ ! -d "$$$$TREE" ]; then \
		echo "Building the tree"; \
		podman unshare $(RDEBOOTSTRAP) -n $(DOWNLOADS) -m $(CURDIR)/$(1)-build.toml build --path "$$$$TREE"; \
	fi

$(1)-packages: $(CURDIR)/target/$(1)-build/.spec-id $(1)-tree version
	@command -v $(PODMAN) >/dev/null 2>&1 || { echo "podman is required but not installed."; exit 1; }
	@command -v dpkg-parsechangelog >/dev/null 2>&1 || { echo "dpkg-parsechangelog is required but not installed."; exit 1; }
	@TREE="$$(<D)/$$$$(cat "$$<")"; \
	echo "Running the package builder"; \
	version=$$$$(dpkg-parsechangelog -SVersion); \
	dist=$$$$(dpkg-parsechangelog -SDistribution); \
	maint=$$$$(dpkg-parsechangelog -SMaintainer); \
	if [ -z "$$$$version" ] || [ -z "$$$$dist" ] || [ -z "$$$$maint" ]; then \
		echo "Failed to read changelog metadata (version/distribution/maintainer)" >&2; \
		exit 1; \
	fi; \
	suffix="$($(1)_suffix)"; \
	if [ "v$$(ver)" != "$$$$version" ]; then \
		version="v$$(ver)"; \
	fi; \
	case "$$$$version" in \
		*+$$$$suffix[0-9]*) new_version="$$$$version" ;; \
		*) new_version="$$$$version+$$$$suffix""1" ;; \
	esac; \
	if [ "$$$$dist" = "UNRELEASED" ]; then \
		dch_mode=update; \
	else \
		dch_mode=new; \
		dch_message="$(1) package build"; \
	fi; \
	cp debian/changelog debian/orig-changelog; \
	trap 'mv debian/orig-changelog debian/changelog || true' EXIT; \
	echo $(PODMAN) run --rm --systemd=always \
		--volume "$$(<D):/root/build" \
		--volume "$$(CURDIR):/root/build/src" \
		--volume "$$(<D)/target:/root/build/src/target" \
		--workdir /root/build/src \
		--env DCH_MODE="$$$$dch_mode" \
		--env DCH_DIST="$$$$dist" \
		--env DCH_NEW_VERSION="$$$$new_version" \
		--env DCH_MESSAGE="$$$$dch_message" \
		--env DEBEMAIL="$$$$maint" \
		--rootfs "$$$$TREE:O" \
		/bin/sh -ec ' \
			case "$$$$DCH_MODE" in \
				update) \
					dch -m -v "$$$$DCH_NEW_VERSION" -D UNRELEASED "" ;; \
				new) \
					dch -b -m -v "$$$$DCH_NEW_VERSION" -D "$$$$DCH_DIST" "$$$$DCH_MESSAGE" ;; \
				*) \
					echo "Unknown DCH_MODE=$$$$DCH_MODE" >&2; \
					exit 1 ;; \
			esac; \
			dpkg-buildpackage -us -uc -b'

packages: $(1)-packages

.PHONY: $(1)-tree $(1)-packages
endef

$(foreach distro,$(DISTROS),$(eval $(call DISTRO_template,$(distro))))
