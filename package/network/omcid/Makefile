# SPDX-License-Identifier: Apache-2.0
#
# OpenWrt package: omcid
#
# G.988 OMCI daemon (airoha-omcid) for the Airoha EN7581 (XG-040G-MD).
# Talks to the xpon-portable kernel driver through /dev/airoha-xgs-omcc
# using the airoha-omci "device" transport backend.
#
# BUILD REQUIREMENT: a Go 1.24+ toolchain on the build host
#   (e.g. `apt install golang-go` inside the OpenWrt build VM/container).
# The sources ship a vendor/ tree, so no network access is needed at build
# time. We cross-compile with CGO disabled (pure-Go, no cgo deps).

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk

PKG_NAME:=omcid
PKG_VERSION:=0.1
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=xg040

define Package/omcid
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Airoha EN7581 OMCI daemon (airoha-omcid)
  DEPENDS:=+kmod-xpon-portable
endef

define Package/omcid/description
  G.988 OMCI stack for the Airoha EN7581 (XG-040G-MD). Connects to the
  xpon-portable kernel driver through /dev/airoha-xgs-omcc (the airoha-omci
  "device" transport backend) and implements the ONU MIB / management.

  Requires a Go 1.24+ toolchain on the build host (vendor/ is bundled, build
  is offline). Loads only after kmod-xpon-portable has created the OMCC
  character device.
endef

# Copy the Go module (cmd/ internal/ + vendored deps) into the build dir.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	cd $(PKG_BUILD_DIR) && \
		GOARCH=arm64 GOOS=linux CGO_ENABLED=0 \
		go build -mod=vendor -trimpath -o omcid ./cmd/airoha-omcid
endef

define Package/omcid/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/omcid $(1)/usr/sbin/omcid
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/omcid.init $(1)/etc/init.d/omcid
	$(INSTALL_BIN) ./files/xpon.init $(1)/etc/init.d/xpon
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/omcid.config $(1)/etc/config/omcid
	$(INSTALL_CONF) ./files/xpon.config $(1)/etc/config/xpon
endef

$(eval $(call BuildPackage,omcid))
