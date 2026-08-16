# SPDX-License-Identifier: Apache-2.0
#
# LuCI application: luci-app-xpon
#
# Web UI for the EN7581 xpon-portable PON driver (kmod-xpon-portable).
# Configures SN / password / PON mode and displays optical monitoring
# (RX/TX power, temperature, LOS, ONU activation state, TCONT counters).

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-xpon
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=xg040
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

LUCI_TITLE:=Airoha EN7581 XPON PON management
LUCI_DEPENDS:=+kmod-xpon-portable +omcid +luci-compat
LUCI_PKGARCH:=all

# For luci.mk based builds (when luci feed is present). Falls through to
# the plain BuildPackage below if luci.mk is unavailable in this tree.
ifneq ($(wildcard ../../luci/luci.mk),)
include ../../luci/luci.mk
else
include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=$(LUCI_TITLE)
  DEPENDS:=$(LUCI_DEPENDS)
  PKGARCH:=$(LUCI_PKGARCH)
endef

define Package/$(PKG_NAME)/description
  LuCI web UI for the EN7581 PON driver. Configures ONU SN/password/mode
  and displays optical power, temperature, LOS, activation state.
endef

define Build/Compile
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/network
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/network/xpon.js \
		$(1)/www/luci-static/resources/view/network/xpon.js
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./root/usr/share/rpcd/acl.d/luci-app-xpon.json \
		$(1)/usr/share/rpcd/acl.d/luci-app-xpon.json
	$(INSTALL_DIR) $(1)/usr/share/rpcd
	$(INSTALL_BIN) ./root/usr/share/rpcd/luci.xpon \
		$(1)/usr/share/rpcd/luci.xpon
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./root/etc/uci-defaults/luci-app-xpon \
		$(1)/etc/uci-defaults/luci-app-xpon
endef

define Package/$(PKG_NAME)/conffiles
/etc/config/xpon
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
endif
