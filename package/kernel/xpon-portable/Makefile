# SPDX-License-Identifier: GPL-2.0
#
# OpenWrt package: kmod-xpon-portable
#
# Reverse-engineered, SOURCE-BASED XPON driver for the Airoha EN7581
# (AN7581DT) found in the XG-040G-MD GPON optical modem.
#
# Compiles the driver from source against whatever kernel OpenWrt is building
# (the KernelPackage infrastructure supplies $(LINUX_DIR), ARCH, CROSS_COMPILE
# and vermagic automatically). On the an7581 target this is Linux 6.18, so the
# module is built for that kernel — it does NOT depend on the stock 5.4.55
# vendor tree or the proprietary ecnt_hooks / frame_engine framework.
#
# Register programming status (as of this revision):
#   * Airoha QDMA OMCI/OAM path (TX queue 7 / RX ring 15) is REAL, ported from
#     airoha_kernel airoha_eth.c / airoha_xpon.c.
#   * GEM sniffer engine (G_OMCI_ID@0x4048, 0x437c, 0x4394) is REAL, verified
#     against re/bitfields.json (vendor xpon.ko disassembly).
#   * FE CDM2 OAM_QSEL routing (ring 15) is programmed so downstream OAM is
#     actually received.
#   * PLOAM / activation state machine / SN / password / TCONT are REAL.
#   * SERDES/PCS link training and the G.988 OMCI protocol stack are NOT done.
#
# Install:
#   (this directory lives at package/kernel/xpon-portable)
#   make menuconfig   # Kernel modules -> Network Devices -> kmod-xpon-portable
#   make package/kernel/xpon-portable/compile

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=xpon-portable
PKG_VERSION:=0.2
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/xpon-portable
  SUBMENU:=Network Devices
  TITLE:=Airoha EN7581 (AN7581DT) XPON driver (reverse-engineered source)
  FILES:=$(PKG_BUILD_DIR)/xpon.ko
  AUTOLOAD:=$(call AutoLoad,50,xpon)
  DEPENDS:=@TARGET_airoha
endef

define KernelPackage/xpon-portable/description
  Reverse-engineered source driver for the Airoha EN7581 (AN7581DT) XPON /
  GPON / EPON block used in the XG-040G-MD optical modem.

  Reproduces the vendor xpon.ko userspace ABI (the "epon_mac" and "PON MCI"
  char devices plus the PON netdevice ioctl) so existing userland tools keep
  working, and implements the Airoha QDMA OMCI/OAM data path and GEM sniffer
  from source against the active OpenWrt kernel (no dependency on the stock
  5.4.55 tree or the proprietary ecnt_hooks / frame_engine framework).

  Loads and exposes the ioctl ABI / char devices / netdevice. Bring-up of the
  optical link still requires the SERDES/PCS training and a G.988 OMCI stack,
  which are not yet implemented.
endef

# Copy the module sources (src/) into the build dir, then build as an
# out-of-tree kmod via the active kernel's Kbuild.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(LINUX_MAKE_FLAGS) \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		SUBDIRS="$(PKG_BUILD_DIR)" \
		modules
endef

$(eval $(call KernelPackage,xpon-portable))
