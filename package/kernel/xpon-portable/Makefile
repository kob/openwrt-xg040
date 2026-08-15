# SPDX-License-Identifier: GPL-2.0
#
# OpenWrt package: kmod-xpon-portable
#
# Reverse-engineered, SOURCE-BASED XPON driver for the Airoha EN7581
# (AN7581DT) found in the Nokia/Barrot XG-040G-MD GPON optical modem.
#
# Unlike the prebuilt kmod-xpon package (which ships the vendor .ko binaries
# that only load on the stock 5.4.55 kernel with the proprietary ecnt_hooks /
# frame_engine framework), THIS package compiles the driver from source against
# whatever kernel OpenWrt is building (the KernelPackage infrastructure supplies
# $(LINUX_DIR), ARCH, CROSS_COMPILE and vermagic automatically).
#
# The resulting module (xpon.ko) is intentionally NOT autoloaded by this
# package: the companion xpon-portable-config init.d script loads it with the
# correct PON mode / EPON LLID MAC so the identity is set at insmod time.
#
# Build:
#   make package/kernel/xpon-portable/compile V=s
# Result:
#   bin/targets/.../kmod-xpon-portable_*.ipk  (contains xpon.ko)

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
  # No AUTOLOAD: xpon-portable-config loads it explicitly with module params.
  DEPENDS:=@TARGET_airoha
endef

define KernelPackage/xpon-portable/description
  Reverse-engineered source driver for the Airoha EN7581 (AN7581DT) XPON /
  GPON / EPON / XGS-PON / 10G-EPON block used in the XG-040G-MD optical modem.

  Reproduces the vendor xpon.ko userspace ABI (the "epon_mac" and "PON MCI"
  char devices plus the PON netdevice ioctl) so existing userland tools such
  as ponmgr keep working.

  Compiles from source against the active OpenWrt kernel (no dependency on the
  stock 5.4.55 tree or the proprietary ecnt_hooks / frame_engine framework).

  NOTE: register programming is register-accurate but the optical link is NOT
  yet brought up by this driver alone -- the SERDES/PCS line training and the
  OMCI daemon must also be present. See the feed README.
endef

# Copy the module sources (src/) into the build dir, then build as an
# out-of-tree kmod via the active kernel's Kbuild.
define Build/Prepare
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(LINUX_MAKE_FLAGS) \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		M="$(PKG_BUILD_DIR)" \
		modules
endef

$(eval $(call KernelPackage,xpon-portable))
