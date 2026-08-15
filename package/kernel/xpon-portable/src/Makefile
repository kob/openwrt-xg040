# SPDX-License-Identifier: GPL-2.0
#
# kbuild Makefile for the EN7581 (AN7581DT) XPON driver (reverse-engineered
# portable source). Builds a single module: xpon.ko
#
# --- Standalone build (needs a configured kernel tree) ---------------
#   export ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
#   make -C /path/to/linux-5.4.55 M=$(PWD) modules
#
# --- OpenWrt build --------------------------------------------------
#   This file is invoked by the package Makefile (KDIR = $(LINUX_DIR)).
#   Lives at package/kernel/xpon-portable/src/Makefile in the feed.

obj-m += xpon.o

xpon-y := core/xpon_main.o \
          core/xpon_mci.o \
          core/xpon_epon.o \
          core/xpon_gpon.o \
          core/xpon_phy.o \
          core/xpon_ploam.o \
          core/xpon_act.o \
          core/xpon_netdev.o \
          core/xpon_omcc.o \
          core/xpon_gem.o \
          core/xpon_qdma.o

ccflags-y := -I$(src)/include
