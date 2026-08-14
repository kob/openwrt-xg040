/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xpon.h - internal definitions for the EN7581 (AN7581DT) XPON driver skeleton.
 *
 * Hardware resources below are taken verbatim from the extracted device tree
 * (kernel.dtb -> kernel.dts), node xpon@1fb64000 / pon_phy@1faf0000 /
 * serdes_common_phy@1fa5a000 / xpon_usxgmii@1fa80000.
 *
 * NOTE: this is a reverse-engineering *skeleton*. The register programming
 * inside the *_cmd_proc / eponMac* / gpon* / pon_phy* handlers is STUBBED.
 * Real register layouts require the vendor GPL source or deeper RE.
 */
#ifndef _XPON_H
#define _XPON_H

#include <linux/types.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/platform_device.h>
#include <linux/netdevice.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/phy/phy.h>
#include <linux/regmap.h>
#include <linux/mfd/syscon.h>
#include <linux/bits.h>

#include "xpon_ioctl.h"

/* ----------------------- Register bases (from DTS) ----------------------- */
#define XPON_MAC_BASE		0x1fb64000	/* reg[0] = GPON sub-block (GPON_REG_OFFSET 0x4000) */
#define XPON_MAC_SIZE		0x3e8
#define XPON_XGSPON_REG_OFFSET	0x5000	/* XGS-PON MAC engine block within PON MAC window (XGSPON_REG_OFFSET in airoha_xpon.c) */
/* The PON MAC window is shared by three sibling sub-blocks (vendor
 * airoha_xpon.c: GPON_REG_OFFSET 0x4000 / XGSPON_REG_OFFSET 0x5000 /
 * EPON_REG_OFFSET 0x6000). DTS reg[0] only exposes the GPON sub-block
 * (0x1fb64000, size 0x3e8), so the XGS-PON sub-block is mapped directly by
 * the driver at its fixed physical address below -- mac + 0x5000 would land
 * OUTSIDE the GPON ioremap window and fault. */
#define XPON_XGS_BLOCK_BASE	(XPON_MAC_BASE + XPON_XGSPON_REG_OFFSET) /* 0x1fb69000 */
#define XPON_XGS_BLOCK_SIZE	0x2000
#define XPON_MAC2_BASE		0x1fb66000	/* reg[1] */
#define XPON_MAC2_SIZE		0x23c
#define XPON_MAC3_BASE		0x1fb65000	/* reg[2] */
#define XPON_MAC3_SIZE		0xff8

#define PON_PHY_BASE		0x1faf0000	/* reg[0] */
#define PON_PHY_SIZE		0x1fff
#define PON_PHY_GPIO_BASE	0x1fa2ff24	/* reg[1] (4 bytes) */
#define PON_PHY_AUX0_BASE	0x1faf3000	/* reg[2] */
#define PON_PHY_AUX0_SIZE	0xfff
#define PON_PHY_AUX1_BASE	0x1faf4000	/* reg[3] */
#define PON_PHY_AUX1_SIZE	0xfff

#define SERDES_COMMON_BASE	0x1fa5a000
#define SERDES_COMMON_SIZE	0xfff

#define XPON_USXGMII_BASE	0x1fa80000
#define XPON_USXGMII_SIZE	0xff

/* PON protocol-mode switching (mirrors airoha_kernel airoha_xpon.c).
 * The actual line-rate / PCS reconfiguration is performed by the generic
 * SERDES PHY (drivers/phy/airoha/phy-airoha-xpon.c) via phy_set_mode_ext(),
 * and the SoC WAN line path is selected in the SCU. Only GPON and EPON are
 * supported; XG(S)-PON and 10G-EPON need a MAC engine + BOSA optics that are
 * not yet ported (see report §2/§11) -- vendor airoha_eth_set_xpon_mode() also
 * rejects anything other than GPON/EPON. */
#define XPON_SCU_WAN_CONF\t\t0x070\t/* offset in airoha,en7581-scu syscon */
#define XPON_SCU_WAN_MODE_MASK\tGENMASK(7, 0)
#define XPON_SCU_WAN_MODE_GPON\t0x00
#define XPON_SCU_WAN_MODE_EPON\t0x01
/* submodes for phy_set_mode_ext(phy, PHY_MODE_ETHERNET, submode) */
#define XPON_PHY_SUBMODE_GPON\t0
#define XPON_PHY_SUBMODE_EPON\t1

/* Interrupt lines from DTS (GIC SPI numbers). */
#define XPON_IRQ_0		42	/* 0x2a */
#define XPON_IRQ_1		34	/* 0x22 */

/* ----------------------- Driver state ----------------------- */
/* Global handle, defined in xpon_main.c, referenced by sub-modules. */
extern struct xpon_dev *g_xp;

struct gpon_priv;

struct xpon_dev {
	struct device		*dev;

	/* ioremapped register spaces */
	void __iomem		*mac;
	void __iomem		*mac2;
	void __iomem		*mac3;
	void __iomem		*pon_phy;
	void __iomem		*pon_phy_aux0;
	void __iomem		*pon_phy_aux1;
	void __iomem		*serdes;
	void __iomem		*xpon_usxgmii;

	int			irq[2];

	/* char devices exposed to userspace */
	struct cdev		epon_mac_cdev;	/* "epon_mac"   fops=eponMacFops   */
	struct cdev		mci_cdev;	/* "PON MCI"    fops=xmci_fops     */
	struct cdev		omcc_cdev;	/* "airoha-xgs-omcc" omcid transport */
	struct class		*cls;
	dev_t			epon_mac_devt;
	dev_t			mci_devt;
	dev_t			omcc_devt;

	/* secure OMCC RX queue (xpon_omcc.c): FIFO of 12-byte-header + OMCI
	 * message records handed to read(). */
	struct list_head	omcc_rx_q;
	spinlock_t		omcc_rx_lock;
	wait_queue_head_t	omcc_rx_wait;
	atomic_t		omcc_rx_enq;
	atomic_t		omcc_rx_drop;
	atomic_t		omcc_tx;

	/* PON netdevice (xpon_netdev_ops) */
	struct net_device	*netdev;

	enum xpon_mode		mode;		/* GPON/EPON/... */
	bool			probed;

	struct mutex		lock;

	/* GPON activation state machine (xpon_gpon.c / xpon_ploam.c) */
	struct gpon_priv	*gpon;

	/* Airoha/EN7581 QDMA engine private state (xpon_qdma.c) */
	void		*qdma;

	/* Protocol-mode switching resources (xpon_phy.c). Both are optional:
	 * if the kernel ships drivers/phy/airoha/phy-airoha-xpon.c the PCS
	 * line-rate is reconfigured via xpon_serdes_phy; the SCU selects the WAN
	 * line path. Absent => the switch is delegated to the mainline PCS driver
	 * and a warning is logged. */
	struct phy		*xpon_serdes_phy;
	struct regmap		*scu;
	void __iomem		*xgspon_reg;	/* XGS-PON MAC engine (mac + 0x5000) */
	bool			serdes_phy_init;
	bool			serdes_phy_powered;
};

/* ----------------------- GPON MAC registers ---------------------------------
 * Recovered from the stock xpon.ko and cross-validated (117/126 offsets, 92.9%)
 * against the open-source econet-xpon header
 * gpon_mac_reg_c_header_en7521.h, which declares the *same* global symbol name
 * `g_gpon_mac_reg_BASE`. Register names below are that header's names.
 *
 * How the offsets were established
 * --------------------------------
 * In an unlinked .ko every `adrp` disassembles with imm=0, so the only way to
 * know which global a base pointer came from is `.rela.text`. Relocations show
 * hardware is touched exclusively through `g_gpon_mac_reg_BASE`, via the
 * helpers get_xpon_data() (read) / set_xpon_data() (write):
 *
 *   adrp x0, g_gpon_mac_reg_BASE
 *   ldr  x1, [x0]            ; ioremap'd base
 *   mov  x0, #0x40b4         ; register offset
 *   add  x0, x1, x0
 *   bl   set_xpon_data
 *
 * Base convention: `g_gpon_mac_reg_BASE` maps 0x1fb60000, so header offset
 * 0x4000 == physical 0x1fb64000 == DTS reg[0]. All 126 recovered offsets fall
 * inside the single 0x4000 page, and the header's 119 registers span
 * 0x4000..0x43c8, which fits DTS reg[0] (size 0x3e8). Therefore reg[0] *is* the
 * whole GPON MAC block, and driver-relative offset = header offset - 0x4000.
 *
 * IMPORTANT correction to earlier revisions of this driver
 * -------------------------------------------------------
 * A previous version wrote the SN to `mac + 0x1dd` and the password to
 * `mac + 0x1e8`. Those offsets are WRONG: they are field offsets inside
 * `gpGponPriv`, the stock driver's *software* private struct, not registers.
 * Ground truth from xmcs_set_sn_passwd (@0x545cc) is `adrp x0, gpGponPriv`.
 * Likewise the old TCONT counter maths came from `get_counter_from_reg`, which
 * dereferences `gpWanPriv` -- also software state, not hardware.
 */
#define GPON_REG_WINDOW_OFF	0x4000	/* header offset of DTS reg[0] */
#define GPON_REG(hdr_off)	((hdr_off) - GPON_REG_WINDOW_OFF)

/* Bit-field layouts below come from the econet-xpon header's little-endian
 * (`#else`) arm; ARM64 is little-endian. Offsets are additionally confirmed by
 * econet-xpon debug code that pokes the same registers by absolute address:
 * `IO_GREG(0xbfb640bcu) & 0xf` for the activation state (physical 0x1fb640bc =
 * header 0x40bc) and `0xBFB64300..0xBFB64338` for the counters below.
 */
#define XP_MASK(w)		((1u << (w)) - 1u)
#define XP_GET(v, lo, w)	(((v) >> (lo)) & XP_MASK(w))
#define XP_SET(v, lo, w, x)	(((v) & ~(XP_MASK(w) << (lo))) | \
				 (((u32)(x) & XP_MASK(w)) << (lo)))
#define XP_BIT(n)		(1u << (n))

/* Identity / activation */
#define G_ONU_ID		GPON_REG(0x4000)	/* assigned ONU-ID */
#define  G_ONU_ID_ID_LO		0
#define  G_ONU_ID_ID_W		8
#define  G_ONU_ID_VLD		XP_BIT(15)
#define G_GBL_CFG		GPON_REG(0x4004)	/* global config */
#define  G_GBL_CFG_SR_BLK_LO	0			/* sr_blk_size[7:0] */
#define  G_GBL_CFG_SR_BLK_W	8
#define  G_GBL_CFG_US_FEC_EN	XP_BIT(16)
#define G_VENDOR_ID		GPON_REG(0x40b0)	/* SN bytes [0..3] */
#define G_VS_SN			GPON_REG(0x40b4)	/* SN bytes [4..7] */
#define G_SN_MSG_CFG		GPON_REG(0x40b8)	/* SN PLOAM response cfg */
#define  G_SN_MSG_RDM_DLY_LO	0			/* rdm_dly[11:0] */
#define  G_SN_MSG_RDM_DLY_W	12
#define  G_SN_MSG_TX_PWR_LO	16			/* tx_power_mode[17:16] */
#define  G_SN_MSG_TX_PWR_W	2
#define  G_SN_MSG_REQ_THR_LO	24			/* sn_req_thr[31:24] */
#define  G_SN_MSG_REQ_THR_W	8
#define G_ACTIVATION_ST		GPON_REG(0x40bc)	/* O1..O7 state machine */
#define  G_ACT_ST_LO		0			/* act_st[2:0] */
#define  G_ACT_ST_W		3

/* Interrupts. G_INT_STATUS and G_INT_ENABLE share the same bit assignment;
 * the status register is write-1-to-clear. */
#define G_INT_STATUS		GPON_REG(0x4008)
#define G_INT_ENABLE		GPON_REG(0x400c)
#define  G_INT_PLOAMD_RECV	XP_BIT(0)	/* downstream PLOAM arrived */
#define  G_INT_PLOAMU_SEND	XP_BIT(1)	/* upstream PLOAM sent */
#define  G_INT_SN_REQ_RECV	XP_BIT(2)	/* OLT opened an SN window */
#define  G_INT_SN_SEND_O3	XP_BIT(3)	/* SN burst emitted in O3 */
#define  G_INT_RANGING_REQ	XP_BIT(4)	/* ranging request received */
#define  G_INT_SN_SEND_O4	XP_BIT(5)	/* SN burst emitted in O4 */
#define  G_INT_SN_REQ_CRS	XP_BIT(6)	/* SN request count crossed thr */
#define  G_INT_LOS_GEM_DEL	XP_BIT(7)	/* LOS / GEM deleted */
#define  G_INT_AES_KEY_SW_DONE	XP_BIT(8)
#define  G_INT_TOD_UPD_DONE	XP_BIT(9)
#define  G_INT_TOD_1PPS		XP_BIT(10)
#define  G_INT_DYING_GASP_SENT	XP_BIT(11)
#define  G_INT_RX_ERR		XP_BIT(16)
#define  G_INT_FIFO_ERR		XP_BIT(17)
#define  G_INT_BST_SGL_DIFF	XP_BIT(18)
#define  G_INT_TX_LATE_START	XP_BIT(19)
#define  G_INT_RX_EOF_ERR	XP_BIT(20)
#define  G_INT_RX_GEM_INTLV_ERR	XP_BIT(21)
#define  G_INT_BFIFO_FULL	XP_BIT(22)
#define  G_INT_SFIFO_FULL	XP_BIT(23)
#define  G_INT_O5_EQD_ADJ_DONE	XP_BIT(24)
#define  G_INT_OLT_DS_FEC_CHG	XP_BIT(25)
#define  G_INT_ONU_US_FEC_CHG	XP_BIT(26)
#define  G_INT_POPUP_IN_O6	XP_BIT(27)
#define  G_INT_FWI		XP_BIT(28)
#define  G_INT_LWI		XP_BIT(29)
#define  G_INT_BWM_STOP_TIME_ERR XP_BIT(30)
#define  G_INT_BWM_US_FEC_ERR	XP_BIT(31)

/* Classification masks used by the ISR to route a status word.
 *
 * These mirror econet-xpon's GPON_INT_* groups in gpon_reg.h, which are an
 * independent confirmation of the bit numbering above:
 *   GPON_INT_PLOAM      0x00000003  -> bits 0,1
 *   GPON_INT_TOD        0x00000600  -> bits 9,10
 *   GPON_INT_INDICATION 0x3F00093C  -> bits 2,3,4,5,8,11,24..29
 *   GPON_INT_ERROR      0x40FF00C0  -> bits 6,7,16..23,30
 */
#define GPON_INT_PLOAM		(G_INT_PLOAMD_RECV | G_INT_PLOAMU_SEND)
#define GPON_INT_ACTIVATION	(G_INT_SN_REQ_RECV | G_INT_SN_SEND_O3 | \
				 G_INT_RANGING_REQ | G_INT_SN_SEND_O4 | \
				 G_INT_AES_KEY_SW_DONE | G_INT_DYING_GASP_SENT | \
				 G_INT_O5_EQD_ADJ_DONE | G_INT_OLT_DS_FEC_CHG | \
				 G_INT_ONU_US_FEC_CHG | G_INT_POPUP_IN_O6 | \
				 G_INT_FWI | G_INT_LWI)
#define GPON_INT_ERRORS		(G_INT_SN_REQ_CRS | G_INT_LOS_GEM_DEL | \
				 G_INT_RX_ERR | G_INT_FIFO_ERR | \
				 G_INT_BST_SGL_DIFF | G_INT_TX_LATE_START | \
				 G_INT_RX_EOF_ERR | G_INT_RX_GEM_INTLV_ERR | \
				 G_INT_BFIFO_FULL | G_INT_SFIFO_FULL | \
				 G_INT_BWM_STOP_TIME_ERR)

/* Value written to G_INT_ENABLE at init. Byte-for-byte what the stock
 * gpon_INT_init() programs on EN7521 (0x77ff0bfd):
 *   ploamu_send (bit 1)  OFF - upstream PLOAM completion is polled through
 *                              G_PLOAMu_FIFO_STS.avail, no interrupt needed.
 *   tod_1pps    (bit 10) OFF - no 1PPS consumer in this driver.
 *   popup_in_O6 (bit 27) OFF - POPUP is handled from the downstream PLOAM
 *                              message itself; the stock driver leaves the
 *                              hardware indication masked.
 */
#define GPON_INT_ENABLE_DEFAULT	((GPON_INT_ERRORS | GPON_INT_ACTIVATION | \
				  G_INT_PLOAMD_RECV | G_INT_TOD_UPD_DONE) & \
				 ~G_INT_POPUP_IN_O6)
#define GPON_INT_ENABLE_EXPECT	0x77ff0bfdu	/* compile-time cross-check */

/* PLOAM messaging FIFOs */
#define G_PLOAMu_FIFO_STS	GPON_REG(0x4050)
#define  G_PLOAMU_AVAIL_LO	0		/* ploamu_fifo_avail[7:0] */
#define  G_PLOAMU_AVAIL_W	8
#define  G_PLOAMU_UDRN		XP_BIT(31)
#define G_PLOAMu_WDATA		GPON_REG(0x4054)
#define G_PLOAMd_FIFO_STS	GPON_REG(0x4058)
#define  G_PLOAMD_USED_LO	0		/* ploamd_fifo_used[7:0] */
#define  G_PLOAMD_USED_W	8
#define  G_PLOAMD_OVRN		XP_BIT(31)
#define G_PLOAMd_RDATA		GPON_REG(0x405c)

/* AES */
#define G_AES_CFG		GPON_REG(0x4060)
#define G_AES_ACTIVE_KEY0	GPON_REG(0x4064)	/* .. KEY3 @ 0x4070 */
#define G_AES_SHADOW_KEY0	GPON_REG(0x4074)	/* .. KEY3 @ 0x4080 */
#define G_AES_KEY_SWITCH_BY_SW	GPON_REG(0x4084)

/* OMCI channel (OMCC GEM port) */
#define G_OMCI_ID		GPON_REG(0x4048)
#define  G_OMCI_GPID_LO		0			/* omci_gpid[11:0] */
#define  G_OMCI_GPID_W		12
#define  G_OMCI_VLD		XP_BIT(16)

/* GEM port table (indirect: write CFG, poll STS.cmd_done) */
#define G_GEM_PORT_CFG		GPON_REG(0x4040)
#define  G_GEM_CFG_ID_LO	0			/* gem_port_id[11:0] */
#define  G_GEM_CFG_ID_W		12
#define  G_GEM_CFG_VLD		XP_BIT(16)
#define  G_GEM_CFG_ENCRYPT	XP_BIT(17)
#define  G_GEM_CFG_CMD		XP_BIT(31)
#define G_GEM_PORT_STS		GPON_REG(0x4044)
#define  G_GEM_STS_VLD		XP_BIT(0)
#define  G_GEM_STS_ENCRYPT	XP_BIT(1)
#define  G_GEM_STS_CMD_DONE	XP_BIT(31)
#define G_GEM_TBL_INIT		GPON_REG(0x404c)
#define  G_GEM_TBL_INIT_START	XP_BIT(0)
#define  G_GEM_TBL_INIT_DONE	XP_BIT(8)

/* ----------------------- XGS-PON (10G) GEM/OMCI registers ----------------
 * The XGS-PON MAC engine (xgspon_reg = mac + 0x5000) is a *parallel* of the
 * GPON MAC engine. vendor airoha_xpon.c places GPON@0x4000 / XGS@0x5000 /
 * EPON@0x6000 as three sibling sub-blocks inside the one PON MAC window, and
 * Airoha reuses the identical GEM/OMCI register layout in each sub-block. The
 * offsets below therefore EQUAL the GPON block's relative offsets (0x040/0x044/
 * 0x048/0x04c/0x20c); they are spelled out explicitly so the XGS path is
 * self-documenting and each can be corrected independently on hardware.
 *
 *   >>> MIRRORED FROM THE GPON BLOCK -- VERIFY ON XGS-PON HARDWARE <<<
 * Bit-field meanings are identical to the G_GEM_* / G_OMCI_* definitions
 * above, so the GPON bit-field macros are reused on the XGS base. */
#define XGS_GEM_PORT_CFG	0x040	/* == G_GEM_PORT_CFG relative offset */
#define XGS_GEM_PORT_STS	0x044
#define XGS_OMCI_ID		0x048
#define XGS_GEM_TBL_INIT	0x04c
#define XGS_IDLE_GEM_THLD	0x20c	/* == DBG_IDLE_GEM_THLD relative offset */

/* Upstream physical-layer overhead (programmed from Upstream_Overhead PLOAM) */
#define G_PLOu_OVERHEAD		GPON_REG(0x4090)	/* plou_overhead[7:0] */
#define G_PLOu_GUARD_BIT	GPON_REG(0x4094)	/* guard_bit[7:0] */
#define  G_PLOU_GUARD_LO	0
#define  G_PLOU_GUARD_W		8
#define G_PLOu_PRMBL_TYPE1_2	GPON_REG(0x4098)
#define  G_PLOU_PRMB1_LO	0			/* prmb1_bit[7:0] */
#define  G_PLOU_PRMB1_W		8
#define  G_PLOU_PRMB2_LO	8			/* prmb2_bit[15:8] */
#define  G_PLOU_PRMB2_W		8
#define G_PLOu_PRMBL_TYPE3	GPON_REG(0x409c)
#define  G_PLOU_PRMB3_O34_LO	0		/* ext_prmb3_o3_o4_num[7:0] */
#define  G_PLOU_PRMB3_O34_W	8
#define  G_PLOU_PRMB3_O5_LO	8		/* ext_prmb3_o5_num[15:8] */
#define  G_PLOU_PRMB3_O5_W	8
#define  G_PLOU_PRMB3_EBL_EN	XP_BIT(24)
#define G_PLOu_DELM_BIT		GPON_REG(0x40a0)	/* delm_bit[7:0] */

/* Ranging / delay */
#define G_PRE_ASSIGNED_DLY	GPON_REG(0x40a4)
#define  G_PRE_DLY_LO		0			/* pre_dly[15:0] */
#define  G_PRE_DLY_W		16
#define  G_PRE_DLY_EN		XP_BIT(31)
#define G_EQD			GPON_REG(0x40a8)	/* eqd[31:0] */
#define G_RSP_TIME		GPON_REG(0x40ac)	/* tresp[15:0] */
#define  G_RSP_TIME_LO		0
#define  G_RSP_TIME_W		16

/* T-CONT / Alloc-ID mapping: 16 T-CONTs packed two per 32-bit register
 * (G_TCONT_ID_0_1 .. G_TCONT_ID_14_15), then a cfg/sts pair for 16..31.
 *   even T-CONT: t_cont0_id[11:0]  t_cont0_vld[15]
 *   odd  T-CONT: t_cont1_id[27:16] t_cont1_vld[31]
 * The Alloc-ID field is 12 bits wide. (An earlier revision masked with 0x7fff;
 * 0x7fff is the GEM *index* mask, GPON_GEM_IDX_MASK, and does not apply here.)
 */
#define G_TCONT_ID_BASE		GPON_REG(0x4020)
#define G_TCONT_ID_REGS		8	/* 0x4020..0x403c */
#define GPON_TCONT_PER_REG	2
#define GPON_TCONT_HW_MAX	16	/* covered by the packed registers */
#define GPON_ALLOC_ID_W		12
#define GPON_ALLOC_ID_MASK	XP_MASK(GPON_ALLOC_ID_W)
#define GPON_TCONT_VLD_BIT	15	/* within the selected 16-bit half */
/* T-CONTs 16..31 are not memory-mapped; they go through a cfg/sts command pair
 * (same handshake style as the GEM port table). */
#define G_TCONT_ID_16_31_CFG	GPON_REG(0x4180)
#define  G_TCONT16_WR_ID_LO	0			/* wr_tcont_id[11:0] */
#define  G_TCONT16_WR_ID_W	12
#define  G_TCONT16_IDX_LO	16			/* tcont_id_index[19:16] */
#define  G_TCONT16_IDX_W	4
#define  G_TCONT16_WR_VLD	XP_BIT(27)
#define  G_TCONT16_CMD_WRITE	XP_BIT(31)		/* 1 = write, 0 = read */
#define G_TCONT_ID_16_31_STS	GPON_REG(0x4184)
#define  G_TCONT16_RD_ID_LO	0			/* rd_tcont_id[11:0] */
#define  G_TCONT16_RD_ID_W	12
#define  G_TCONT16_RD_VLD	XP_BIT(16)
#define  G_TCONT16_CMD_DONE	XP_BIT(31)
#define GPON_TCONT_MAX		32	/* CONFIG_GPON_MAX_TCONT in econet-xpon */
#define GPON_MAX_GEM_ID		4096
#define GPON_MAX_ALLOC_ID	4096
#define GPON_UNASSIGN_ONU_ID	0xff
#define GPON_UNASSIGN_ALLOC_ID	0xff
#define GPON_UNASSIGN_GEM_ID	0xffff

/* Table initialisers. All share the same shape: write bit0 to start, poll bit8
 * for done. They wipe the corresponding hardware table in one command, which is
 * why this driver uses them instead of econet-xpon's 4096-iteration loop. */
#define G_TX_FCS_TBL_INIT	GPON_REG(0x4100)
#define G_MIB_TBL_INIT		GPON_REG(0x4134)
#define G_GPIDX_TBL_INIT	GPON_REG(0x4148)
#define  G_TBL_INIT_START	XP_BIT(0)
#define  G_TBL_INIT_DONE	XP_BIT(8)

/* MIB (per-GEM byte/frame counters), indirect read via G_MIB_CTRL_STS */
#define G_MIB_CTRL_STS		GPON_REG(0x4120)
#define G_MIB_RDATA_L32		GPON_REG(0x4124)
#define G_MIB_RDATA_H32		GPON_REG(0x4128)
#define G_MIB_WDATA_L32		GPON_REG(0x412c)
#define G_MIB_WDATA_H32		GPON_REG(0x4130)

/* GEM-port index table (maps GEM port ID -> MIB row) */
#define G_GPIDX_TBL_CTRL	GPON_REG(0x4140)
#define G_GPIDX_TBL_STS		GPON_REG(0x4144)

/* MBI = the bus between the GPON MAC and the frame engine (GDM2/CDM2).
 * Both halves must be stopped around a MAC reset, and started before traffic.
 * 1 = stop, 0 = run. */
#define G_MBI_STOP		GPON_REG(0x4160)
#define  G_MBI_RX_STOP		XP_BIT(0)
#define  G_MBI_TX_STOP		XP_BIT(8)

/* Soft reset of the whole GPON MAC. Active-LOW: write 0 to assert, 1 to
 * release. Mirrors econet-xpon REG_G_GPON_MAC_SET.gpon_mac_sw_rst_n. */
#define DBG_GPON_MAC_SET	GPON_REG(0x43a0)
#define  DBG_GPON_MAC_SW_RST_N	XP_BIT(0)

/* Time-of-day (not used by activation; listed so the window is documented) */
#define G_TOD_CFG		GPON_REG(0x40d0)
#define G_TOD_CLK_PERIOD	GPON_REG(0x40e4)

/* Debug/config block. Despite the DBG_ prefix these carry real configuration:
 * DBG_CAP_SETTING enables the MIB counters, DBG_DLY holds the internal delay
 * fine-tune that ranging accuracy depends on, and DBG_US_DYING_GASP_CTRL
 * decides whether Dying-Gasp is emitted by hardware or software. */
#define DBG_CAP_SETTING		GPON_REG(0x4200)
#define  DBG_CAP_MAX_RDM_DLY_LO	0			/* max_rdm_dly[11:0] */
#define  DBG_CAP_MAX_RDM_DLY_W	12
#define  DBG_CAP_RPT_MSG_FLT	XP_BIT(16)
#define  DBG_CAP_US_NO_MSG_INT	XP_BIT(24)
#define  DBG_CAP_GPON_MIB_EN	XP_BIT(25)
#define  DBG_CAP_MIB_FRAME_TYPE	XP_BIT(26)	/* 0 = GEM, 1 = frame */
#define DBG_DLY			GPON_REG(0x4208)
#define  DBG_DLY_PHY_TX_LO	0			/* phy_tx_dly[7:0] */
#define  DBG_DLY_PHY_TX_W	8
#define  DBG_DLY_FINE_INT_LO	8			/* fine_int_dly[15:8] */
#define  DBG_DLY_FINE_INT_W	8
#define  DBG_DLY_FIX_PHY_RX_LO	16			/* fix_phy_rx_dly[27:16] */
#define  DBG_DLY_FIX_PHY_RX_W	12
#define  DBG_DLY_PHY_RX_SEL	XP_BIT(31)
#define DBG_IDLE_GEM_THLD	GPON_REG(0x420c)
#define  DBG_IDLE_GEM_THLD_LO	0			/* idle_gem_thld[15:0] */
#define  DBG_IDLE_GEM_THLD_W	16
#define DBG_US_NO_MSG0		GPON_REG(0x4210)	/* No_Message template */
#define DBG_US_NO_MSG1		GPON_REG(0x4214)
#define DBG_US_NO_MSG2		GPON_REG(0x4218)
#define DBG_US_DYING_GASP_CTRL	GPON_REG(0x421c)
#define  DBG_DG_MSG_TYPE_LO	0			/* dying_gasp_msg_type[7:0] */
#define  DBG_DG_MSG_TYPE_W	8
#define  DBG_DG_HW_EN		XP_BIT(8)
#define  DBG_DG_TEST		XP_BIT(16)
#define  DBG_DG_NUM_LO		24			/* dying_gasp_num[27:24] */
#define  DBG_DG_NUM_W		4
#define DBG_PLOAMD_FILTER_IN_O5	GPON_REG(0x4360)

/* Defaults lifted from econet-xpon (gpon_const.h / gpon_dev.h) */
#define GPON_IDLE_GEM_THLD_DEF	0x200	/* 0xA0 only on the MT7520 ASIC */
#define GPON_DBA_BLOCK_SIZE_DEF	48
#define GPON_INTERNAL_DLY_DEF	0x1c
#define GPON_TOD_CLK_PERIOD_DEF	0x0a

/* Hardware packet/error counters (read by gpon_isr in the stock driver).
 * Independently confirmed by econet-xpon's gpon_dump_mac_rxcnt(), which reads
 * the same set at absolute 0xBFB64300/04/08/0C/10/30/34/38. */
#define DBG_RX_GEM_CNT		GPON_REG(0x4300)
#define DBG_RX_CRC_ERR_CNT	GPON_REG(0x4304)
#define DBG_RX_GTC_CNT		GPON_REG(0x4308)
#define DBG_TX_GEM_CNT		GPON_REG(0x430c)
#define DBG_TX_BST_CNT		GPON_REG(0x4310)
#define DBG_GEM_HEC_ONE_ERR_CNT	GPON_REG(0x4330)
#define DBG_GEM_HEC_TWO_ERR_CNT	GPON_REG(0x4334)
#define DBG_GEM_HEC_UC_ERR_CNT	GPON_REG(0x4338)

#define GPON_SN_LEN		8
#define GPON_PW_MAX		10

/* ----------------------- Activation state machine -----------------------
 * G.984.3 ONU states. Values match the hardware `act_st` field (3 bits) and
 * the econet-xpon ENUM_GponState_t, which starts at 1.
 *
 * act_st is *software written*: the driver decides the state from downstream
 * PLOAM and tells the MAC, which then gates its upstream behaviour (it only
 * bursts the Serial Number autonomously while act_st == O3, and only allows
 * user traffic in O5).
 */
enum gpon_state {
	GPON_STATE_O1 = 1,	/* initial, no downstream sync */
	GPON_STATE_O2,		/* standby, waiting Upstream_Overhead */
	GPON_STATE_O3,		/* serial number, MAC bursts SN */
	GPON_STATE_O4,		/* ranging, waiting Ranging_Time */
	GPON_STATE_O5,		/* operation, registered */
	GPON_STATE_O6,		/* POPUP */
	GPON_STATE_O7,		/* emergency stop */
};

/* PLOAM message geometry. A GPON PLOAM message is 13 bytes on the wire, the
 * last being a CRC the MAC appends/checks, so software moves 12 bytes = 3
 * 32-bit FIFO words:
 *   byte0 = ONU-ID (downstream: destination; 0xff = broadcast)
 *   byte1 = Message-ID
 *   byte2..11 = payload
 * The first wire byte sits in the *most significant* byte of a FIFO word, so
 * words are packed/unpacked big-endian explicitly rather than by casting a
 * struct (which is what forces the stock driver's swab32 on little-endian).
 */
#define GPON_PLOAM_LEN		12
#define GPON_PLOAM_WORDS	3
#define GPON_PLOAM_BCAST	0xff
#define GPON_PLOAM_OFF_ONU_ID	0
#define GPON_PLOAM_OFF_MSG_ID	1
#define GPON_PLOAM_OFF_PAYLOAD	2

/* Downstream (OLT -> ONU) message IDs, G.984.3 table 11-2 */
#define PLOAM_DS_UPSTREAM_OVERHEAD	0x01
#define PLOAM_DS_ASSIGN_ONU_ID		0x03
#define PLOAM_DS_RANGING_TIME		0x04
#define PLOAM_DS_DEACTIVATE_ONU_ID	0x05
#define PLOAM_DS_DISABLE_SERIAL_NUM	0x06
#define PLOAM_DS_ENCRYPTED_PORT_ID	0x08
#define PLOAM_DS_REQUEST_PASSWORD	0x09
#define PLOAM_DS_ASSIGN_ALLOC_ID	0x0a
#define PLOAM_DS_POPUP			0x0c
#define PLOAM_DS_REQUEST_KEY		0x0d
#define PLOAM_DS_CONFIG_PORT_ID		0x0e
#define PLOAM_DS_PEE			0x0f
#define PLOAM_DS_CPL			0x10
#define PLOAM_DS_PST			0x11
#define PLOAM_DS_BER_INTERVAL		0x12
#define PLOAM_DS_KEY_SWITCHING_TIME	0x13
#define PLOAM_DS_EXTENDED_BURST_LENGTH	0x14
#define PLOAM_DS_PON_ID			0x15
#define PLOAM_DS_SWIFT_POPUP		0x16
#define PLOAM_DS_RANGING_ADJUSTMENT	0x17
#define PLOAM_DS_SLEEP_ALLOW		0x18
#define PLOAM_DS_MAX			0x19

/* Upstream (ONU -> OLT) message IDs */
#define PLOAM_US_SERIAL_NUMBER		0x01
#define PLOAM_US_PASSWORD		0x02
#define PLOAM_US_DYING_GASP		0x03
#define PLOAM_US_NO_MESSAGE		0x04
#define PLOAM_US_ENCRYPTION_KEY		0x05
#define PLOAM_US_PEE			0x06
#define PLOAM_US_PST			0x07
#define PLOAM_US_REI			0x08
#define PLOAM_US_ACKNOWLEDGE		0x09
#define PLOAM_US_SLEEP_REQUEST		0x0a

/* Repeat counts and timers (G.984.3 / stock defaults) */
#define GPON_PLOAM_REPEAT		3	/* upstream messages sent N times */
#define GPON_ACT_TO1_MS			10000	/* O3/O4 timeout -> O2 */
#define GPON_ACT_TO2_MS			100	/* O6 timeout -> O1 */
#define GPON_TO1_RESET_CNT		20	/* TO1 expiries before HW reset */
#define GPON_SN_REQ_THRESHOLD		10	/* G_SN_MSG_CFG.sn_req_thr */
#define GPON_DEFAULT_RSP_TIME		0x577	/* stock G_RSP_TIME.tresp */
#define GPON_EQD_BYTE_MASK		(~0x7u)
#define GPON_EQD_BIT_MASK		(0x7u)
#define GPON_EQD_O5_MAX_DELTA		16	/* ignore larger O5 adjustments */

/* Per-device GPON state. Guarded by `lock`, which is taken from both the
 * interrupt handler and process context, hence spin_lock_irqsave(). */
struct gpon_priv {
	spinlock_t		lock;
	enum gpon_state		state;

	u8			sn[GPON_SN_LEN];
	u8			password[GPON_PW_MAX];
	u8			sn_len;
	u8			pw_len;
	bool			sn_programmed;

	u8			onu_id;
	bool			onu_id_valid;

	/* ranging */
	u32			eqd;
	u32			byte_delay;
	u32			bit_delay;
	u16			response_time;

	/* upstream overhead cached from PLOAM (for re-apply after reset) */
	u8			guard_bits;
	u8			preamble_t1;
	u8			preamble_t2;
	u8			preamble_t3;
	u32			delimiter;
	bool			overhead_valid;

	/* SN transmit power stepping, driven by G_INT_SN_REQ_CRS */
	u8			tx_power_mode;

	struct timer_list	to1_timer;
	struct timer_list	to2_timer;
	atomic_t		to1_expiry_cnt;
	atomic_t		hw_reset_cnt;

	/* deferred PLOAM processing out of hard IRQ context */
	struct work_struct	ploam_work;

	/* statistics */
	u32			ploam_rx_cnt;
	u32			ploam_tx_cnt;
	u32			ploam_unknown_cnt;
	u32			ploam_dropped_cnt;
	u32			state_change_cnt;
	u32			int_err_cnt;
	u32			last_int_status;
};

/* Userspace ABI for the SN/Password ioctl (MCI_GPON_W/R(3)).
 *
 * Only the SN reaches hardware. The GPON password is *not* a register: the
 * econet-xpon header declares no password register, and in the stock driver the
 * only password writer (xmcs_set_sn_passwd) stores it in gpGponPriv. That is
 * protocol-correct -- G.984.3 carries the password in an upstream PLOAM message
 * (Password), emitted on demand, so the driver keeps it in software and feeds it
 * to the PLOAM path. It is retained here so the UI round-trips.
 */
struct gpon_onu_id_cfg {
	char	sn[GPON_SN_LEN];	/* ONU Serial Number (vendor 4 + serial 4) */
	char	password[GPON_PW_MAX];	/* GPON Password / LOID (ASCII, software) */
	__u8	sn_len;
	__u8	pw_len;
	__u8	reserved[4];
} __attribute__((packed));

/* T-CONT / Alloc-ID query (MCI_GPON_W/R(75)).
 * Reads the packed G_TCONT_ID_* registers. The old implementation's counter
 * maths was software-struct dereferencing and has been removed; per-T-CONT byte
 * counters live in the MIB table (G_MIB_* @0x4120..0x4134), which needs its own
 * indexed read sequence and is not implemented yet.
 */
struct gpon_tcont_counter {
	__u16	tcont_id;	/* input: T-CONT index (0..15) */
	__u16	alloc_id;	/* output: Alloc-ID programmed in hardware */
	__u32	valid;		/* output: 1 if the T-CONT is enabled */
	__u32	reserved;
} __attribute__((packed));

/* GPON MAC hardware counters (DBG_*_CNT, sampled by gpon_isr in the stock
 * driver). Read-to-clear behaviour is unverified, so treat these as snapshots. */
struct gpon_hw_counters {
	__u32	rx_gem;
	__u32	rx_crc_err;
	__u32	rx_gtc;
	__u32	tx_gem;
	__u32	tx_burst;
	__u32	hec_one_err;
	__u32	hec_two_err;
	__u32	hec_uc_err;
} __attribute__((packed));

/* ----------------------- Prototypes (mirror RE symbols) ----------------------- */
/* xpon_main.c */
int  xpon_hw_init(struct xpon_dev *xp);
void xpon_hw_deinit(struct xpon_dev *xp);

/* xpon_mci.c - pon_mci_ioctl dispatch (type byte 0xd7..0xdb) */
long pon_mci_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
int  phy_cmd_proc (unsigned int cmd, unsigned long arg);
int  epon_cmd_proc(unsigned int cmd, unsigned long arg);
int  gpon_cmd_proc(unsigned int cmd, unsigned long arg);
int  if_cmd_proc  (unsigned int cmd, unsigned long arg);
int  fdet_cmd_proc(unsigned int cmd, unsigned long arg);

/* xpon_epon.c - eponMacIoctl (char "epon_mac", magic 'j') */
long eponMacIoctl(struct file *filp, unsigned int cmd, unsigned long arg);
int  eponMacOpen(void);
void eponMacTableInit(void);
int  eponMpcpStart(void);
int  epon_llid_cfg(struct xpon_io_buf *b);

/* xpon_gpon.c - gpon_cmd_proc + hardware bring-up */
int  gpon_dev_init(void);
void gpon_dev_deinit(void);
void gpon_init_qdma_tx_buff(void);
void gpon_qos_setup(void);
void gpon_SD_SF_init(void);
int  gpon_set_sn_passwd(const struct gpon_onu_id_cfg *cfg);
int  gpon_get_sn_passwd(struct gpon_onu_id_cfg *cfg);
int  gpon_get_tcont_counter(struct gpon_tcont_counter *c);
const char *gpon_get_password(u8 *len);
u32  gpon_get_activation_state(void);
u32  gpon_get_onu_id(void);
void gpon_get_hw_counters(struct gpon_hw_counters *hc);
int  gpon_program_serial_number(void);
int  gpon_gem_table_init(void);
int  gpon_gem_port_write(u16 gem_port, bool valid, bool encrypt);
int  gpon_gem_port_read(u16 gem_port, bool *valid, bool *encrypt);
int  gpon_set_omcc_port(u16 gem_port, bool valid);
int  gpon_set_alloc_id(u8 tcont, u16 alloc_id, bool valid);
int  gpon_get_alloc_id(u8 tcont, u16 *alloc_id, bool *valid);
int  gpon_bind_alloc_id(u16 alloc_id);		/* -> T-CONT index, or errno */
int  gpon_unbind_alloc_id(u16 alloc_id);
int  gpon_set_onu_id(u8 onu_id, bool valid);
int  gpon_deactivate_onu(void);
void gpon_set_us_fec(bool on);
void gpon_set_dba_block_size(u16 block_size);
void gpon_mbi_stop(bool stop);
void gpon_int_disable_all(void);

/* xpon_ploam.c - PLOAM transport + downstream message dispatch */
int  gpon_ploam_recv(u8 *msg);
int  gpon_ploam_send(const u8 *msg, unsigned int times);
int  gpon_ploam_send_password(void);
int  gpon_ploam_send_no_message(void);
int  gpon_ploam_send_dying_gasp(void);
int  gpon_ploam_send_acknowledge(u8 downstream_msg_id);
int  gpon_ploam_dispatch(const u8 *msg);
void gpon_ploam_drain(void);
int  gpon_ploam_init(void);
void gpon_ploam_process_all(void);
irqreturn_t gpon_irq_handler(int irq, void *dev_id);

/* xpon_act.c - O1..O7 activation state machine */
int  gpon_act_init(void);
void gpon_act_deinit(void);
void gpon_act_change_state(enum gpon_state new_state);
enum gpon_state gpon_act_get_state(void);
void gpon_act_sn_power_step(void);
const char *gpon_state_name(enum gpon_state st);

/* xpon_phy.c - phy_cmd_proc */
int  XPON_PHY_SET_MODE(enum xpon_mode mode);
void pon_phy_reset(void);
void pon_phy_tx_enable(bool on);
void PhyTxLedConf(void);
int  pon_serdes_init(void);

/* xpon_gpon.c - shared register helpers (also used by xpon_hw_init / xpon_phy.c) */
void __iomem *gpon_mac(void);
void gpon_rmw(u32 off, u32 clear, u32 set);
void gpon_field(u32 off, u32 lo, u32 w, u32 val);

/* xpon_netdev.c - xpon_netdev_ops / ndo_do_ioctl */
int  xpon_netdev_init(struct xpon_dev *xp);
void xpon_netdev_free(struct xpon_dev *xp);
int  xpon_ndo_do_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd);

/* xpon_omcc.c - secure OMCC character device (airoha-omci transport ABI) */
int  xpon_omcc_setup(struct xpon_dev *xp);
void xpon_omcc_teardown(struct xpon_dev *xp);
int  xpon_omcc_rx_omci(const u8 *frame_with_mic, size_t len, u32 mic_flags);
int  xpon_omcc_set_hw_send(int (*fn)(struct xpon_dev *xp, const u8 *gem,
				     size_t len));

/* Hardware OMCI MIC status flags reported by the QDMA RX descriptor (msg0) on
 * the xPON OAM ring. Mirrors airoha_eth.h AIROHA_XPON_OAM_RX_F_*. The MAC checks
 * the G.988 MIC independently of software; these are cross-check metadata that
 * xpon_omcc_rx_omci() surfaces in the OMCC RX record header. The OMCI PDU itself
 * already carries the 4-byte MIC trailer (validated in software by omcc_crc32a).
 *   MIC_PRESENT : hardware saw a MIC (msg0 NO_MIC clear)
 *   MIC_VALID   : hardware MIC check passed (msg0 CRC_ERR clear)
 *   CRC_ERROR   : hardware MIC CRC mismatch (msg0 CRC_ERR set) */
#define XPON_OMCI_RX_F_MIC_PRESENT	BIT(0)
#define XPON_OMCI_RX_F_MIC_VALID	BIT(1)
#define XPON_OMCI_RX_F_CRC_ERROR	BIT(2)

/* xpon_gem.c - GEM data path via the GTC<->Ethernet sniffer engine.
 * OMCI PDUs are bridged between the OMCC GEM port and the OMCC char device by
 * re-tagging them as Ethernet frames through the MAC sniffer (0x4368 group);
 * the actual CPU<->MAC DMA still needs QDMA (see file header). */
struct xpon_gem_cfg {
	u16	tx_ethertype;
	u16	rx_ethertype;
	u16	tx_da_h16;
	u32	tx_da_lo32;
	u16	tx_sa_h16;
	u32	tx_sa_lo32;
	u16	rx_da_h16;
	u32	rx_da_lo32;
	u16	rx_sa_h16;
	u32	rx_sa_lo32;
	u16	tx_vid;
	u16	rx_vid;
	u16	tx_tpid;
	u16	rx_tpid;
	u8	packet_padding;
	u16	omci_gpid;	/* GEM Port Id that carries OMCI (-> G_OMCI_ID@0x4048) */
	u16	rx_eth_pid;	/* sniffer RX ETH PID (-> SNIFF_TX_RX_PID@0x4394) */
	u16	tx_eth_pid;	/* sniffer TX ETH PID (-> SNIFF_TX_RX_PID@0x4394) */
	u8	sniff_all_gem;	/* 1=extract ALL GEM flows (dbg_ds_all_gem_filter) */
};
int  xpon_gem_init(struct xpon_dev *xp);
int  xpon_gem_sniffer_enable(bool on);
int  xpon_gem_rx_ethernet_frame(struct xpon_dev *xp, const u8 *eth, size_t len,
				u32 mic_flags);
int  xpon_gem_set_hw_xmit(int (*fn)(struct xpon_dev *xp, const u8 *eth,
				    size_t len));

/* xpon_qdma.c - Airoha/EN7581 QDMA engine (OMCI/OAM data path) */
int  xpon_qdma_init(struct xpon_dev *xp);
void xpon_qdma_exit(struct xpon_dev *xp);
int  xpon_qdma_xmit(struct xpon_dev *xp, const u8 *data, size_t len);


/* Register helpers.
 *
 * The stock driver funnels every GPON MAC access through two helpers,
 * get_xpon_data() / set_xpon_data(). Both are `U` (undefined) in xpon.ko and
 * are not defined by any other module in the stock rootfs, so they live in the
 * vendor's monolithic kernel and their bodies were not available to inspect.
 *
 * Plain 32-bit MMIO is used here because econet-xpon drives the *same* register
 * block through `IO_GREG`/`IO_SREG`, which expand to ioread32()/iowrite32()
 * (inc/common/drv_types.h:36). Every recovered access is also 32-bit wide and
 * 4-byte aligned. If the vendor helpers turn out to add a bus quirk (an extra
 * barrier or a serialising lock), it would be centralised here.
 */
static inline u32 xpon_readl(void __iomem *base, u32 off)
{
	return readl(base + off);
}
static inline void xpon_writel(void __iomem *base, u32 off, u32 val)
{
	writel(val, base + off);
}
static inline u8 xpon_readb(void __iomem *base, u32 off)
{
	return readb(base + off);
}
static inline void xpon_writeb(void __iomem *base, u32 off, u8 val)
{
	writeb(val, base + off);
}

#endif /* _XPON_H */
