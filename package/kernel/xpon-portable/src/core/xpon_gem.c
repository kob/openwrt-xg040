// SPDX-License-Identifier: GPL-2.0
/*
 * xpon_gem.c - GEM data path via the GTC<->Ethernet sniffer engine (EN7581)
 *
 * This module closes the gap left by the OMCC character device (xpon_omcc.c):
 * it moves real OMCI PDUs between the optical port's OMCC GEM port and the
 * secure OMCC char device that airoha-omci talks to.
 *
 * Mechanism (recovered from econet-xpon gponDevSetSniffMode() in gpon_dev.c
 * and cross-checked against the stock xpon.ko disassembly of the same
 * function):
 *
 *   The GPON MAC has a GTC<->Ethernet extraction engine (DBG_GTC_ETH_EXTR @
 *   0x4368). When enabled, the MAC rewrites an OMCI GEM frame into a plain
 *   Ethernet frame (DA/SA/ETYPE programmed via the SNIFF_* registers) on the
 *   *downstream* path and does the reverse on the *upstream* path. This is the
 *   "software path omci tx" exposed by the stock ponmgr.
 *
 *   RX (optical -> CPU):  OMCI GEM frame -> sniffer -> Ethernet frame ->
 *                         QDMA RX -> xpon_gem_rx_ethernet_frame() -> strip
 *                         L2 header -> xpon_omcc_rx_omci() (raw OMCI+MIC).
 *   TX (CPU -> optical):  xpon_omcc write() -> xpon_gem_omcc_xmit() wraps the
 *                         raw OMCI+MIC in an Ethernet header -> QDMA TX ->
 *                         sniffer un-wraps -> OMCI GEM frame on the fibre.
 *
 * IMPORTANT HARDWARE DEPENDENCY (honest boundary):
 *   On EN7581 (XG-040G-MD) the sniffer only re-tags the frame; the actual
 *   DMA to/from the CPU still goes through the Airoha (EN7581) QDMA engine
 *   (see xpon_qdma.c). This driver does NOT ship
 *   a QDMA engine, so the hardware xmit/recv hooks (g_gem_hw_xmit) are left
 *   NULL and xpon_gem_omcc_xmit() returns -ENOSYS until a QDMA path is wired.
 *   The MAC-side sniffer programming below is still correct and reusable.
 *
 *   Likewise, upstream MIC: xpon_omcc.c computes the G.988 MIC in software and
 *   appends it before calling us, so the MAC sniffer must be configured for
 *   *software* MIC (no hardware MIC stamping). That MIC-control register is
 *   not yet programmed here (see report sec. 13).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "xpon.h"

/* --------------------------------------------------------------------------
 * Sniffer / extraction engine registers, EN7581 GPON MAC. Field bit positions
 * are taken verbatim from the vendor xpon.ko reverse map (re/bitfields.json):
 *   DBG_GTC_ETH_EXTR            @0x4368  dbg_gtc_eth_extr_en/.../sniff_dbg_tx_rst
 *   DBG_DS/US_GTC_EXTR_ETH_HDR  @0x436c/0x4370  EtherType + stream port
 *   SNIFF_TX/RX_DA_SA           @0x438c/0x4390  wrapped DA/SA high halves
 *   SNIFF_RX_TX_TPID            @0x439c  VLAN TPID
 *   SNIFF_GTC_GTC_INVLD_GEM_BYTE@0x437c  dbg_ds_gem_filter_exclude_omci / all_gem
 *   SNIFF_TX_RX_PID             @0x4394  rx/tx eth pid
 *   G_OMCI_ID                   @0x4048  omci_gpid / omci_port_id_vld  <-- selects
 *                                            the GEM Port that carries OMCI
 * Offsets are wrapped through GPON_REG() (header window base 0x4000), matching
 * the vendor firmware (0x4048 == G_OMCI_ID in re/bitfields.json).
 * ------------------------------------------------------------------------ */
#define DBG_GTC_ETH_EXTR		GPON_REG(0x4368)
#define   ETH_EXTR_EN			XP_BIT(0)
#define   ETH_EXTR_PAD_EN		XP_BIT(8)
#define   ETH_EXTR_TX_RST		XP_BIT(31)
#define DBG_DS_GTC_EXTR_ETH_HDR	GPON_REG(0x436c)
#define   DS_EXTR_ET_LO			16
#define   DS_EXTR_ET_W			16
#define   DS_EXTR_SP_LO			0
#define   DS_EXTR_SP_W			16
#define DBG_US_GTC_EXTR_ETH_HDR	GPON_REG(0x4370)
#define   US_EXTR_ET_LO			16
#define   US_EXTR_ET_W			16
#define   US_EXTR_SP_LO			0
#define   US_EXTR_SP_W			16
#define SNIFF_TX_DA_SA			GPON_REG(0x438c)
#define   TX_DA_H16_LO			16
#define   TX_DA_H16_W			16
#define   TX_SA_H16_LO			0
#define   TX_SA_H16_W			16
#define SNIFF_RX_DA_SA			GPON_REG(0x4390)
#define   RX_DA_H16_LO			16
#define   RX_DA_H16_W			16
#define   RX_SA_H16_LO			0
#define   RX_SA_H16_W			16
#define SNIFF_RX_TX_TPID		GPON_REG(0x439c)
#define   RX_TPID_LO			16
#define   RX_TPID_W			16
#define   TX_TPID_LO			0
#define   TX_TPID_W			16

/* OMCI GEM Port selection: tells the MAC which GEM Port is OMCI so its frames
 * are eligible for extraction/sniffing (re/bitfields.json G_OMCI_ID @0x4048). */
#define G_OMCI_ID			GPON_REG(0x4048)
#define   OMCI_GPID_LO			0
#define   OMCI_GPID_W			12
#define   OMCI_PORT_ID_VLD_LO		16
#define   OMCI_PORT_ID_VLD_W		1

/* Downstream GEM filter: bit27 exclude_omci must be 0 so OMCI is extracted;
 * bit31 all_gem_filter=1 extracts every GEM flow (flood). (re/bitfields.json
 * SNIFF_GTC_GTC_INVLD_GEM_BYTE @0x437c) */
#define SNIFF_GTC_GTC_INVLD_GEM_BYTE	GPON_REG(0x437c)
#define   EXCL_OMCI_LO			27
#define   EXCL_OMCI_W			1
#define   ALL_GEM_FILTER_LO		31
#define   ALL_GEM_FILTER_W		1

/* Sniffer pseudo-Ethernet PIDs (re/bitfields.json SNIFF_TX_RX_PID @0x4394) */
#define SNIFF_TX_RX_PID		GPON_REG(0x4394)
#define   RX_ETH_PID_LO			0
#define   RX_ETH_PID_W			12
#define   TX_ETH_PID_LO			16
#define   TX_ETH_PID_W			12

/* Default OMCI ethertype on the sniffer pseudo-Ethernet path. The CPU never
 * sees these frames (they live between the MAC sniffer and QDMA), so the value
 * only has to be self-consistent. 0x888A is the OMCI EtherType. */
#define XPON_OMCI_ETHERTYPE		0x888A

#define XPON_GEM_ETH_HDR_LEN		14
#define XPON_GEM_MAX_OMCI		2048	/* OMCI msg (<=1980) + MIC(4) + margin */

/* Module parameters: OMCI GEM Port Id (default 0x0001, implicit ONU-ID) and
 * whether to extract ALL downstream GEM flows (flood). Both are vendor-firmware
 * grounded via G_OMCI_ID@0x4048 and SNIFF_GTC_GTC_INVLD_GEM_BYTE@0x437c. */
static ushort gem_omci_port = 0x0001;
module_param(gem_omci_port, ushort, 0444);
MODULE_PARM_DESC(gem_omci_port, "OMCI GEM Port Id (G_OMCI_ID.omci_gpid)");
static bool gem_sniff_all;
module_param(gem_sniff_all, bool, 0444);
MODULE_PARM_DESC(gem_sniff_all, "Extract ALL downstream GEM flows (debug flood)");

/* Cached sniffer config (single instance). */
static struct xpon_gem_cfg g_gem_cfg;

/* Hardware xmit hook: pushes a fully-built Ethernet frame (OMCI payload) down
 * the QDMA path. NULL until a QDMA driver wires it (Airoha QDMA on EN7581). */
static int (*g_gem_hw_xmit)(struct xpon_dev *xp, const u8 *eth, size_t len);

/* Allow a QDMA driver to register its xmit. */
int xpon_gem_set_hw_xmit(int (*fn)(struct xpon_dev *xp, const u8 *eth,
				    size_t len))
{
	g_gem_hw_xmit = fn;
	return 0;
}
EXPORT_SYMBOL(xpon_gem_set_hw_xmit);

/* Program the sniffer engine from cfg. enable=false just leaves the extract
 * headers programmed but clears the enable bit. Mirrors econet-xpon
 * gponDevSetSniffMode() ordering: program headers, pulse TX reset, then
 * enable. */
static void xpon_gem_sniffer_program(const struct xpon_gem_cfg *c, bool enable)
{
	if (!gpon_mac())
		return;

	/* downstream (RX) extract header: ethertype + stream port */
	gpon_field(DBG_DS_GTC_EXTR_ETH_HDR, DS_EXTR_ET_LO, DS_EXTR_ET_W,
		   c->rx_ethertype);
	gpon_field(DBG_DS_GTC_EXTR_ETH_HDR, DS_EXTR_SP_LO, DS_EXTR_SP_W,
		   c->rx_vid);
	/* upstream (TX) extract header */
	gpon_field(DBG_US_GTC_EXTR_ETH_HDR, US_EXTR_ET_LO, US_EXTR_ET_W,
		   c->tx_ethertype);
	gpon_field(DBG_US_GTC_EXTR_ETH_HDR, US_EXTR_SP_LO, US_EXTR_SP_W,
		   c->tx_vid);
	/* DA/SA high halves (the MAC keeps the low 32 bits from its default) */
	gpon_field(SNIFF_TX_DA_SA, TX_DA_H16_LO, TX_DA_H16_W, c->tx_da_h16);
	gpon_field(SNIFF_TX_DA_SA, TX_SA_H16_LO, TX_SA_H16_W, c->tx_sa_h16);
	gpon_field(SNIFF_RX_DA_SA, RX_DA_H16_LO, RX_DA_H16_W, c->rx_da_h16);
	gpon_field(SNIFF_RX_DA_SA, RX_SA_H16_LO, RX_SA_H16_W, c->rx_sa_h16);
	/* VLAN TPID */
	gpon_field(SNIFF_RX_TX_TPID, RX_TPID_LO, RX_TPID_W, c->rx_tpid);
	gpon_field(SNIFF_RX_TX_TPID, TX_TPID_LO, TX_TPID_W, c->tx_tpid);

	/* OMCI GEM Port selection (re/bitfields.json G_OMCI_ID @0x4048). The MAC
	 * routes the OMCI GEM flow through the extractor only once this names the
	 * port and marks it valid. This is the missing link that makes downstream
	 * OMCI actually get sniffed out to the CPU. */
	gpon_field(G_OMCI_ID, OMCI_GPID_LO, OMCI_GPID_W, c->omci_gpid);
	gpon_field(G_OMCI_ID, OMCI_PORT_ID_VLD_LO, OMCI_PORT_ID_VLD_W, 1);

	/* Downstream GEM filter (re/bitfields.json SNIFF_GTC_GTC_INVLD_GEM_BYTE
	 * @0x437c). exclude_omci MUST be 0 so OMCI is not filtered out of the
	 * extract path; all_gem_filter=1 floods every GEM flow (debug only). */
	gpon_field(SNIFF_GTC_GTC_INVLD_GEM_BYTE, EXCL_OMCI_LO, EXCL_OMCI_W, 0);
	gpon_field(SNIFF_GTC_GTC_INVLD_GEM_BYTE, ALL_GEM_FILTER_LO,
		   ALL_GEM_FILTER_W, c->sniff_all_gem ? 1 : 0);

	/* Sniffer pseudo-Ethernet PIDs (re/bitfields.json SNIFF_TX_RX_PID @0x4394).
	 * Self-consistent vendor default; verify against the board firmware. */
	gpon_field(SNIFF_TX_RX_PID, RX_ETH_PID_LO, RX_ETH_PID_W, c->rx_eth_pid);
	gpon_field(SNIFF_TX_RX_PID, TX_ETH_PID_LO, TX_ETH_PID_W, c->tx_eth_pid);

	/* pulse the upstream sniffer TX reset, then release */
	gpon_rmw(DBG_GTC_ETH_EXTR, 0, ETH_EXTR_TX_RST);
	gpon_rmw(DBG_GTC_ETH_EXTR, ETH_EXTR_TX_RST, 0);

	/* packet padding + enable */
	gpon_field(DBG_GTC_ETH_EXTR, ETH_EXTR_PAD_EN, 1,
		   enable ? c->packet_padding : 0);
	gpon_field(DBG_GTC_ETH_EXTR, ETH_EXTR_EN, 1, enable ? 1 : 0);
}

/* Build an Ethernet frame around an OMCI(+MIC) payload and push it to QDMA. */
static int xpon_gem_omcc_xmit(struct xpon_dev *xp, const u8 *gem, size_t len)
{
	u8 *frame;
	size_t flen = XPON_GEM_ETH_HDR_LEN + len;

	if (len == 0 || len > XPON_GEM_MAX_OMCI)
		return -EINVAL;
	if (!g_gem_hw_xmit) {
		/* No QDMA xmit wired: the frame cannot reach the optical port.
		 * This is the expected state until an EN7581 QDMA driver is
		 * attached; -ENOSYS is reported so the char dev write fails loud. */
		pr_debug(DRV_NAME ": gem omcc xmit skipped (no QDMA hw_xmit)\n");
		return -ENOSYS;
	}

	frame = kmalloc(flen, GFP_ATOMIC);
	if (!frame)
		return -ENOMEM;

	/* DA */
	frame[0] = (g_gem_cfg.tx_da_h16 >> 8) & 0xff;
	frame[1] = g_gem_cfg.tx_da_h16 & 0xff;
	frame[2] = (g_gem_cfg.tx_da_lo32 >> 24) & 0xff;
	frame[3] = (g_gem_cfg.tx_da_lo32 >> 16) & 0xff;
	frame[4] = (g_gem_cfg.tx_da_lo32 >> 8) & 0xff;
	frame[5] = g_gem_cfg.tx_da_lo32 & 0xff;
	/* SA */
	frame[6] = (g_gem_cfg.tx_sa_h16 >> 8) & 0xff;
	frame[7] = g_gem_cfg.tx_sa_h16 & 0xff;
	frame[8] = (g_gem_cfg.tx_sa_lo32 >> 24) & 0xff;
	frame[9] = (g_gem_cfg.tx_sa_lo32 >> 16) & 0xff;
	frame[10] = (g_gem_cfg.tx_sa_lo32 >> 8) & 0xff;
	frame[11] = g_gem_cfg.tx_sa_lo32 & 0xff;
	/* EtherType */
	frame[12] = (g_gem_cfg.tx_ethertype >> 8) & 0xff;
	frame[13] = g_gem_cfg.tx_ethertype & 0xff;

	memcpy(frame + XPON_GEM_ETH_HDR_LEN, gem, len);

	return g_gem_hw_xmit(xp, frame, flen);
}

/* RX entry point for the QDMA receive path. Called with an extracted
 * Ethernet frame; validates the EtherType, strips the L2 header and hands the
 * raw OMCI(+MIC) PDU to the OMCC character device. mic_flags carries the
 * hardware MIC status from the QDMA RX descriptor (see XPON_OMCI_RX_F_*). */
int xpon_gem_rx_ethernet_frame(struct xpon_dev *xp, const u8 *eth, size_t len,
			       u32 mic_flags)
{
	u16 et;
	const u8 *omci;
	size_t olen;

	if (len < XPON_GEM_ETH_HDR_LEN + 4)
		return -EINVAL;
	et = ((u16)eth[12] << 8) | eth[13];
	if (et != g_gem_cfg.rx_ethertype)
		return -ENOMSG;	/* not an OMCI frame; let the stack handle it */

	omci = eth + XPON_GEM_ETH_HDR_LEN;
	olen = len - XPON_GEM_ETH_HDR_LEN;
	return xpon_omcc_rx_omci(omci, olen, mic_flags);
}
EXPORT_SYMBOL(xpon_gem_rx_ethernet_frame);

/* Enable/disable the sniffer. Called from the activation state machine once
 * the OMCC GEM port is up (O5 reached). */
int xpon_gem_sniffer_enable(bool on)
{
	xpon_gem_sniffer_program(&g_gem_cfg, on);
	return 0;
}
EXPORT_SYMBOL(xpon_gem_sniffer_enable);

/* One-time init: default the OMCI pseudo-Ethernet addressing, program the
 * sniffer engine (disabled), and wire the OMCC char device TX path to the GEM
 * xmit so airoha-omci's writes reach the fibre. */
int xpon_gem_init(struct xpon_dev *xp)
{
	g_gem_cfg.rx_ethertype = XPON_OMCI_ETHERTYPE;
	g_gem_cfg.tx_ethertype = XPON_OMCI_ETHERTYPE;
	/* 48-bit addresses; the MAC sniffer only stores the high 16 bits in the
	 * registers, so keep low 32 bits consistent here for frame build/check. */
	g_gem_cfg.tx_da_h16 = 0x0180; g_gem_cfg.tx_da_lo32 = 0xc0000000;
	g_gem_cfg.tx_sa_h16 = 0x0200; g_gem_cfg.tx_sa_lo32 = 0x00000001;
	g_gem_cfg.rx_da_h16 = 0x0180; g_gem_cfg.rx_da_lo32 = 0xc0000000;
	g_gem_cfg.rx_sa_h16 = 0x0200; g_gem_cfg.rx_sa_lo32 = 0x00000001;
	g_gem_cfg.tx_vid = 0;
	g_gem_cfg.rx_vid = 0;
	g_gem_cfg.tx_tpid = 0x8100;
	g_gem_cfg.rx_tpid = 0x8100;
	g_gem_cfg.packet_padding = 1;
	/* firmware-grounded OMCI selection + sniffer PID defaults */
	g_gem_cfg.omci_gpid = gem_omci_port ? gem_omci_port : 0x0001;
	g_gem_cfg.rx_eth_pid = XPON_OMCI_ETHERTYPE;
	g_gem_cfg.tx_eth_pid = XPON_OMCI_ETHERTYPE;
	g_gem_cfg.sniff_all_gem = gem_sniff_all ? 1 : 0;
	xp->omci_gem_port = g_gem_cfg.omci_gpid;

	xpon_gem_sniffer_program(&g_gem_cfg, false);

	/* route OMCC char-dev writes through the GEM xmit */
	xpon_omcc_set_hw_send(xpon_gem_omcc_xmit);

	pr_info(DRV_NAME ": GEM sniffer engine programmed (QDMA xmit %s)\n",
		g_gem_hw_xmit ? "wired" : "not wired (-ENOSYS until QDMA attaches)");
	return 0;
}
