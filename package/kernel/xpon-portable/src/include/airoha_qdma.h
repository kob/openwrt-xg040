/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * airoha_qdma.h - EN7523/EN7581 Airoha QDMA register & descriptor model
 *
 * Derived from drivers/net/ethernet/airoha/{airoha_regs.h,airoha_eth.h} in the
 * Sirherobrine23/airoha_kernel tree (the EN7523/7581 vendor kernel). The GPON
 * OMCI/OAM data path on EN7581 rides the SoC Airoha QDMA engine, NOT the
 * Econet en75_qdma engine used by the older EN751221 family. This header
 * captures only the subset needed to move OMCI frames upstream (TX queue 7,
 * OAM) and receive them downstream (RX queue 15, the dedicated xPON OAM ring).
 *
 * All offsets/masks verified against airoha_regs.h commit f3d4a743.
 */

#ifndef _XPON_AIROHA_QDMA_H
#define _XPON_AIROHA_QDMA_H

#include <linux/types.h>

/* ---- QDMA descriptor (32 bytes, little-endian fields) ---------------- */
struct airoha_qdma_desc {
	__le32 tcp_ts_reply;
	__le32 ctrl;
	__le32 addr;
	__le32 data;
	__le32 msg0;
	__le32 msg1;
	__le32 msg2;
	__le32 msg3;
};

/* CTRL word (TX/RX) */
#define QDMA_DESC_DONE_MASK		BIT(31)
#define QDMA_DESC_DROP_MASK		BIT(30)	/* tx: drop - rx: overflow */
#define QDMA_DESC_MORE_MASK		BIT(29)	/* more SG elements follow */
#define QDMA_DESC_LEN_MASK		GENMASK(15, 0)
#define EN7523_QDMA_DESC_LEN_MASK	GENMASK(15, 0)	/* identical to above */

/* data word: next descriptor index (for TX scatter chains) */
#define QDMA_DESC_NEXT_ID_MASK		GENMASK(15, 0)

/* ---- TX message 0 (QDMA_ETH_TXMSG_*) -------------------------------- */
#define QDMA_ETH_TXMSG_OAM_MASK		BIT(8)
#define QDMA_ETH_TXMSG_CHAN_MASK	GENMASK(7, 3)	/* T-CONT */
#define QDMA_ETH_TXMSG_QUEUE_MASK	GENMASK(2, 0)	/* QoS queue */
#define QDMA_ETH_TXMSG_SP_TAG_MASK	GENMASK(29, 14)	/* GEM Port-Id */

/* ---- TX message 1 (QDMA_ETH_TXMSG_*) -------------------------------- */
#define QDMA_ETH_TXMSG_NO_DROP		BIT(31)
#define QDMA_ETH_TXMSG_METER_MASK	GENMASK(30, 24)	/* 0x7f = no meters */
#define QDMA_ETH_TXMSG_FPORT_MASK	GENMASK(23, 20)	/* front port */
#define QDMA_ETH_TXMSG_NBOQ_MASK	GENMASK(19, 15)	/* NBOQ / T-CONT */

/* ---- RX message 0/1 (EN7523_QDMA_ETH_RXMSG_*) ----------------------- */
#define EN7523_QDMA_ETH_RXMSG_OAM_MASK		BIT(8)
#define EN7523_QDMA_ETH_RXMSG_CHAN_MASK		GENMASK(7, 3)
#define EN7523_QDMA_ETH_RXMSG_GEM_MASK		GENMASK(29, 14)
#define EN7523_QDMA_ETH_RXMSG_NO_MIC_MASK	BIT(30)
#define EN7523_QDMA_ETH_RXMSG_CRC_ERR_MASK	BIT(11)
#define EN7523_QDMA_ETH_RXMSG_SPORT_MASK	GENMASK(21, 14)

/* ---- QDMA global / ring registers (per airoha_regs.h) --------------- */
#define REG_QDMA_GLOBAL_CFG		0x0004
#define GLOBAL_CFG_TX_DMA_EN_MASK		BIT(0)
#define GLOBAL_CFG_RX_DMA_EN_MASK		BIT(2)
#define GLOBAL_CFG_RX_DMA_BUSY_MASK		BIT(3)
#define GLOBAL_CFG_TX_DMA_BUSY_MASK		BIT(1)
#define GLOBAL_CFG_CHECK_DONE_MASK		BIT(7)
#define GLOBAL_CFG_TX_WB_DONE_MASK		BIT(6)
#define GLOBAL_CFG_RESET_MASK			BIT(23)
#define GLOBAL_CFG_RESET_DONE_MASK		BIT(22)
#define GLOBAL_CFG_IRQ0_EN_MASK			BIT(19)
#define GLOBAL_CFG_IRQ1_EN_MASK			BIT(20)
#define GLOBAL_CFG_LOOPBACK_MASK		BIT(16)
#define GLOBAL_CFG_PAYLOAD_BYTE_SWAP_MASK	BIT(26)
#define GLOBAL_CFG_MSG_WORD_SWAP_MASK		BIT(27)	/* DSCP byte swap on 7523 */

/* Interrupt status / enable banks (n = bank 0..4) */
#define REG_INT_STATUS(_n)						\
	(((_n) == 4) ? 0x0730 :						\
	 ((_n) == 3) ? 0x0724 :						\
	 ((_n) == 2) ? 0x0720 :						\
	 ((_n) == 1) ? 0x0024 : 0x0020)

#define REG_INT_ENABLE(_b, _n)						\
	(((_n) == 6) ? 0x0034 + ((_b) << 5) :				\
	 ((_n) == 5) ? 0x0030 + ((_b) << 5) :				\
	 ((_n) == 4) ? 0x0750 + ((_b) << 5) :				\
	 ((_n) == 3) ? 0x0744 + ((_b) << 5) :				\
	 ((_n) == 2) ? 0x0740 + ((_b) << 5) :				\
	 ((_n) == 1) ? 0x002c + ((_b) << 3) :				\
		       0x0028 + ((_b) << 3))

/* Coherent / done interrupt bits (INT_ENABLE1, bank 0) */
#define TX0_COHERENT_INT_MASK	BIT(8)
#define TX7_COHERENT_INT_MASK	BIT(15)
#define RX0_COHERENT_INT_MASK	BIT(16)
#define RX15_COHERENT_INT_MASK	BIT(31)
#define IRQ0_INT_MASK		BIT(0)
#define IRQ0_FULL_INT_MASK	BIT(1)

#define TX_DONE_INT_MASK(_n)						\
	((_n) ? BIT(4) | BIT(5) : BIT(0) | BIT(1))
#define INT_TX0_MASK		TX0_COHERENT_INT_MASK
#define INT_RX15_MASK		RX15_COHERENT_INT_MASK

/* TX rings: queue 0..7 at 0x0100+, queue 8..15 at 0x0b00+ (stride 0x20) */
#define REG_TX_RING_BASE(_n)						\
	(((_n) < 8) ? 0x0100 + ((_n) << 5) : 0x0b00 + (((_n) - 8) << 5))
#define REG_TX_CPU_IDX(_n)						\
	(((_n) < 8) ? 0x0108 + ((_n) << 5) : 0x0b08 + (((_n) - 8) << 5))
#define REG_TX_DMA_IDX(_n)						\
	(((_n) < 8) ? 0x010c + ((_n) << 5) : 0x0b0c + (((_n) - 8) << 5))
#define TX_RING_CPU_IDX_MASK	GENMASK(15, 0)
#define TX_RING_DMA_IDX_MASK	GENMASK(15, 0)

/* RX rings: queue 0..15 at 0x0200+ (stride 0x20) */
#define REG_RX_RING_BASE(_n)	0x0200 + ((_n) << 5)
#define REG_RX_RING_SIZE(_n)	0x0204 + ((_n) << 5)
#define REG_RX_CPU_IDX(_n)	0x0208 + ((_n) << 5)
#define REG_RX_DMA_IDX(_n)	0x020c + ((_n) << 5)
#define REG_RX_SCATTER_CFG(_n)	0x0214 + ((_n) << 5)
#define RX_RING_SIZE_MASK	GENMASK(15, 0)
#define RX_RING_THR_MASK	GENMASK(31, 16)
#define RX_RING_CPU_IDX_MASK	GENMASK(15, 0)
#define RX_RING_DMA_IDX_MASK	GENMASK(15, 0)
#define RX_RING_SG_EN_MASK	BIT(0)

/* Airoha QDMA engine index used for xPON (the SoC has qdma[0] and qdma[1];
 * the vendor xpon driver uses qdma[1] = &dev->eth->qdma[1]). */
#define AIROHA_QDMA_XPON_ENGINE	1

/* OMCI/OAM dedicated queues (mirrors airoha: OAM TX queue 7, RX ring 15) */
#define AIROHA_QDMA_OMCI_TX_Q	7
#define AIROHA_QDMA_OMCI_RX_Q	15

/* ---- FE / CDM routing: deliver extracted xPON OAM into a QDMA RX ring ----
 * These registers live in the Airoha FE (forwarding engine) block at fe_base
 * (EN7581: 0x1fb50000), NOT inside the QDMA engine block (0x1fb54000). They are
 * derived from drivers/net/ethernet/airoha/airoha_regs.h.
 *
 * Downstream OMCI/OAM flow (the LAST hop before xpon_qdma_rx_drain() sees a
 * frame):
 *   PON MAC sniffer extracts the OMCI GEM Port (G_OMCI_ID@0x4048 in
 *   xpon_gem.c) -> CDM2 (xPON front-port CPU DMA) classifies it as OAM ->
 *   REG_CDM_FWD_CFG(2).OAM_QSEL selects which QDMA RX ring receives it.
 * Setting OAM_QSEL = 15 routes those frames into RX ring 15, the dedicated
 * xPON OAM ring. Mirrors airoha_eth.c:1190 (GENMASK(31,27) on EN7581-class).
 * This is the single knob that makes downstream OAM actually arrive. */
#define AIROHA_FE_CDM2_OAM_QSEL	15	/* -> QDMA RX ring 15 */

#define REG_FE_CDM2_FWD_CFG	0x1408	/* CDM_BASE(2) + 0x08 */
#define FE_CDM_OAM_QSEL_MASK	GENMASK(31, 27)	/* EN7581-class, 5-bit */
#define FE_CDM_VIP_QSEL_MASK	GENMASK(24, 20)

#endif /* _XPON_AIROHA_QDMA_H */
