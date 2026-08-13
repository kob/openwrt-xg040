/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * xpon_qdma.c - EN7581 Airoha QDMA transport for the XPON OMCI/OAM path
 *
 * This is the LAST hop of the OMCI data plane on EN7581:
 *
 *   OMCC char dev -> xpon_gem_omcc_xmit (Ethernet wrap) -> g_gem_hw_xmit
 *                -> xpon_qdma_xmit (Airoha QDMA) -> optical port
 *
 * The EN7581 PON subsystem reuses the Airoha (ex-Econet EN7523 family) SoC
 * QDMA engine, NOT the older Econet en75_qdma used by EN751221. The register
 * and descriptor model here is a focused port of
 * drivers/net/ethernet/airoha/{airoha_eth.c,airoha_regs.h} from the
 * Sirherobrine23/airoha_kernel tree (commit f3d4a743). Only the OMCI/OAM
 * subset is implemented:
 *   - TX queue 7  : upstream OAM frames (OAM bit set in msg0)
 *   - RX queue 15 : dedicated xPON OAM receive ring
 *
 * The downstream half needs one extra routing knob in the FE block (not the
 * QDMA engine): REG_CDM_FWD_CFG(2).OAM_QSEL must point at RX ring 15, so the
 * PON MAC sniffer's extracted OAM frames (selected by G_OMCI_ID@0x4048 in
 * xpon_gem.c) are DMA'd into ring 15 where xpon_qdma_rx_drain() picks them up.
 * See the FE/CDM macros in airoha_qdma.h.
 *
 * Ring/doorbell/descriptor fields mirror __airoha_dev_xmit() (TX) and the
 * airoha_qdma_rx_process() OAM branch (RX). Unverified on hardware: there is
 * no aarch64 toolchain or EN7581 board in this environment.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/bitops.h>
#include <linux/bitfield.h>
#include <linux/sizes.h>
#include <linux/minmax.h>

#include "xpon.h"
#include "airoha_qdma.h"

/* ---- module parameters ------------------------------------------------ */
/* EN7581 board addresses (target/linux/airoha/dts/an7581.dtsi, airoha,en7581-eth):
 *   fe     = 0x1fb50000
 *   qdma0  = 0x1fb54000   <- primary QDMA engine (use this for OMCI)
 *   qdma1  = 0x1fb56000
 * IRQs (GIC_SPI, from the same node): 37,55,56,57,38,58,59,60,49,64. The QDMA
 * bank-0 line is one of these; confirm on hardware which feeds qdma0.
 * PON front port = GDM2 (ethernet@2, pcs-handle = pon_pcs) => fport 2. */
static ulong qdma_base = 0x1fb54000; /* EN7581 QDMA0 phys base (0=loopback) */
module_param(qdma_base, ulong, 0444);
MODULE_PARM_DESC(qdma_base, "Airoha QDMA register base (phys). EN7581=0x1fb54000 (qdma0); 0=OMCC loopback");

/* FE (forwarding engine) base. EN7581: 0x1fb50000. This block owns the CDM2
 * forward config that routes extracted xPON OAM into the QDMA RX ring 15.
 * If 0, skip FE programming (assume the main airoha_eth driver already set
 * OAM_QSEL=15, or running in loopback). */
static ulong fe_base = 0x1fb50000;
module_param(fe_base, ulong, 0444);
MODULE_PARM_DESC(fe_base, "Airoha FE register base (phys). EN7581=0x1fb50000; 0=skip CDM2 OAM routing");

static int qdma_irq = 55; /* candidate EN7581 QDMA bank IRQ (GIC_SPI); -1=poll */
module_param(qdma_irq, int, 0444);
MODULE_PARM_DESC(qdma_irq, "Airoha QDMA IRQ line (EN7581 candidates 37/55/56/57/38/58/59/60/49/64); -1=poll");

static int qdma_ndesc = 256;	/* descriptors per ring */
module_param(qdma_ndesc, int, 0444);
MODULE_PARM_DESC(qdma_ndesc, "QDMA ring depth (TX/RX)");

/* Front port used for upstream OAM egress. Confirmed by an7581.dtsi: the PON
 * (xPON) front port is GDM2 (ethernet@2, pcs-handle = &pon_pcs) => fport 2. */
static int qdma_omci_fport = 2;
module_param(qdma_omci_fport, int, 0444);
MODULE_PARM_DESC(qdma_omci_fport, "Front-port for upstream OAM (EN7581 PON = GDM2 = 2)");

#define XPON_QDMA_IOMAP_SIZE	SZ_16K
#define XPON_FE_IOMAP_SIZE	SZ_64K

/* ---- per-ring state ---------------------------------------------------- */
struct xpon_qdma_ring {
	struct airoha_qdma_desc *desc;	/* coherent ring of descriptors */
	dma_addr_t		desc_dma;
	void			**buf;	/* per-slot CPU buffer (RX) */
	dma_addr_t		*buf_dma;/* per-slot DMA addr (RX) */
	struct sk_buff		**skb;	/* in-flight skb (TX) */
	u16			head;	/* next produce index */
	u16			tail;	/* next reclaim index */
	u16			queued;	/* outstanding entries */
	u16			ndesc;
	u8			qid;	/* hardware queue id */
	spinlock_t		lock;
};

struct xpon_qdma {
	void __iomem		*regs;	/* QDMA engine block (0x1fb54000) */
	void __iomem		*fe;	/* FE block (0x1fb50000), CDM2 routing */
	struct device		*dev;
	struct xpon_dev		*xp;
	struct xpon_qdma_ring	tx;
	struct xpon_qdma_ring	rx;
	struct tasklet_struct	rx_tasklet;
	int			irq;
};

/* ---- register access --------------------------------------------------- */
static inline u32 qdma_rreg(struct xpon_qdma *q, u32 off)
{
	return readl(q->regs + off);
}

static inline void qdma_wreg(struct xpon_qdma *q, u32 off, u32 val)
{
	writel(val, q->regs + off);
}

static inline void qdma_rmw(struct xpon_qdma *q, u32 off, u32 clr, u32 set)
{
	u32 v = qdma_rreg(q, off);
	v = (v & ~clr) | set;
	qdma_wreg(q, off, v);
}

/* ---- FE (forwarding engine) register access -------------------------- */
static inline u32 fe_rreg(struct xpon_qdma *q, u32 off)
{
	return readl(q->fe + off);
}

static inline void fe_wreg(struct xpon_qdma *q, u32 off, u32 val)
{
	writel(val, q->fe + off);
}

static inline void fe_rmw(struct xpon_qdma *q, u32 off, u32 clr, u32 set)
{
	u32 v = fe_rreg(q, off);
	v = (v & ~clr) | set;
	fe_wreg(q, off, v);
}

/* Route the PON MAC sniffer's extracted xPON OAM frames into the QDMA RX ring
 * 15 (the dedicated xPON OAM ring). This is REG_CDM_FWD_CFG(2).OAM_QSEL in the
 * FE block; CDM2 is the xPON front-port CPU DMA. Without this, downstream OMCI
 * is extracted by the MAC but never DMA'd into a ring our RX drain can read.
 * Mirrors airoha_eth.c:1190. Idempotent if airoha_eth already configured it. */
static void xpon_qdma_route_oam_to_ring15(struct xpon_qdma *q)
{
	if (!q->fe)
		return;
	fe_rmw(q, REG_FE_CDM2_FWD_CFG, FE_CDM_OAM_QSEL_MASK,
	       FIELD_PREP(FE_CDM_OAM_QSEL_MASK, AIROHA_FE_CDM2_OAM_QSEL));
}

/* ---- TX: reclaim completed OAM descriptors (DONE bit, TX_WB_DONE on) --- */
static void xpon_qdma_tx_reclaim(struct xpon_qdma *q)
{
	struct xpon_qdma_ring *r = &q->tx;

	while (r->queued) {
		struct airoha_qdma_desc *desc = &r->desc[r->tail];
		u32 ctrl = le32_to_cpu(READ_ONCE(desc->ctrl));
		u32 len;
		dma_addr_t addr;

		if (!(ctrl & QDMA_DESC_DONE_MASK))
			break;

		addr = le32_to_cpu(desc->addr);
		len = FIELD_GET(EN7523_QDMA_DESC_LEN_MASK, ctrl);
		if (addr)
			dma_unmap_single(q->dev, addr, len, DMA_TO_DEVICE);

		WRITE_ONCE(desc->ctrl, 0);
		WRITE_ONCE(desc->addr, 0);
		WRITE_ONCE(desc->msg0, 0);
		WRITE_ONCE(desc->msg1, 0);

		r->tail = (r->tail + 1) % r->ndesc;
		r->queued--;
	}
}

/* ---- TX: transmit one OAM frame upstream (Airoha OAM path) ------------ */
int xpon_qdma_xmit(struct xpon_dev *xp, const u8 *data, size_t len)
{
	struct xpon_qdma *q = xp ? xp->qdma : NULL;
	struct xpon_qdma_ring *r;
	struct airoha_qdma_desc *desc;
	dma_addr_t addr;
	u32 msg0, msg1, ctrl, idx;
	unsigned long flags;

	if (!q || !q->regs)
		return -ENOSYS;
	if (!len || len > SKB_WITH_OVERHEAD(PAGE_SIZE))
		return -EINVAL;

	r = &q->tx;
	spin_lock_irqsave(&r->lock, flags);
	xpon_qdma_tx_reclaim(q);

	if (r->queued >= r->ndesc) {
		spin_unlock_irqrestore(&r->lock, flags);
		return -EBUSY;
	}

	idx = r->head;
	desc = &r->desc[idx];

	addr = dma_map_single(q->dev, (void *)data, len, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(q->dev, addr))) {
		spin_unlock_irqrestore(&r->lock, flags);
		return -ENOMEM;
	}

	/* ctrl: length only (EN7523 descriptor length field). */
	ctrl = FIELD_PREP(EN7523_QDMA_DESC_LEN_MASK, len);
	WRITE_ONCE(desc->ctrl, cpu_to_le32(ctrl));
	WRITE_ONCE(desc->addr, cpu_to_le32(addr));
	WRITE_ONCE(desc->data,
		   cpu_to_le32(FIELD_PREP(QDMA_DESC_NEXT_ID_MASK,
					   (idx + 1) % r->ndesc)));
	WRITE_ONCE(desc->msg2, 0);
	WRITE_ONCE(desc->msg3, 0);

	/* msg0: OAM frame on the implicit T-CONT 0, GEM Port-Id = omci_gem_port.
	 * Deliberately do NOT set QDMA_ETH_TXMSG_MIC_IDX_MASK (BIT(30)): the
	 * G.988 MIC is computed and appended in software by xpon_omcc.c before
	 * it reaches us, so the MAC must not re-stamp it (see xpon_gem.c header,
	 * "software MIC"). This is the per-descriptor control that keeps the
	 * upstream path on software MIC. NOTE: the vendor firmware also exposes a
	 * global OMCI MIC source switch (xgponmgr_lib_set_omci_mic_ctrl) in the
	 * GPON MAC; its register is not present in our extracted regmap
	 * (re/bitfields.json has no mic field) and is left for hardware
	 * validation. Omitting MIC_IDX here is sufficient in the Airoha QDMA
	 * model. */
	msg0 = FIELD_PREP(QDMA_ETH_TXMSG_QUEUE_MASK, AIROHA_QDMA_OMCI_TX_Q) |
	       FIELD_PREP(QDMA_ETH_TXMSG_CHAN_MASK, 0) |
	       FIELD_PREP(QDMA_ETH_TXMSG_SP_TAG_MASK, xp->omci_gem_port) |
	       QDMA_ETH_TXMSG_OAM_MASK;

	/* msg1: front port egress, no meters, never drop OAM */
	msg1 = FIELD_PREP(QDMA_ETH_TXMSG_NBOQ_MASK, 0) |
	       FIELD_PREP(QDMA_ETH_TXMSG_FPORT_MASK, qdma_omci_fport) |
	       FIELD_PREP(QDMA_ETH_TXMSG_METER_MASK, 0x7f) |
	       QDMA_ETH_TXMSG_NO_DROP;

	WRITE_ONCE(desc->msg0, cpu_to_le32(msg0));
	WRITE_ONCE(desc->msg1, cpu_to_le32(msg1));

	dma_wmb();

	r->head = (idx + 1) % r->ndesc;
	r->queued++;

	/* doorbell: advance producer to the filled descriptor */
	qdma_wreg(q, REG_TX_CPU_IDX(r->qid),
		  FIELD_PREP(TX_RING_CPU_IDX_MASK, idx));

	spin_unlock_irqrestore(&r->lock, flags);
	return 0;
}

/* ---- RX: (re)arm one descriptor with a fresh DMA buffer --------------- */
static int xpon_qdma_rx_arm(struct xpon_qdma *q, u16 idx)
{
	struct xpon_qdma_ring *r = &q->rx;
	struct page *pg;
	dma_addr_t dma;
	void *va;

	pg = alloc_page(GFP_ATOMIC);
	if (!pg)
		return -ENOMEM;
	va = page_address(pg);
	dma = dma_map_single(q->dev, va, PAGE_SIZE, DMA_FROM_DEVICE);
	if (unlikely(dma_mapping_error(q->dev, dma))) {
		__free_page(pg);
		return -ENOMEM;
	}
	r->buf[idx] = va;
	r->buf_dma[idx] = dma;
	WRITE_ONCE(r->desc[idx].addr, cpu_to_le32(dma));
	WRITE_ONCE(r->desc[idx].ctrl, 0);
	WRITE_ONCE(r->desc[idx].data, 0);
	WRITE_ONCE(r->desc[idx].msg0, 0);
	WRITE_ONCE(r->desc[idx].msg1, 0);
	WRITE_ONCE(r->desc[idx].msg2, 0);
	WRITE_ONCE(r->desc[idx].msg3, 0);
	return 0;
}

/* ---- RX: drain the xPON OAM ring and feed GEM bridge ------------------ */
static int xpon_qdma_rx_drain(struct xpon_qdma *q)
{
	struct xpon_qdma_ring *r = &q->rx;
	struct xpon_dev *xp = q->xp;
	int budget = r->ndesc;
	int processed = 0;

	while (budget--) {
		struct airoha_qdma_desc *desc = &r->desc[r->tail];
		u32 ctrl, msg0, msg1, len, mic_flags;
		void *old_buf;
		dma_addr_t old_dma;

		ctrl = le32_to_cpu(READ_ONCE(desc->ctrl));
		if (!(ctrl & QDMA_DESC_DONE_MASK))
			break;

		dma_rmb();

		len = FIELD_GET(EN7523_QDMA_DESC_LEN_MASK, ctrl);
		msg0 = le32_to_cpu(READ_ONCE(desc->msg0));
		msg1 = le32_to_cpu(READ_ONCE(desc->msg1));

		/* Ring 15 carries only xPON OAM; silently drop anything else. */
		if (!(msg0 & EN7523_QDMA_ETH_RXMSG_OAM_MASK) || !len)
			goto refill;

		old_buf = r->buf[r->tail];
		old_dma = r->buf_dma[r->tail];
		r->buf[r->tail] = NULL;

		dma_sync_single_for_cpu(q->dev, old_dma, len, DMA_FROM_DEVICE);
		/* Translate the MAC's hardware MIC observation (RX msg0) into
		 * cross-check flags for the OMCC record, then deliver the
		 * Ethernet-wrapped OMCI frame to the GEM bridge, which strips
		 * the L2 header and pushes the bare OMCI(+MIC) up to the char
		 * device. NO_MIC clear => a MIC was present; CRC_ERR clear =>
		 * the hardware MIC check passed. */
		mic_flags = 0;
		if (!(msg0 & EN7523_QDMA_ETH_RXMSG_NO_MIC_MASK))
			mic_flags |= XPON_OMCI_RX_F_MIC_PRESENT;
		if (msg0 & EN7523_QDMA_ETH_RXMSG_CRC_ERR_MASK)
			mic_flags |= XPON_OMCI_RX_F_CRC_ERROR;
		else
			mic_flags |= XPON_OMCI_RX_F_MIC_VALID;
		xpon_gem_rx_ethernet_frame(xp, old_buf, len, mic_flags);

		dma_unmap_single(q->dev, old_dma, PAGE_SIZE, DMA_FROM_DEVICE);
		free_page((unsigned long)old_buf);
		processed++;

refill:
		/* install a fresh buffer and advance the RX consumer index */
		if (xpon_qdma_rx_arm(q, r->tail))
			break;	/* out of memory: stop, HW sees stale slot */
		r->tail = (r->tail + 1) % r->ndesc;
		qdma_wreg(q, REG_RX_CPU_IDX(r->qid),
			  FIELD_PREP(RX_RING_CPU_IDX_MASK, r->tail));
	}
	return processed;
}

static void xpon_qdma_rx_tasklet(unsigned long data)
{
	struct xpon_qdma *q = (struct xpon_qdma *)data;

	xpon_qdma_rx_drain(q);
}

/* ---- ISR -------------------------------------------------------------- */
static irqreturn_t xpon_qdma_isr(int irq, void *ctx)
{
	struct xpon_qdma *q = ctx;
	u32 status;

	status = qdma_rreg(q, REG_INT_STATUS(0));
	if (!status)
		return IRQ_NONE;

	/* Acknowledge the bits we handle. */
	qdma_wreg(q, REG_INT_STATUS(0), status);

	if (status & (TX_DONE_INT_MASK(0) | INT_TX0_MASK))
		xpon_qdma_tx_reclaim(q);

	if (status & (INT_RX15_MASK | RX0_COHERENT_INT_MASK))
		tasklet_schedule(&q->rx_tasklet);

	return IRQ_HANDLED;
}

/* ---- ring allocation -------------------------------------------------- */
static int xpon_qdma_tx_ring_alloc(struct xpon_qdma *q)
{
	struct xpon_qdma_ring *r = &q->tx;
	size_t sz = qdma_ndesc * sizeof(struct airoha_qdma_desc);
	int i;

	r->ndesc = qdma_ndesc;
	r->qid = AIROHA_QDMA_OMCI_TX_Q;
	r->head = r->tail = r->queued = 0;
	spin_lock_init(&r->lock);

	r->desc = dma_alloc_coherent(q->dev, sz, &r->desc_dma, GFP_KERNEL);
	if (!r->desc)
		return -ENOMEM;

	/* EN7523: every TX descriptor starts owned-by-HW (DONE=1) so the engine
	 * treats the ring as free. Ring size is implicit for EN7523 (no size
	 * register is written, mirroring airoha_qdma_tx_ring_alloc). */
	memset(r->desc, 0, sz);
	for (i = 0; i < qdma_ndesc; i++)
		WRITE_ONCE(r->desc[i].ctrl, cpu_to_le32(QDMA_DESC_DONE_MASK));

	qdma_wreg(q, REG_TX_RING_BASE(r->qid), r->desc_dma);
	qdma_wreg(q, REG_TX_CPU_IDX(r->qid), 0);
	qdma_wreg(q, REG_TX_DMA_IDX(r->qid), 0);
	return 0;
}

static int xpon_qdma_rx_ring_alloc(struct xpon_qdma *q)
{
	struct xpon_qdma_ring *r = &q->rx;
	size_t sz = qdma_ndesc * sizeof(struct airoha_qdma_desc);
	int i;

	r->ndesc = qdma_ndesc;
	r->qid = AIROHA_QDMA_OMCI_RX_Q;
	r->head = r->tail = r->queued = 0;
	spin_lock_init(&r->lock);

	r->desc = dma_alloc_coherent(q->dev, sz, &r->desc_dma, GFP_KERNEL);
	if (!r->desc)
		return -ENOMEM;
	memset(r->desc, 0, sz);

	r->buf = kcalloc(qdma_ndesc, sizeof(*r->buf), GFP_KERNEL);
	r->buf_dma = kcalloc(qdma_ndesc, sizeof(*r->buf_dma), GFP_KERNEL);
	if (!r->buf || !r->buf_dma)
		return -ENOMEM;

	for (i = 0; i < qdma_ndesc; i++) {
		if (xpon_qdma_rx_arm(q, i))
			return -ENOMEM;
	}

	qdma_wreg(q, REG_RX_RING_BASE(r->qid), r->desc_dma);
	qdma_wreg(q, REG_RX_RING_SIZE(r->qid),
		  FIELD_PREP(RX_RING_SIZE_MASK, qdma_ndesc) |
		  FIELD_PREP(RX_RING_THR_MASK, clamp(qdma_ndesc >> 3, 1, 32)));
	/* OAM ring 15 is a single-buffer ring: disable scatter/GRO. */
	qdma_rmw(q, REG_RX_SCATTER_CFG(r->qid), RX_RING_SG_EN_MASK, 0);
	/* HW producer index starts at 0 (all slots armed). */
	qdma_wreg(q, REG_RX_DMA_IDX(r->qid), 0);
	qdma_wreg(q, REG_RX_CPU_IDX(r->qid), 0);
	return 0;
}

/* ---- init / exit ------------------------------------------------------ */
int xpon_qdma_init(struct xpon_dev *xp)
{
	struct xpon_qdma *q;
	int ret;

	/* No QDMA base supplied: keep OMCC loopback (g_gem_hw_xmit stays NULL,
	 * xpon_gem_omcc_xmit() returns -ENOSYS, matching the no-hardware path). */
	if (!qdma_base) {
		dev_info(xp->dev, "xpon_qdma: qdma_base=0, OMCI loopback only\n");
		return 0;
	}

	q = kzalloc(sizeof(*q), GFP_KERNEL);
	if (!q)
		return -ENOMEM;

	q->dev = xp->dev;
	q->xp = xp;
	q->irq = qdma_irq;
	xp->qdma = q;
	xp->omci_gem_port = 0x0001;	/* implicit ONU-ID OMCI GEM Port */

	q->regs = ioremap(qdma_base, XPON_QDMA_IOMAP_SIZE);
	if (!q->regs) {
		ret = -ENOMEM;
		goto err_free;
	}

	/* FE block: needed only to set the CDM2 OAM->ring15 route. Optional. */
	if (fe_base) {
		q->fe = ioremap(fe_base, XPON_FE_IOMAP_SIZE);
		if (!q->fe)
			dev_warn(xp->dev,
				 "xpon_qdma: FE iomap failed, OAM routing skipped\n");
	}

	tasklet_init(&q->rx_tasklet, xpon_qdma_rx_tasklet, (unsigned long)q);

	ret = xpon_qdma_tx_ring_alloc(q);
	if (ret)
		goto err_unmap;
	ret = xpon_qdma_rx_ring_alloc(q);
	if (ret)
		goto err_unmap;

	/* Global config: enable TX/RX DMA, write-back DONE on TX so we can
	 * reclaim by the descriptor DONE bit, and check DONE on RX. */
	qdma_rmw(q, REG_QDMA_GLOBAL_CFG,
		 GLOBAL_CFG_RESET_MASK,
		 GLOBAL_CFG_TX_DMA_EN_MASK | GLOBAL_CFG_RX_DMA_EN_MASK |
		 GLOBAL_CFG_CHECK_DONE_MASK | GLOBAL_CFG_TX_WB_DONE_MASK |
		 GLOBAL_CFG_IRQ0_EN_MASK);

	/* Route downstream OAM (PON MAC sniffer -> CDM2) into RX ring 15.
	 * Must be set before DMA is enabled so the first OAM frame lands in
	 * the ring our drain reads. */
	xpon_qdma_route_oam_to_ring15(q);

	/* Enable TX-done (IRQ0) and RX15 coherent interrupts. RX15 is the
	 * dedicated xPON OAM ring; its coherent bit lives in INT_ENABLE bank0
	 * reg1, TX done in bank0 reg0. */
	qdma_rmw(q, REG_INT_ENABLE(0, 0), 0,
		 IRQ0_INT_MASK | IRQ0_FULL_INT_MASK | TX0_COHERENT_INT_MASK);
	qdma_rmw(q, REG_INT_ENABLE(0, 1), 0, INT_RX15_MASK);

	if (q->irq >= 0) {
		ret = request_irq(q->irq, xpon_qdma_isr, IRQF_SHARED,
				  "xpon_qdma", q);
		if (ret)
			dev_warn(xp->dev, "xpon_qdma: request_irq failed: %d\n",
				 ret);
	} else {
		dev_warn(xp->dev,
			 "xpon_qdma: qdma_irq=-1, RX needs polling/IRQ to drain\n");
	}

	/* Hook the OMCI data plane: OMCC -> GEM wrap -> Airoha QDMA. */
	xpon_gem_set_hw_xmit(xpon_qdma_xmit);

	dev_info(xp->dev, "xpon_qdma: Airoha QDMA ready (base %#lx, irq %d)\n",
		 qdma_base, q->irq);
	return 0;

err_unmap:
	if (q->regs)
		iounmap(q->regs);
	if (q->fe)
		iounmap(q->fe);
err_free:
	xp->qdma = NULL;
	kfree(q);
	return ret;
}

void xpon_qdma_exit(struct xpon_dev *xp)
{
	struct xpon_qdma *q = xp->qdma;

	if (!q)
		return;

	tasklet_kill(&q->rx_tasklet);
	if (q->irq >= 0)
		free_irq(q->irq, q);

	/* stop DMA */
	qdma_rmw(q, REG_QDMA_GLOBAL_CFG,
		 GLOBAL_CFG_TX_DMA_EN_MASK | GLOBAL_CFG_RX_DMA_EN_MASK, 0);

	if (q->rx.desc)
		dma_free_coherent(q->dev,
				  q->rx.ndesc * sizeof(struct airoha_qdma_desc),
				  q->rx.desc, q->rx.desc_dma);
	if (q->tx.desc)
		dma_free_coherent(q->dev,
				  q->tx.ndesc * sizeof(struct airoha_qdma_desc),
				  q->tx.desc, q->tx.desc_dma);

	if (q->regs)
		iounmap(q->regs);
	if (q->fe)
		iounmap(q->fe);

	xp->qdma = NULL;
	kfree(q);
}
