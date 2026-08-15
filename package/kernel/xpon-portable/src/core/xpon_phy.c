// SPDX-License-Identifier: GPL-2.0
/*
 * xpon_phy.c - PON PHY / optical sub-stack.
 *
 * Reverse-engineered from the stock XG-040G-MD xpon.ko (kernel 5.4.55). The
 * register-level bring-up sequence is now validated against the econet-xpon
 * EN7521 GPON MAC header at 92.9% offset overlap (see
 * work/re/EN7581-GPON-regmap-validated.md), so the GPON MAC window programming
 * below is grounded in recovered register names/bitfields.
 *
 * What lives WHERE (important for "don't invent registers"):
 *   - The GPON MAC register window (xp->mac, base 0x1fb64000) holds MBI stop,
 *     the activation state machine, PLOAM, T-CONT/GEM, AES, and the PLOu
 *     preamble/guard/delimiter registers. These are programmed by xpon_gpon.c,
 *     xpon_ploam.c, xpon_act.c.
 *   - The protocol mode (GPON/XG(S)-PON/EPON), the SERDES lane bring-up
 *     (equalisation, TX/RX calibration, PCS link training) and the laser
 *     enable belong to OTHER blocks: the Airoha serdes_common PHY driver and
 *     the mainline `airoha,an7581-pcs-pon` PCS driver, plus the BOSA/en7572
 *     optical module driver. This driver does NOT own those register spaces,
 *     so the functions here deliberately avoid guessing their bits.
 */

#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/of_net.h>		/* of_get_mac_address() */
#include <linux/etherdevice.h>	/* mac_pton / is_valid_ether_addr */
#include "xpon.h"

/* 10G-EPON (XEPON) MAC bring-up.
 *
 * The EPON sub-block (xp->mac2 == DTS reg[1] == 0x1fb66000) is the SAME IP the
 * open-source EN7523 airoha_xpon.c drives in 1G EPON mode. 10G-EPON (XEPON) is
 * that block switched to 10G framing via EPON_GLB_CFG[GLB_MODE_SEL]. The static
 * bring-up below is ported 1:1 from that driver's epon_sw_reset() + epon_hw_init()
 * (the authoritative sequence for this IP); only the GLB_MODE_SEL bit differs for
 * XEPON. The OLT-driven runtime state (LLID assignment, OLT MAC, unicast/encrypt
 * keys, MPCP discovery & registration FSM, DBA report, OAM keepalive) is LEFT AS
 * TODO and is meant to be driven by the MPCP state machine. NOT compiled / NOT
 * hardware-verified. */

/* Program one 128-bit security key for a given LLID (1G EPON indirect key).
 * Ported from open-source airoha_xpon.c epon_set_security_key(). The runtime
 * MPCP FSM calls this with the key negotiated with the OLT. */
static void xpon_epon_set_security_key(struct xpon_dev *xp, int llid_idx,
				      int key_idx, const u8 key[16])
{
	void __iomem *ep = xp->mac2;
	int dw;

	if (!ep)
		return;
	for (dw = 0; dw < 4; dw++) {
		u32 cfg = EPON_SEC_KEY_WRITE_CMD |
			  ((llid_idx & 7) << EPON_SEC_KEY_LLID_SHIFT) |
			  ((key_idx  & 1) << EPON_SEC_KEY_IDX_SHIFT)  |
			  ((dw       & 3) << EPON_SEC_KEY_DW_SHIFT);
		u32 data = ((u32)key[dw * 4 + 0] << 24) |
			   ((u32)key[dw * 4 + 1] << 16) |
			   ((u32)key[dw * 4 + 2] <<  8) |
			   ((u32)key[dw * 4 + 3]);

		xpon_writel(ep, EPON_SECURITY_KEY_CFG, cfg);
		xpon_writel(ep, EPON_SECURITY_KEY_DATA, data);
	}
}

/* 10G-XEPON LLID key (an7581_epon_set_llid_key): EPON_LLID_KEY_0/1 with
 * EPON_LLID_KEY_VLD. Runtime MPCP FSM calls this. Bit-field TBD on hardware. */
static void __maybe_unused xpon_epon_set_llid_key(struct xpon_dev *xp,
						  u32 key_lo, u32 key_hi)
{
	void __iomem *ep = xp->mac2;

	if (!ep)
		return;
	xpon_writel(ep, EPON_LLID_KEY_0, key_lo);
	xpon_writel(ep, EPON_LLID_KEY_1, key_hi | EPON_LLID_KEY_VLD);
}

static int xpon_epon_init(struct xpon_dev *xp)
{
	void __iomem *ep = xp->mac2;
	u32 v;
	int i;
	u8 zero_key[16] = {};

	if (!ep) {
		dev_warn(xp->dev, "XEPON: EPON sub-block (xp->mac2) unmapped; cannot init\n");
		return -ENODEV;
	}

	/* 1) MAC soft-reset pulse (EPON_GLB_CFG bit4) + RPT_TXPRI_CTRL, then
	 *    post-reset timing parameters. Ported from epon_sw_reset(). */
	v = xpon_readl(ep, EPON_GLB_CFG);
	xpon_writel(ep, EPON_GLB_CFG, v | EPON_GLB_MAC_SW_RST);
	udelay(10);
	v = xpon_readl(ep, EPON_GLB_CFG);
	v &= ~EPON_GLB_MAC_SW_RST;
	xpon_writel(ep, EPON_GLB_CFG, v);
	udelay(10);
	v |= EPON_GLB_RPT_TXPRI_CTRL;
	xpon_writel(ep, EPON_GLB_CFG, v);

	xpon_writel(ep, EPON_GRD_THRSHLD,      EPON_GRD_THRSHLD_DEFAULT);
	xpon_writel(ep, EPON_TRX_ADJUST_TIME1, EPON_TRX_ADJUST_TIME1_DEF);
	xpon_writel(ep, EPON_TRX_ADJUST_TIME2, EPON_TRX_ADJUST_TIME2_DEF);
	xpon_writel(ep, EPON_TXFETCH_CFG,      EPON_TXFETCH_DEFAULT);

	/* 2) Select 1G EPON vs 10G-EPON (XEPON) framing. GLB_MODE_SEL=1 puts the
	 *    block into 10G-XEPON mode (doEponSetMode's 10G path). */
	if (xp->mode == XPON_MODE_XEPON)
		v |= EPON_GLB_MODE_SEL;
	else
		v &= ~EPON_GLB_MODE_SEL;
	xpon_writel(ep, EPON_GLB_CFG, v);

	/* 3) Stop MBI, forward MPCP/FCS, enable discovery burst (epon_hw_init). */
	v = xpon_readl(ep, EPON_GLB_CFG);
	v |= EPON_GLB_TXMBI_STOP | EPON_GLB_RXMBI_STOP;
	v |= EPON_GLB_MPCP_FWD | EPON_GLB_FCS_ERR_FWD | EPON_GLB_DISCV_BURST_EN;
	xpon_writel(ep, EPON_GLB_CFG, v);

	/* 4) Layer-2 timing / grant parameters. */
	xpon_writel(ep, EPON_PENDING_GNT_NUM,    EPON_PENDING_GNT_DEFAULT);
	xpon_writel(ep, EPON_MPCP_TIMEOUT_INTVL, EPON_MPCP_TIMEOUT_DEFAULT);
	xpon_writel(ep, EPON_RPT_TIMEOUT_INTVL,  EPON_RPT_TIMEOUT_DEFAULT);
	xpon_writel(ep, EPON_MAX_FUTURE_GNT,     EPON_MAX_FUTURE_GNT_DEFAULT);
	xpon_writel(ep, EPON_MIN_PROC_TIME,      EPON_MIN_PROC_TIME_DEFAULT);
	xpon_writel(ep, EPON_LASER_ONOFF_TIME,   EPON_LASER_ONOFF_DEFAULT);
	xpon_writel(ep, EPON_TX_CAL_CNST,        EPON_TX_CAL_CNST_DEFAULT);

	/* 5) Hardware dying gasp detection (magic value per ref). */
	xpon_writel(ep, EPON_DYINGGSP_CFG, EPON_DYINGGSP_CFG_HW_ENABLE);

	/* 6) Clear all LLID security keys (epon_hw_init loop). */
	for (i = 0; i < EPON_MAX_LLID; i++)
		xpon_epon_set_security_key(xp, i, 0, zero_key);

	/* 7) Enable interrupts: discovery gate + per-LLID registration. */
	xpon_writel(ep, EPON_INT_EN,
		    EPON_INT_DISCV_GATE |
		    EPON_INT_LLID_RGST(0) | EPON_INT_LLID_RGST(1) |
		    EPON_INT_LLID_RGST(2) | EPON_INT_LLID_RGST(3) |
		    EPON_INT_LLID_RGST(4) | EPON_INT_LLID_RGST(5) |
		    EPON_INT_LLID_RGST(6) | EPON_INT_LLID_RGST(7));

	/* TODO (runtime, driven by OLT via MPCP):
	 *   - LLID assignment + OLT MAC (EPON_LLID_MAC_ADDR_0/1); discovery/
	 *     registration FSM driving EPON_LLID_DSCVRY_CTRL
	 *     (EPON_DSCVRY_MPCP_REG_REQ / _ACK).
	 *   - per-LLID unicast/encrypt keys via xpon_epon_set_security_key()
	 *     (1G) and xpon_epon_set_llid_key() (10G-XEPON DPOE key).
	 *   - DBA report, OAM keepalive, MPCP timeout handling.
	 * The 10G line-rate / serdes PCS for XEPON is configured by the stock
	 * firmware's own serdes path (out of scope for this MAC driver). */
	dev_info(xp->dev, "XEPON: EPON MAC init done (mode=%s, GLB_CFG=0x%08x)\n",
		 (xp->mode == XPON_MODE_XEPON) ? "10G-EPON" : "1G-EPON",
		 xpon_readl(ep, EPON_GLB_CFG));

	xpon_epon_start_registration(xp);
	return 0;
}

/* --- XEPON ONU MAC source resolution ---------------------------------------
 *
 * The MAC we advertise as the source of an EPON LLID's upstream frames is a
 * board/factory property, NOT a register we invent. Resolve it once at probe:
 *   1. module parameter epon_onu_mac_override  (highest precedence, for lab use)
 *   2. device tree `local-mac-address` / `mac-address`
 *        - on production units this is typically an nvmem cell pointing at the
 *          factory partition (e.g. nvmem-cells = <&macaddr_factory_0>;), which
 *          of_get_mac_address() resolves transparently.
 *   3. otherwise leave zero and warn (registration still runs, but with a
 *      zero source MAC until the user supplies one via sysfs). */
int xpon_epon_resolve_onu_mac(struct xpon_dev *xp)
{
	struct device_node *np = xp->dev ? xp->dev->of_node : NULL;
	const char *src = NULL;

	/* 1. module parameter override (AA:BB:CC:DD:EE:FF) */
	if (epon_onu_mac_override &&
	    mac_pton(epon_onu_mac_override, xp->epon_onu_mac) &&
	    is_valid_ether_addr(xp->epon_onu_mac))
		src = "module-param";
	/* 2. device tree (covers local-mac-address / mac-address / nvmem factory) */
	else if (np) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
		if (of_get_mac_address(np, xp->epon_onu_mac) == 0 &&
		    is_valid_ether_addr(xp->epon_onu_mac))
			src = "device-tree";
#else
		const u8 *m = of_get_mac_address(np);
		if (!IS_ERR_OR_NULL(m) && is_valid_ether_addr(m)) {
			ether_addr_copy(xp->epon_onu_mac, m);
			src = "device-tree";
		}
#endif
	}

	if (src) {
		dev_info(xp->dev, "XEPON: ONU MAC = %pM (source: %s)\n",
			 xp->epon_onu_mac, src);
		return 0;
	}

	dev_warn(xp->dev,
		 "XEPON: no ONU MAC sourced (module param epon_onu_mac or DTS local-mac-address); "
		 "EPON LLID will register with a zero source MAC until set via sysfs\n");
	return -ENOENT;
}

/* --- XEPON (10G-EPON) MPCP registration FSM -------------------------------- */

/* Ask the HW to emit a REGISTER_REQUEST on the next discovery opportunity. The
 * MPCP command register differs by framing (10G-XEPON uses EPON_MPCP_TX_DONE
 * @0x07c; 1G EPON uses EPON_LLID_DSCVRY_CTRL @0x028 -- same bit layout). */
static void xpon_epon_send_register_request(struct xpon_dev *xp)
{
	void __iomem *ep = xp->mac2;
	u32 cmd = EPON_MPCP_CMD_REG(xp);

	if (!ep)
		return;
	xpon_writel(ep, cmd, xpon_readl(ep, cmd) | EPON_DSCVRY_MPCP_REG_REQ);
}

/* Auto-send REGISTER_ACK to the OLT after a REGISTER frame (MPCP_CMD[ACK] +
 * CMD_DONE). Observed in stock epon_dev_send_mpcp_register_ack (writes window
 * 0x607c = EPON_MPCP_TX_DONE with 0xc0000000 | 0x10000). */
static void xpon_epon_send_register_ack(struct xpon_dev *xp)
{
	void __iomem *ep = xp->mac2;
	u32 cmd = EPON_MPCP_CMD_REG(xp);

	if (!ep)
		return;
	xpon_writel(ep, cmd,
		    xpon_readl(ep, cmd) | EPON_DSCVRY_MPCP_ACK | EPON_DSCVRY_CMD_DONE);
}

/* Handle a received REGISTER frame for LLID n: capture the assigned onu_id,
 * program our ONU MAC as the LLID source address, enable the LLID data path,
 * then auto-send REGISTER_ACK. */
static void xpon_epon_handle_register(struct xpon_dev *xp, unsigned int n)
{
	void __iomem *ep = xp->mac2;
	u32 cfg, onu_id;

	if (!ep || n >= EPON_MAX_LLID)
		return;

	/* The assigned LLID (onu_id) is stored by HW in the per-LLID 8-bit slice
	 * of EPON_LLID0_3_CFG / EPON_LLID4_7_CFG on REGISTER. */
	cfg = xpon_readl(ep, EPON_LLID_CFG_REG(n));
	onu_id = (cfg >> EPON_LLID_CFG_SHIFT(n)) & EPON_LLID_CFG_LLID_MASK;
	xp->epon_llid_id[n] = onu_id;

	/* Program our ONU MAC as the source MAC for this LLID's upstream frames
	 * (EPON_LLID_MAC_ADDR_0/1 == window 0x6104/0x6108). Sourced at probe via
	 * xpon_epon_resolve_onu_mac() (module param > DTS local-mac-address /
	 * factory nvmem cell > sysfs override). */
	xpon_writel(ep, EPON_LLID_MAC_ADDR_0,
		    ((u32)xp->epon_onu_mac[0] << 24) | ((u32)xp->epon_onu_mac[1] << 16) |
		    ((u32)xp->epon_onu_mac[2] <<  8) |  (u32)xp->epon_onu_mac[3]);
	xpon_writel(ep, EPON_LLID_MAC_ADDR_1,
		    ((u32)xp->epon_onu_mac[4] << 24) | ((u32)xp->epon_onu_mac[5] << 16));

	/* Program the assigned LLID value into its 8-bit slice of the per-LLID
	 * config register (EPON_LLID0_3_CFG / EPON_LLID4_7_CFG). The upstream
	 * data-path *enable* is intentionally NOT written here: the four 8-bit LLID
	 * fields occupy the entire 32-bit register, so a per-slice enable bit
	 * (placeholder EPON_LLID_CFG_EN) would collide with a neighbouring LLID's
	 * value bits and, for slice 3, shift out of the register (UB). The real
	 * enable mechanism is hardware-specific and must be confirmed on silicon
	 * before this FSM can open the upstream path. TODO: locate the real enable
	 * register/field and program it here. */
	cfg = xpon_readl(ep, EPON_LLID_CFG_REG(n));
	cfg &= ~(EPON_LLID_CFG_LLID_MASK << EPON_LLID_CFG_SHIFT(n));
	cfg |= (u32)onu_id << EPON_LLID_CFG_SHIFT(n);
	xpon_writel(ep, EPON_LLID_CFG_REG(n), cfg);

	xpon_epon_send_register_ack(xp);

	xp->epon_llid_state[n] = EPON_LLID_ST_WAIT_ACK;
	dev_info(xp->dev, "XEPON: LLID%d got REGISTER (onu_id=%u), REGISTER_ACK sent\n",
		 n, onu_id);
}

irqreturn_t xpon_epon_isr(struct xpon_dev *xp)
{
	void __iomem *ep = xp->mac2;
	u32 status, en, pend;
	unsigned int n;
	unsigned long flags;

	if (!ep)
		return IRQ_NONE;
	status = xpon_readl(ep, EPON_INT_STATUS);
	en = xpon_readl(ep, EPON_INT_EN);
	pend = status & en;
	if (!pend)
		return IRQ_NONE;
	xpon_writel(ep, EPON_INT_STATUS, pend);	/* write-1-to-clear */

	spin_lock_irqsave(&xp->epon_fsm_lock, flags);

	/* Discovery gate from the OLT: trigger REGISTER_REQUEST for any idle LLID. */
	if (pend & EPON_INT_DISCV_GATE) {
		for (n = 0; n < EPON_MAX_LLID; n++)
			if (xp->epon_llid_state[n] == EPON_LLID_ST_INIT)
				xp->epon_llid_state[n] = EPON_LLID_ST_WAIT_REG;
		xpon_epon_send_register_request(xp);
	}

	/* Per-LLID REGISTER frame received -> register and ACK. */
	for (n = 0; n < EPON_MAX_LLID; n++)
		if (pend & EPON_INT_LLID_RGST(n))
			xpon_epon_handle_register(xp, n);

	/* REGISTER_ACK fully sent: mark WAIT_ACK LLIDs as REGISTERED. */
	if (pend & EPON_INT_REG_ACK_DONE) {
		for (n = 0; n < EPON_MAX_LLID; n++)
			if (xp->epon_llid_state[n] == EPON_LLID_ST_WAIT_ACK)
				xp->epon_llid_state[n] = EPON_LLID_ST_REGISTERED;
		dev_info(xp->dev, "XEPON: registration complete (LLID(s) up)\n");
	}

	if (pend & EPON_INT_REG_REQ_DONE)
		dev_dbg(xp->dev, "XEPON: REGISTER_REQUEST sent\n");
	if (pend & EPON_INT_MPCP_TIMEOUT)
		dev_dbg(xp->dev, "XEPON: MPCP timeout\n");

	spin_unlock_irqrestore(&xp->epon_fsm_lock, flags);
	return IRQ_HANDLED;
}

void xpon_epon_start_registration(struct xpon_dev *xp)
{
	unsigned long flags;
	unsigned int n;

	if (!xp->mac2)
		return;
	spin_lock_irqsave(&xp->epon_fsm_lock, flags);
	for (n = 0; n < EPON_MAX_LLID; n++) {
		xp->epon_llid_state[n] = EPON_LLID_ST_INIT;
		xp->epon_llid_id[n] = 0;
	}
	spin_unlock_irqrestore(&xp->epon_fsm_lock, flags);
	dev_info(xp->dev, "XEPON: MPCP registration FSM started; awaiting discovery gate\n");
}

void xpon_epon_stop_registration(struct xpon_dev *xp)
{
	unsigned long flags;
	unsigned int n;

	if (!xp->mac2)
		return;
	spin_lock_irqsave(&xp->epon_fsm_lock, flags);
	for (n = 0; n < EPON_MAX_LLID; n++)
		xp->epon_llid_state[n] = EPON_LLID_ST_INIT;
	spin_unlock_irqrestore(&xp->epon_fsm_lock, flags);
}

int XPON_PHY_SET_MODE(enum xpon_mode mode)
{
	struct xpon_dev *xp = g_xp;
	int submode, ret = 0;
	u32 wan_val;

	if (!xp)
		return -ENODEV;

	/* The EN7581 PON serdes/PCS (phy-airoha-xpon, derived from EN7523/EN7571)
	 * only accepts GPON/EPON submodes, so the generic PHY is driven for those
	 * two and left alone for XGS-PON (its 10G line rate is configured by the
	 * stock firmware's own serdes path). XGS-PON itself IS supported: the
	 * XGS-PON MAC engine at mac+0x5000 is a parallel of the GPON engine and its
	 * GEM/OMCI register block is now ported (see the XPON_MODE_XGPON case and
	 * xpon.h XGS_GEM_*).
	 *
	 * The GPON/EPON path below also drives the generic PON SERDES/PCS line rate
	 * + PCS mode; the EN7581 serdes PHY driver only accepts GPON/EPON submodes,
	 * so the 10G modes (XGS-PON, 10G-EPON) deliberately skip it -- their 10G
	 * line rate is configured by the stock firmware's own serdes path and the
	 * SCU WAN_CONF field (GPON/EPON only) is left untouched. 10G-EPON further
	 * needs the 10G MAC switched to IEEE 802.3av framing (doEponSetMode in
	 * xpon_10g.ko); that register map is still TBD. */
	switch (mode) {
	case XPON_MODE_GPON:
		submode = XPON_PHY_SUBMODE_GPON;
		wan_val = XPON_SCU_WAN_MODE_GPON;
		break;
	case XPON_MODE_EPON:
		submode = XPON_PHY_SUBMODE_EPON;
		wan_val = XPON_SCU_WAN_MODE_EPON;
		break;
	case XPON_MODE_XGPON:
		/* XGS-PON (10G symmetric) IS supported by the hardware and the stock
		 * firmware: the XGS-PON MAC engine lives at base+0x5000 (xgspon_reg,
		 * XGSPON_REG_OFFSET in airoha_xpon.c) and the stock xpon.ko programmes
		 * it at runtime. The GEM/OMCI register block there is a *parallel* of
		 * the GPON engine (vendor airoha_xpon.c: GPON@0x4000 / XGS@0x5000 /
		 * EPON@0x6000 sibling sub-blocks, identical relative offsets), so the
		 * GEM port table, OMCI channel and idle-GEM threshold are now ported
		 * and the gpon_gem_* / gpon_set_omcc_port helpers switch to xgspon_reg
		 * automatically while mode == XGS-PON.
		 *   - Caveat: the relative offsets are taken from the GPON register
		 *     map and assumed to mirror in the XGS block; verify on hardware.
		 *   - The EN7581 serdes PHY driver (phy-airoha-xpon, derived from
		 *     EN7523/EN7571) only accepts GPON/EPON submodes; the 10G line
		 *     rate for XGS-PON is configured by the stock firmware own serdes
		 *     path, so we deliberately do NOT call the generic PHY here.
		 *   - The SCU WAN_CONF field (EN7523 layout) defines only GPON/EPON;
		 *     the stock firmware selects XGS-PON WAN via a different (econet)
		 *     SCU path, so SCU is left untouched. */
		xp->mode = mode;

		if (xp->xgspon_reg) {
			gpon_gem_table_init();
			xpon_writel(xp->xgspon_reg, DBG_IDLE_GEM_THLD,
				    GPON_IDLE_GEM_THLD_DEF);
			dev_info(xp->dev, "XGS-PON mode selected; GEM/OMCI engine at 0x1fb65000 initialised\n");
		} else {
			dev_warn(xp->dev, "XGS-PON mode selected but xgspon_reg unmapped; GEM/OMCI TBD\n");
		}
		return 0;

	case XPON_MODE_XEPON:
		/* 10G-EPON (XEPON, IEEE 802.3av) uses its OWN sub-block at +0x6000
		 * inside the PON MAC window: xp->mac2 == DTS reg[1] == 0x1fb66000. This
		 * is DISTINCT from the XGS-PON sub-block at +0x5000 (xp->mac3 /
		 * xgspon_reg); the two 10G modes share only the 64KB window and the
		 * serdes lane, differing in MAC framing (XEPON = MPCP/LLID/OAM/DBA;
		 * XGS-PON = GEM/OMCI).
		 *
		 * Hardware mode switch (correction to earlier notes): doEponSetMode()
		 * in xpon_10g.ko does NOT write a GPON-block mode register. The MAC
		 * framing switch lives in THIS EPON block:
		 *   - EPON_GLB_CFG[GLB_MODE_SEL] (bit0) is the IP's documented MODE_SEL
		 *     bit and is the most likely 1G-EPON vs 10G-XEPON selector; TBD on
		 *     hardware (the EN7523 open-source driver is 1G-only and never sets
		 *     it). xpon_epon_init() sets it for XPON_MODE_XEPON pending confirm.
		 *   - the rest of doEponSetMode() dispatches through UNION_IC_FUNCTION_HOOK
		 *     and calls eponSetRateMode(); the 10G line-rate / serdes PCS is
		 *     configured by the stock firmware's own serdes path (out of scope
		 *     here).
		 * The open-source EN7523 SCU WAN mux only encodes GPON(0x00)/EPON(0x01),
		 * so 10G-EPON reuses the EPON WAN path (set below). */
		xp->mode = mode;

		/* Select the PON WAN line path in the SCU: 10G-EPON shares the EPON
		 * WAN mux (no 10G SCU value exists). Optional if no SCU phandle. */
		if (xp->scu)
			regmap_update_bits(xp->scu, XPON_SCU_WAN_CONF,
					   XPON_SCU_WAN_MODE_MASK,
					   XPON_SCU_WAN_MODE_EPON);
		else
			dev_warn(xp->dev, "no SCU mapped; XEPON WAN path select skipped\n");

		return xpon_epon_init(xp);

	default:
		dev_err(xp->dev, "xPON mode %d not supported\n", mode);
		return -EOPNOTSUPP;
	}

	/* 1) Drive the PON serdes/PCS line rate + PCS mode. The generic PHY bound
	 *    to the phy-airoha-xpon driver performs the actual SERDES equalisation
	 *    and PCS link training (mirrors airoha_xpon_phy_start()). Optional: if
	 *    the kernel build has no phy-airoha-xpon, this is NULL and the switch
	 *    is delegated to the mainline PCS driver. */
	if (xp->xpon_serdes_phy) {
		if (!xp->serdes_phy_init) {
			ret = phy_init(xp->xpon_serdes_phy);
			if (ret)
				goto out;
			xp->serdes_phy_init = true;
		}
		ret = phy_set_mode_ext(xp->xpon_serdes_phy,
					PHY_MODE_ETHERNET, submode);
		if (ret)
			goto out;
		if (!xp->serdes_phy_powered) {
			ret = phy_power_on(xp->xpon_serdes_phy);
			if (ret)
				goto out;
			xp->serdes_phy_powered = true;
		}
	} else {
		dev_warn(xp->dev, "no xPON serdes PHY bound; PCS line-rate switch skipped\n");
	}

	/* 2) Select the PON WAN line path in the SCU (GPON=0x00 / EPON=0x01).
	 *    Offset XPON_SCU_WAN_CONF=0x070 within the airoha,en7581-scu syscon;
	 *    the macro name is inherited from the EN7523 SCU but the field is the
	 *    same on EN7581. Optional: delegated if no SCU phandle is present. */
	if (xp->scu) {
		regmap_update_bits(xp->scu, XPON_SCU_WAN_CONF,
				   XPON_SCU_WAN_MODE_MASK, wan_val);
	} else {
		dev_warn(xp->dev, "no SCU mapped; WAN path select skipped\n");
	}

	xp->mode = mode;
	return 0;

out:
	dev_err(xp->dev, "xPON serdes PHY mode switch to %d failed: %d\n", mode, ret);
	return ret;
}

void pon_phy_reset(void)
{
	/* Stop the MAC<->frame-engine bus (MBI) so the MAC registers can be safely
	 * reprogrammed. Mirrors stock gponDevResetCtrl -> gponDevMbiStop/MpiStop:
	 *   gponDevMbiStop  -> set G_MBI_STOP.mbi_rx_stop / mbi_tx_stop
	 * (the MPI stop is part of the same bus gating on EN7581). */
	gpon_rmw(G_MBI_STOP, 0, G_MBI_RX_STOP | G_MBI_TX_STOP);
	udelay(10);
}

void epon_set_laser_time(u8 laser_on, u8 laser_off)
{
	struct xpon_dev *xp = g_xp;

	/* Reverse-engineered from stock xpon.ko eponSetlaserTime (0x31804) and
	 * xpon_10g.ko doEponLaserTime (0x352f4): the laser on/off timing lives in
	 * EPON_LASER_ONOFF_TIME -- low byte = laser-on, bits 8-15 = laser-off.
	 * Default EPON_LASER_ONOFF_DEFAULT (0x2020) = on 0x20 / off 0x20. */
	if (!xp || !xp->mac2)
		return;
	xpon_writel(xp->mac2, EPON_LASER_ONOFF_TIME,
		    ((u32)laser_off << 8) | (u32)laser_on);
}

void pon_phy_tx_enable(bool on)
{
	struct xpon_dev *xp = g_xp;
	void __iomem *ep;
	u32 v;

	if (!xp || !xp->mac2)
		return;
	ep = xp->mac2;

	/* Reverse-engineered from stock xpon_10g.ko epon_dev_tx_rx_disable
	 * (0x4096c): "TX/RX disable" gates the EPON MAC<->frame-engine bus by
	 * setting EPON_GLB_CFG bits 8/9 (TXMBI_STOP|RXMBI_STOP) plus bits 12/13
	 * (0x3300 mask), then stops the MPI bus. Enable clears them. This is the
	 * MAC-side upstream-transmission gate; the per-burst laser timing is the
	 * separate EPON_LASER_ONOFF_TIME register (see epon_set_laser_time()). */
	v = xpon_readl(ep, EPON_GLB_CFG);
	if (on)
		v &= ~(EPON_GLB_TXMBI_STOP | EPON_GLB_RXMBI_STOP |
		       EPON_GLB_TXRX_GATE_TBD);
	else
		v |=  (EPON_GLB_TXMBI_STOP | EPON_GLB_RXMBI_STOP |
		       EPON_GLB_TXRX_GATE_TBD);
	xpon_writel(ep, EPON_GLB_CFG, v);
}

void PhyTxLedConf(void)
{
	/* The TX activity LED is driven by the activation state machine in
	 * xpon_act.c (gpon_pon_led_update) via GPIO, according to the LED mapping
	 * recovered from the stock driver (GPIO3 = red O2/O3/O4, GPIO32 = green
	 * O5). There is nothing to configure in the MAC window. */
}

/* XPON serdes PLL bring-up sequences, reverse-engineered from the stock
 * kernel vmlinux.elf (JCPLL_BringUp/TXPLL_BringUp/Phya_BringUp + JCPLL
 * sub-functions). Windows: xpon_serdes=0x1fa8a000, xpon_serdes_aux=0x1fa8b000. */

static void serdes_jcpll_en(struct xpon_dev *xp, int en)
{
	/* JCPLL_EN(): read-modify-write AUX[0x828] EN field.
	 * vendor: v = (0xfefe & (tmp >> 16)) | ((en & 1) | 0x100) */
	u32 tmp = xpon_readl(xp->xpon_serdes_aux, 0x828);
	u32 v = ((tmp >> 16) & 0xfefe) | ((en & 1) | 0x100);

	xpon_writel(xp->xpon_serdes_aux, 0x828, v);
}

static void serdes_jcpll_bringup(struct xpon_dev *xp)
{
	u32 t;

	/* JCPLL_BringUp body */
	t = xpon_readl(xp->xpon_serdes, 0x48);
	t |= 0x2000;
	xpon_writel(xp->xpon_serdes, 0x48, t);
	xpon_writel(xp->xpon_serdes, 0x1c, xpon_readl(xp->xpon_serdes, 0x1c));
	t = xpon_readl(xp->xpon_serdes, 0x1c);
	t |= 0x100;
	xpon_writel(xp->xpon_serdes, 0x1c, t);

	serdes_jcpll_en(xp, 0);		/* disable while reprogramming */

	/* JCPLL_SDM */
	xpon_writel(xp->xpon_serdes, 0x1c, 0xfcfeffff);
	xpon_writel(xp->xpon_serdes, 0x20, 0xfefcfcfe);
	t = xpon_readl(xp->xpon_serdes, 0x24);
	t &= ~0x1;
	xpon_writel(xp->xpon_serdes, 0x24, t);

	/* JCPLL_SSC */
	xpon_writel(xp->xpon_serdes, 0x38, 0x00000000);
	t = xpon_readl(xp->xpon_serdes, 0x34);
	t &= ~0x1;
	xpon_writel(xp->xpon_serdes, 0x34, t);
	xpon_writel(xp->xpon_serdes, 0x30, 0xfffcf8f8);

	/* JCPLL_LPF */
	xpon_writel(xp->xpon_serdes, 0x04, 0xc0c0feff);
	xpon_writel(xp->xpon_serdes, 0x08, 0x00101f0a);
	t = xpon_readl(xp->xpon_serdes, 0x0c);
	t &= ~0x1f;
	xpon_writel(xp->xpon_serdes, 0x0c, t);

	/* JCPLL_VCO */
	xpon_writel(xp->xpon_serdes, 0x2c, 0x04010100);
	xpon_writel(xp->xpon_serdes, 0x30, xpon_readl(xp->xpon_serdes, 0x30));

	/* JCPLL_PCW */
	xpon_writel(xp->xpon_serdes_aux, 0x800, 0x25800000);
	t = xpon_readl(xp->xpon_serdes_aux, 0x79c);
	t |= 0x10000;
	xpon_writel(xp->xpon_serdes_aux, 0x79c, t);

	/* JCPLL_DIV */
	t = xpon_readl(xp->xpon_serdes, 0x14);
	t &= ~0x3;
	xpon_writel(xp->xpon_serdes, 0x14, t);
	t = xpon_readl(xp->xpon_serdes, 0x2c);
	t &= ~0x3;
	xpon_writel(xp->xpon_serdes, 0x2c, t);

	/* JCPLL_KBand */
	xpon_writel(xp->xpon_serdes, 0x10, 0xfffcfcfc);
	xpon_writel(xp->xpon_serdes, 0x0c, 0x02e40000);

	/* JCPLL_TCL(0x10) */
	xpon_writel(xp->xpon_serdes, 0x48, xpon_readl(xp->xpon_serdes, 0x48));
	xpon_writel(xp->xpon_serdes, 0x24, 0x05010100);
	xpon_writel(xp->xpon_serdes, 0x28, xpon_readl(xp->xpon_serdes, 0x28));

	serdes_jcpll_en(xp, 1);		/* enable */

	/* JCPLL_Out */
	xpon_writel(xp->xpon_serdes_aux, 0x828, 0x00000101);
}

static void serdes_txpll_bringup(struct xpon_dev *xp)
{
	/* TXPLL_BringUp body */
	xpon_writel(xp->xpon_serdes, 0x84, xpon_readl(xp->xpon_serdes, 0x84));
	xpon_writel(xp->xpon_serdes, 0x64, 0x01040001);
}

static void serdes_phya_bringup(struct xpon_dev *xp)
{
	/* Phya_BringUp body */
	xpon_writel(xp->xpon_serdes_aux, 0x580, xpon_readl(xp->xpon_serdes_aux, 0x580));
	xpon_writel(xp->xpon_serdes_aux, 0x260, 0x00000101);
}

int pon_serdes_init(void)
{
	struct xpon_dev *xp = g_xp;

	if (!xp || !xp->xpon_serdes || !xp->xpon_serdes_aux) {
		pr_warn("serdes init: windows not mapped, skip xSGMII programming\n");
		return -ENODEV;
	}

	/* SERDES lane bring-up, register sequence reverse-engineered from the
	 * stock kernel xsgmii_ini() (XPON instance, vmlinux.elf @0xc3574).
	 * The vendor MCI cmd 29/31 path reduces to this xSGMII API: 142 writes
	 * across four USXGMII PCS windows (see work/serdes序列完整提取-最终.c.txt).
	 * This is the static init only; dynamic training (R2T / Rate / AN /
	 * JCPLL-TXPLL read-modify-write) is still TODO. */
  xpon_writel(xp->xpon_serdes, 0x000, 0x10040000);
  xpon_writel(xp->xpon_serdes, 0x048, 0x001000ff);
  xpon_writel(xp->xpon_serdes, 0x01c, 0x03000004);
  xpon_writel(xp->xpon_serdes_aux, 0x828, 0x00000000);
  xpon_writel(xp->xpon_serdes, 0x020, 0x00030000);
  xpon_writel(xp->xpon_serdes, 0x024, 0x05010100);
  xpon_writel(xp->xpon_serdes, 0x038, 0x031b0082);
  xpon_writel(xp->xpon_serdes, 0x034, 0x00008201);
  xpon_writel(xp->xpon_serdes, 0x030, 0x0002301d);
  xpon_writel(xp->xpon_serdes, 0x004, 0x00180000);
  xpon_writel(xp->xpon_serdes, 0x008, 0x00101f0a);
  xpon_writel(xp->xpon_serdes, 0x00c, 0x02ff0000);
  xpon_writel(xp->xpon_serdes, 0x02c, 0x04010100);
  xpon_writel(xp->xpon_serdes_aux, 0x800, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x79c, 0x00000000);
  xpon_writel(xp->xpon_serdes, 0x014, 0x00010000);
  xpon_writel(xp->xpon_serdes, 0x010, 0x01000300);
  xpon_writel(xp->xpon_serdes, 0x028, 0x00010400);
  xpon_writel(xp->xpon_serdes, 0x084, 0x0101031b);
  xpon_writel(xp->xpon_serdes, 0x064, 0x00040001);
  xpon_writel(xp->xpon_serdes_aux, 0x854, 0x00000000);
  xpon_writel(xp->xpon_serdes, 0x068, 0x00000300);
  xpon_writel(xp->xpon_serdes, 0x06c, 0x01000003);
  xpon_writel(xp->xpon_serdes, 0x080, 0x00820082);
  xpon_writel(xp->xpon_serdes, 0x07c, 0x00010000);
  xpon_writel(xp->xpon_serdes, 0x050, 0x1f05000c);
  xpon_writel(xp->xpon_serdes, 0x054, 0x00000005);
  xpon_writel(xp->xpon_serdes, 0x074, 0x03000001);
  xpon_writel(xp->xpon_serdes, 0x078, 0x04040401);
  xpon_writel(xp->xpon_serdes_aux, 0x798, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x794, 0x00000000);
  xpon_writel(xp->xpon_serdes, 0x058, 0x030003ff);
  xpon_writel(xp->xpon_serdes, 0x05c, 0x00000100);
  xpon_writel(xp->xpon_serdes, 0x094, 0x00010010);
  xpon_writel(xp->xpon_serdes, 0x070, 0x04000903);
  xpon_writel(xp->xpon_serdes_aux, 0x580, 0x00000002);
  xpon_writel(xp->xpon_serdes, 0x0c4, 0x00010400);
  xpon_writel(xp->xpon_serdes_aux, 0x874, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x77c, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x784, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x778, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x780, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x260, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x374, 0x00000002);
  xpon_writel(xp->xpon_serdes_aux, 0x184, 0x040003ff);
  xpon_writel(xp->xpon_serdes, 0x148, 0x00000000);
  xpon_writel(xp->xpon_serdes, 0x144, 0x00000000);
  xpon_writel(xp->xpon_serdes, 0x11c, 0x02000400);
  xpon_writel(xp->xpon_serdes_aux, 0x004, 0x0c100a00);
  xpon_writel(xp->xpon_serdes, 0x13c, 0x00000000);
  xpon_writel(xp->xpon_serdes, 0x120, 0x00000008);
  xpon_writel(xp->xpon_serdes_aux, 0x320, 0x01010101);
  xpon_writel(xp->xpon_serdes_aux, 0x48c, 0x01000203);
  xpon_writel(xp->xpon_serdes, 0x0dc, 0x00000100);
  xpon_writel(xp->xpon_serdes_aux, 0x80c, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x814, 0x00000000);
  xpon_writel(xp->xpon_serdes, 0x10c, 0x00070600);
  xpon_writel(xp->xpon_serdes_aux, 0x88c, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x768, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x390, 0x00100010);
  xpon_writel(xp->xpon_serdes_aux, 0x394, 0x0019000d);
  xpon_writel(xp->xpon_serdes_aux, 0x39c, 0x00003307);
  xpon_writel(xp->xpon_serdes, 0x0d4, 0xcaab1030);
  xpon_writel(xp->xpon_serdes_aux, 0x100, 0x00c80064);
  xpon_writel(xp->xpon_serdes_aux, 0x08c, 0x00000101);
  xpon_writel(xp->xpon_serdes_aux, 0x104, 0x00000002);
  xpon_writel(xp->xpon_serdes_aux, 0x090, 0x03e80002);
  xpon_writel(xp->xpon_serdes_aux, 0x09c, 0x03e80002);
  xpon_writel(xp->xpon_serdes_aux, 0x094, 0x03e80002);
  xpon_writel(xp->xpon_serdes_aux, 0x098, 0x03e80002);
  xpon_writel(xp->xpon_serdes_aux, 0x76c, 0x00000000);
  xpon_writel(xp->xpon_serdes, 0x0e8, 0x02000000);
  xpon_writel(xp->xpon_serdes, 0x0f8, 0x04010808);
  xpon_writel(xp->xpon_serdes, 0x0fc, 0x00080606);
  xpon_writel(xp->xpon_serdes_aux, 0x120, 0x00000503);
  xpon_writel(xp->xpon_serdes_aux, 0x088, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x38c, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x000, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x33c, 0x01010101);
  xpon_writel(xp->xpon_serdes_aux, 0x330, 0x00000000);
  xpon_writel(xp->xpon_serdes, 0x118, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x824, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x81c, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x894, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x84c, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x34c, 0x00000000);
  xpon_writel(xp->xpon_serdes, 0x114, 0x00040000);
  xpon_writel(xp->xpon_serdes, 0x110, 0x00000200);
  xpon_writel(xp->xpon_serdes_aux, 0x350, 0x00000000);
  xpon_writel(xp->xpon_serdes, 0x0d8, 0x0100000a);
  xpon_writel(xp->xpon_serdes, 0x0cc, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x818, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x460, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x150, 0x0019000d);
  xpon_writel(xp->xpon_serdes_aux, 0x14c, 0x00100010);
  xpon_writel(xp->xpon_serdes_aux, 0x158, 0x00003307);
  xpon_writel(xp->xpon_serdes_aux, 0x154, 0x0019000d);
  xpon_writel(xp->xpon_serdes, 0x0f4, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x820, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x19c, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x174, 0x04010000);
  xpon_writel(xp->xpon_serdes, 0x100, 0x00010001);
  xpon_writel(xp->xpon_serdes_r0, 0x000, 0x00002040);
  xpon_writel(xp->xpon_serdes_r0, 0x22c, 0x00004c4c);
  xpon_writel(xp->xpon_serdes_r0, 0x2c8, 0x00000000);
  xpon_writel(xp->xpon_serdes_r0, 0x2cc, 0x00000000);
  xpon_writel(xp->xpon_serdes_r0, 0x2e0, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x360, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x380, 0x0800a101);
  xpon_writel(xp->xpon_serdes_r0, 0x2f8, 0x06330001);
  xpon_writel(xp->xpon_serdes_r0, 0x030, 0x0000100d);
  xpon_writel(xp->xpon_serdes, 0x000, 0x0c000c00);
  xpon_writel(xp->xpon_serdes_aux, 0x474, 0x00000000);
  xpon_writel(xp->xpon_serdes_r0, 0x2c0, 0x00000000);
  xpon_writel(xp->xpon_serdes_r0, 0x2c4, 0x00000000);
  xpon_writel(xp->xpon_serdes_r0, 0x2f0, 0x000000ff);
  xpon_writel(xp->xpon_serdes_r0, 0x2f4, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x10c, 0x01010101);
  xpon_writel(xp->xpon_serdes_aux, 0x114, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x47c, 0x00000100);
  xpon_writel(xp->xpon_serdes_aux, 0x16c, 0x00000000);
  xpon_writel(xp->xpon_serdes_aux, 0x208, 0x00010101);
  xpon_writel(xp->xpon_serdes_r0, 0x2e8, 0x07070707);
  xpon_writel(xp->xpon_serdes_r0, 0x2fc, 0x00001601);
  xpon_writel(xp->xpon_serdes_r0, 0x320, 0x00000000);
  xpon_writel(xp->xpon_serdes_r0, 0x31c, 0x00000000);
  xpon_writel(xp->xpon_serdes, 0x02c, 0x00000004);
  xpon_writel(xp->xpon_serdes, 0x100, 0x80000000);
  xpon_writel(xp->xpon_serdes_r1, 0x000, 0x0c9cc000);
  xpon_writel(xp->xpon_serdes_aux, 0x178, 0x00020403);
  xpon_writel(xp->xpon_serdes, 0x000, 0x00001140);
  xpon_writel(xp->xpon_serdes, 0x018, 0x00000000);
  xpon_writel(xp->xpon_serdes, 0x034, 0x31120009);
  xpon_writel(xp->xpon_serdes, 0x014, 0x00000000);
  xpon_writel(xp->xpon_serdes, 0x020, 0x00000011);
  xpon_writel(xp->xpon_serdes_r1, 0x014, 0x00000013);
  xpon_writel(xp->xpon_serdes, 0x010, 0x00000001);
  xpon_writel(xp->xpon_serdes_r1, 0x020, 0x00000113);
  xpon_writel(xp->xpon_serdes, 0x14c, 0x00000001);
  xpon_writel(xp->xpon_serdes, 0x018, 0x0100009c);
  xpon_writel(xp->xpon_serdes, 0x004, 0x050f010f);
  xpon_writel(xp->xpon_serdes_r1, 0x024, 0x00000000);

	/* PLL bring-up (JCPLL/TXPLL/Phya), reverse-engineered from stock. */
	serdes_jcpll_bringup(xp);
	serdes_txpll_bringup(xp);
	serdes_phya_bringup(xp);

	return 0;
}
