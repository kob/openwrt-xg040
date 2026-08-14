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
static void xpon_epon_set_llid_key(struct xpon_dev *xp, u32 key_lo, u32 key_hi)
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
	xpon_writel(ep, EPON_GLB_CFG, v & ~EPON_GLB_MAC_SW_RST);
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
	 * (EPON_LLID_MAC_ADDR_0/1 == window 0x6104/0x6108). TODO: source this from
	 * the factory MAC / DTS; for now it is xp->epon_onu_mac (default zero). */
	xpon_writel(ep, EPON_LLID_MAC_ADDR_0,
		    ((u32)xp->epon_onu_mac[0] << 24) | ((u32)xp->epon_onu_mac[1] << 16) |
		    ((u32)xp->epon_onu_mac[2] <<  8) |  (u32)xp->epon_onu_mac[3]);
	xpon_writel(ep, EPON_LLID_MAC_ADDR_1,
		    ((u32)xp->epon_onu_mac[4] << 24) | ((u32)xp->epon_onu_mac[5] << 16));

	/* Enable the LLID data path. NOTE: the enable-bit position is UNVERIFIED
	 * (placeholder EPON_LLID_CFG_EN); confirm on hardware. */
	cfg = xpon_readl(ep, EPON_LLID_CFG_REG(n));
	cfg &= ~(EPON_LLID_CFG_LLID_MASK << EPON_LLID_CFG_SHIFT(n));
	cfg |= (u32)onu_id << EPON_LLID_CFG_SHIFT(n);
	cfg |= EPON_LLID_CFG_EN << EPON_LLID_CFG_SHIFT(n);
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
	 * xpon.h XGS_GEM_*). 10G modes (XGS-PON and 10G-EPON). The 10G MAC engine is the sibling block at
	 * mac+0x5000 (xgspon_reg); its 10G line rate is configured by the stock firmware's
	 * own serdes path, so the generic PHY is deliberately not driven and the SCU
	 * WAN_CONF field (GPON/EPON only) is left untouched. 10G-EPON additionally
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
			xpon_writel(xp->xgspon_reg, XGS_IDLE_GEM_THLD,
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
	 *    Offset EN7523_SCU_WAN_CONF=0x070 within the airoha,en7581-scu syscon;
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

void pon_phy_tx_enable(bool on)
{
	/* The upstream laser enable lives in the BOSA/en7572 optical module driver
	 * (bosa_en7572.ko / the Airoha optical driver), NOT in the GPON MAC window.
	 * The MAC only gates the per-burst upstream transmission; the actual laser
	 * on/off is the optical module's job. We therefore do not touch any MAC
	 * register here and simply record the intent.
	 *
	 * TODO: if a PON_PHY-block TX-enable bit is reverse-engineered, set it here
	 * (register/bit TBD — must come from the SoC PON_PHY space at 0x1faf0000,
	 * not the GPON MAC window). */
	(void)on;
}

void PhyTxLedConf(void)
{
	/* The TX activity LED is driven by the activation state machine in
	 * xpon_act.c (gpon_pon_led_update) via GPIO, according to the LED mapping
	 * recovered from the stock driver (GPIO3 = red O2/O3/O4, GPIO32 = green
	 * O5). There is nothing to configure in the MAC window. */
}

int pon_serdes_init(void)
{
	/* SERDES lane bring-up (equalisation, TX/RX calibration, PCS link up) is
	 * the largest remaining unknown. In the stock firmware it is performed by
	 * the serdes_common PHY driver and the airoha,an7581-pcs-pon PCS driver,
	 * which own serdes_common@1fa5a000 / xpon_usxgmii@1fa80000. The GPON MAC
	 * register window (this driver) contains no SERDES registers.
	 *
	 * Until those sequences are reverse-engineered we rely on the mainline PCS
	 * driver being probed for &pon_pcs. Return 0 so MAC bring-up continues; the
	 * link will not train without the PCS driver, which is expected and
	 * documented in the project README. */
	return 0;
}
