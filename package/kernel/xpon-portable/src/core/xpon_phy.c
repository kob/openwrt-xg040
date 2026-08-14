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

/* 10G-EPON (XEPON) MAC bring-up skeleton.
 *
 * Register offsets/bits come from disassembling xpon_10g.ko (an7581_epon_*,
 * epon_*) cross-checked with the open-source EN7523 airoha_xpon.c EPON map
 * (see xpon.h). This is the STATIC / hardware part of init; the protocol
 * state (LLID assignment, OLT MAC, unicast/encrypt keys, MPCP discovery &
 * registration, DBA report, OAM keepalive) is driven by the OLT at runtime and
 * is LEFT AS TODO. NOT compiled / NOT hardware-verified. */
static int xpon_epon_init(struct xpon_dev *xp)
{
	void __iomem *ep = xp->mac2;
	u32 v;

	if (!ep) {
		dev_warn(xp->dev, "XEPON: EPON sub-block (xp->mac2) unmapped; cannot init\n");
		return -ENODEV;
	}

	/* 1) MAC soft-reset pulse (EPON_GLB_CFG bit4, per EN7523 airoha_xpon.c) */
	v = xpon_readl(ep, EPON_GLB_CFG);
	xpon_writel(ep, EPON_GLB_CFG, v | EPON_GLB_MAC_SW_RST);
	udelay(10);
	v = xpon_readl(ep, EPON_GLB_CFG);
	xpon_writel(ep, EPON_GLB_CFG, v & ~EPON_GLB_MAC_SW_RST);
	udelay(10);

	/* 2) Default MPCP timeout (10-bit field, EPON_MPCP_TO_MASK) */
	xpon_writel(ep, EPON_MPCP_TIMEOUT_10G, 0x3ff & EPON_MPCP_TO_MASK); /* TODO: real value */

	/* 3) Default queue threshold (an7581_epon_set_queue_threshold_cfg, 0x12c) */
	xpon_writel(ep, EPON_QUEUE_THRESHOLD_CFG, 0x0); /* TODO: real threshold */

	/* 4) Enable interrupts: discovery gate + per-LLID registration */
	xpon_writel(ep, EPON_INT_EN,
		    EPON_INT_DISCV_GATE |
		    EPON_INT_LLID_RGST(0) | EPON_INT_LLID_RGST(1) |
		    EPON_INT_LLID_RGST(2) | EPON_INT_LLID_RGST(3) |
		    EPON_INT_LLID_RGST(4) | EPON_INT_LLID_RGST(5) |
		    EPON_INT_LLID_RGST(6) | EPON_INT_LLID_RGST(7));

	/* TODO (runtime, driven by OLT via MPCP):
	 *   - epon_llid_enable(): EPON_PENDING_GNT_NUM / EPON_LLID_DSCVRY_CTRL
	 *   - epon_set_llid_regs_mac_address(): EPON_LLID_MAC_ADDR_0/1
	 *   - an7581_epon_set_llid_key(): EPON_LLID_KEY_0/1 (+EPON_LLID_KEY_VLD)
	 *   - an7581_epon_set_dpoe_decrypt/encrypt_llid_key(): EPON_DPOE_DECRYPT_KEY_*,
	 *     EPON_DPOE_ENCRYPT_KEY_CFG, EPON_DPOE_ENCRYPT_LLID_KEY
	 *   - MPCP discovery/registration FSM, DBA report, OAM keepalive */
	dev_info(xp->dev, "XEPON: static MAC init done (reset+MPCP-to+Q-thr+intr); LLID/key/MPCP-FSM TODO\n");
	return 0;
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
		 * XGS-PON = GEM/OMCI). The firmware selects framing via doEponSetMode()
		 * in xpon_10g.ko (a small GPON-block mode register, offset 0x14..0x20).
		 * The XEPON register map (MPCP/LLID/OAM/DBA/encryption) HAS been
		 * extracted from xpon_10g.ko and added to xpon.h; drive the static MAC
		 * bring-up now, deferring the OLT-driven runtime state. The generic
		 * serdes PHY does not accept a 10G-EPON submode and the SCU WAN_CONF
		 * field encodes only GPON/EPON, so both are left untouched (cf. XGS-PON). */
		xp->mode = mode;
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
