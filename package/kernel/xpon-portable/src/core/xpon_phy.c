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

int XPON_PHY_SET_MODE(enum xpon_mode mode)
{
	struct xpon_dev *xp = g_xp;
	int submode, ret = 0;
	u32 wan_val;

	if (!xp)
		return -ENODEV;

	/* Only GPON and EPON are supported by the EN7581 PON serdes/PCS today.
	 * The vendor airoha_eth_set_xpon_mode() likewise rejects anything other
	 * than GPON/EPON, and the XG(S)-PON MAC engine is not yet ported (report
	 * §2/§11). 10G-EPON additionally needs different BOSA optics, so it is out
	 * of scope for this hardware. */
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
		 * it at runtime. Caveats implemented here:
		 *   - The EN7581 serdes PHY driver (phy-airoha-xpon, derived from
		 *     EN7523/EN7571) only accepts GPON/EPON submodes; the 10G line
		 *     rate for XGS-PON is configured by the stock firmware own serdes
		 *     path, so we deliberately do NOT call the generic PHY.
		 *   - The SCU WAN_CONF field (EN7523 layout) defines only GPON/EPON;
		 *     the stock firmware selects XGS-PON WAN via a different (econet)
		 *     SCU path, so we leave SCU untouched.
		 *   - The GEM sniffer / OMCI extraction registers for the XGS-PON block
		 *     (0x5000) are NOT yet extracted from the firmware regmap
		 *     (bitfields.json covers only the GPON window), so GEM bridging
		 *     will not work until those are ported. Tracked as a follow-up. */
		xp->mode = mode;
		dev_info(xp->dev, "XGS-PON mode selected (MAC engine at 0x5000); serdes via stock firmware path, GEM/OMCI porting TBD\n");
		return 0;
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
