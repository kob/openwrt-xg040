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
	if (g_xp)
		g_xp->mode = mode;

	/* Protocol mode is owned by the SERDES/PCS block (pon_pcs), not the GPON
	 * MAC window. The mainline airoha,an7581-pcs-pon driver programmes it from
	 * the &pon_pcs phandle. Nothing to do here beyond recording the request. */
	return 0;
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
