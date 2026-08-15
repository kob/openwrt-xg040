// SPDX-License-Identifier: GPL-2.0
/*
 * xpon_act.c - GPON ONU activation state machine (G.984.3 O1..O7) for the
 * EN7581 (AN7581DT).
 *
 * This is the policy half of activation: it decides the MAC activation state
 * from the downstream PLOAM flow (xpon_ploam.c drives most transitions by
 * calling here) and from the TO1/TO2 timers, then writes G_ACTIVATION_ST and
 * arms the appropriate timer. It also owns the LED indication tasklet.
 *
 * What this file encodes that the reference tree fought with
 * ---------------------------------------------------------
 *  - SESSION 12 ROOT-CAUSE FIX (SN = 0 at O3): the MAC bursts the Serial
 *    Number autonomously once act_st == O3, reading G_VENDOR_ID/G_VS_SN at that
 *    instant. If anything cleared them, the ONU transmits an all-zero SN, the
 *    OLT never answers with Assign_ONU-ID, and the link sits in O3 forever -
 *    indistinguishable from a bad fibre. So the SN is re-armed on every path
 *    into O2/O3/O4.
 *  - SN launch-power stepping on each O3 entry (G_SN_MSG_CFG[17:16]), so the
 *    ONU walks through its power levels when the OLT keeps opening SN windows.
 *  - O5 PLOAM filtering (DBG_PLOAMD_FILTER_IN_O5) so the OLT's periodic
 *    Upstream_Overhead / Extended_Burst_Length messages stop re-shaping our
 *    already-ranged burst.
 *  - O3/O4 extended T3 preamble mirror into G_PLOu_PRMBL_TYPE3 (ebl_en), so the
 *    SN/ranging burst carries enough preamble for the OLT to AGC/CDR-lock.
 *
 * NOT VALIDATED ON HARDWARE. Faithful transcription, not a tested driver.
 */
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/interrupt.h>
#include <linux/atomic.h>

#include "xpon.h"

/* ---------------- local register helpers ---------------- */
static inline void __iomem *xp_mac(void)
{
	return (g_xp && g_xp->mac) ? g_xp->mac : NULL;
}

static void xp_rmw(u32 off, u32 clr, u32 set)
{
	void __iomem *m = xp_mac();
	u32 v;

	if (!m)
		return;
	v = xpon_readl(m, off);
	v = (v & ~clr) | set;
	xpon_writel(m, off, v);
}

static void xp_field(u32 off, u32 lo, u32 w, u32 val)
{
	void __iomem *m = xp_mac();

	if (!m)
		return;
	xpon_writel(m, off, XP_SET(xpon_readl(m, off), lo, w, val));
}

static struct tasklet_struct gpon_led_tasklet;

/* ---------------- helpers ---------------- */

const char *gpon_state_name(enum gpon_state st)
{
	switch (st) {
	case GPON_STATE_O1: return "O1-Initial";
	case GPON_STATE_O2: return "O2-Standby";
	case GPON_STATE_O3: return "O3-SerialNumber";
	case GPON_STATE_O4: return "O4-Ranging";
	case GPON_STATE_O5: return "O5-Operation";
	case GPON_STATE_O6: return "O6-Popup";
	case GPON_STATE_O7: return "O7-EmergencyStop";
	default:            return "O0-Unknown";
	}
}

enum gpon_state gpon_act_get_state(void)
{
	return (g_xp && g_xp->gpon) ? g_xp->gpon->state : GPON_STATE_O1;
}

/* Step the SN launch-power-mode (driven by G_INT_SN_REQ_CRS, and also on each
 * O3 entry). mode cycles 0 -> 1 -> 2. */
void gpon_act_sn_power_step(void)
{
	void __iomem *m = xp_mac();
	u32 v, mode;

	if (!m)
		return;
	v = xpon_readl(m, G_SN_MSG_CFG);
	mode = (v >> G_SN_MSG_TX_PWR_LO) & XP_MASK(G_SN_MSG_TX_PWR_W);
	mode = (mode + 1) % 3;
	xpon_writel(m, G_SN_MSG_CFG,
		    XP_SET(v, G_SN_MSG_TX_PWR_LO, G_SN_MSG_TX_PWR_W, mode));
	if (g_xp->gpon)
		g_xp->gpon->tx_power_mode = (u8)mode;
}

/* ---------------- core: change activation state ---------------- */

void gpon_act_change_state(enum gpon_state new_state)
{
	struct xpon_dev *xp = g_xp;
	struct gpon_priv *gp;
	void __iomem *m;
	u32 cur;
	unsigned long flags;

	if (!xp || !xp->gpon || !xp->mac)
		return;
	gp = xp->gpon;
	m  = xp->mac;

	spin_lock_irqsave(&gp->lock, flags);

	if (new_state == gp->state) {
		spin_unlock_irqrestore(&gp->lock, flags);
		return;
	}

	/* SESSION 12 ROOT-CAUSE FIX: re-arm SN before any autonomous burst. */
	if (new_state == GPON_STATE_O2 || new_state == GPON_STATE_O3 ||
	    new_state == GPON_STATE_O4)
		gpon_program_serial_number();

	/* Step SN launch power each time we enter O3. */
	if (new_state == GPON_STATE_O3)
		gpon_act_sn_power_step();

	if (new_state == GPON_STATE_O5) {
		/* Filter out the OLT's periodic overhead / ext-burst PLOAMs now that
		 * we are ranged, so they don't keep re-shaping our upstream burst.
		 * The PHY-side oper_ranged_st=0x3 is owned by mainline pon_pcs. */
		xp_field(DBG_PLOAMD_FILTER_IN_O5, 0, 1, 0x1); /* us_overhead filter */
		xp_field(DBG_PLOAMD_FILTER_IN_O5, 8, 1, 0x1); /* ext_bst_len filter */

		/* O5 = operation. Enable the GEM sniffer so downstream OMCI on
		 * GEM Port 0x0001 is extracted to the CPU (QDMA ring15 -> OMCC
		 * char device). Until now the sniffer was programmed but disabled
		 * (see xpon_gem_init), so the OMCI control plane stays dark. */
		xpon_gem_sniffer_enable(true);
	} else if (new_state == GPON_STATE_O3 || new_state == GPON_STATE_O4) {
		/* Mirror the cached extended T3 preamble into the MAC so the
		 * SN/ranging burst carries enough preamble to be received. */
		if (gp->overhead_valid) {
			xp_field(G_PLOu_PRMBL_TYPE3, G_PLOU_PRMB3_O34_LO,
				 G_PLOU_PRMB3_O34_W, gp->preamble_t3);
			xp_field(G_PLOu_PRMBL_TYPE3, G_PLOU_PRMB3_O5_LO,
				 G_PLOU_PRMB3_O5_W, gp->preamble_t3);
			xp_rmw(G_PLOu_PRMBL_TYPE3, 0, G_PLOU_PRMB3_EBL_EN);
		}
	} else if (new_state == GPON_STATE_O2) {
		/* Clear the extended preamble and re-apply the response-time /
		 * fine-delay knobs before the next O3 SN burst. */
		xp_rmw(G_PLOu_PRMBL_TYPE3, G_PLOU_PRMB3_EBL_EN, 0);
		xp_field(G_RSP_TIME, G_RSP_TIME_LO, G_RSP_TIME_W,
			 GPON_DEFAULT_RSP_TIME);
		xp_field(DBG_DLY, DBG_DLY_FINE_INT_LO, DBG_DLY_FINE_INT_W,
			 GPON_INTERNAL_DLY_DEF);

		/* Dropped back to ranging: OMCI is no longer usable, stop
		 * extracting OMCI to the CPU. */
		xpon_gem_sniffer_enable(false);
	}

	/* Write the activation state into the MAC. */
	cur = xpon_readl(m, G_ACTIVATION_ST);
	xpon_writel(m, G_ACTIVATION_ST,
		    XP_SET(cur, G_ACT_ST_LO, G_ACT_ST_W, new_state));

	gp->state = new_state;
	gp->state_change_cnt++;

	if (new_state == GPON_STATE_O5)
		atomic_set(&gp->to1_expiry_cnt, GPON_TO1_RESET_CNT);

	spin_unlock_irqrestore(&gp->lock, flags);

	/* Timers (outside the lock). */
	if (new_state == GPON_STATE_O3 || new_state == GPON_STATE_O4) {
		mod_timer(&gp->to1_timer,
			  jiffies + msecs_to_jiffies(GPON_ACT_TO1_MS));
	} else if (new_state == GPON_STATE_O6) {
		mod_timer(&gp->to2_timer,
			  jiffies + msecs_to_jiffies(GPON_ACT_TO2_MS));
	} else {
		timer_delete(&gp->to1_timer);
		timer_delete(&gp->to2_timer);
	}

	dev_info(xp->dev, "gpon: activation state -> %s\n",
		 gpon_state_name(new_state));
	tasklet_schedule(&gpon_led_tasklet);
}

/* ---------------- timers ---------------- */

static void gpon_act_to1_expires(struct timer_list *t)
{
	struct gpon_priv *gp = timer_container_of(gp, t, to1_timer);
	struct xpon_dev *xp = g_xp;

	if (!xp || !gp)
		return;
	if (gp->state != GPON_STATE_O3 && gp->state != GPON_STATE_O4)
		return;

	dev_warn(xp->dev,
		 "gpon: TO1 (%ums) timeout in %s -> O2\n",
		 GPON_ACT_TO1_MS, gpon_state_name(gp->state));

	if (atomic_dec_and_test(&gp->to1_expiry_cnt)) {
		dev_err(xp->dev,
			"gpon: TO1 expired %u times, restarting connection\n",
			GPON_TO1_RESET_CNT);
		atomic_set(&gp->to1_expiry_cnt, GPON_TO1_RESET_CNT);
		atomic_inc(&gp->hw_reset_cnt);
		/* Full restart: re-init the MAC tables/state and fall back to O1. */
		gpon_dev_init();
		gpon_act_change_state(GPON_STATE_O1);
		return;
	}

	gpon_act_change_state(GPON_STATE_O2);
}

static void gpon_act_to2_expires(struct timer_list *t)
{
	struct gpon_priv *gp = timer_container_of(gp, t, to2_timer);
	struct xpon_dev *xp = g_xp;

	if (!xp || !gp)
		return;
	if (gp->state != GPON_STATE_O6)
		return;

	dev_warn(xp->dev, "gpon: TO2 timeout in O6 -> O1 (link down)\n");
	gpon_act_change_state(GPON_STATE_O1);
}

/* ---------------- LED indication ----------------
 * The front PON LED is board/SoC specific. On EN7528 the reference drove it via
 * absolute MIPS-physical GPIO addresses (GPIO3 = red, GPIO32 = green), but the
 * EN7581 GPIO controller is a different block, not mapped by this driver. We log
 * the intended state; the board DTS / LED subsystem should drive the real LEDs.
 */
static void gpon_pon_led_update(void)
{
	struct gpon_priv *gp = g_xp ? g_xp->gpon : NULL;

	if (!gp || !g_xp->dev)
		return;
	dev_dbg(g_xp->dev, "gpon: LED %s\n",
		gp->state == GPON_STATE_O5 ? "GREEN(registered)"
		: (gp->state == GPON_STATE_O2 || gp->state == GPON_STATE_O3 ||
		   gp->state == GPON_STATE_O4) ? "RED(ranging)"
		: "OFF");
}

static void gpon_act_led_tasklet_fn(struct tasklet_struct *t)
{
	(void)t;
	gpon_pon_led_update();
}

/* ---------------- init / deinit ---------------- */

int gpon_act_init(void)
{
	struct gpon_priv *gp = g_xp ? g_xp->gpon : NULL;

	if (!gp)
		return -ENODEV;

	tasklet_setup(&gpon_led_tasklet, gpon_act_led_tasklet_fn);
	timer_setup(&gp->to1_timer, gpon_act_to1_expires, 0);
	timer_setup(&gp->to2_timer, gpon_act_to2_expires, 0);
	atomic_set(&gp->to1_expiry_cnt, GPON_TO1_RESET_CNT);
	atomic_set(&gp->hw_reset_cnt, 0);
	gp->state = GPON_STATE_O1;

	gpon_ploam_init();	/* set up the deferred PLOAM workqueue */

	return 0;
}

void gpon_act_deinit(void)
{
	struct gpon_priv *gp = g_xp ? g_xp->gpon : NULL;

	if (gp) {
		timer_delete_sync(&gp->to1_timer);
		timer_delete_sync(&gp->to2_timer);
	}
	tasklet_kill(&gpon_led_tasklet);
}
