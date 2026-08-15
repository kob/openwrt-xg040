// SPDX-License-Identifier: GPL-2.0
/*
 * xpon_ploam.c - PLOAM transport and downstream message dispatch for the
 * EN7581 (AN7581DT) GPON driver.
 *
 * Responsibilities
 * ----------------
 *  - Pull 12-byte downstream PLOAMs out of the RX FIFO (3 x 32-bit words).
 *  - Push 12-byte upstream PLOAMs into the TX FIFO (repeated N times).
 *  - Decode every downstream message G.984.3 sends and drive the right
 *    hardware action + state transition (most transitions funnel through
 *    gpon_act_change_state() in xpon_act.c).
 *  - Provide the top-half IRQ handler that clears the MAC interrupt status and
 *    defers the RX FIFO drain into a workqueue (so the heavy dispatch runs
 *    outside hard IRQ context).
 *
 * Byte order (why no swab32)
 * -------------------------
 * A PLOAM is 13 wire bytes; the last is a MAC-appended CRC, so software moves
 * 12 bytes = 3 FIFO words. The FIRST wire byte (destination ONU-ID) lands in
 * the MOST significant byte of the first FIFO word. On this little-endian ARM64
 * that means, after a plain readl(), byte i = (word[i/4] >> (24 - 8*(i%4))) & 0xff
 * on RX and word = (b0<<24)|(b1<<16)|(b2<<8)|b3 on TX. This explicit big-endian
 * packing/unpacking is what the stock driver reaches for via swab32; doing it
 * directly keeps send and receive symmetric and avoids the tx_ploam_swab bug
 * that was garbling O5 upstream PLOAMs in the reference tree.
 *
 * NOT VALIDATED ON HARDWARE. No board was available, so this is a faithful
 * transcription of econet-xpon's gpon.c / gpon_ploam.c dispatch, not a tested
 * driver.
 */
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>
#include <linux/atomic.h>

#include "xpon.h"

/* ---------------- local register helpers ----------------
 * gpon_gpon.c keeps its own static copies of these; they are repeated here so
 * this file is self-contained (one module, no cross-file symbol needed). */
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

/* ---------------- PLOAM RX FIFO ---------------- */

/*
 * Read one 12-byte PLOAM from the downstream FIFO.
 * Returns 1 if a message was consumed, 0 if the FIFO is empty.
 */
int gpon_ploam_recv(u8 *msg)
{
	void __iomem *m = xp_mac();
	u32 sts, w[GPON_PLOAM_WORDS];
	int i;

	if (!m || !msg)
		return 0;

	sts = xpon_readl(m, G_PLOAMd_FIFO_STS);
	if (XP_GET(sts, G_PLOAMD_USED_LO, G_PLOAMD_USED_W) < GPON_PLOAM_WORDS)
		return 0;

	for (i = 0; i < GPON_PLOAM_WORDS; i++)
		w[i] = xpon_readl(m, G_PLOAMd_RDATA);

	/* explicit big-endian unpack: first wire byte in the MSB of word 0 */
	for (i = 0; i < GPON_PLOAM_LEN; i++)
		msg[i] = (u8)(w[i / 4] >> (24 - 8 * (i % 4)));

	return 1;
}

/* Discard everything currently in the downstream FIFO (used on shutdown). */
void gpon_ploam_drain(void)
{
	u8 msg[GPON_PLOAM_LEN];

	while (gpon_ploam_recv(msg))
		; /* discard */
}

/* ---------------- PLOAM TX FIFO ---------------- */

/*
 * Push one 12-byte PLOAM into the upstream FIFO, `times` back-to-back copies
 * (GPON_PLOAM_REPEAT for the message types the OLT expects repeated).
 */
int gpon_ploam_send(const u8 *msg, unsigned int times)
{
	void __iomem *m = xp_mac();
	u32 w[GPON_PLOAM_WORDS];
	unsigned int t, i;

	if (!m || !msg)
		return -EINVAL;
	if (times == 0)
		times = 1;

	w[0] = ((u32)msg[0] << 24) | ((u32)msg[1] << 16) |
	       ((u32)msg[2] << 8)  |  (u32)msg[3];
	w[1] = ((u32)msg[4] << 24) | ((u32)msg[5] << 16) |
	       ((u32)msg[6] << 8)  |  (u32)msg[7];
	w[2] = ((u32)msg[8] << 24) | ((u32)msg[9] << 16) |
	       ((u32)msg[10] << 8) |  (u32)msg[11];

	for (t = 0; t < times; t++)
		for (i = 0; i < GPON_PLOAM_WORDS; i++)
			xpon_writel(m, G_PLOAMu_WDATA, w[i]);

	return 0;
}

static u8 ploam_dst(void)
{
	struct gpon_priv *gp = g_xp ? g_xp->gpon : NULL;

	if (gp && gp->onu_id_valid)
		return gp->onu_id;
	return GPON_PLOAM_BCAST;
}

int gpon_ploam_send_password(void)
{
	u8 msg[GPON_PLOAM_LEN];
	u8 pw_len = 0;
	const char *pw = gpon_get_password(&pw_len);

	memset(msg, 0, sizeof(msg));
	msg[GPON_PLOAM_OFF_ONU_ID] = GPON_PLOAM_BCAST;
	msg[GPON_PLOAM_OFF_MSG_ID]  = PLOAM_US_PASSWORD;
	if (pw && pw_len)
		memcpy(&msg[GPON_PLOAM_OFF_PAYLOAD], pw,
		       min_t(size_t, pw_len, (size_t)GPON_PW_MAX));
	return gpon_ploam_send(msg, GPON_PLOAM_REPEAT);
}

int gpon_ploam_send_no_message(void)
{
	u8 msg[GPON_PLOAM_LEN];

	memset(msg, 0, sizeof(msg));
	msg[GPON_PLOAM_OFF_ONU_ID] = GPON_PLOAM_BCAST;
	msg[GPON_PLOAM_OFF_MSG_ID]  = PLOAM_US_NO_MESSAGE;
	return gpon_ploam_send(msg, GPON_PLOAM_REPEAT);
}

int gpon_ploam_send_dying_gasp(void)
{
	u8 msg[GPON_PLOAM_LEN];

	memset(msg, 0, sizeof(msg));
	msg[GPON_PLOAM_OFF_ONU_ID] = ploam_dst();
	msg[GPON_PLOAM_OFF_MSG_ID]  = PLOAM_US_DYING_GASP;
	return gpon_ploam_send(msg, 1);
}

int gpon_ploam_send_acknowledge(u8 downstream_msg_id)
{
	u8 msg[GPON_PLOAM_LEN];

	memset(msg, 0, sizeof(msg));
	msg[GPON_PLOAM_OFF_ONU_ID] = ploam_dst();
	msg[GPON_PLOAM_OFF_MSG_ID]  = PLOAM_US_ACKNOWLEDGE;
	msg[GPON_PLOAM_OFF_PAYLOAD] = downstream_msg_id;
	return gpon_ploam_send(msg, GPON_PLOAM_REPEAT);
}

/* ---------------- downstream message handlers ---------------- */

static void gpon_handle_upstream_overhead(const u8 *m)
{
	struct gpon_priv *gp = g_xp->gpon;

	gp->guard_bits   = m[2];
	gp->preamble_t1  = m[3];
	gp->preamble_t2  = m[4];
	gp->preamble_t3  = m[5];
	gp->delimiter    = ((u32)m[6] << 16) | ((u32)m[7] << 8) | m[8];
	gp->overhead_valid = true;

	/* Program the upstream burst shape the OLT told us to use. These are MAC
	 * registers this driver owns; the PHY-side half is left to mainline
	 * pon_pcs. */
	xp_field(G_PLOu_GUARD_BIT, 0, 8, gp->guard_bits);
	xp_field(G_PLOu_PRMBL_TYPE1_2, G_PLOU_PRMB1_LO, G_PLOU_PRMB1_W, gp->preamble_t1);
	xp_field(G_PLOu_PRMBL_TYPE1_2, G_PLOU_PRMB2_LO, G_PLOU_PRMB2_W, gp->preamble_t2);
	xp_field(G_PLOu_PRMBL_TYPE3, G_PLOU_PRMB3_O34_LO, G_PLOU_PRMB3_O34_W, gp->preamble_t3);
	xp_field(G_PLOu_PRMBL_TYPE3, G_PLOU_PRMB3_O5_LO,  G_PLOU_PRMB3_O5_W,  gp->preamble_t3);
	xp_rmw(G_PLOu_PRMBL_TYPE3, 0, G_PLOU_PRMB3_EBL_EN);
	xp_field(G_PLOu_DELM_BIT, 0, 8, m[8]);

	dev_dbg(g_xp->dev,
		"ploam: Upstream_Overhead guard=%u t1=%u t2=%u t3=%u delim=%06x\n",
		gp->guard_bits, gp->preamble_t1, gp->preamble_t2,
		gp->preamble_t3, gp->delimiter);
}

static void gpon_handle_assign_onu_id(const u8 *m)
{
	struct xpon_dev *xp = g_xp;
	struct gpon_onu_id_cfg cfg;
	u8 onu_id = m[2];

	/* m[3..10] is the 8-byte serial number the OLT is addressing. Only accept
	 * if it matches the SN we were configured with. */
	if (gpon_get_sn_passwd(&cfg) == 0 &&
	    memcmp(&m[3], cfg.sn, GPON_SN_LEN) != 0) {
		dev_dbg(xp->dev, "ploam: Assign_ONU-ID SN mismatch, ignored\n");
		return;
	}

	dev_info(xp->dev, "ploam: Assign_ONU-ID=%u\n", onu_id);
	gpon_set_onu_id(onu_id, true);
	/* O3 -> O4 (Ranging) per G.984.3 */
	gpon_act_change_state(GPON_STATE_O4);
}

static void gpon_handle_ranging_time(const u8 *m)
{
	struct gpon_priv *gp = g_xp->gpon;
	void __iomem *mm = xp_mac();
	u32 eqd = ((u32)m[3] << 24) | ((u32)m[4] << 16) |
		  ((u32)m[5] << 8)  |  (u32)m[6];

	gp->eqd        = eqd;
	gp->byte_delay = eqd & GPON_EQD_BYTE_MASK;
	gp->bit_delay  = eqd & GPON_EQD_BIT_MASK;
	if (mm)
		xpon_writel(mm, G_EQD, eqd);

	dev_info(g_xp->dev, "ploam: Ranging_Time eqd=0x%08x -> O5\n", eqd);
	gpon_act_change_state(GPON_STATE_O5);
}

static void gpon_handle_deactivate_onu_id(const u8 *m)
{
	struct xpon_dev *xp = g_xp;

	dev_info(xp->dev, "ploam: Deactivate_ONU-ID (mode %u)\n", m[2]);
	gpon_deactivate_onu();
	/* Back to standby; the OLT will re-drive discovery. */
	gpon_act_change_state(GPON_STATE_O2);
}

static void gpon_handle_disable_serial_num(const u8 *m)
{
	/* The OLT is asking us to stop answering SN. We keep the SN programmed so
	 * we can still re-range, and just note it. */
	dev_warn(g_xp->dev,
		 "ploam: Disable_Serial_Number (mode %u) - kept SN programmed\n",
		 m[2]);
}

static void gpon_handle_encrypted_port_id(const u8 *m)
{
	struct xpon_dev *xp = g_xp;
	u16 port = ((u16)m[3] << 4) | ((u16)m[4] & 0xf);
	u8  enc  = m[2] & 0x3;

	dev_info(xp->dev, "ploam: Encrypted_Port-ID port=%u enc=%u\n", port, enc);
	gpon_gem_port_write(port, true, enc != 0);
}

static void gpon_handle_assign_alloc_id(const u8 *m)
{
	struct xpon_dev *xp = g_xp;
	u16 alloc = ((u16)m[2] << 4) | ((u16)m[3] & 0xf);
	int ret = gpon_bind_alloc_id(alloc);

	dev_info(xp->dev, "ploam: Assign_Alloc-ID=%u -> tcont %d\n",
		 alloc, ret >= 0 ? ret : -1);
}

static void gpon_handle_config_port_id(const u8 *m)
{
	struct xpon_dev *xp = g_xp;
	bool activate = !!(m[2] & 0x1);
	u16  port = ((u16)m[3] << 4) | ((u16)m[4] & 0xf);

	dev_info(xp->dev, "ploam: Configure_Port-ID port=%u activate=%u (OMCC)\n",
		 port, activate);
	gpon_set_omcc_port(port, activate);
}

static void gpon_handle_extended_burst_length(const u8 *m)
{
	struct gpon_priv *gp = g_xp->gpon;
	u8 o3 = m[2];
	u8 o5 = m[3];

	if (o5)
		gp->preamble_t3 = o5;
	xp_field(G_PLOu_PRMBL_TYPE3, G_PLOU_PRMB3_O34_LO, G_PLOU_PRMB3_O34_W, o3);
	xp_field(G_PLOu_PRMBL_TYPE3, G_PLOU_PRMB3_O5_LO,  G_PLOU_PRMB3_O5_W,  o5);
	xp_rmw(G_PLOu_PRMBL_TYPE3, 0, G_PLOU_PRMB3_EBL_EN);

	dev_dbg(g_xp->dev, "ploam: Extended_Burst_Length o3=%u o5=%u\n", o3, o5);
}

static void gpon_handle_ranging_adjustment(const u8 *m)
{
	struct gpon_priv *gp = g_xp->gpon;
	void __iomem *mm = xp_mac();
	u32 adj = ((u32)m[3] << 24) | ((u32)m[4] << 16) |
		  ((u32)m[5] << 8)  |  (u32)m[6];
	bool neg = !!(m[2] & 0x02);	/* s_bit: 1 = negative adjustment */
	s32 delta = neg ? -(s32)adj : (s32)adj;
	u32 cur, new;

	if (!mm)
		return;
	if ((u32)(delta < 0 ? -delta : delta) > GPON_EQD_O5_MAX_DELTA) {
		dev_dbg(g_xp->dev,
			"ploam: Ranging_Adjustment %d too large, ignored\n", delta);
		return;
	}
	cur = xpon_readl(mm, G_EQD);
	new = cur + (u32)delta;
	xpon_writel(mm, G_EQD, new);
	gp->eqd = new;
	dev_dbg(g_xp->dev,
		"ploam: Ranging_Adjustment cur=0x%08x delta=%d new=0x%08x\n",
		cur, delta, new);
}

static void gpon_handle_pon_id(const u8 *m)
{
	dev_dbg(g_xp->dev, "ploam: PON-ID a=%u class=%u (cached)\n",
		m[2] & 0x1, (m[2] >> 1) & 0x7);
}

static void gpon_handle_key_switching_time(const u8 *m)
{
	/* OLT tells us when to switch to the new AES key (by MAC counter). The
	 * actual switch is driven by the Request_Key -> Encryption_Key exchange
	 * plus a key-switch scheduler, which is out of scope here; log it. */
	(void)m;
	dev_dbg(g_xp->dev, "ploam: Key_Switching_Time (deferred)\n");
}

static void gpon_handle_sleep_allow(const u8 *m)
{
	dev_dbg(g_xp->dev, "ploam: Sleep_Allow=%u\n", m[2] & 0x1);
}

static void gpon_handle_request_key(const u8 *m)
{
	struct xpon_dev *xp = g_xp;
	struct gpon_onu_id_cfg cfg;
	u8 key[16];
	u8 msg[GPON_PLOAM_LEN];
	int i;
	void __iomem *mm = xp_mac();

	/* Derive a deterministic 16-byte key from the SN. A production driver
	 * should pull this from a CSPRNG / secure keystore. */
	if (gpon_get_sn_passwd(&cfg) == 0) {
		for (i = 0; i < 16; i++)
			key[i] = (u8)(cfg.sn[i % GPON_SN_LEN] ^ (i * 0x5a));
	} else {
		memset(key, 0xa5, sizeof(key));
	}

	if (mm) {
		xpon_writel(mm, G_AES_SHADOW_KEY0,
			    ((u32)key[12] << 24) | ((u32)key[13] << 16) |
			    ((u32)key[14] << 8)  |  (u32)key[15]);
		xpon_writel(mm, G_AES_SHADOW_KEY1,
			    ((u32)key[8] << 24) | ((u32)key[9] << 16) |
			    ((u32)key[10] << 8) |  (u32)key[11]);
		xpon_writel(mm, G_AES_SHADOW_KEY2,
			    ((u32)key[4] << 24) | ((u32)key[5] << 16) |
			    ((u32)key[6] << 8)  |  (u32)key[7]);
		xpon_writel(mm, G_AES_SHADOW_KEY3,
			    ((u32)key[0] << 24) | ((u32)key[1] << 16) |
			    ((u32)key[2] << 8)  |  (u32)key[3]);
	}

	/* Send the key in two 8-byte fragments (G.984.3 Encryption_Key PLOAM). */
	memset(msg, 0, sizeof(msg));
	msg[GPON_PLOAM_OFF_ONU_ID] = ploam_dst();
	msg[GPON_PLOAM_OFF_MSG_ID]  = PLOAM_US_ENCRYPTION_KEY;
	msg[2] = 0;	/* key_idx */
	msg[3] = 0;	/* frag_idx 0 */
	memcpy(&msg[4], &key[0], 8);
	gpon_ploam_send(msg, GPON_PLOAM_REPEAT);

	memset(msg, 0, sizeof(msg));
	msg[GPON_PLOAM_OFF_ONU_ID] = ploam_dst();
	msg[GPON_PLOAM_OFF_MSG_ID]  = PLOAM_US_ENCRYPTION_KEY;
	msg[2] = 0;
	msg[3] = 1;	/* frag_idx 1 */
	memcpy(&msg[4], &key[8], 8);
	gpon_ploam_send(msg, GPON_PLOAM_REPEAT);

	dev_info(xp->dev, "ploam: Request_Key -> sent Encryption_Key (2 frags)\n");
}

/* ---------------- dispatch ---------------- */

/*
 * Route one downstream PLOAM to its handler. Called from process context
 * (the PLOAM workqueue). Address filter: accept broadcast (0xff) and messages
 * addressed to our assigned ONU-ID; drop the rest.
 */
int gpon_ploam_dispatch(const u8 *msg)
{
	struct xpon_dev *xp = g_xp;
	struct gpon_priv *gp;
	u8 mid, dest;

	if (!xp || !xp->gpon)
		return -ENODEV;
	gp = xp->gpon;

	dest = msg[GPON_PLOAM_OFF_ONU_ID];
	mid  = msg[GPON_PLOAM_OFF_MSG_ID];

	/* Address filter: before we are assigned an ONU-ID we may only act on
	 * broadcast PLOAMs. Once registered, also accept messages addressed to our
	 * ONU-ID. (GPON_UNASSIGN_ONU_ID == 0xff == BCAST, so a naive comparison
	 * would wrongly accept unicast-to-others while unregistered.) */
	if (!gp->onu_id_valid) {
		if (dest != GPON_PLOAM_BCAST) {
			gp->ploam_dropped_cnt++;
			return 0;
		}
	} else if (dest != GPON_PLOAM_BCAST && dest != gp->onu_id) {
		gp->ploam_dropped_cnt++;
		return 0;
	}

	switch (mid) {
	case PLOAM_DS_UPSTREAM_OVERHEAD:
		gpon_handle_upstream_overhead(msg);
		break;
	case PLOAM_DS_ASSIGN_ONU_ID:
		gpon_handle_assign_onu_id(msg);
		break;
	case PLOAM_DS_RANGING_TIME:
		gpon_handle_ranging_time(msg);
		break;
	case PLOAM_DS_DEACTIVATE_ONU_ID:
		gpon_handle_deactivate_onu_id(msg);
		break;
	case PLOAM_DS_DISABLE_SERIAL_NUM:
		gpon_handle_disable_serial_num(msg);
		break;
	case PLOAM_DS_ENCRYPTED_PORT_ID:
		gpon_handle_encrypted_port_id(msg);
		break;
	case PLOAM_DS_REQUEST_PASSWORD:
		gpon_ploam_send_password();
		break;
	case PLOAM_DS_ASSIGN_ALLOC_ID:
		gpon_handle_assign_alloc_id(msg);
		break;
	case PLOAM_DS_POPUP:
	case PLOAM_DS_SWIFT_POPUP:
		gpon_act_change_state(GPON_STATE_O6);
		break;
	case PLOAM_DS_REQUEST_KEY:
		gpon_handle_request_key(msg);
		break;
	case PLOAM_DS_CONFIG_PORT_ID:
		gpon_handle_config_port_id(msg);
		break;
	case PLOAM_DS_EXTENDED_BURST_LENGTH:
		gpon_handle_extended_burst_length(msg);
		break;
	case PLOAM_DS_RANGING_ADJUSTMENT:
		gpon_handle_ranging_adjustment(msg);
		break;
	case PLOAM_DS_PON_ID:
		gpon_handle_pon_id(msg);
		break;
	case PLOAM_DS_KEY_SWITCHING_TIME:
		gpon_handle_key_switching_time(msg);
		break;
	case PLOAM_DS_SLEEP_ALLOW:
		gpon_handle_sleep_allow(msg);
		break;
	case PLOAM_DS_PEE:
	case PLOAM_DS_CPL:
	case PLOAM_DS_PST:
	case PLOAM_DS_BER_INTERVAL:
		dev_dbg(xp->dev, "ploam: DS msg 0x%02x ignored (no action)\n", mid);
		break;
	default:
		gp->ploam_unknown_cnt++;
		dev_dbg(xp->dev, "ploam: unknown DS msg 0x%02x (dest %02x)\n",
			mid, dest);
		break;
	}

	return 0;
}

/* ---------------- de-duplication + workqueue ---------------- */

static u8 g_last_ploam[GPON_PLOAM_LEN];
static int g_same_ploam_cnt;

static bool ploam_is_same(const u8 *a, const u8 *b, bool ranging_time)
{
	/* Ranging_Time compares only the first 7 bytes (dest/msg/eqd_type/delay);
	 * all others compare the full 12. Mirrors econet-xpon. */
	if (ranging_time)
		return memcmp(a, b, 7) == 0;
	return memcmp(a, b, GPON_PLOAM_LEN) == 0;
}

void gpon_ploam_process_all(void);

static void gpon_ploam_work_fn(struct work_struct *work)
{
	(void)work;
	gpon_ploam_process_all();
}

int gpon_ploam_init(void)
{
	if (g_xp && g_xp->gpon)
		INIT_WORK(&g_xp->gpon->ploam_work, gpon_ploam_work_fn);
	return 0;
}

/*
 * Drain the RX FIFO, de-duplicate (drop 2 of every 3 consecutive identical
 * messages, per G.984.3 PLOAM repetition), and dispatch. Called from the
 * workqueue; safe to also call directly.
 */
void gpon_ploam_process_all(void)
{
	struct gpon_priv *gp = g_xp ? g_xp->gpon : NULL;
	u8 msg[GPON_PLOAM_LEN];
	bool ranging_time;

	if (!gp)
		return;

	while (gpon_ploam_recv(msg)) {
		gp->ploam_rx_cnt++;
		ranging_time = (msg[GPON_PLOAM_OFF_MSG_ID] == PLOAM_DS_RANGING_TIME);

		if (ploam_is_same(g_last_ploam, msg, ranging_time)) {
			g_same_ploam_cnt++;
			if ((g_same_ploam_cnt % 3) != 0) {
				gp->ploam_dropped_cnt++;
				continue;
			}
		} else {
			g_same_ploam_cnt = 0;
		}
		memcpy(g_last_ploam, msg, GPON_PLOAM_LEN);
		gpon_ploam_dispatch(msg);
	}
}

/* ---------------- IRQ top half ---------------- */

/*
 * Top-half handler for the GPON MAC interrupt. Clears status (write-1-clear),
 * counts error classes, and defers the RX FIFO drain to the PLOAM workqueue.
 * Activation-state interrupts that need an immediate reaction (SN threshold
 * crossed, POPUP in O6) are handled here; everything else is driven by the
 * state machine.
 */
irqreturn_t gpon_irq_handler(int irq, void *dev_id)
{
	struct xpon_dev *xp = dev_id;
	void __iomem *m;
	u32 status, enable;

	(void)irq;
	if (!xp || !xp->mac)
		return IRQ_NONE;
	m = xp->mac;

	status = xpon_readl(m, G_INT_STATUS);
	enable = xpon_readl(m, G_INT_ENABLE);
	status &= enable;
	if (!status)
		return IRQ_NONE;

	/* write-1-to-clear */
	xpon_writel(m, G_INT_STATUS, status);

	if (xp->gpon)
		xp->gpon->last_int_status = status;

	if (status & G_INT_PLOAMD_RECV && xp->gpon)
		schedule_work(&xp->gpon->ploam_work);

	if (status & G_INT_SN_REQ_CRS)
		gpon_act_sn_power_step();

	if (status & G_INT_POPUP_IN_O6)
		gpon_act_change_state(GPON_STATE_O6);

	if (status & GPON_INT_ERRORS) {
		if (xp->gpon)
			xp->gpon->int_err_cnt++;
		dev_dbg(xp->dev, "gpon: interrupt errors 0x%08x\n",
			status & GPON_INT_ERRORS);
	}

	return IRQ_HANDLED;
}
