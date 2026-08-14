// SPDX-License-Identifier: GPL-2.0
/*
 * xpon_gpon.c - GPON MAC device layer for the EN7581 (AN7581DT).
 *
 * This is the hardware-facing half of the GPON stack: bring-up, the GEM port
 * table, the T-CONT/Alloc-ID map, the OMCC channel, the serial number and the
 * counters. The protocol halves live next door in xpon_ploam.c (PLOAM
 * transport + downstream dispatch) and xpon_act.c (the O1..O7 state machine).
 *
 * Provenance of every register touched here
 * -----------------------------------------
 * Offsets and bit fields were recovered from the stock xpon.ko and then
 * cross-validated against the open-source econet-xpon EN7521 header, which
 * declares the same `g_gpon_mac_reg_BASE` symbol (117/126 offsets, 92.9%).
 * The programming *order* follows econet-xpon's gpon_dev_init() /
 * gpon_INT_init() (src/gpon/gpon_dev.c:2425,2469), which is the only readable
 * implementation of this MAC's init sequence.
 *
 * Deliberate deviations from econet-xpon, and why
 * ----------------------------------------------
 * 1. GEM table wipe. econet-xpon's gponDevResetGemInfo() issues 4096 indirect
 *    write commands with an mdelay(1) retry each. This driver uses the
 *    hardware table initialiser G_GEM_TBL_INIT (start bit0 / done bit8) --
 *    same block, one command -- and only falls back to the per-entry loop if
 *    the initialiser never reports done.
 * 2. No MBI stop/start here. The MBI (MAC <-> frame engine bus) handshake
 *    needs feDevGdm2Cdm2Stop(), a frame-engine call this driver does not own.
 *    gpon_mbi_stop() programs the MAC side only and is left to the caller, so
 *    a wrong-order poke cannot wedge the frame engine.
 * 3. Reset and PHY are not touched. On this SoC the reset controller and the
 *    PON PHY belong to other drivers (mainline pon_pcs / reset framework);
 *    doing it from here would fight them.
 *
 * NOT VALIDATED ON HARDWARE. No board was available, so nothing below has been
 * observed to work; it is a faithful transcription, not a tested driver.
 */
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include "xpon.h"

/* Command handshake budget. econet-xpon uses 3000 x udelay(1) for GEM/T-CONT
 * writes and 3 x mdelay(1) for reads; 3 ms total either way. */
#define GPON_CMD_RETRY		3000
#define GPON_TBL_INIT_RETRY	1000

/* ---------------- register helpers ---------------- */

void __iomem *gpon_mac(void)
{
	return (g_xp && g_xp->mac) ? g_xp->mac : NULL;
}

void gpon_rmw(u32 off, u32 clear, u32 set)
{
	void __iomem *mac = gpon_mac();
	u32 v;

	if (!mac)
		return;
	v = xpon_readl(mac, off);
	v = (v & ~clear) | set;
	xpon_writel(mac, off, v);
}

void gpon_field(u32 off, u32 lo, u32 w, u32 val)
{
	void __iomem *mac = gpon_mac();

	if (!mac)
		return;
	xpon_writel(mac, off, XP_SET(xpon_readl(mac, off), lo, w, val));
}

/* GEM/OMCI register window for the *active* PON mode. The XGS-PON MAC engine
 * (xgspon_reg = mac + 0x5000) mirrors the GPON engine's GEM/OMCI layout, so in
 * XGS-PON mode the GEM port table / OMCI channel must be programmed into the
 * XGS sub-block. The relative offsets are identical (XGS_GEM_PORT_CFG etc.),
 * only the base differs. */
static inline bool xpon_gem_is_xgs(void)
{
	return g_xp && g_xp->mode == XPON_MODE_XGPON && g_xp->xgspon_reg;
}

void __iomem *xpon_gem_base(void)
{
	if (xpon_gem_is_xgs())
		return g_xp->xgspon_reg;
	return gpon_mac();
}

/* ---------------- ONU SN / Password ----------------
 *
 * Only the SN reaches hardware. The GPON MAC has no password register: G.984.3
 * carries the password in an upstream PLOAM message, so it stays in software
 * and xpon_ploam.c reads it back through gpon_get_password().
 */
static char gpon_password[GPON_PW_MAX];
static u8   gpon_password_len;
static u8   gpon_sn_cache[GPON_SN_LEN];
static bool gpon_sn_cached;

/*
 * Byte order, verbatim from gponDevSetSerialNumber (stock full.asm @0x1e730,
 * econet-xpon gpon_dev.c:227): the first wire byte lands in the *most*
 * significant byte of the register.
 *
 *   vendor = sn[0]<<24 | sn[1]<<16 | sn[2]<<8 | sn[3]  ->  G_VENDOR_ID (0x40b0)
 *   serial = sn[4]<<24 | sn[5]<<16 | sn[6]<<8 | sn[7]  ->  G_VS_SN     (0x40b4)
 */
static void gpon_write_sn(const u8 *sn)
{
	void __iomem *mac = gpon_mac();
	u32 vendor, serial;

	if (!mac)
		return;

	vendor = ((u32)sn[0] << 24) | ((u32)sn[1] << 16) |
		 ((u32)sn[2] << 8)  |  (u32)sn[3];
	serial = ((u32)sn[4] << 24) | ((u32)sn[5] << 16) |
		 ((u32)sn[6] << 8)  |  (u32)sn[7];

	xpon_writel(mac, G_VENDOR_ID, vendor);
	xpon_writel(mac, G_VS_SN, serial);
}

int gpon_set_sn_passwd(const struct gpon_onu_id_cfg *cfg)
{
	const u8 *sn = (const u8 *)cfg->sn;

	if (!gpon_mac())
		return -ENODEV;

	memcpy(gpon_sn_cache, sn, GPON_SN_LEN);
	gpon_sn_cached = true;
	gpon_write_sn(sn);

	memset(gpon_password, 0, sizeof(gpon_password));
	gpon_password_len = min_t(u8, cfg->pw_len, GPON_PW_MAX);
	memcpy(gpon_password, cfg->password, gpon_password_len);

	if (g_xp->gpon) {
		memcpy(g_xp->gpon->sn, sn, GPON_SN_LEN);
		g_xp->gpon->sn_len = GPON_SN_LEN;
		memcpy(g_xp->gpon->password, gpon_password, GPON_PW_MAX);
		g_xp->gpon->pw_len = gpon_password_len;
		g_xp->gpon->sn_programmed = true;
	}

	return 0;
}

int gpon_get_sn_passwd(struct gpon_onu_id_cfg *cfg)
{
	void __iomem *mac = gpon_mac();
	u32 vendor, serial;
	u8 *sn;

	if (!mac)
		return -ENODEV;

	memset(cfg, 0, sizeof(*cfg));

	vendor = xpon_readl(mac, G_VENDOR_ID);
	serial = xpon_readl(mac, G_VS_SN);

	sn = (u8 *)cfg->sn;
	sn[0] = (u8)(vendor >> 24); sn[1] = (u8)(vendor >> 16);
	sn[2] = (u8)(vendor >> 8);  sn[3] = (u8)vendor;
	sn[4] = (u8)(serial >> 24); sn[5] = (u8)(serial >> 16);
	sn[6] = (u8)(serial >> 8);  sn[7] = (u8)serial;
	cfg->sn_len = GPON_SN_LEN;

	memcpy(cfg->password, gpon_password, GPON_PW_MAX);
	cfg->pw_len = gpon_password_len;

	return 0;
}

const char *gpon_get_password(u8 *len)
{
	if (len)
		*len = gpon_password_len;
	return gpon_password;
}

/*
 * Re-arm the SN registers from the cache.
 *
 * This exists because of a documented field failure. econet-xpon's gpon_act.c
 * carries a "SESSION 12 ROOT-CAUSE FIX (SN=0 at O3)" note: the MAC bursts the
 * serial number autonomously once act_st == O3, reading whatever is in
 * G_VENDOR_ID/G_VS_SN at that instant. If a MAC reset cleared them, the ONU
 * transmits an all-zero SN, the OLT never answers with Assign_ONU-ID, and the
 * link sits in O3 forever -- a failure that looks exactly like a bad fibre.
 * So the SN is re-written on every path into O3.
 */
int gpon_program_serial_number(void)
{
	if (!gpon_mac())
		return -ENODEV;
	if (!gpon_sn_cached)
		return -ENODATA;

	gpon_write_sn(gpon_sn_cache);
	return 0;
}

/* ---------------- table initialisers ----------------
 * G_GEM_TBL_INIT / G_MIB_TBL_INIT / G_GPIDX_TBL_INIT / G_TX_FCS_TBL_INIT all
 * share one shape: write bit0 to start, poll bit8 for done.
 */
static int gpon_table_init_one(u32 off, const char *what)
{
	void __iomem *mac = xpon_gem_base();
	int retry = GPON_TBL_INIT_RETRY;

	if (!mac)
		return -ENODEV;

	xpon_writel(mac, off, G_TBL_INIT_START);

	while (retry--) {
		if (xpon_readl(mac, off) & G_TBL_INIT_DONE)
			return 0;
		udelay(1);
	}

	dev_warn(g_xp->dev, "gpon: %s table init did not report done\n", what);
	return -ETIMEDOUT;
}

/* Per-entry fallback: invalidate all 4096 GEM ports one command at a time.
 * This is econet-xpon's gponDevResetGemInfo(), used only if the hardware
 * initialiser above is unavailable. */
static int gpon_gem_table_clear_slow(void)
{
	int i, ret = 0;

	for (i = 0; i < GPON_MAX_GEM_ID; i++) {
		ret = gpon_gem_port_write(i, false, false);
		if (ret)
			return ret;
	}
	return 0;
}

int gpon_gem_table_init(void)
{
	int ret;
	u32 off = xpon_gem_is_xgs() ? XGS_GEM_TBL_INIT : G_GEM_TBL_INIT;

	ret = gpon_table_init_one(off, "GEM port");
	if (ret == -ETIMEDOUT)
		ret = gpon_gem_table_clear_slow();

	return ret;
}

/* ---------------- GEM port table (indirect) ----------------
 * Write:  G_GEM_PORT_CFG = cmd(1) | vld | encrypt | port_id, poll STS.cmd_done.
 * Read:   G_GEM_PORT_CFG = cmd(0) | port_id,        poll STS.cmd_done, then
 *         STS.vld / STS.encrypt hold the answer.
 */
int gpon_gem_port_write(u16 gem_port, bool valid, bool encrypt)
{
	void __iomem *mac = xpon_gem_base();
	u32 cfg_off = xpon_gem_is_xgs() ? XGS_GEM_PORT_CFG : G_GEM_PORT_CFG;
	u32 sts_off = xpon_gem_is_xgs() ? XGS_GEM_PORT_STS : G_GEM_PORT_STS;
	int retry = GPON_CMD_RETRY;
	u32 cfg;

	if (!mac)
		return -ENODEV;
	if (gem_port >= GPON_MAX_GEM_ID)
		return -EINVAL;

	cfg = G_GEM_CFG_CMD |
	      XP_SET(0, G_GEM_CFG_ID_LO, G_GEM_CFG_ID_W, gem_port);
	if (valid)
		cfg |= G_GEM_CFG_VLD;
	if (encrypt)
		cfg |= G_GEM_CFG_ENCRYPT;

	xpon_writel(mac, cfg_off, cfg);

	while (retry--) {
		if (xpon_readl(mac, sts_off) & G_GEM_STS_CMD_DONE)
			return 0;
		udelay(1);
	}

	return -ETIMEDOUT;
}

int gpon_gem_port_read(u16 gem_port, bool *valid, bool *encrypt)
{
	void __iomem *mac = xpon_gem_base();
	u32 cfg_off = xpon_gem_is_xgs() ? XGS_GEM_PORT_CFG : G_GEM_PORT_CFG;
	u32 sts_off = xpon_gem_is_xgs() ? XGS_GEM_PORT_STS : G_GEM_PORT_STS;
	int retry = GPON_CMD_RETRY;
	u32 sts;

	if (!mac)
		return -ENODEV;
	if (gem_port >= GPON_MAX_GEM_ID)
		return -EINVAL;

	xpon_writel(mac, cfg_off,
		    XP_SET(0, G_GEM_CFG_ID_LO, G_GEM_CFG_ID_W, gem_port));

	while (retry--) {
		sts = xpon_readl(mac, sts_off);
		if (sts & G_GEM_STS_CMD_DONE) {
			if (valid)
				*valid = !!(sts & G_GEM_STS_VLD);
			if (encrypt)
				*encrypt = !!(sts & G_GEM_STS_ENCRYPT);
			return 0;
		}
		udelay(1);
	}

	return -ETIMEDOUT;
}

/* OMCC: the GEM port that carries OMCI. Programmed from the downstream
 * Configure_Port-ID PLOAM message. */
int gpon_set_omcc_port(u16 gem_port, bool valid)
{
	void __iomem *mac = xpon_gem_base();
	u32 omci_off = xpon_gem_is_xgs() ? XGS_OMCI_ID : G_OMCI_ID;
	u32 v;

	if (!mac)
		return -ENODEV;
	if (valid && gem_port >= GPON_MAX_GEM_ID)
		return -EINVAL;

	v = XP_SET(0, G_OMCI_GPID_LO, G_OMCI_GPID_W, valid ? gem_port : 0);
	if (valid)
		v |= G_OMCI_VLD;
	xpon_writel(mac, omci_off, v);

	/* The OMCC port must also exist in the GEM table to be received. */
	if (valid)
		return gpon_gem_port_write(gem_port, true, false);

	return 0;
}

/* ---------------- T-CONT / Alloc-ID ----------------
 * 0..15 are memory-mapped two per register (even = low half, odd = high half),
 * Alloc-ID is 12 bits with the valid flag at bit 15 of the half-word.
 * 16..31 go through the G_TCONT_ID_16_31_CFG/STS command pair.
 *
 * Note the encoding of "unused": econet-xpon writes Alloc-ID 0xFF (not 0) with
 * valid=0, because Alloc-ID 0 is a legal value (it aliases the ONU-ID).
 */
static int gpon_tcont_write_lo(u8 tcont, u16 alloc_id, bool valid)
{
	void __iomem *mac = gpon_mac();
	u32 off = G_TCONT_ID_BASE + (tcont / GPON_TCONT_PER_REG) * 4;
	u32 shift = (tcont & 1) ? 16 : 0;
	u32 reg;

	reg = xpon_readl(mac, off);
	reg &= ~(0xffffu << shift);
	reg |= ((u32)(alloc_id & GPON_ALLOC_ID_MASK)) << shift;
	if (valid)
		reg |= 1u << (shift + GPON_TCONT_VLD_BIT);
	xpon_writel(mac, off, reg);

	return 0;
}

static int gpon_tcont_write_hi(u8 tcont, u16 alloc_id, bool valid)
{
	void __iomem *mac = gpon_mac();
	int retry = GPON_CMD_RETRY;
	u32 cfg;

	cfg = G_TCONT16_CMD_WRITE |
	      XP_SET(0, G_TCONT16_IDX_LO, G_TCONT16_IDX_W, tcont - 16) |
	      XP_SET(0, G_TCONT16_WR_ID_LO, G_TCONT16_WR_ID_W, alloc_id);
	if (valid)
		cfg |= G_TCONT16_WR_VLD;

	xpon_writel(mac, G_TCONT_ID_16_31_CFG, cfg);

	while (retry--) {
		if (xpon_readl(mac, G_TCONT_ID_16_31_STS) & G_TCONT16_CMD_DONE)
			return 0;
		udelay(1);
	}

	return -ETIMEDOUT;
}

int gpon_set_alloc_id(u8 tcont, u16 alloc_id, bool valid)
{
	if (!gpon_mac())
		return -ENODEV;
	if (tcont >= GPON_TCONT_MAX)
		return -EINVAL;
	if (valid && alloc_id >= GPON_MAX_ALLOC_ID)
		return -EINVAL;
	if (!valid)
		alloc_id = GPON_UNASSIGN_ALLOC_ID;

	if (tcont < GPON_TCONT_HW_MAX)
		return gpon_tcont_write_lo(tcont, alloc_id, valid);

	return gpon_tcont_write_hi(tcont, alloc_id, valid);
}

int gpon_get_alloc_id(u8 tcont, u16 *alloc_id, bool *valid)
{
	void __iomem *mac = gpon_mac();
	int retry = GPON_CMD_RETRY;
	u32 reg, half, sts;

	if (!mac)
		return -ENODEV;
	if (tcont >= GPON_TCONT_MAX)
		return -EINVAL;

	if (tcont < GPON_TCONT_HW_MAX) {
		reg = xpon_readl(mac,
				 G_TCONT_ID_BASE +
				 (tcont / GPON_TCONT_PER_REG) * 4);
		half = (tcont & 1) ? (reg >> 16) : (reg & 0xffff);
		if (alloc_id)
			*alloc_id = (u16)(half & GPON_ALLOC_ID_MASK);
		if (valid)
			*valid = !!(half & (1u << GPON_TCONT_VLD_BIT));
		return 0;
	}

	xpon_writel(mac, G_TCONT_ID_16_31_CFG,
		    XP_SET(0, G_TCONT16_IDX_LO, G_TCONT16_IDX_W, tcont - 16));

	while (retry--) {
		sts = xpon_readl(mac, G_TCONT_ID_16_31_STS);
		if (sts & G_TCONT16_CMD_DONE) {
			if (alloc_id)
				*alloc_id = (u16)XP_GET(sts, G_TCONT16_RD_ID_LO,
						        G_TCONT16_RD_ID_W);
			if (valid)
				*valid = !!(sts & G_TCONT16_RD_VLD);
			return 0;
		}
		udelay(1);
	}

	return -ETIMEDOUT;
}

/*
 * Assign_Alloc-ID handler helper: find a free T-CONT for `alloc_id`, replacing
 * any existing binding first. T-CONT 0 is skipped because it shadows the
 * ONU-ID (econet-xpon gpon_dev.c:1709).
 */
int gpon_bind_alloc_id(u16 alloc_id)
{
	u16 id;
	bool valid;
	int i, ret;

	/* drop a stale binding of the same Alloc-ID */
	for (i = 0; i < GPON_TCONT_MAX; i++) {
		if (gpon_get_alloc_id(i, &id, &valid))
			continue;
		if (valid && id == alloc_id)
			gpon_set_alloc_id(i, 0, false);
	}

	for (i = 1; i < GPON_TCONT_MAX; i++) {
		if (gpon_get_alloc_id(i, &id, &valid))
			continue;
		if (!valid) {
			ret = gpon_set_alloc_id(i, alloc_id, true);
			return ret ? ret : i;
		}
	}

	return -ENOSPC;
}

int gpon_unbind_alloc_id(u16 alloc_id)
{
	u16 id;
	bool valid;
	int i;

	for (i = 0; i < GPON_TCONT_MAX; i++) {
		if (gpon_get_alloc_id(i, &id, &valid))
			continue;
		if (valid && id == alloc_id) {
			gpon_set_alloc_id(i, 0, false);
			return i;
		}
	}

	return -ENOENT;
}

static void gpon_tcont_reset_all(void)
{
	int i;

	for (i = 0; i < GPON_TCONT_MAX; i++)
		gpon_set_alloc_id(i, 0, false);
}

/* ---------------- ONU-ID ---------------- */

int gpon_set_onu_id(u8 onu_id, bool valid)
{
	void __iomem *mac = gpon_mac();
	u32 v;

	if (!mac)
		return -ENODEV;

	v = XP_SET(0, G_ONU_ID_ID_LO, G_ONU_ID_ID_W,
		   valid ? onu_id : GPON_UNASSIGN_ONU_ID);
	if (valid)
		v |= G_ONU_ID_VLD;
	xpon_writel(mac, G_ONU_ID, v);

	if (g_xp->gpon) {
		g_xp->gpon->onu_id = valid ? onu_id : GPON_UNASSIGN_ONU_ID;
		g_xp->gpon->onu_id_valid = valid;
	}

	return 0;
}

u32 gpon_get_onu_id(void)
{
	void __iomem *mac = gpon_mac();

	return mac ? xpon_readl(mac, G_ONU_ID) : 0;
}

/*
 * Deactivate_ONU-ID / Deactivate on LOS: drop the ONU-ID, turn off upstream
 * FEC and invalidate every GEM port. Transcribed from gponDevDeactiveOnu().
 */
int gpon_deactivate_onu(void)
{
	if (!gpon_mac())
		return -ENODEV;

	gpon_set_onu_id(GPON_UNASSIGN_ONU_ID, false);
	gpon_rmw(G_GBL_CFG, G_GBL_CFG_US_FEC_EN, 0);
	gpon_gem_table_init();
	gpon_set_omcc_port(0, false);

	return 0;
}

/* ---------------- upstream FEC ---------------- */

void gpon_set_us_fec(bool on)
{
	gpon_rmw(G_GBL_CFG, G_GBL_CFG_US_FEC_EN, on ? G_GBL_CFG_US_FEC_EN : 0);
}

/* ---------------- DBA status-reporting block size ----------------
 * G_GBL_CFG.sr_blk_size is not a byte count: the hardware wants a bit-reversed
 * "2048 / blockSize" seed. Transcribed from gponDevSetDBABlockSize()
 * (econet-xpon gpon_dev.c:2096) rather than re-derived, since the encoding is
 * not documented anywhere this driver can cite.
 */
static u8 gpon_dba_blk_encode(u16 block_size)
{
	u8 seed, val = 0;
	int i;

	if (!block_size || block_size >= 2048)
		return 0x80;

	seed = (u8)((2048 / block_size) +
		    (((2048 % block_size) >= (block_size >> 1)) ? 1 : 0));

	for (i = 0; i < 8; i++)
		val += (seed & (1u << i)) ? (1u << (7 - i)) : 0;

	return val;
}

void gpon_set_dba_block_size(u16 block_size)
{
	gpon_field(G_GBL_CFG, G_GBL_CFG_SR_BLK_LO, G_GBL_CFG_SR_BLK_W,
		   gpon_dba_blk_encode(block_size));
}

/* ---------------- MBI (MAC <-> frame engine bus) ----------------
 * MAC side only; see the file header for why the frame-engine half is not
 * driven from here. 1 = stop.
 */
void gpon_mbi_stop(bool stop)
{
	gpon_rmw(G_MBI_STOP, G_MBI_RX_STOP | G_MBI_TX_STOP,
		 stop ? (G_MBI_RX_STOP | G_MBI_TX_STOP) : 0);
	mdelay(1);
}

/* ---------------- activation state ---------------- */

u32 gpon_get_activation_state(void)
{
	void __iomem *mac = gpon_mac();

	if (!mac)
		return 0;
	return XP_GET(xpon_readl(mac, G_ACTIVATION_ST), G_ACT_ST_LO, G_ACT_ST_W);
}

/* ---------------- T-CONT query (ioctl nr 75) ---------------- */

int gpon_get_tcont_counter(struct gpon_tcont_counter *c)
{
	u16 alloc_id = 0;
	bool valid = false;
	int ret;

	if (!gpon_mac())
		return -ENODEV;

	ret = gpon_get_alloc_id((u8)c->tcont_id, &alloc_id, &valid);
	if (ret)
		return ret;

	c->alloc_id = alloc_id;
	c->valid = valid ? 1 : 0;
	c->reserved = 0;

	return 0;
}

/* ---------------- hardware counters ----------------
 * Read-to-clear behaviour is unverified, so callers should treat these as
 * snapshots rather than deltas.
 */
void gpon_get_hw_counters(struct gpon_hw_counters *hc)
{
	void __iomem *mac = gpon_mac();

	if (!mac) {
		memset(hc, 0, sizeof(*hc));
		return;
	}
	hc->rx_gem      = xpon_readl(mac, DBG_RX_GEM_CNT);
	hc->rx_crc_err  = xpon_readl(mac, DBG_RX_CRC_ERR_CNT);
	hc->rx_gtc      = xpon_readl(mac, DBG_RX_GTC_CNT);
	hc->tx_gem      = xpon_readl(mac, DBG_TX_GEM_CNT);
	hc->tx_burst    = xpon_readl(mac, DBG_TX_BST_CNT);
	hc->hec_one_err = xpon_readl(mac, DBG_GEM_HEC_ONE_ERR_CNT);
	hc->hec_two_err = xpon_readl(mac, DBG_GEM_HEC_TWO_ERR_CNT);
	hc->hec_uc_err  = xpon_readl(mac, DBG_GEM_HEC_UC_ERR_CNT);
}

/* ---------------- interrupt mask ---------------- */

static void gpon_int_init(void)
{
	void __iomem *mac = gpon_mac();

	if (!mac)
		return;

	/* status is write-1-to-clear */
	xpon_writel(mac, G_INT_STATUS, 0xffffffffu);
	xpon_writel(mac, G_INT_ENABLE, GPON_INT_ENABLE_DEFAULT);
}

void gpon_int_disable_all(void)
{
	void __iomem *mac = gpon_mac();

	if (!mac)
		return;
	xpon_writel(mac, G_INT_ENABLE, 0);
	xpon_writel(mac, G_INT_STATUS, 0xffffffffu);
}

/* ---------------- bring-up ----------------
 *
 * Order follows econet-xpon gpon_dev_init() with the caveats in the file
 * header. What is intentionally absent:
 *   - WAN mux select (SCU 0xBFB00070): a pinmux/SoC-glue concern, and on this
 *     platform mainline owns it.
 *   - MAC/PHY reset and PHY init: owned by the reset framework and pon_pcs.
 *   - Sniffer mode, DBA backdoor, ToD/1PPS: not needed to reach O5.
 */
int gpon_dev_init(void)
{
	struct gpon_priv *gp;
	int ret;

	if (!gpon_mac())
		return -ENODEV;

	/* 1. mask everything while the tables are in flux */
	gpon_int_disable_all();

	/* 2. wipe the per-port tables. Order matters only in that the GEM port
	 *    table must be clear before the index/MIB tables are reset, so no
	 *    live port points at a row that is about to be zeroed. */
	ret = gpon_gem_table_init();
	if (ret && ret != -ETIMEDOUT)
		return ret;
	gpon_table_init_one(G_GPIDX_TBL_INIT, "GEM index");
	gpon_table_init_one(G_MIB_TBL_INIT, "MIB");
	gpon_table_init_one(G_TX_FCS_TBL_INIT, "TX FCS");

	/* 3. no ONU-ID, no OMCC, no Alloc-IDs: this is state O1. */
	gpon_set_onu_id(GPON_UNASSIGN_ONU_ID, false);
	gpon_set_omcc_port(0, false);
	gpon_tcont_reset_all();

	/* 4. upstream FEC follows the OLT (Upstream_Overhead PLOAM); off here. */
	gpon_set_us_fec(false);

	/* 5. Dying Gasp in software. The hardware engine (DBG_DG_HW_EN) fires
	 *    the message from a template in DBG_US_NO_MSG*, which only helps if
	 *    the template is maintained; the PLOAM path can emit it on demand
	 *    with less to go wrong. */
	gpon_rmw(DBG_US_DYING_GASP_CTRL, DBG_DG_HW_EN, 0);
	gpon_field(DBG_US_DYING_GASP_CTRL, DBG_DG_NUM_LO, DBG_DG_NUM_W,
		   GPON_PLOAM_REPEAT);

	/* 6. idle-GEM threshold and MIB counters */
	gpon_field(DBG_IDLE_GEM_THLD, DBG_IDLE_GEM_THLD_LO,
		   DBG_IDLE_GEM_THLD_W, GPON_IDLE_GEM_THLD_DEF);
	gpon_rmw(DBG_CAP_SETTING, DBG_CAP_MIB_FRAME_TYPE,
		 DBG_CAP_GPON_MIB_EN);	/* MIB on, per-GEM counting */

	/* 7. DBA status-report block size */
	gpon_set_dba_block_size(GPON_DBA_BLOCK_SIZE_DEF);

	/* 8. internal delay fine-tune. Ranging maths lands on the wrong bit
	 *    without it; 0x1c is the stock value. */
	gpon_field(DBG_DLY, DBG_DLY_FINE_INT_LO, DBG_DLY_FINE_INT_W,
		   GPON_INTERNAL_DLY_DEF);

	/* 9. SN response: threshold that triggers the transmit-power step, and
	 *    the initial power mode. */
	gpon_field(G_SN_MSG_CFG, G_SN_MSG_REQ_THR_LO, G_SN_MSG_REQ_THR_W,
		   GPON_SN_REQ_THRESHOLD);
	gpon_field(G_SN_MSG_CFG, G_SN_MSG_TX_PWR_LO, G_SN_MSG_TX_PWR_W, 0);

	/* 10. ONU response time. Stock programs 0x577 in O5; pre-loading it
	 *     means the first Ranging_Time does not have to. */
	gpon_field(G_RSP_TIME, G_RSP_TIME_LO, G_RSP_TIME_W,
		   GPON_DEFAULT_RSP_TIME);

	/* 11. clear any pre-assigned delay left by the bootloader */
	xpon_writel(g_xp->mac, G_PRE_ASSIGNED_DLY, 0);
	xpon_writel(g_xp->mac, G_EQD, 0);

	/* 12. SN before interrupts: from here on the MAC may enter O3 and burst
	 *     it (see gpon_program_serial_number). */
	if (gpon_sn_cached)
		gpon_program_serial_number();

	/* 13. arm interrupts last */
	gpon_int_init();

	gp = g_xp->gpon;
	if (gp) {
		gp->state = GPON_STATE_O1;
		gp->onu_id = GPON_UNASSIGN_ONU_ID;
		gp->onu_id_valid = false;
		gp->overhead_valid = false;
		gp->eqd = 0;
		gp->response_time = GPON_DEFAULT_RSP_TIME;
		gp->tx_power_mode = 0;
	}

	dev_info(g_xp->dev,
		 "gpon: MAC initialised (int_en=0x%08x, act_st=O%u)\n",
		 xpon_readl(g_xp->mac, G_INT_ENABLE),
		 gpon_get_activation_state());

	return 0;
}

void gpon_dev_deinit(void)
{
	if (!gpon_mac())
		return;

	gpon_int_disable_all();
	gpon_deactivate_onu();
	gpon_tcont_reset_all();
}

/* ---------------- not implemented ----------------
 * These were stubs in the earlier skeleton and stay stubs: they belong to the
 * frame engine (QDMA rings, QoS/queue scheduling) and to the SD/SF BER monitor,
 * neither of which is inside the GPON MAC window this driver owns.
 */
void gpon_init_qdma_tx_buff(void)
{
}

void gpon_qos_setup(void)
{
}

void gpon_SD_SF_init(void)
{
}
