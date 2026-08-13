// SPDX-License-Identifier: GPL-2.0
/*
 * xpon_mci.c - PON MCI ioctl dispatch, reverse-engineered from pon_mci_ioctl.
 *
 * The binary logic (verified in re/pon_mci_ioctl.asm) is:
 *   type = (cmd >> 8) & 0xff;
 *   switch (type) {
 *     case 0xd9: return gpon_cmd_proc(cmd, arg);
 *     case 0xd8: return epon_cmd_proc(cmd, arg);
 *     case 0xda: return if_cmd_proc(cmd, arg);
 *     case 0xdb: return fdet_cmd_proc(cmd, arg);
 *     case 0xd7: return phy_cmd_proc(cmd, arg);
 *     default:   return -EINVAL;   // binary defaulted to -22
 *   }
 *
 * Each *_cmd_proc then switches on (cmd & 0xff) = nr. The accepted nr ranges
 * were DECODED from the *_cmd_proc handlers (see include/xpon_ioctl.h and
 * re/mci_enum.json). Below we reproduce those ranges so the driver rejects
 * out-of-range commands exactly like the binary (returns -EINVAL/-22).
 *
 * The per-nr bodies are STUBBED: the register programming behind each nr must
 * still be RE'd from xpon.ko (that is beyond "portable source").
 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/ioctl.h>

#include "xpon.h"

/* True if nr is in the decoded PON PHY set for the given direction. */
static bool phy_nr_valid(unsigned int nr, bool write)
{
	if (write)
		return nr == 1 || nr == 2 || nr == 3 || nr == 4 ||
		       nr == 6 || nr == 8;
	return nr >= 1 && nr <= 7;
}

/* ---------------- PON PHY sub-handler (type 0xd7) ---------------- */
int phy_cmd_proc(unsigned int cmd, unsigned long arg)
{
	unsigned int nr = cmd & 0xff;
	bool write = (_IOC_DIR(cmd) & _IOC_WRITE) != 0;

	if (!phy_nr_valid(nr, write)) {
		dev_dbg(g_xp ? g_xp->dev : NULL,
			"phy_cmd_proc nr=%u %s: out of range\n",
			nr, write ? "W" : "R");
		return -EINVAL;
	}
	/* TODO: RE pon_phy register programming behind each nr. */
	dev_dbg(g_xp ? g_xp->dev : NULL, "phy_cmd_proc nr=%u (stub)\n", nr);
	return -EOPNOTSUPP;
}

/* ---------------- EPON sub-handler (type 0xd8) ----------------
 * epon_cmd_proc in the binary only checks a state bit then bl's out; the real
 * EPON control path is the epon_mac char device (channel 1). So MCI EPON is
 * effectively unimplemented there too. */
int epon_cmd_proc(unsigned int cmd, unsigned long arg)
{
	dev_dbg(g_xp ? g_xp->dev : NULL, "epon_cmd_proc cmd=0x%08x (stub)\n", cmd);
	return -EOPNOTSUPP;
}

/* ---------------- GPON sub-handler (type 0xd9) ----------------
 * Decoded ranges: READ nr 1..MCI_GPON_R_MAX, WRITE nr 1..MCI_GPON_W_MAX.
 *
 * Two commands are now REAL (reverse-engineered):
 *   nr 3  - ONU Serial Number / Password  (GET via R, SET via W)
 *   nr 75 - TCONT RX/TX counter read
 * The rest remain stubs pending deeper RE of the jump-table handlers. */
int gpon_cmd_proc(unsigned int cmd, unsigned long arg)
{
	unsigned int nr = cmd & 0xff;
	bool write = (_IOC_DIR(cmd) & _IOC_WRITE) != 0;
	int ret;

	if (write) {
		if (nr < 1 || nr > MCI_GPON_W_MAX)
			return -EINVAL;
	} else {
		if (nr < 1 || nr > MCI_GPON_R_MAX)
			return -EINVAL;
	}

	switch (nr) {
	case 3: {	/* ONU SN / Password */
		struct gpon_onu_id_cfg cfg;

		if (write) {
			if (copy_from_user(&cfg, (void __user *)arg, sizeof(cfg)))
				return -EFAULT;
			ret = gpon_set_sn_passwd(&cfg);
		} else {
			ret = gpon_get_sn_passwd(&cfg);
			if (ret == 0 &&
			    copy_to_user((void __user *)arg, &cfg, sizeof(cfg)))
				return -EFAULT;
		}
		return ret;
	}
	case 75: {	/* TCONT counter (read-only; accept either direction) */
		struct gpon_tcont_counter c;

		if (copy_from_user(&c, (void __user *)arg, sizeof(c)))
			return -EFAULT;
		ret = gpon_get_tcont_counter(&c);
		if (ret == 0 &&
		    copy_to_user((void __user *)arg, &c, sizeof(c)))
			return -EFAULT;
		return ret;
	}
	default:
		dev_dbg(g_xp ? g_xp->dev : NULL,
			"gpon_cmd_proc nr=%u (stub)\n", nr);
		return -EOPNOTSUPP;
	}
}

/* ---------------- interface sub-handler (type 0xda) ----------------
 * Decoded ranges: READ nr 1..MCI_IF_R_MAX, WRITE nr 1..MCI_IF_W_MAX. */
int if_cmd_proc(unsigned int cmd, unsigned long arg)
{
	unsigned int nr = cmd & 0xff;
	bool write = (_IOC_DIR(cmd) & _IOC_WRITE) != 0;

	if (write) {
		if (nr < 1 || nr > MCI_IF_W_MAX)
			return -EINVAL;
	} else {
		if (nr < 1 || nr > MCI_IF_R_MAX)
			return -EINVAL;
	}
	dev_dbg(g_xp ? g_xp->dev : NULL, "if_cmd_proc nr=%u (stub)\n", nr);
	return -EOPNOTSUPP;
}

/* ---------------- failure-detection sub-handler (type 0xdb) ----------------
 * Decoded: READ nrs {1,2,3}, WRITE nr {3}. */
int fdet_cmd_proc(unsigned int cmd, unsigned long arg)
{
	unsigned int nr = cmd & 0xff;
	bool write = (_IOC_DIR(cmd) & _IOC_WRITE) != 0;

	if (write) {
		if (nr != 3)
			return -EINVAL;
	} else {
		if (nr < 1 || nr > 3)
			return -EINVAL;
	}
	dev_dbg(g_xp ? g_xp->dev : NULL, "fdet_cmd_proc nr=%u (stub)\n", nr);
	return -EOPNOTSUPP;
}

/* ---------------- top-level pon_mci_ioctl ---------------- */
long pon_mci_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	unsigned int type = (cmd >> 8) & 0xff;

	switch (type) {
	case XPON_MCI_TYPE_GPON:	return gpon_cmd_proc(cmd, arg);
	case XPON_MCI_TYPE_EPON:	return epon_cmd_proc(cmd, arg);
	case XPON_MCI_TYPE_IF:		return if_cmd_proc(cmd, arg);
	case XPON_MCI_TYPE_FDET:	return fdet_cmd_proc(cmd, arg);
	case XPON_MCI_TYPE_PHY:	return phy_cmd_proc(cmd, arg);
	default:			return -EINVAL; /* binary returned -22 */
	}
}
EXPORT_SYMBOL(pon_mci_ioctl);
