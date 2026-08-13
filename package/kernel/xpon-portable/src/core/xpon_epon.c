// SPDX-License-Identifier: GPL-2.0
/*
 * xpon_epon.c - epon_mac char device ioctl, reverse-engineered from eponMacIoctl.
 *
 * The binary compares the FULL 32-bit _IOC value (magic 'j', type byte 0x6a).
 * 13 commands were recovered (see include/xpon_ioctl.h). nr values that are
 * READ use _IOC_READ, nr=35 is WRITE. Payload length is dynamic in the binary
 * (size field = 0), so we copy through a generic xpon_io_buf.
 *
 * Bodies are STUBBED: the actual EPON MAC / MPCP register programming lives in
 * eponMac* / eponMpcp* / eponLlid* and must be RE'd from xpon.ko.
 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#include "xpon.h"

/* Local EPON MAC state stubs (mirror RE'd globals). */
static u8 epon_llid[2];
static bool epon_mac_opened;

int eponMacOpen(void)
{
	epon_mac_opened = true;
	/* TODO: RE eponMacOpen register sequence. */
	return 0;
}

void eponMacTableInit(void)
{
	/* TODO: RE eponMacTableInit (MAC table / FDB setup). */
}

int eponMpcpStart(void)
{
	/* TODO: RE eponMpcp* MPCP state machine start. */
	return 0;
}

int epon_llid_cfg(struct xpon_io_buf *b)
{
	if (!b || b->len < 2)
		return -EINVAL;
	epon_llid[0] = b->data[0];
	epon_llid[1] = b->data[1];
	return 0;
}

/* ---------------- ioctl handler ---------------- */
static long xpon_epon_dispatch(struct xpon_dev *xp, unsigned int cmd,
			       unsigned long arg)
{
	struct xpon_io_buf __user *uarg = (void __user *)arg;
	struct xpon_status st = {0};
	void *kbuf = NULL;
	unsigned int nr = cmd & 0xff;
	long ret = 0;

	/* For WRITE commands, copy the user payload in (dynamic length). */
	if (_IOC_DIR(cmd) & _IOC_WRITE) {
		struct xpon_io_buf hdr;
		if (copy_from_user(&hdr, uarg, sizeof(hdr)))
			return -EFAULT;
		if (hdr.len > 4096)
			return -E2BIG;
		kbuf = kzalloc(sizeof(hdr) + hdr.len, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;
		if (copy_from_user(kbuf, uarg, sizeof(hdr) + hdr.len)) {
			kfree(kbuf);
			return -EFAULT;
		}
	}

	switch (cmd) {
	case EPONMAC_GET_0:
		/* likely: ONU/version/state snapshot */
		st.mode = xp ? xp->mode : XPON_MODE_UNKNOWN;
		if (copy_to_user(uarg, &st, sizeof(st)))
			ret = -EFAULT;
		break;
	case EPONMAC_GET_6:
	case EPONMAC_GET_7:
	case EPONMAC_GET_9:
	case EPONMAC_GET_11:
	case EPONMAC_GET_13:
	case EPONMAC_GET_15:
	case EPONMAC_GET_16:
	case EPONMAC_GET_17:
	case EPONMAC_GET_23:
	case EPONMAC_GET_25:
	case EPONMAC_GET_36:
		/* TODO: RE each GET nr's register read + payload layout. */
		dev_dbg(xp ? xp->dev : NULL, "epon_mac GET nr=%u (stub)\n", nr);
		ret = -EOPNOTSUPP;
		break;
	case EPONMAC_SET_35:
		if (kbuf)
			ret = epon_llid_cfg(kbuf);
		else
			ret = -EINVAL;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	kfree(kbuf);
	return ret;
}

long eponMacIoctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct xpon_dev *xp = filp->private_data;

	/* sanity: must be our magic */
	if (_IOC_TYPE(cmd) != XPON_EPONMAC_MAGIC)
		return -EINVAL;

	if (!xp)
		xp = g_xp;
	if (!xp)
		return -ENODEV;

	return xpon_epon_dispatch(xp, cmd, arg);
}
EXPORT_SYMBOL(eponMacIoctl);
