// SPDX-License-Identifier: GPL-2.0
/*
 * xpon_omcc.c - secure OMCC character device for the EN7581 (AN7581DT) GPON
 * driver.
 *
 * Purpose
 * -------
 * Bridge the GPON MAC's OMCC GEM port to the userspace OMCI stack
 * (airoha-omci's omcid, https://github.com/YYH2913/airoha-omci). omcid opens a
 * character device and exchanges *bare* OMCI messages over it; the kernel is
 * responsible for the security framing that G.988 calls the Message Integrity
 * Check (MIC):
 *
 *   downstream (OLT -> ONU): the MAC delivers an OMCI message with a 4-byte
 *       MIC trailer. The kernel verifies the MIC, strips the trailer, wraps the
 *       clean message in a 12-byte "XOMC" header (flags = MICVerified |
 *       TrailerStripped) and hands it to read().
 *   upstream (ONU -> OLT): write() supplies the 12-byte header + a clean OMCI
 *       message. The kernel appends the 4-byte MIC and pushes the result to the
 *       OMCC GEM port.
 *
 * ABI contract (matches internal/transport/device*.go in airoha-omci exactly)
 * --------------------------------------------------------------------------
 *   device node : /dev/airoha-xgs-omcc   (airoha-omci default -device path)
 *   ioctl       : _IOR('X', 0, __u32) = 0x80045800 -> capabilities u32
 *                 bit[7:0]  = ABI version (must == 1)
 *                 bit[8]    = VerifiedDownstreamMIC   (we verify RX MIC)
 *                 bit[9]    = SignedUpstreamMIC      (we sign TX MIC)
 *                 => 0x301. parseDeviceInfo() in airoha-omci REQUIRES both
 *                     MIC bits set, even in GPON mode, so we always report them.
 *   RX record   : 12-byte header + OMCI message (MIC already stripped)
 *                   [0:4]  magic   "XOMC" = 0x584f4d43 (big-endian)
 *                   [4]    version = 1
 *                   [5]    direction = 1 (RX)
 *                   [6:8]  flags   = 0x0003 (MICVerified | TrailerStripped)
 *                   [8:10] length  = OMCI message length (big-endian u16)
 *                   [10:12] reserved = 0
 *   TX record   : 12-byte header + OMCI message (MIC NOT included)
 *                   [0:4]  magic   "XOMC"
 *                   [4]    version = 1
 *                   [5]    direction = 2 (TX)
 *                   [6:8]  flags   = 0 (ignored by the kernel)
 *                   [8:10] length  = OMCI message length (big-endian u16)
 *                   [10:12] reserved = 0
 *   OMCI message length is bounded by MaxFrameSize = 1980 (airoha-omci's
 *   transport.MaxFrameSize). A valid message is at least 4 bytes.
 *
 * MIC algorithm
 * -------------
 * CRC-32/ITU-I.363.5 (non-reflected, poly 0x04C11DB7, init 0xFFFFFFFF, final
 * XOR 0xFFFFFFFF). This is airoha-omci's internal/checksum/crc32a.go, which is
 * the G.988 OMCI MIC. The 4-byte MIC is appended in network (big-endian) order.
 *
 * Hardware seam (the data path this RE skeleton does not yet own)
 * -------------------------------------------------------------
 *   xpon_omcc_rx_omci()  - called by the (future) GEM RX path when it decodes a
 *                          frame addressed to the OMCC GEM port. Takes a pointer
 *                          to OMCI+MIC and does verify+strip+enqueue.
 *   xpon_omcc_set_hw_send() - lets the future GEM TX engine register its send
 *                          hook. Until then TX is dropped by a one-shot-warned
 *                          stub, or (for bench testing) looped straight back to
 *                          RX when the omcc_loopback module parameter is set.
 *
 * NOT VALIDATED ON HARDWARE. No board was available; this is a faithful
 * transcription of airoha-omci's transport ABI, not a tested driver.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/ioctl.h>
#include <linux/list.h>
#include <linux/types.h>

#include "xpon.h"

/* ---------------- ABI constants (mirror airoha-omci transport) ---------------- */
#define OMCC_DEV_NAME		"airoha-xgs-omcc"
#define OMCC_MAGIC		0x584f4d43u	/* "XOMC" */
#define OMCC_ABI_VERSION	1
#define OMCC_HDR_SIZE		12
#define OMCC_DIR_RX		1
#define OMCC_DIR_TX		2
#define OMCC_FLAG_MIC_VERIFIED	(1u << 0)
#define OMCC_FLAG_TRAILER_STRIPPED (1u << 1)
/* Hardware MIC status (cross-check vs the software validation above), lifted
 * from the QDMA RX descriptor msg0 by the GEM RX path. See XPON_OMCI_RX_F_*. */
#define OMCC_FLAG_HW_MIC_PRESENT	(1u << 2)
#define OMCC_FLAG_HW_MIC_VALID		(1u << 3)
#define OMCC_FLAG_HW_MIC_CRCERR		(1u << 4)
#define OMCC_MAX_FRAME		1980		/* transport.MaxFrameSize */
/* _IOR('X', 0, __u32) == 0x80045800. Reported capabilities:
 *   version(1) | VerifiedDownstreamMIC(bit8) | SignedUpstreamMIC(bit9) = 0x301 */
#define OMCC_CAP_VERSION	0x00000001u
#define OMCC_CAP_VERIFIED_DS	0x00000100u
#define OMCC_CAP_SIGNED_US	0x00000200u
#define OMCC_GET_INFO		_IOR('X', 0, __u32)

/* Bench-test aid: feed TX straight back into RX so the sign->verify->header
 * chain can be exercised without an OLT. */
static bool omcc_loopback;
module_param(omcc_loopback, bool, 0444);
MODULE_PARM_DESC(omcc_loopback,
		 "Loop TX back into RX to exercise the OMCC ABI without an OLT");

/* ---------------- little helpers ---------------- */
#define RD_BE32(p) (((u32)(p)[0] << 24) | ((u32)(p)[1] << 16) | \
		    ((u32)(p)[2] << 8)  |  (u32)(p)[3])
#define RD_BE16(p) (((u32)(p)[0] << 8)  |  (u32)(p)[1])
#define WR_BE32(p, v) do { (p)[0] = (v) >> 24; (p)[1] = (v) >> 16; \
			   (p)[2] = (v) >> 8;  (p)[3] = (v); } while (0)
#define WR_BE16(p, v) do { (p)[0] = (v) >> 8; (p)[1] = (v); } while (0)

/*
 * CRC-32/ITU-I.363.5 (non-reflected), the G.988 OMCI MIC.
 * Initial 0xFFFFFFFF, final XOR 0xFFFFFFFF, polynomial 0x04C11DB7. This is a
 * byte-for-byte port of airoha-omci's internal/checksum/crc32a.go, so the MIC
 * we compute matches what omcid expects.
 */
static u32 omcc_crc32a(const u8 *data, size_t n)
{
	u32 crc = 0xffffffffu;
	size_t i;
	int bit;

	for (i = 0; i < n; i++) {
		crc ^= (u32)data[i] << 24;
		for (bit = 0; bit < 8; bit++) {
			if (crc & 0x80000000u)
				crc = (crc << 1) ^ 0x04c11db7u;
			else
				crc <<= 1;
		}
	}
	return crc ^ 0xffffffffu;
}

/* ---------------- RX queue ---------------- */
struct omcc_rec {
	struct list_head	list;
	size_t			len;	/* header(12) + OMCI message */
	u8			data[];	/* 12-byte header followed by OMCI message */
};

static int (*g_omcc_hw_send)(struct xpon_dev *xp, const u8 *gem,
			     size_t len) = NULL;

/*
 * Default TX sink. The GEM data path is not implemented in this RE skeleton, so
 * the signed OMCI+MIC frame is dropped after a single warning. A real GEM TX
 * engine registers a replacement via xpon_omcc_set_hw_send().
 */
static int xpon_omcc_hw_send_stub(struct xpon_dev *xp, const u8 *gem, size_t len)
{
	(void)gem;
	(void)len;

	static bool warned;
	if (!warned) {
		warned = true;
		dev_warn(xp ? xp->dev : NULL,
			 "OMCC TX: GEM data path not implemented, dropping %zu-byte frame\n",
			 len);
	}
	return 0;
}

/*
 * Ingest one OMCI message + 4-byte MIC trailer from the OMCC GEM port (called
 * by the GEM RX path). Verifies the MIC, strips it, wraps the clean message in
 * a 12-byte RX header and enqueues it for read().
 *
 * Context: may be called from interrupt / softirq, hence GFP_ATOMIC and the
 *          IRQ-safe RX spinlock.
 */
int xpon_omcc_rx_omci(const u8 *frame_with_mic, size_t len, u32 mic_flags)
{
	struct xpon_dev *xp = g_xp;
	struct omcc_rec *rec;
	size_t omci_len;
	u32 crc, rx_mic;
	u16 hdr_flags;
	unsigned long flags;

	if (!xp)
		return -ENODEV;
	if (len < 8)			/* at least 4-byte OMCI + 4-byte MIC */
		return -EINVAL;
	omci_len = len - 4;
	if (omci_len < 4 || omci_len > OMCC_MAX_FRAME)
		return -EINVAL;

	crc = omcc_crc32a(frame_with_mic, omci_len);
	rx_mic = RD_BE32(frame_with_mic + omci_len);
	if (rx_mic != crc) {
		atomic_inc(&xp->omcc_rx_drop);
		return -EBADMSG;
	}

	rec = kmalloc(sizeof(*rec) + OMCC_HDR_SIZE + omci_len, GFP_ATOMIC);
	if (!rec) {
		atomic_inc(&xp->omcc_rx_drop);
		return -ENOMEM;
	}
	hdr_flags = OMCC_FLAG_MIC_VERIFIED | OMCC_FLAG_TRAILER_STRIPPED;
	/* Surface the MAC's own MIC observation as a cross-check for the OMCI
	 * daemon (software already verified above). NO_MIC clear => MIC present;
	 * CRC_ERR clear => hardware check passed. */
	if (mic_flags & XPON_OMCI_RX_F_MIC_PRESENT)
		hdr_flags |= OMCC_FLAG_HW_MIC_PRESENT;
	if (mic_flags & XPON_OMCI_RX_F_MIC_VALID)
		hdr_flags |= OMCC_FLAG_HW_MIC_VALID;
	if (mic_flags & XPON_OMCI_RX_F_CRC_ERROR)
		hdr_flags |= OMCC_FLAG_HW_MIC_CRCERR;

	WR_BE32(rec->data + 0, OMCC_MAGIC);
	rec->data[4] = OMCC_ABI_VERSION;
	rec->data[5] = OMCC_DIR_RX;
	WR_BE16(rec->data + 6, hdr_flags);
	WR_BE16(rec->data + 8, omci_len);
	WR_BE16(rec->data + 10, 0);
	memcpy(rec->data + OMCC_HDR_SIZE, frame_with_mic, omci_len);
	rec->len = OMCC_HDR_SIZE + omci_len;

	spin_lock_irqsave(&xp->omcc_rx_lock, flags);
	list_add_tail(&rec->list, &xp->omcc_rx_q);
	spin_unlock_irqrestore(&xp->omcc_rx_lock, flags);

	atomic_inc(&xp->omcc_rx_enq);
	wake_up_interruptible(&xp->omcc_rx_wait);
	return 0;
}
EXPORT_SYMBOL(xpon_omcc_rx_omci);

/*
 * Register the hardware GEM TX send hook. Pass NULL to revert to the stub.
 */
int xpon_omcc_set_hw_send(int (*fn)(struct xpon_dev *, const u8 *, size_t))
{
	g_omcc_hw_send = fn ? fn : xpon_omcc_hw_send_stub;
	return 0;
}
EXPORT_SYMBOL(xpon_omcc_set_hw_send);

/* ---------------- char device fops ---------------- */

static int xpon_omcc_open(struct inode *ino, struct file *filp)
{
	(void)ino;
	filp->private_data = g_xp;
	return 0;
}

static int xpon_omcc_release(struct inode *ino, struct file *filp)
{
	(void)ino;
	(void)filp;
	return 0;
}

static ssize_t xpon_omcc_read(struct file *filp, char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct xpon_dev *xp = filp->private_data;
	struct omcc_rec *rec;
	ssize_t ret = 0;

	(void)ppos;
	if (!xp)
		return -ENODEV;

	spin_lock_irq(&xp->omcc_rx_lock);
	if (list_empty(&xp->omcc_rx_q)) {
		spin_unlock_irq(&xp->omcc_rx_lock);
		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;
		if (wait_event_interruptible(xp->omcc_rx_wait,
					     !list_empty(&xp->omcc_rx_q)))
			return -ERESTARTSYS;
		spin_lock_irq(&xp->omcc_rx_lock);
	}
	rec = list_first_entry(&xp->omcc_rx_q, struct omcc_rec, list);
	list_del(&rec->list);
	spin_unlock_irq(&xp->omcc_rx_lock);

	/* airoha-omci reads in one shot; if the buffer cannot hold the whole
	 * record, put it back and tell userspace to use a bigger read. */
	if (count < rec->len) {
		spin_lock_irq(&xp->omcc_rx_lock);
		list_add(&rec->list, &xp->omcc_rx_q);
		spin_unlock_irq(&xp->omcc_rx_lock);
		return -ENOBUFS;
	}
	if (copy_to_user(buf, rec->data, rec->len)) {
		spin_lock_irq(&xp->omcc_rx_lock);
		list_add(&rec->list, &xp->omcc_rx_q);
		spin_unlock_irq(&xp->omcc_rx_lock);
		return -EFAULT;
	}
	ret = rec->len;
	kfree(rec);
	return ret;
}

static ssize_t xpon_omcc_write(struct file *filp, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct xpon_dev *xp = filp->private_data;
	u8 hdr[OMCC_HDR_SIZE];
	u8 *frame;
	size_t omci_len, total;
	u32 crc;
	ssize_t ret = 0;

	(void)ppos;
	if (!xp)
		return -ENODEV;
	if (count < OMCC_HDR_SIZE)
		return -EINVAL;
	if (copy_from_user(hdr, buf, OMCC_HDR_SIZE))
		return -EFAULT;

	if (RD_BE32(hdr) != OMCC_MAGIC)
		return -EINVAL;
	if (hdr[4] != OMCC_ABI_VERSION)
		return -EINVAL;
	if (hdr[5] != OMCC_DIR_TX)
		return -EINVAL;
	/* reserved field must be zero (airoha-omci's encodeDeviceTX clears it) */
	if (RD_BE16(hdr + 10) != 0)
		return -EINVAL;

	omci_len = RD_BE16(hdr + 8);
	if (omci_len < 4 || omci_len > OMCC_MAX_FRAME)
		return -EINVAL;
	total = OMCC_HDR_SIZE + omci_len;
	if (count < total)
		return -EINVAL;

	frame = kmalloc(omci_len + 4, GFP_KERNEL);
	if (!frame)
		return -ENOMEM;
	if (copy_from_user(frame, buf + OMCC_HDR_SIZE, omci_len)) {
		kfree(frame);
		return -EFAULT;
	}

	/* sign: append the 4-byte MIC in network order */
	crc = omcc_crc32a(frame, omci_len);
	WR_BE32(frame + omci_len, crc);

	atomic_inc(&xp->omcc_tx);
	if (omcc_loopback)
		/* looped-back frame saw no hardware MIC check; pass 0. */
		ret = xpon_omcc_rx_omci(frame, omci_len + 4, 0);
	else
		ret = (g_omcc_hw_send ? g_omcc_hw_send :
		       xpon_omcc_hw_send_stub)(xp, frame, omci_len + 4);

	kfree(frame);
	if (ret < 0)
		return ret;
	return total;
}

static __poll_t xpon_omcc_poll(struct file *filp, poll_table *wait)
{
	struct xpon_dev *xp = filp->private_data;
	__poll_t mask = 0;

	if (!xp)
		return EPOLLERR;
	poll_wait(filp, &xp->omcc_rx_wait, wait);
	spin_lock_irq(&xp->omcc_rx_lock);
	if (!list_empty(&xp->omcc_rx_q))
		mask |= EPOLLIN | EPOLLRDNORM;
	spin_unlock_irq(&xp->omcc_rx_lock);
	/* TX is buffered in memory; always ready to accept a frame. */
	mask |= EPOLLOUT | EPOLLWRNORM;
	return mask;
}

static long xpon_omcc_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long arg)
{
	struct xpon_dev *xp = filp->private_data;
	u32 cap;

	(void)xp;
	switch (cmd) {
	case OMCC_GET_INFO:
		cap = OMCC_CAP_VERSION | OMCC_CAP_VERIFIED_DS | OMCC_CAP_SIGNED_US;
		if (copy_to_user((void __user *)arg, &cap, sizeof(cap)))
			return -EFAULT;
		return 0;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations xpon_omcc_fops = {
	.owner		= THIS_MODULE,
	.open		= xpon_omcc_open,
	.release	= xpon_omcc_release,
	.read		= xpon_omcc_read,
	.write		= xpon_omcc_write,
	.poll		= xpon_omcc_poll,
	.unlocked_ioctl	= xpon_omcc_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= xpon_omcc_ioctl,
#endif
};

/* ---------------- device lifecycle ---------------- */

int xpon_omcc_setup(struct xpon_dev *xp)
{
	int ret;

	if (!xp || !xp->cls)
		return -ENODEV;

	INIT_LIST_HEAD(&xp->omcc_rx_q);
	spin_lock_init(&xp->omcc_rx_lock);
	init_waitqueue_head(&xp->omcc_rx_wait);
	atomic_set(&xp->omcc_rx_enq, 0);
	atomic_set(&xp->omcc_rx_drop, 0);
	atomic_set(&xp->omcc_tx, 0);
	g_omcc_hw_send = xpon_omcc_hw_send_stub;

	ret = alloc_chrdev_region(&xp->omcc_devt, 0, 1, OMCC_DEV_NAME);
	if (ret)
		return ret;
	cdev_init(&xp->omcc_cdev, &xpon_omcc_fops);
	ret = cdev_add(&xp->omcc_cdev, xp->omcc_devt, 1);
	if (ret)
		goto err_region;
	device_create(xp->cls, NULL, xp->omcc_devt, NULL, OMCC_DEV_NAME);

	dev_info(xp->dev, "secure OMCC device /dev/%s created\n", OMCC_DEV_NAME);
	return 0;

err_region:
	unregister_chrdev_region(xp->omcc_devt, 1);
	return ret;
}

void xpon_omcc_teardown(struct xpon_dev *xp)
{
	struct omcc_rec *rec, *tmp;

	if (!xp)
		return;
	device_destroy(xp->cls, xp->omcc_devt);
	cdev_del(&xp->omcc_cdev);
	unregister_chrdev_region(xp->omcc_devt, 1);
	list_for_each_entry_safe(rec, tmp, &xp->omcc_rx_q, list) {
		list_del(&rec->list);
		kfree(rec);
	}
}
