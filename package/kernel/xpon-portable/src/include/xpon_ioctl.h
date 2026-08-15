/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xpon_ioctl.h - Userspace <-> kernel ABI for the EN7581 (AN7581DT) XPON driver
 *
 * This header is *reverse-engineered* from the vendor binary xpon.ko
 * (kernel 5.4.55, aarch64, NOT stripped). It documents the three ioctl
 * channels that the vendor `ponmgr` utility uses to talk to the driver:
 *
 *   1) epon_mac char device  - magic/type byte 'j' (0x6a), 13 commands
 *   2) PON MCI  char device  - dispatch by (cmd>>8)&0xff type byte 0xd7..0xdb
 *   3) PON netdevice         - SIOCDEVPRIVATE ndo_do_ioctl
 *
 * Values were recovered from the disassembly of eponMacIoctl / pon_mci_ioctl
 * and the _cmd_proc sub-handlers. The _IOC size field in the binary is 0 for
 * most commands, meaning the actual payload length is passed dynamically by the
 * handler (copy_from_user with a runtime-computed size). We therefore declare
 * payload structs as fixed-size best-effort placeholders; real layouts need the
 * vendor GPL source.
 */
#ifndef _XPON_IOCTL_H
#define _XPON_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>

/* ------------------------------------------------------------------ */
/* Channel 1: epon_mac char device                                    */
/*   type byte = 'j' (0x6a). 13 commands recovered.                   */
/* ------------------------------------------------------------------ */
#define XPON_EPONMAC_MAGIC	'j'

/* The binary builds these as _IOC(dir, 'j', nr, 0). We mirror that exactly. */
#define XPON_EP_R(nr)	_IOC(_IOC_READ,  XPON_EPONMAC_MAGIC, (nr), 0)
#define XPON_EP_W(nr)	_IOC(_IOC_WRITE, XPON_EPONMAC_MAGIC, (nr), 0)

enum {
	EPONMAC_GET_0		= XPON_EP_R(0),		/* nr=0   READ  */
	EPONMAC_GET_6		= XPON_EP_R(6),		/* nr=6   READ  */
	EPONMAC_GET_7		= XPON_EP_R(7),		/* nr=7   READ  */
	EPONMAC_GET_9		= XPON_EP_R(9),		/* nr=9   READ  */
	EPONMAC_GET_11		= XPON_EP_R(11),	/* nr=11  READ  */
	EPONMAC_GET_13		= XPON_EP_R(13),	/* nr=13  READ  */
	EPONMAC_GET_15		= XPON_EP_R(15),	/* nr=15  READ  */
	EPONMAC_GET_16		= XPON_EP_R(16),	/* nr=16  READ  */
	EPONMAC_GET_17		= XPON_EP_R(17),	/* nr=17  READ  */
	EPONMAC_GET_23		= XPON_EP_R(23),	/* nr=23  READ  */
	EPONMAC_GET_25		= XPON_EP_R(25),	/* nr=25  READ  */
	EPONMAC_GET_36		= XPON_EP_R(36),	/* nr=36  READ  */
	EPONMAC_SET_35		= XPON_EP_W(35),	/* nr=35  WRITE */
};

/* ------------------------------------------------------------------ */
/* Channel 2: PON MCI char device ("PON MCI")                         */
/*   pon_mci_ioctl dispatches on (cmd>>8)&0xff (the type byte):        */
/*     0xd7 -> phy_cmd_proc                                           */
/*     0xd8 -> epon_cmd_proc                                          */
/*     0xd9 -> gpon_cmd_proc                                          */
/*     0xda -> if_cmd_proc                                            */
/*     0xdb -> fdet_cmd_proc                                          */
/*   Each sub-handler then switches on (cmd & 0xff) = nr.             */
/* ------------------------------------------------------------------ */
#define XPON_MCI_TYPE_PHY	0xd7
#define XPON_MCI_TYPE_EPON	0xd8
#define XPON_MCI_TYPE_GPON	0xd9
#define XPON_MCI_TYPE_IF		0xda
#define XPON_MCI_TYPE_FDET	0xdb

#define XPON_MCI_R(type, nr)	_IOC(_IOC_READ,  (type), (nr), 0)
#define XPON_MCI_W(type, nr)	_IOC(_IOC_WRITE, (type), (nr), 0)

/*
 * PON MCI sub-command sets -- DECODED from the *_cmd_proc handlers.
 *
 * Two dispatch styles exist in the binary:
 *   * Jump tables  (gpon, if):  pon_mci_ioctl -> *_cmd_proc builds an index
 *     idx = nr - 1 (verified: index = cmd + C, C cancels type<<8 + dir<<30),
 *     then `br x0` into a handler table. The cmp limit in the asm bounds the
 *     accepted nr. Decoded tables:
 *        gpon_cmd_proc  READ  table@0x6c4c8 base 0x563e8  nr 1..102 (cmp #0x65)
 *                       WRITE table@0x6c660 base 0x56418  nr 1..110 (cmp #0x6d)
 *        if_cmd_proc   READ  table@0x6ca38 base 0x62a2c  nr 1..132 (cmp #0x83)
 *                       WRITE table@0x6cc48 base 0x64bf0  nr 1..133 (cmp #0x84)
 *   * Linear cmp chain (phy, fdet, epon): exact _IOC match against a constant
 *     built as `mov w0,#lo; movk w0,#hi,lsl#16`. Decoded nrs below.
 *
 * The full nr->handler map for the jump-table sets is in re/mci_enum.json.
 */

/* --- PON PHY (type 0xd7): linear cmp chain, exact matches ---------- */
/* READ  nrs: 1,2,3,4,5,6,7   (0x8000d701..0x8000d707)                */
/* WRITE nrs: 1,2,3,4,6,8     (0x4000d701/2/3/4/6/8; 5 & 7 are not    */
/*                            handled by a dedicated WRITE handler)    */
#define MCI_PHY_R(nr)   XPON_MCI_R(XPON_MCI_TYPE_PHY, (nr))
#define MCI_PHY_W(nr)   XPON_MCI_W(XPON_MCI_TYPE_PHY, (nr))

/* --- GPON (type 0xd9): jump table, contiguous nr ranges ------------ */
/* READ  nr 1..102   WRITE nr 1..110                                   */
#define MCI_GPON_R(nr)  XPON_MCI_R(XPON_MCI_TYPE_GPON, (nr))
#define MCI_GPON_W(nr)  XPON_MCI_W(XPON_MCI_TYPE_GPON, (nr))
#define MCI_GPON_R_MAX  102
#define MCI_GPON_W_MAX  110

/* --- IF / interface (type 0xda): jump table, contiguous nr ranges -- */
/* READ  nr 1..132   WRITE nr 1..133                                   */
#define MCI_IF_R(nr)    XPON_MCI_R(XPON_MCI_TYPE_IF, (nr))
#define MCI_IF_W(nr)    XPON_MCI_W(XPON_MCI_TYPE_IF, (nr))
#define MCI_IF_R_MAX    132
#define MCI_IF_W_MAX    133

/* --- FDET (type 0xdb): linear cmp chain, exact matches ------------ */
/* READ  nrs: 1,2,3   (0x8000db01/2/3)                                 */
/* WRITE nrs: 3       (0x4000db03)                                     */
#define MCI_FDET_R(nr)  XPON_MCI_R(XPON_MCI_TYPE_FDET, (nr))
#define MCI_FDET_W(nr)  XPON_MCI_W(XPON_MCI_TYPE_FDET, (nr))

/* --- EPON (type 0xd8): MCI channel is NOT implemented -------------- */
/* epon_cmd_proc only checks a state bit then bl's out; real EPON        */
/* control is done through the epon_mac char device (channel 1) above.   */
#define MCI_EPON_R(nr)  XPON_MCI_R(XPON_MCI_TYPE_EPON, (nr))
#define MCI_EPON_W(nr)  XPON_MCI_W(XPON_MCI_TYPE_EPON, (nr))

/* ------------------------------------------------------------------ */
/* Channel 3: PON netdevice ndo_do_ioctl (SIOCDEVPRIVATE family)      */
/* ------------------------------------------------------------------ */
/* Self-contained: SIOCDEVPRIVATE is normally from <linux/sockios.h>;  */
/* define it here so this uAPI header compiles standalone in userspace. */
#ifndef SIOCDEVPRIVATE
#define SIOCDEVPRIVATE		0x89F0
#endif
#define SIOC_XPON_PRIVATE	(SIOCDEVPRIVATE + 0)

/* ------------------------------------------------------------------ */
/* Generic, ABI-safe exchange buffer.                                 */
/* Real per-command structs are unknown; we copy a caller-supplied     */
/* length so the dispatch logic matches the binary's dynamic copying.  */
/* ------------------------------------------------------------------ */
struct xpon_io_buf {
	__u32 len;	/* number of valid bytes in data[] */
	__u8  data[];	/* flexible payload */
};

/* PON mode reported by the driver (mirrors hcfg.conf Pon.Uplink.Mode). */
enum xpon_mode {
	XPON_MODE_GPON = 0,
	XPON_MODE_EPON = 1,
	XPON_MODE_XGPON = 2,
	XPON_MODE_XEPON = 3,
	XPON_MODE_UNKNOWN = 0xff,
};

/* Minimal link/state snapshot returned by GET_0 / status ioctls. */
struct xpon_status {
	__u32 mode;		/* enum xpon_mode */
	__u32 laser_on;		/* 0/1 */
	__u32 los;		/* loss of signal */
	__u32 link_up;		/* 0/1 */
	__u32 rx_power;		/* raw / 1000 -> dBm (placeholder) */
	__u32 tx_power;		/* raw / 1000 -> dBm (placeholder) */
	__u8  onu_id;
	__u8  llid[2];
	__u8  reserved[1];
} __attribute__((packed));

#endif /* _XPON_IOCTL_H */
