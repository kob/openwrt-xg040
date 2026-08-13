// SPDX-License-Identifier: GPL-2.0
/*
 * xpon_netdev.c - PON netdevice (xpon_netdev_ops) and ndo_do_ioctl.
 *
 * The binary registered a network interface for the PON port (register_netdev)
 * whose ops struct was named xpon_netdev_ops and included ndo_do_ioctl. This is
 * the 3rd userspace channel: ponmgr/ioctl(socket, SIOCDEVPRIVATE, ...).
 */
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <linux/uaccess.h>

#include "xpon.h"

static int xpon_ndo_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

static int xpon_ndo_stop(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

static netdev_tx_t xpon_ndo_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	/* PON data-path is handled by the vendor frame_engine (ecnt_hooks),
	 * not the standard qdisc. Stub: free and count. */
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

int xpon_ndo_do_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct xpon_dev *xp = *(struct xpon_dev **)netdev_priv(dev);

	if (cmd != SIOC_XPON_PRIVATE)
		return -EINVAL;

	/* The vendor xpon.ko routed the PON netdevice's SIOCDEVPRIVATE ioctl into
	 * the same MCI command space as the "PON MCI" char device, but the exact
	 * payload encoding (which ifreq->ifr_data field maps to which MCI cmd, and
	 * how copy_from/to_user is done) was NOT recovered from the binary.
	 *
	 * We therefore leave this channel as a safe stub. It does not corrupt the
	 * netdevice and returns -EOPNOTSUPP so callers know it is intentionally
	 * unimplemented, rather than silently mis-dispatching. Recover the mapping
	 * from xpon_netdev_ops.ndo_do_ioctl in a future RE step if needed. */
	(void)xp;
	(void)ifr;
	return -EOPNOTSUPP;
}

static const struct net_device_ops xpon_netdev_ops = {
	.ndo_open		= xpon_ndo_open,
	.ndo_stop		= xpon_ndo_stop,
	.ndo_start_xmit		= xpon_ndo_start_xmit,
	.ndo_do_ioctl		= xpon_ndo_do_ioctl,
};

int xpon_netdev_init(struct xpon_dev *xp)
{
	struct net_device *ndev;
	struct xpon_dev **pp;

	ndev = alloc_etherdev(sizeof(struct xpon_dev *));
	if (!ndev)
		return -ENOMEM;

	pp = netdev_priv(ndev);
	*pp = xp;
	xp->netdev = ndev;

	eth_hw_addr_random(ndev);
	ndev->netdev_ops = &xpon_netdev_ops;
	ndev->flags |= IFF_NOARP;
	strscpy(ndev->name, "pon%d", IFNAMSIZ);
	ndev->priv_flags |= IFF_LIVE_ADDR_CHANGE;

	if (register_netdev(ndev) != 0) {
		free_netdev(ndev);
		xp->netdev = NULL;
		return -ENODEV;
	}

	netdev_info(ndev, "PON netdevice registered (xpon_netdev_ops)\n");
	return 0;
}

void xpon_netdev_free(struct xpon_dev *xp)
{
	if (xp->netdev) {
		unregister_netdev(xp->netdev);
		free_netdev(xp->netdev);
		xp->netdev = NULL;
	}
}
