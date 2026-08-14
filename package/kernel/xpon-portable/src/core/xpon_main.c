// SPDX-License-Identifier: GPL-2.0
/*
 * xpon_main.c - EN7581 (AN7581DT) XPON driver core.
 *
 * Reverse-engineered skeleton from vendor xpon.ko (kernel 5.4.55, aarch64).
 * Mirrors the module's structure: probe the "econet,ecnt-xpon" node, map the
 * register spaces from the DTS, register the two char devices ("epon_mac" and
 * "PON MCI") and the PON netdevice. Hardware programming is stubbed.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/of_device.h>
#include <linux/of_address.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/reset.h>
#include <linux/of_net.h>		/* of_get_mac_address() */
#include <linux/etherdevice.h>	/* mac_pton / is_valid_ether_addr */

#include "xpon.h"

/* class_create() lost its owner argument in Linux 6.4. Provide a compat shim so
 * the same source builds on the stock 5.4.55 firmware kernel and on 6.x OpenWrt
 * kernels alike. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
#define xpon_class_create(name) class_create(THIS_MODULE, name)
#else
#define xpon_class_create(name) class_create(name)
#endif

#define DRV_NAME	"xpon"
#define DRV_VERSION	"0.1-re"

static int pon_mode = XPON_MODE_GPON;
module_param(pon_mode, int, 0444);
MODULE_PARM_DESC(pon_mode, "PON protocol mode: 0=GPON, 1=EPON, 2=XGS-PON, 3=10G-EPON(XEPON)");

/* ONU MAC advertised as the EPON LLID source address. Highest precedence over
 * the DTS / factory value. Format: AA:BB:CC:DD:EE:FF (for lab / fixed-MAC use).
 * Non-static on purpose: xpon_phy.c references it via the extern in xpon.h. */
char *epon_onu_mac_override;
module_param(epon_onu_mac_override, charp, 0444);
MODULE_PARM_DESC(epon_onu_mac_override, "Override ONU MAC for EPON LLID (AA:BB:CC:DD:EE:FF)");

struct xpon_dev *g_xp;

/* ---------------- interrupt handlers ---------------- */
static irqreturn_t xpon_irq0_handler(int irq, void *dev_id)
{
	/* The GPON MAC interrupt is handled in xpon_ploam.c: it clears the status
	 * register, defers the RX FIFO drain to the PLOAM workqueue, and reacts to
	 * the SN-threshold / POPUP indications. */
	return gpon_irq_handler(irq, dev_id);
}

static irqreturn_t xpon_irq1_handler(int irq, void *dev_id)
{
	(void)dev_id;
	(void)irq;
	return IRQ_NONE;
}

/* ---------------- hardware init / teardown ----------------
 *
 * Bring-up order reverse-engineered from the stock xpon.ko trace
 * (see work/re/EN7581-GPON-bringup-sequence.md and ...regmap-validated.md):
 *   1. stop the MAC<->frame-engine bus (MBI/MPI)        gponDevMbiStop/MpiStop
 *   2. pulse the SoC-level GPON block reset             gponDevResetCtrl SCU RST
 *   3. MAC soft-reset (gpon_mac_sw_rst_n, active-low)  gponDevSwReset
 *   4. clear latched interrupt status                  G_INT_STATUS write-1-c
 *   5. PHY / optical / SERDES primitives
 * The gpon_* register helpers all resolve the base through the global g_xp,
 * so we publish xp there before touching any MAC register.
 */
int xpon_hw_init(struct xpon_dev *xp)
{
	void __iomem *mac = xp->mac;
	struct reset_control *rst;
	int ret = 0;

	if (!mac || !xp->pon_phy || !xp->serdes) {
		dev_err(xp->dev, "register space not mapped\n");
		return -ENODEV;
	}

	/* publish the device so gpon_mac() (used by gpon_rmw/gpon_field) works */
	g_xp = xp;

	/* 1. Stop the MAC<->frame-engine bus (MBI) before reconfiguring. */
	gpon_rmw(G_MBI_STOP, 0, G_MBI_RX_STOP | G_MBI_TX_STOP);
	udelay(10);

	/* 2. Optional SoC-level reset of the GPON block, supplied by the device
	 *    tree (e.g. an Airoha SCU reset line). If the DT provides one we pulse
	 *    it; otherwise we rely on the MAC soft-reset below. No register values
	 *    are guessed here. */
	rst = devm_reset_control_get_optional_exclusive(xp->dev, NULL);
	if (!IS_ERR_OR_NULL(rst)) {
		ret = reset_control_assert(rst);
		if (!ret) {
			udelay(10);
			reset_control_deassert(rst);
			udelay(10);
		}
	}

	/* 3. MAC soft-reset (active-low gpon_mac_sw_rst_n). */
	xpon_writel(mac, DBG_GPON_MAC_SET, 0);
	udelay(10);
	xpon_writel(mac, DBG_GPON_MAC_SET, DBG_GPON_MAC_SW_RST_N);
	udelay(10);

	/* 4. Clear any latched interrupt status (write-1-to-clear). */
	xpon_writel(mac, G_INT_STATUS, ~0u);

	/* 5. PHY / optical / SERDES bring-up. Best-effort: the SERDES and laser
	 *    are owned by the mainline pon_pcs / BOSA drivers, so this only stops
	 *    the bus and records the requested protocol mode. */
	pon_phy_reset();
	XPON_PHY_SET_MODE(xp->mode);
	pon_phy_tx_enable(false);
	PhyTxLedConf();
	pon_serdes_init();

	dev_info(xp->dev, "hw init ok (mac=%p, phy=%p, serdes=%p)\n",
		 mac, xp->pon_phy, xp->serdes);
	return 0;
}

void xpon_hw_deinit(struct xpon_dev *xp)
{
	/* Stop the upstream bus so the MAC is quiescent before it is torn down. */
	if (g_xp && g_xp->mac)
		gpon_rmw(G_MBI_STOP, 0, G_MBI_RX_STOP | G_MBI_TX_STOP);
	(void)xp;
}

/* ---------------- char device fops ---------------- */
static int xpon_open(struct inode *ino, struct file *filp)
{
	filp->private_data = g_xp;
	return 0;
}
static int xpon_release(struct inode *ino, struct file *filp)
{
	return 0;
}

static const struct file_operations eponMacFops = {
	.owner		= THIS_MODULE,
	.open		= xpon_open,
	.release	= xpon_release,
	.unlocked_ioctl	= eponMacIoctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= eponMacIoctl,
#endif
};

static const struct file_operations xmci_fops = {
	.owner		= THIS_MODULE,
	.open		= xpon_open,
	.release	= xpon_release,
	.unlocked_ioctl	= pon_mci_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= pon_mci_ioctl,
#endif
};

static int xpon_setup_chrdevs(struct xpon_dev *xp)
{
	int ret;

	xp->cls = xpon_class_create(DRV_NAME);
	if (IS_ERR(xp->cls))
		return PTR_ERR(xp->cls);

	/* "epon_mac" char device (matches RE: eponMacFops) */
	ret = alloc_chrdev_region(&xp->epon_mac_devt, 0, 1, "epon_mac");
	if (ret)
		goto err_cls;
	cdev_init(&xp->epon_mac_cdev, &eponMacFops);
	ret = cdev_add(&xp->epon_mac_cdev, xp->epon_mac_devt, 1);
	if (ret)
		goto err_epon_region;
	device_create(xp->cls, NULL, xp->epon_mac_devt, NULL, "epon_mac");

	/* "PON MCI" char device (matches RE: xmci_fops -> pon_mci_ioctl) */
	ret = alloc_chrdev_region(&xp->mci_devt, 0, 1, "pon_mci");
	if (ret)
		goto err_epon_dev;
	cdev_init(&xp->mci_cdev, &xmci_fops);
	ret = cdev_add(&xp->mci_cdev, xp->mci_devt, 1);
	if (ret)
		goto err_mci_region;
	device_create(xp->cls, NULL, xp->mci_devt, NULL, "pon_mci");

	/* "airoha-xgs-omcc" secure OMCC char device (airoha-omci transport) */
	ret = xpon_omcc_setup(xp);
	if (ret)
		goto err_mci_dev;

	pr_info(DRV_NAME ": char devices epon_mac, pon_mci & airoha-xgs-omcc created\n");
	return 0;

err_mci_dev:
	device_destroy(xp->cls, xp->mci_devt);
	cdev_del(&xp->mci_cdev);
err_mci_region:
	unregister_chrdev_region(xp->mci_devt, 1);
err_epon_dev:
	device_destroy(xp->cls, xp->epon_mac_devt);
	cdev_del(&xp->epon_mac_cdev);
err_epon_region:
	unregister_chrdev_region(xp->epon_mac_devt, 1);
err_cls:
	class_destroy(xp->cls);
	return ret;
}

static void xpon_teardown_chrdevs(struct xpon_dev *xp)
{
	xpon_omcc_teardown(xp);
	device_destroy(xp->cls, xp->mci_devt);
	cdev_del(&xp->mci_cdev);
	unregister_chrdev_region(xp->mci_devt, 1);
	device_destroy(xp->cls, xp->epon_mac_devt);
	cdev_del(&xp->epon_mac_cdev);
	unregister_chrdev_region(xp->epon_mac_devt, 1);
	class_destroy(xp->cls);
}

/* ---------------- sysfs (for the LuCI web UI) ----------------
 * Exposes ONU SN / Password as read-write attributes and TCONT counters as a
 * read-only attribute, so luci-app-xpon can configure the PON without going
 * through the char-device ioctl. */
static ssize_t sn_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct gpon_onu_id_cfg cfg;
	int n;

	(void)attr;
	if (gpon_get_sn_passwd(&cfg))
		return -EIO;
	/* print the 8 raw bytes; non-printable bytes are shown literally */
	n = snprintf(buf, PAGE_SIZE, "%.8s\n", cfg.sn);
	return n;
}

static ssize_t sn_store(struct device *dev, struct device_attribute *attr,
			const char *buf, size_t count)
{
	struct gpon_onu_id_cfg cfg;
	size_t len = count;

	(void)attr;
	(void)dev;
	if (len > 0 && buf[len - 1] == '\n')
		len--;
	if (len > GPON_SN_LEN)
		len = GPON_SN_LEN;

	memset(&cfg, 0, sizeof(cfg));
	if (gpon_get_sn_passwd(&cfg))
		return -EIO;
	memset(cfg.sn, 0, GPON_SN_LEN);
	memcpy(cfg.sn, buf, len);
	cfg.sn_len = len;
	if (gpon_set_sn_passwd(&cfg))
		return -EIO;
	return count;
}
static DEVICE_ATTR_RW(sn);

static ssize_t password_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct gpon_onu_id_cfg cfg;

	(void)attr;
	if (gpon_get_sn_passwd(&cfg))
		return -EIO;
	return snprintf(buf, PAGE_SIZE, "%.*s\n", (int)cfg.pw_len, cfg.password);
}

static ssize_t password_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct gpon_onu_id_cfg cfg;
	size_t len = count;

	(void)attr;
	(void)dev;
	if (len > 0 && buf[len - 1] == '\n')
		len--;
	if (len > GPON_PW_MAX)
		len = GPON_PW_MAX;

	memset(&cfg, 0, sizeof(cfg));
	if (gpon_get_sn_passwd(&cfg))
		return -EIO;
	memset(cfg.password, 0, GPON_PW_MAX);
	memcpy(cfg.password, buf, len);
	cfg.pw_len = len;
	if (gpon_set_sn_passwd(&cfg))
		return -EIO;
	return count;
}
static DEVICE_ATTR_RW(password);

/* T-CONT / Alloc-ID map, read from G_TCONT_ID_0_1..G_TCONT_ID_14_15. */
static ssize_t tcont_stats_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct gpon_tcont_counter c;
	ssize_t off = 0;
	int i, ret;

	(void)attr;
	(void)dev;
	for (i = 0; i < GPON_TCONT_HW_MAX; i++) {
		memset(&c, 0, sizeof(c));
		c.tcont_id = i;
		ret = gpon_get_tcont_counter(&c);
		if (ret)
			break;
		off += snprintf(buf + off, PAGE_SIZE - off,
				"tcont%d: alloc_id=%u valid=%u\n",
				i, c.alloc_id, c.valid);
	}
	return off;
}
static DEVICE_ATTR_RO(tcont_stats);

/* ONU activation state (G_ACTIVATION_ST) and assigned ONU-ID (G_ONU_ID). */
static ssize_t onu_state_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	(void)attr;
	(void)dev;
	return snprintf(buf, PAGE_SIZE,
			"activation_state=0x%08x\nonu_id=0x%08x\n",
			gpon_get_activation_state(), gpon_get_onu_id());
}
static DEVICE_ATTR_RO(onu_state);

/* GPON MAC hardware counters (DBG_*_CNT). */
static ssize_t gpon_counters_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct gpon_hw_counters hc;

	(void)attr;
	(void)dev;
	gpon_get_hw_counters(&hc);
	return snprintf(buf, PAGE_SIZE,
			"rx_gem=%u\nrx_crc_err=%u\nrx_gtc=%u\n"
			"tx_gem=%u\ntx_burst=%u\n"
			"hec_one_err=%u\nhec_two_err=%u\nhec_uc_err=%u\n",
			hc.rx_gem, hc.rx_crc_err, hc.rx_gtc,
			hc.tx_gem, hc.tx_burst,
			hc.hec_one_err, hc.hec_two_err, hc.hec_uc_err);
}
static DEVICE_ATTR_RO(gpon_counters);

/* EPON LLID source MAC (runtime-overridable before OLT registration). */
static ssize_t epon_onu_mac_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct xpon_dev *xp = platform_get_drvdata(to_platform_device(dev));
	(void)attr;
	return snprintf(buf, PAGE_SIZE, "%pM\n", xp->epon_onu_mac);
}
static ssize_t epon_onu_mac_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct xpon_dev *xp = platform_get_drvdata(to_platform_device(dev));
	u8 mac[ETH_ALEN];
	(void)attr;
	if (!mac_pton(buf, mac) || !is_valid_ether_addr(mac))
		return -EINVAL;
	spin_lock(&xp->epon_fsm_lock);
	ether_addr_copy(xp->epon_onu_mac, mac);
	spin_unlock(&xp->epon_fsm_lock);
	dev_info(dev, "XEPON: ONU MAC set to %pM via sysfs\n", mac);
	return count;
}
static DEVICE_ATTR_RW(epon_onu_mac);

static struct attribute *xpon_attrs[] = {
	&dev_attr_sn.attr,
	&dev_attr_password.attr,
	&dev_attr_tcont_stats.attr,
	&dev_attr_onu_state.attr,
	&dev_attr_gpon_counters.attr,
	&dev_attr_epon_onu_mac.attr,
	NULL,
};
ATTRIBUTE_GROUPS(xpon);

/* ---------------- DTS probe ---------------- */
static int xpon_probe(struct platform_device *pdev)
{
	struct xpon_dev *xp;
	struct resource *res;
	int ret, i;

	xp = devm_kzalloc(&pdev->dev, sizeof(*xp), GFP_KERNEL);
	if (!xp)
		return -ENOMEM;
	xp->dev = &pdev->dev;
	mutex_init(&xp->lock);
	spin_lock_init(&xp->epon_fsm_lock);

	/* map the three XPON MAC register regions */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	xp->mac = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(xp->mac))
		return PTR_ERR(xp->mac);

	/* The 64KB PON MAC window holds three sibling sub-blocks (vendor
	 * airoha_xpon.c: GPON@0x4000 / XGS@0x5000 / EPON@0x6000). DTS reg[0]=0x1fb64000
	 * is GPON, reg[1]=0x1fb66000 is EPON, reg[2]=0x1fb65000 is XGS-PON. So
	 * xp->xgspon_reg maps to reg[2].
	 * NOTE: xp->mac is the GPON sub-block, so "mac + 0x5000" would wrongly
	 * address 0x1fb69000; the correct XGS base is 0x1fb65000 (mac + 0x1000). */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	xp->mac2 = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(xp->mac2))
		return PTR_ERR(xp->mac2);
	res = platform_get_resource(pdev, IORESOURCE_MEM, 2);
	xp->mac3 = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(xp->mac3))
		return PTR_ERR(xp->mac3);
	xp->xgspon_reg = xp->mac3;	/* XGS-PON sub-block @ 0x1fb65000 */

	/* Resolve the ONU MAC used as the EPON LLID source address (module param >
	 * DTS local-mac-address / factory nvmem cell). Done before xpon_hw_init()
	 * because XPON_PHY_SET_MODE -> xpon_epon_init() starts the MPCP FSM, which
	 * needs a valid MAC ready at REGISTER time. */
	xpon_epon_resolve_onu_mac(xp);

	/* PON PHY region(s) via phandle "econet,ecnt-pon_phy" */
	xp->pon_phy = devm_ioremap(&pdev->dev, PON_PHY_BASE, PON_PHY_SIZE);
	xp->pon_phy_aux0 = devm_ioremap(&pdev->dev, PON_PHY_AUX0_BASE, PON_PHY_AUX0_SIZE);
	xp->pon_phy_aux1 = devm_ioremap(&pdev->dev, PON_PHY_AUX1_BASE, PON_PHY_AUX1_SIZE);
	xp->serdes = devm_ioremap(&pdev->dev, SERDES_COMMON_BASE, SERDES_COMMON_SIZE);
	xp->xpon_usxgmii = devm_ioremap(&pdev->dev, XPON_USXGMII_BASE, XPON_USXGMII_SIZE);

	/* Optional xPON SERDES/PCS generic PHY used for protocol-mode switching.
	 * If the kernel ships drivers/phy/airoha/phy-airoha-xpon.c, the PCS line
	 * rate is reconfigured through it (phy-names "xpon"); otherwise the switch
	 * is delegated to the mainline PCS driver and a warning is logged. */
	xp->xpon_serdes_phy = devm_phy_optional_get(&pdev->dev, "xpon");
	if (IS_ERR(xp->xpon_serdes_phy)) {
		dev_warn(&pdev->dev, "xPON serdes PHY optional-get failed: %ld\n",
			 PTR_ERR(xp->xpon_serdes_phy));
		xp->xpon_serdes_phy = NULL;
	}
	xp->scu = syscon_regmap_lookup_by_phandle(pdev->dev.of_node, "airoha,scu");
	if (IS_ERR(xp->scu)) {
		dev_warn(&pdev->dev, "SCU syscon not found; WAN path select disabled\n");
		xp->scu = NULL;
	}

	/* Allocate the GPON activation/private state. Sub-modules (xpon_gpon.c,
	 * xpon_ploam.c, xpon_act.c) reference xp->gpon, so it must exist before
	 * any of the gpon_*_init() calls below. */
	xp->gpon = devm_kzalloc(&pdev->dev, sizeof(*xp->gpon), GFP_KERNEL);
	if (!xp->gpon)
		return -ENOMEM;
	spin_lock_init(&xp->gpon->lock);
	xp->gpon->state = GPON_STATE_O1;
	xp->gpon->onu_id = GPON_UNASSIGN_ONU_ID;
	xp->gpon->onu_id_valid = false;
	xp->gpon->overhead_valid = false;
	atomic_set(&xp->gpon->to1_expiry_cnt, GPON_TO1_RESET_CNT);
	atomic_set(&xp->gpon->hw_reset_cnt, 0);

	/* This driver now accepts all four PON protocol modes at the MAC level:
	 * GPON(0), EPON(1), XGS-PON(2, 10G GEM/OMCI, ported), 10G-EPON/XEPON(3,
	 * register map TBD). Default to GPON unless overridden via the pon_mode
	 * module parameter. */
	switch (pon_mode) {
	case XPON_MODE_GPON:
	case XPON_MODE_EPON:
	case XPON_MODE_XGPON:
	case XPON_MODE_XEPON:
		xp->mode = pon_mode;
		break;
	default:
		dev_warn(&pdev->dev, "invalid pon_mode=%d, defaulting to GPON\n", pon_mode);
		xp->mode = XPON_MODE_GPON;
	}

	ret = xpon_hw_init(xp);
	if (ret)
		return ret;

	/* Bring up the GPON MAC and the O1..O7 activation state machine. SN/Password
	 * come later via sysfs/LuCI (gpon_set_sn_passwd), which re-programs the SN
	 * registers; until then the ONU stays in O1. */
	ret = gpon_dev_init();
	if (ret)
		dev_warn(&pdev->dev, "gpon dev init failed: %d\n", ret);
	ret = gpon_act_init();
	if (ret)
		dev_warn(&pdev->dev, "gpon act init failed: %d\n", ret);

	/* Request IRQs only after gpon_act_init() has initialised the PLOAM
	 * workqueue (the IRQ top-half schedules it), so a pending interrupt can
	 * never touch an uninitialised work_struct. By now G_INT_ENABLE is also
	 * programmed, so the MAC may legitimately assert them. */
	for (i = 0; i < 2; i++) {
		ret = platform_get_irq(pdev, i);
		if (ret < 0)
			break;
		xp->irq[i] = ret;
		ret = devm_request_irq(&pdev->dev, xp->irq[i],
				       i == 0 ? xpon_irq0_handler : xpon_irq1_handler,
				       IRQF_SHARED, DRV_NAME, xp);
		if (ret)
			dev_warn(&pdev->dev, "irq%d request failed\n", xp->irq[i]);
	}

	ret = xpon_setup_chrdevs(xp);
	if (ret)
		goto err_hw;

	/* Wire the OMCC char device to the GEM sniffer data path (programs the
	 * 0x4368 sniffer engine; TX reaches the fibre only once QDMA attaches). */
	ret = xpon_gem_init(xp);
	if (ret)
		dev_warn(&pdev->dev, "gem data path init failed: %d\n", ret);

	/* Attach the real QDMA transport: this overrides the GEM stub hw-send
	 * registered by xpon_gem_init, so OMCC TX reaches the optical port.
	 * When qdma_base=0 it no-ops and the OMCC loopback self-test stays valid. */
	ret = xpon_qdma_init(xp);
	if (ret)
		dev_warn(&pdev->dev, "qdma engine init failed: %d\n", ret);

	ret = xpon_netdev_init(xp);
	if (ret)
		dev_warn(&pdev->dev, "netdev init failed: %d\n", ret);

	xp->probed = true;
	g_xp = xp;
	platform_set_drvdata(pdev, xp);

	ret = devm_device_add_group(&pdev->dev, &xpon_group);
	if (ret)
		dev_warn(&pdev->dev, "sysfs group create failed: %d\n", ret);

	dev_info(&pdev->dev, "EN7581 XPON driver probed (ver %s)\n", DRV_VERSION);
	return 0;

err_hw:
	xpon_hw_deinit(xp);
	return ret;
}

static int xpon_remove(struct platform_device *pdev)
{
	struct xpon_dev *xp = platform_get_drvdata(pdev);

	if (xp->gpon) {
		cancel_work_sync(&xp->gpon->ploam_work);
		gpon_act_deinit();
		gpon_dev_deinit();
	}
	if (xp->netdev)
		xpon_netdev_free(xp);
	xpon_qdma_exit(xp);
	xpon_teardown_chrdevs(xp);
	xpon_hw_deinit(xp);
	return 0;
}

static const struct of_device_id xpon_of_match[] = {
	{ .compatible = "econet,ecnt-xpon", },
	{ .compatible = "airoha,en7581-xpon", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, xpon_of_match);

static struct platform_driver xpon_driver = {
	.probe		= xpon_probe,
	.remove		= xpon_remove,
	.driver = {
		.name	= DRV_NAME,
		.of_match_table = xpon_of_match,
	},
};

module_platform_driver(xpon_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("reverse-engineered from vendor xpon.ko");
MODULE_DESCRIPTION("EN7581/AN7581DT XPON driver skeleton");
MODULE_VERSION(DRV_VERSION);
