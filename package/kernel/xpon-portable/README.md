# xpon-portable — EN7581 (AN7581DT) XPON 驱动可移植源码

从 XG-040G-MD 原厂固件 `xpon.ko`（内核 5.4.55，aarch64，未 strip）**逆向**得到的
XPON/GPON/EPON 驱动**可移植源码**。它复刻了原厂驱动的整个用户态 ABI，可作为 OpenWrt
内核模块从源码构建——不再依赖原厂 5.4.55 内核树与闭源的 `ecnt_hooks` / `frame_engine`
框架。

> 范围说明：本交付是可移植、可构建、且寄存器级**部分真实实现**的源码。
> - **已真实实现**（基于 airoha_kernel 逆向 + re/bitfields.json 校验）：Airoha QDMA OMCI/OAM
>   数据通路（TX queue 7 / RX ring 15）、GEM 嗅探引擎（G_OMCI_ID@0x4048 等）、FE CDM2
>   OAM_QSEL 路由（让下行 OAM 真正进入 ring15）、PLOAM 收发与激活状态机、SN/密码/TCONT
>   寄存器编程。
> - **用户态 OMCI 协议栈**：G.988 OMCI 由配套的 `airoha-omci`（omcid）守护进程实现，内核驱动
>   通过 `/dev/airoha-xgs-omcc` 字符设备暴露 OMCC ABI 与之对接（见「OMCI / omcid」一节）。
> - **仍为未知量**：SERDES/PCS 链路训练（光口能否 train 取决于主线 `airoha,an7581-pcs-pon`
>   驱动与 `&pon_pcs` 接线）；真机未经验证（本环境无 aarch64 工具链/硬件）。

---

## 目录结构

```
xpon-portable/
├── Makefile                 # OpenWrt KernelPackage 包（从源码构建）
├── src/
│   ├── Makefile             # kbuild（独立构建用）
│   ├── Kbuild               # kbuild 别名
│   ├── include/
│   │   ├── xpon_ioctl.h     # ★ 逆向出的用户态 ABI（ioctl 号、结构体）
│   │   └── xpon.h           # 内部定义：寄存器基址(DTS)、状态、原型
│   └── core/
│       ├── xpon_main.c      # probe / ioremap / 字符设备 / 网口 / 中断框架
│       ├── xpon_mci.c       # PON MCI ioctl 派发 + 各子模块 nr 范围校验
│       ├── xpon_epon.c      # epon_mac 字符设备 13 个命令（桩）
│       ├── xpon_gpon.c      # GPON 子栈（桩）
│       ├── xpon_phy.c       # PON PHY / 光口子栈（桩）
│       └── xpon_netdev.c    # PON 网口 + ndo_do_ioctl（桩）
├── dts/
│   ├── 0001-xg-040g-md-add-xpon-node.patch   # 针对 bell_xg-040g-md 板级 DTS 的 xpon 节点补丁
│   ├── xg-040g-md-xpon.dtsi                  # 板级 xpon MAC 节点片段（可 #include）
│   └── en7581-xpon-subsystem.dtsi            # ★ SoC 级 PON 子系统节点(pon_phy/serdes/xpon_usxgmii)，需并入 an7581.dtsi
├── tools/
│   ├── integrate.sh       # ★ 自动化集成：复制包 + 注入 DTS 节点 + 启用 kmod
│   ├── abi_test.c         # 主机端 ABI 编码校验（无需内核树即可跑）
│   ├── include/linux/{ioctl,types}.h  # 最小头 shim
│   └── run_abi_test.sh
└── integrate-workflow.patch  # (可选) 给 xiangtailiang/OpenWrt-for-XG-040G-MD 的 CI 加一步集成
```

逆向过程与命令集全量解码见 `../MCI命令集解码报告.md` 与 `../re/` 下的解码脚本/JSON。

---

## ABI 概要（逆向结论）

驱动有三个用户态通道：

1. **`epon_mac` 字符设备** — type 字节 `'j'`(0x6a)，13 个命令（GET_0/6/7/9/11/13/15/16/17/23/25/36、SET_35）。
2. **`PON MCI` 字符设备** — 按 `(cmd>>8)&0xff` 的 type 字节派发：
   | type | 子模块 | 已解码 nr 范围 | 派发方式 |
   |------|--------|---------------|----------|
   | 0xd7 | PHY  | READ 1..7，WRITE 1,2,3,4,6,8 | 线性 cmp 链 |
   | 0xd8 | EPON | （MCI 未实现，控制走 epon_mac） | 平凡 |
   | 0xd9 | GPON | READ 1..102，WRITE 1..110 | 跳转表 |
   | 0xda | IF   | READ 1..132，WRITE 1..133 | 跳转表 |
   | 0xdb | FDET | READ 1,2,3，WRITE 3 | 线性 cmp 链 |
3. **PON 网口** `ndo_do_ioctl`（SIOCDEVPRIVATE 族）— 映射未逆向，留桩返回 `-EOPNOTSUPP`。

所有跳转表的完整 `nr→handler` 偏移映射在 `../re/mci_enum.json`。

---

## 构建方式

### A. 作为 OpenWrt 包（推荐，自动处理 vermagic/ARCH/工具链）

```sh
# 把整个目录放进你的 OpenWrt 源码树
cp -r xpon-portable package/kernel/kmod-xpon-src

make menuconfig
#   Kernel modules -> Network Devices -> kmod-xpon-src  <M>

make package/kernel/kmod-xpon-src/compile V=s
# 产物：bin/targets/.../kmod-xpon-src_*.ipk  （含 xpon.ko）
```

包的 `Makefile` 用 `KernelPackage` 基础设施，由 OpenWrt 提供 `$(LINUX_DIR)`、
`ARCH`、`CROSS_COMPILE` 与 vermagic，因此能针对**当前 OpenWrt 内核**（含 6.x 主线）
构建，而不绑定原厂 5.4.55。

### B. 独立 kbuild（需已配置好的内核树 + aarch64 交叉工具链）

```sh
export ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
make -C /path/to/linux-5.4.55 M=$(pwd)/src modules
# 产物：src/xpon.ko
```

---

## 主机端 ABI 校验（本机即可运行，无需内核树）

`xpon_ioctl.h` 生成的每个 `_IOC` 值都会与从二进制逆向出的数值逐一比对：

```sh
sh tools/run_abi_test.sh
# 例：MCI_PHY_R(7) == 0x8000d707，MCI_GPON_W(110) == 0x4000d96e ...
```

已验证（Apple clang / macOS arm64）：全部 ABI 校验通过。这证明用户态 ABI 编码与
原厂 `xpon.ko` 完全一致。

---

## Device Tree（设备树，必需）

> 基址分工：本节点的 `reg`（0x1fb64000 等）是 **PON MAC 寄存器窗**，供 `xpon_main` /
> `xpon_gem` / `xpon_gpon` 使用；**QDMA（0x1fb54000）与 FE（0x1fb50000，含 CDM2 OAM 路由）
> 由 `xpon_qdma` 的模块参数提供，不依赖本 DTS 节点**，故注入本节点即足够。

驱动通过 `of_device_id` 匹配 `econet,ecnt-xpon` / `airoha,en7581-xpon`，**仅当 DTS 里存在
对应节点时才会 probe**。已验证 `xiangtailiang/OpenWrt-for-XG-040G-MD`（immortalwrt 分支，
内核 6.12）的板级 DTS `patch/an7581-bell_xg-040g-md.dts` **默认不含 xpon 节点**（仅
`#include "an7581.dtsi"`，而该 SoC dtsi 在 immortalwrt 内核对 PON 也尚未支持），因此
**必须叠加补丁**，否则模块编进内核也不会被加载。

应用补丁（在 immortalwrt / OpenWrt 仓库根目录执行）：

```sh
git apply xpon-portable/dts/0001-xg-040g-md-add-xpon-node.patch
```

补丁仅在板级 DTS 的 `keys` 节点之后追加一个 xpon 节点：

```dts
xpon@1fb64000 {
    compatible = "econet,ecnt-xpon";
    reg = <0x00 0x1fb64000 0x00 0x3e8
           0x00 0x1fb66000 0x00 0x23c
           0x00 0x1fb65000 0x00 0xff8>;
    interrupts = <0x00 0x2a 0x04 0x00 0x22 0x04>;
    status = "okay";
};
```

设计要点（与驱动 `xpon_probe` 一致）：
- 三段 `reg` 即驱动 `platform_get_resource(..., 0..2)` 取的 MAC 寄存器窗（取自原厂内核 DTS，
  0x1fb64000 / 0x1fb66000 / 0x1fb65000）。该布局已与社区权威参考
  `merbanan/airoha_ml` 的 `en7581-base.dtsi`（AN7581 事实标准 SoC DTS）逐字节核对一致。
- `interrupts` 0x2a(42) / 0x22(34) 对应驱动 `platform_get_irq(0..1)`（XPON MAC INT 与
  DYINGGASP INT，即 GIC_SPI 42 / 34）。

⚠️ **仅挂 xpon MAC 节点不足以点亮光口**。原厂固件的 DTS 还包含 SoC 级的
**PON 子系统节点**，它们须出现在 `an7581.dtsi` 中：
- `pon_phy@1faf0000`（`econet,ecnt-pon_phy`）—— PON PHY / 光模块接口
- `serdes_common_phy@1fa5a000`（`airoha,serdes_common_phy`）—— SERDES（含 pon_ana_pxp / pon_pma）
- `xpon_usxgmii@1fa80000`（`airoha,air-xpon_usxgmii`）—— MAC↔SERDES 的 USXGMII 链路
- `pio` 里的 `pinctrl_pon`（pon0 功能，GPIO 50–55，来自 `0015-AN7581-pinmux-driver.patch`）

这些节点已整理进 **`dts/en7581-xpon-subsystem.dtsi`**（reg/irq 逐字节抄自
`merbanan/airoha_ml` 的 `en7581-base.dtsi`），需并入 `target/linux/airoha/dts/an7581.dtsi`。
`xg-040g-md-xpon.dtsi` 仅负责板级 MAC 节点 + `pinctrl-0 = <&pinctrl_pon>`。

> 注意：XR 里 airoha_kernel（6.18）的 `airoha,en7523-xpon` 是 **EN7523** 驱动，寄存器布局
> 与 EN7581 不同（例如 SN 偏移 EN7523=0x0B4、EN7581=我们 RE 的 0x1dd）；`econet-xpon` PR
> （EN7528）则硬编址 0x1FB60000。EN7581 的原生 compatible 是 **`econet,ecnt-xpon`**——
> 即我们逆向的原厂 `xpon.ko`，三条驱动谱系互不相同。

- 通用片段 `dts/xg-040g-md-xpon.dtsi` 可直接 `#include` 到其他板子的 DTS。

> 该补丁已用 `git apply --check` 验证可在 `xiangtailiang/OpenWrt-for-XG-040G-MD` 干净应用；
> 克隆验证后已 `git checkout` 还原，仓库未留改动。

---

## Build Integration（联编集成，针对 xiangtailiang/OpenWrt-for-XG-040G-MD）

> 关键前提：该仓库是 **config / overlay 仓库**，本身不含 `target/linux/`、`package/`、
> `.config`。CI 的真实流程是 `git clone immortalwrt/immortalwrt master` → `feeds` →
> 复制 `config/*.config` → `make defconfig` → `make`。因此"集成"的落点是**完整的
> immortalwrt 源码树**（CI 里即 clone 出来的 `openwrt/` 目录），而非这个 overlay 仓库。

### 这个仓库的 CI 不自动注入 `patch/`

核查确认：`.github/workflows/*.yml` 与 `scripts/update-packages.sh` **都不会**把
`patch/an7581-bell_xg-040g-md.dts`、`patch/an7581.mk` 复制到 immortalwrt 树里。它们是作者
留存的**参考/变体**文件。CI 实际构建的是上游已存在的 `nokia_xg-040g-md` 设备（config 里
`CONFIG_TARGET_airoha_an7581_DEVICE_nokia_xg-040g-md=y`），其板级 DTS 由上游提供、默认
**不含 xpon 节点**。所以要把 XPON 驱动打进镜像，必须显式做"注入"。

### 方式一：本地 / 手动（推荐先用，便于排错）

把本目录整包放到完整 immortalwrt 树的任意位置，然后运行 `tools/integrate.sh`：

```sh
# 1) 准备完整 immortalwrt 树（CI 是 git clone 出来的 openwrt/）
git clone --depth 1 --branch master https://github.com/immortalwrt/immortalwrt.git openwrt
cd openwrt
./scripts/feeds update -a && ./scripts/feeds install -a -f
cp /path/to/config/xg-040g-md-immortalwrt.config .config
make defconfig

# 2) 运行集成脚本（自动：复制包 + 找板级 DTS 注入 xpon 节点 + 启用 kmod）
/path/to/xpon-portable/tools/integrate.sh "$(pwd)"

# 3) 构建
make package/kernel/kmod-xpon-src/compile V=s
make
```

`integrate.sh` 会：
1. 把 `xpon-portable` 复制为 `package/kernel/kmod-xpon-src/`（剔除 `tools/`、`dts/`、README，
   保持包目录干净）；
2. 从 `.config` 读当前选中的 airoha 设备，自动定位其板级 DTS
   （`target/linux/airoha/dts/an7581-<设备>.dts`，兜底按板型字符串搜索），**幂等**地追加
   `xpon@1fb64000` 节点（已用 `dtc` 验证节点语法可编译为 dtb）；
3. 在 `.config` 追加 `CONFIG_PACKAGE_kmod-xpon-src=y`。

若自动定位不到 DTS，可用 `--dts <path>` 显式指定：
`tools/integrate.sh "$(pwd)" --dts target/linux/airoha/dts/an7581-nokia_xg-040g-md.dts`
（上游设备名通常是 `nokia_xg-040g-md`）。

### 方式二：接入 CI（可选）

仓库根目录已附带 `integrate-workflow.patch`，给
`.github/workflows/xg-040g-md-immortalwrt.yml` 在 `make defconfig` **之后**加一步调用
`integrate.sh`：

```sh
# 在你的 overlay 仓库根目录执行（需先把 xpon-portable/ 放进仓库，或作 git submodule）
git apply integrate-workflow.patch
```

注意点：
- 补丁在 `make defconfig` 之后插入，避免 `defconfig` 重写 `.config` 覆盖掉我们追加的
  `CONFIG_PACKAGE_kmod-xpon-src=y`；
- 脚本路径假设仓库内含 `xpon-portable/`（直接复制本目录，或 `git submodule add` 引入）；
- 若未找到 `xpon-portable/`，该步仅 `::warning::` 跳过，不影响原镜像构建。

### 验证（构建后）

```sh
# 在路由器的 OpenWrt 上
opkg install kmod-xpon-src_*.ipk
dmesg | grep -i xpon        # 应看到 probe: 映射三段 reg、申请两个 IRQ、建字符设备
ls /dev/                    # 应出现 epon_mac / PON MCI 类设备节点（取决于驱动桩实现）
```

> 注：当前寄存器编程为桩，加载会暴露 ABI 但不会点亮光口；这是 step 2 之后的工作。

---

## PON 设置参数（SN / 密码 / TCONT）逆向结论

在 `work/re/full.asm` 中对 **GPON** 子栈里**唯一有真实语义的 handler** 做了寄存器级解码
（其余 GPON/IF nr 多为薄封装 / 桩）：

### ONU 序列号 & 密码 — `xmcs_set_sn_passwd` (@ 0x545cc)

输入结构（arg0）写入 GPON MAC 寄存器窗（`g_xp->mac` = DTS `reg[0]` = `0x1fb64000`）：

| 输入结构 | 寄存器偏移 | 宽度 | 含义 |
|----------|-----------|------|------|
| 字节 `[0..7]`  | `G_VENDOR_ID`(0x40b0) / `G_VS_SN`(0x40b4) | 8 B  | ONU Serial Number（厂商码 4 + 序列号 4） |
| 字节 `[8..17]` | （无硬件寄存器；密码经上游 PLOAM 消息发送） | 10 B | GPON Password / LOID |
| 字节 `[0x37]`  | `0x1e5` | 1 B  | SN 长度 / 标志 |
| 字节 `[0x39]`  | `0x1e6` | 1 B  | 密码长度 / 标志 |

对应驱动实现：`xpon_gpon.c` 的 `gpon_set_sn_passwd()` / `gpon_get_sn_passwd()`，
用户态 ABI：`MCI_GPON_W/R(3)`（struct `gpon_onu_id_cfg`，见 `xpon.h`）。
> 注：原厂该输入结构更大（≥0x3A 字节）且字段排布不同；此处为驱动 / LuCI 双方约定的**自有 ABI**。
>
> ⚠️ **寄存器偏移澄清**：早期分析把 SN 的偏移写成 `0x1dd`、密码写成 `0x1e8`，这是**错误的**——
> 那两个值是原厂驱动软件私有结构 `gpGponPriv` 的**字段偏移**，不是硬件寄存器。经 relocation
> 感知的反汇编（`.rela.text`）确认，真实的硬件写只经过全局指针 `g_gpon_mac_reg_BASE`，SN 落在
> `G_VENDOR_ID@0x40b0` / `G_VS_SN@0x40b4`，与 econet-xpon 寄存器头 92.9% 吻合。本驱动
> （`gpon_write_sn`）正是写这两个寄存器，注释已更正。详见 `../re/EN7581-GPON-regmap-validated.md`。

### TCONT 计数器 — `get_counter_from_reg` (@ 0x54e98)

两级查表读 12-bit 计数：

```
val   = readw(base + (tcont_id + 0x30) * 2 + 8) & 0x7fff
count = readl(base + 0x2060 + val * 200 + 8) & 0xfff     # RX
tx    = readl(base + 0x2060 + val * 200 + 12) & 0xfff    # TX（相邻，假设）
```

驱动实现：`gpon_get_tcont_counter()`，用户态 ABI：`MCI_GPON_W/R(75)`
（struct `gpon_tcont_counter`）。TX 偏移 `+4` 为**未验证假设**。

### 驱动已真实实现的部分

`gpon_cmd_proc` 现在对 **nr=3（SN/密码）** 与 **nr=75（TCONT 计数）** 走真实寄存器读写，
其余 nr 仍为桩（返回 `-EOPNOTSUPP`）。同时 `xpon_main.c` 暴露 **sysfs** 属性：
`sn`(rw) / `password`(rw) / `tcont_stats`(ro)，供 LuCI 直接使用。

---

## LuCI 界面（luci-app-xpon）

配套 Web 界面在 `../luci-app-xpon/`（独立的 OpenWrt 包 `luci-app-xpon`）：

- **网络 → PON / XPON**：编辑 `/etc/config/xpon` 的 `sn` / `password` / `authmode`；
- 保存应用后 `on_after_apply` 触发 `/etc/init.d/xpon`，把 UCI 值写入驱动 sysfs；
- 页面实时只读显示各 `tcont` 的 RX/TX 计数（读 `tcont_stats` sysfs）。

集成：`xpon-portable/tools/integrate.sh` 在复制内核包的同时会把 `luci-app-xpon/`
一并复制为 `<tree>/package/luci-app-xpon/`。也可手动放置后 `make menuconfig` 选
`LuCI → Applications → luci-app-xpon`。详见 `luci-app-xpon/README.md`。

---

## 可移植性处理

- **内核版本兼容**：`class_create` 在 Linux 6.4 去掉了 owner 参数，已用
  `xpon_class_create()` 兼容宏覆盖 5.4 与 6.x 两套签名。
- **uAPI 头自包含**：`SIOCDEVPRIVATE` 在 `xpon_ioctl.h` 内兜底定义，用户态单独
  `#include` 该头可编译。
- **ABI 边界忠实**：`*_cmd_proc` 严格按逆向出的 nr 范围校验，越界返回 `-EINVAL`，
  与原厂二进制行为一致（非法的 nr 原厂也返回 -22）。

---

## 已知限制 / 后续工作

驱动当前状态（截至本版）：

- **已实现（真实寄存器编程）**
  - PLOAM 收发（`xpon_ploam.c`）：下行 FIFO 大端拆包、上行大端打包重复发送、地址过滤、
    连续 3 次去重。
  - O1–O7 激活状态机（`xpon_act.c`）：进入 O2/O3/O4 重编程 SN（防 O3 全零 SN 卡死）、
    O3 步进 SN 发射功率、O5 使能 `DBG_PLOAMD_FILTER_IN_O5`、O3/O4 镜像 T3 preamble、
    TO1(10s→O2)/TO2(100ms→O1) 管理、连续 20 次 TO1 超时触发全重启。
  - 下行 PLOAM 分发（`gpon_ploam_dispatch`）：Upstream_Overhead→preamble/guard/delimiter、
    Assign_ONU-ID→O4、Ranging_Time→`G_EQD`+O5、Assign_Alloc-ID→tcont、Config_Port-ID→OMCC、
    Request_Key→AES 密钥分片上行、Popup→O6 等 25 种消息。
  - 硬件上电序列（`xpon_hw_init` + `xpon_phy.c`）：MBI 停止、可选 SoC reset、MAC 软复位、
    清中断状态；均基于已验证的 `EN7581-GPON-bringup-sequence.md` 寄存器顺序。
  - SN/密码/ONU-ID/GEM/Alloc-ID/AES/TCONT/计数器 的寄存器读写与 sysfs 暴露。

- **仍为桩 / 最大未知量（点亮光口前必须解决）**
  - **SERDES / PCS 链路训练**：EN7581 的 SERDES 与 `pon_pcs` 由主线 `airoha,an7581-pcs-pon`
    驱动负责，本驱动未逆向其寄存器序列；光口能否 train 起来取决于该 PCS 驱动与
    `&pon_pcs` phandle 接线。`pon_serdes_init()` 当前为空壳（返回 0），**不臆造寄存器值**。
  - **激光 / TX 使能**：在 BOSA/en7572 光模块驱动里，不在 GPON MAC 窗，本驱动只记录意图。
  - **OMCI 协议栈**：G.988 OMCI 由配套用户态守护 `airoha-omci`（omcid）实现，内核驱动通过
    `/dev/airoha-xgs-omcc` OMCC 字符设备暴露 ABI 与之对接（`omcid -transport device
    -device /dev/airoha-xgs-omcc`）。因此"点亮光口后能否跑业务"取决于该 omcid 与 OLT 的互通，
    已非内核驱动空白——详见「OMCI / omcid」一节。
  - **PON 网口 `SIOCDEVPRIVATE`** 的 payload→MCI 映射未逆向，留桩。
  - 中断/时钟/复位流程已按 RE 序列实现，但**未经真机验证**（本机无 aarch64 工具链/硬件）。

> 综上：本驱动已是一个**寄存器级真实、可编译、可加载**的开源 GPON MAC 驱动，但因缺 SERDES
> 训练与 OMCI，真机上大概率停在 O3/O4 或 O5 拿不到业务。要真正"点亮并跑业务"，当前最可靠的
> 路线仍是**原厂 5.4.55 内核 + 预编译 kmod-xpon**（`work/openwrt-packages/`），本源码驱动作为
> 可审计/可维护的透明替代持续完善。
