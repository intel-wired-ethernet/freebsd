/******************************************************************************

  Copyright (c) 2013-2018, Intel Corporation
  All rights reserved.
  
  Redistribution and use in source and binary forms, with or without 
  modification, are permitted provided that the following conditions are met:
  
   1. Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.
  
   2. Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in the 
      documentation and/or other materials provided with the distribution.
  
   3. Neither the name of the Intel Corporation nor the names of its 
      contributors may be used to endorse or promote products derived from 
      this software without specific prior written permission.
  
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.

******************************************************************************/
/*$FreeBSD$*/

#include "ixl.h"
#include "ixlv.h"

/*********************************************************************
 *  Driver version
 *********************************************************************/
#define IXLV_DRIVER_VERSION_MAJOR	1
#define IXLV_DRIVER_VERSION_MINOR	5
#define IXLV_DRIVER_VERSION_BUILD	4

#define IXLV_DRIVER_VERSION_STRING			\
    __XSTRING(IXLV_DRIVER_VERSION_MAJOR) "."		\
    __XSTRING(IXLV_DRIVER_VERSION_MINOR) "."		\
    __XSTRING(IXLV_DRIVER_VERSION_BUILD) "-iflib-k"

/*********************************************************************
 *  PCI Device ID Table
 *
 *  Used by probe to select devices to load on
 *
 *  ( Vendor ID, Device ID, Branding String )
 *********************************************************************/

static pci_vendor_info_t ixlv_vendor_info_array[] =
{
	PVID(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_VF, "Intel(R) Ethernet Virtual Function 700 Series"),
	PVID(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_X722_VF, "Intel(R) Ethernet Virtual Function 700 Series (X722)"),
	PVID(I40E_INTEL_VENDOR_ID, I40E_DEV_ID_ADAPTIVE_VF, "Intel(R) Ethernet Adaptive Virtual Function"),
	/* required last entry */
	PVID_END
};

/*********************************************************************
 *  Function prototypes
 *********************************************************************/
static void	 *ixlv_register(device_t dev);
static int	 ixlv_if_attach_pre(if_ctx_t ctx);
static int	 ixlv_if_attach_post(if_ctx_t ctx);
static int	 ixlv_if_detach(if_ctx_t ctx);
static int	 ixlv_if_shutdown(if_ctx_t ctx);
static int	 ixlv_if_suspend(if_ctx_t ctx);
static int	 ixlv_if_resume(if_ctx_t ctx);
static int	 ixlv_if_msix_intr_assign(if_ctx_t ctx, int msix);
static void	 ixlv_if_enable_intr(if_ctx_t ctx);
static void	 ixlv_if_disable_intr(if_ctx_t ctx);
static int	 ixlv_if_rx_queue_intr_enable(if_ctx_t ctx, uint16_t rxqid);
static int	 ixlv_if_tx_queue_intr_enable(if_ctx_t ctx, uint16_t txqid);
static int	 ixlv_if_tx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int ntxqs, int ntxqsets);
static int	 ixlv_if_rx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int nqs, int nqsets);
static void	 ixlv_if_queues_free(if_ctx_t ctx);
static void	 ixlv_if_update_admin_status(if_ctx_t ctx);
static void	 ixlv_if_multi_set(if_ctx_t ctx);
static int	 ixlv_if_mtu_set(if_ctx_t ctx, uint32_t mtu);
static void	 ixlv_if_media_status(if_ctx_t ctx, struct ifmediareq *ifmr);
static int	 ixlv_if_media_change(if_ctx_t ctx);
static int	 ixlv_if_promisc_set(if_ctx_t ctx, int flags);
static void	 ixlv_if_timer(if_ctx_t ctx, uint16_t qid);
static void	 ixlv_if_vlan_register(if_ctx_t ctx, u16 vtag);
static void	 ixlv_if_vlan_unregister(if_ctx_t ctx, u16 vtag);
static uint64_t	 ixlv_if_get_counter(if_ctx_t ctx, ift_counter cnt);
static void	 ixlv_if_stop(if_ctx_t ctx);

static int	ixlv_allocate_pci_resources(struct ixlv_sc *);
static int	ixlv_reset_complete(struct i40e_hw *);
static int	ixlv_setup_vc(struct ixlv_sc *);
static int	ixlv_reset(struct ixlv_sc *);
static int	ixlv_vf_config(struct ixlv_sc *);
static void	ixlv_init_filters(struct ixlv_sc *);
static void	ixlv_free_pci_resources(struct ixlv_sc *);
static void	ixlv_free_filters(struct ixlv_sc *);
static void	ixlv_setup_interface(device_t, struct ixlv_sc *);
static void	ixlv_add_sysctls(struct ixlv_sc *);
static void	ixlv_enable_adminq_irq(struct i40e_hw *);
static void	ixlv_disable_adminq_irq(struct i40e_hw *);
static void	ixlv_enable_queue_irq(struct i40e_hw *, int);
static void	ixlv_disable_queue_irq(struct i40e_hw *, int);
static void	ixlv_config_rss(struct ixlv_sc *);
static void	ixlv_stop(struct ixlv_sc *);

static int	ixlv_add_mac_filter(struct ixlv_sc *, u8 *, u16);
static int	ixlv_del_mac_filter(struct ixlv_sc *sc, u8 *macaddr);
static int	ixlv_msix_que(void *);
static int	ixlv_msix_adminq(void *);
static void	ixlv_do_adminq_locked(struct ixlv_sc *sc);
static void	ixl_init_cmd_complete(struct ixl_vc_cmd *, void *,
		    enum i40e_status_code);
static void	ixlv_configure_itr(struct ixlv_sc *);

//static void	ixlv_setup_vlan_filters(struct ixlv_sc *);

static char *ixlv_vc_speed_to_string(enum virtchnl_link_speed link_speed);
static int ixlv_sysctl_current_speed(SYSCTL_HANDLER_ARGS);

// static void	ixlv_add_sysctls(struct ixlv_sc *);
#ifdef IXL_DEBUG
static int 	ixlv_sysctl_qtx_tail_handler(SYSCTL_HANDLER_ARGS);
static int 	ixlv_sysctl_qrx_tail_handler(SYSCTL_HANDLER_ARGS);
#endif

/*********************************************************************
 *  FreeBSD Device Interface Entry Points
 *********************************************************************/

static device_method_t ixlv_methods[] = {
	/* Device interface */
	DEVMETHOD(device_register, ixlv_register),
	DEVMETHOD(device_probe, iflib_device_probe),
	DEVMETHOD(device_attach, iflib_device_attach),
	DEVMETHOD(device_detach, iflib_device_detach),
	DEVMETHOD(device_shutdown, iflib_device_shutdown),
	DEVMETHOD_END
};

static driver_t ixlv_driver = {
	"ixlv", ixlv_methods, sizeof(struct ixlv_sc),
};

devclass_t ixlv_devclass;
DRIVER_MODULE(ixlv, pci, ixlv_driver, ixlv_devclass, 0, 0);
MODULE_PNP_INFO("U32:vendor;U32:device;U32:subvendor;U32:subdevice;U32:revision",
    pci, ixlv, ixlv_vendor_info_array,
        nitems(ixlv_vendor_info_array) - 1);
MODULE_VERSION(ixlv, 3);

MODULE_DEPEND(ixlv, pci, 1, 1, 1);
MODULE_DEPEND(ixlv, ether, 1, 1, 1);
MODULE_DEPEND(ixlv, iflib, 1, 1, 1);

static device_method_t ixlv_if_methods[] = {
	DEVMETHOD(ifdi_attach_pre, ixlv_if_attach_pre),
	DEVMETHOD(ifdi_attach_post, ixlv_if_attach_post),
	DEVMETHOD(ifdi_detach, ixlv_if_detach),
	DEVMETHOD(ifdi_shutdown, ixlv_if_shutdown),
	DEVMETHOD(ifdi_suspend, ixlv_if_suspend),
	DEVMETHOD(ifdi_resume, ixlv_if_resume),
	DEVMETHOD(ifdi_init, ixlv_if_init),
	DEVMETHOD(ifdi_stop, ixlv_if_stop),
	DEVMETHOD(ifdi_msix_intr_assign, ixlv_if_msix_intr_assign),
	DEVMETHOD(ifdi_intr_enable, ixlv_if_enable_intr),
	DEVMETHOD(ifdi_intr_disable, ixlv_if_disable_intr),
	DEVMETHOD(ifdi_rx_queue_intr_enable, ixlv_if_rx_queue_intr_enable),
	DEVMETHOD(ifdi_tx_queue_intr_enable, ixlv_if_tx_queue_intr_enable),
	DEVMETHOD(ifdi_tx_queues_alloc, ixlv_if_tx_queues_alloc),
	DEVMETHOD(ifdi_rx_queues_alloc, ixlv_if_rx_queues_alloc),
	DEVMETHOD(ifdi_queues_free, ixlv_if_queues_free),
	DEVMETHOD(ifdi_update_admin_status, ixlv_if_update_admin_status),
	DEVMETHOD(ifdi_multi_set, ixlv_if_multi_set),
	DEVMETHOD(ifdi_mtu_set, ixlv_if_mtu_set),
	DEVMETHOD(ifdi_media_status, ixlv_if_media_status),
	DEVMETHOD(ifdi_media_change, ixlv_if_media_change),
	DEVMETHOD(ifdi_promisc_set, ixlv_if_promisc_set),
	DEVMETHOD(ifdi_timer, ixlv_if_timer),
	DEVMETHOD(ifdi_vlan_register, ixlv_if_vlan_register),
	DEVMETHOD(ifdi_vlan_unregister, ixlv_if_vlan_unregister),
	DEVMETHOD(ifdi_get_counter, ixlv_if_get_counter),
	DEVMETHOD_END
};

static driver_t ixlv_if_driver = {
	"ixlv_if", ixlv_if_methods, sizeof(struct ixlv_sc)
};

/*
** TUNEABLE PARAMETERS:
*/

static SYSCTL_NODE(_hw, OID_AUTO, ixlv, CTLFLAG_RD, 0,
    "ixlv driver parameters");

/*
 * Different method for processing TX descriptor
 * completion.
 */
static int ixlv_enable_head_writeback = 0;
TUNABLE_INT("hw.ixlv.enable_head_writeback",
    &ixlv_enable_head_writeback);
SYSCTL_INT(_hw_ixlv, OID_AUTO, enable_head_writeback, CTLFLAG_RDTUN,
    &ixlv_enable_head_writeback, 0,
    "For detecting last completed TX descriptor by hardware, use value written by HW instead of checking descriptors");

#if 0
// This should be implemented...
static int ixlv_core_debug_mask = 0;
TUNABLE_INT("hw.ixlv.core_debug_mask",
    &ixl_core_debug_mask);
SYSCTL_INT(_hw_ixlv, OID_AUTO, core_debug_mask, CTLFLAG_RDTUN,
    &ixlv_core_debug_mask, 0,
    "Display debug statements that are printed in non-shared code");

static int ixlv_shared_debug_mask = 0;
TUNABLE_INT("hw.ixlv.shared_debug_mask",
    &ixlv_shared_debug_mask);
SYSCTL_INT(_hw_ixlv, OID_AUTO, shared_debug_mask, CTLFLAG_RDTUN,
    &ixlv_shared_debug_mask, 0,
    "Display debug statements that are printed in shared code");

/*
** Controls for Interrupt Throttling
**      - true/false for dynamic adjustment
**      - default values for static ITR
*/
int ixlv_dynamic_rx_itr = 0;
TUNABLE_INT("hw.ixlv.dynamic_rx_itr", &ixlv_dynamic_rx_itr);
SYSCTL_INT(_hw_ixlv, OID_AUTO, dynamic_rx_itr, CTLFLAG_RDTUN,
    &ixlv_dynamic_rx_itr, 0, "Dynamic RX Interrupt Rate");

int ixlv_dynamic_tx_itr = 0;
TUNABLE_INT("hw.ixlv.dynamic_tx_itr", &ixlv_dynamic_tx_itr);
SYSCTL_INT(_hw_ixlv, OID_AUTO, dynamic_tx_itr, CTLFLAG_RDTUN,
    &ixlv_dynamic_tx_itr, 0, "Dynamic TX Interrupt Rate");
#endif

int ixlv_rx_itr = IXL_ITR_8K;
TUNABLE_INT("hw.ixlv.rx_itr", &ixlv_rx_itr);
SYSCTL_INT(_hw_ixlv, OID_AUTO, rx_itr, CTLFLAG_RDTUN,
    &ixlv_rx_itr, 0, "RX Interrupt Rate");

int ixlv_tx_itr = IXL_ITR_4K;
TUNABLE_INT("hw.ixlv.tx_itr", &ixlv_tx_itr);
SYSCTL_INT(_hw_ixlv, OID_AUTO, tx_itr, CTLFLAG_RDTUN,
    &ixlv_tx_itr, 0, "TX Interrupt Rate");

extern struct if_txrx ixl_txrx_hwb;
extern struct if_txrx ixl_txrx_dwb;

static struct if_shared_ctx ixlv_sctx_init = {
	.isc_magic = IFLIB_MAGIC,
	.isc_q_align = PAGE_SIZE,/* max(DBA_ALIGN, PAGE_SIZE) */
	.isc_tx_maxsize = IXL_TSO_SIZE + sizeof(struct ether_vlan_header),
	.isc_tx_maxsegsize = PAGE_SIZE,
	.isc_tso_maxsize = IXL_TSO_SIZE + sizeof(struct ether_vlan_header),
	.isc_tso_maxsegsize = PAGE_SIZE,
	.isc_rx_maxsize = 16384,
	.isc_rx_nsegments = IXL_MAX_RX_SEGS,
	.isc_rx_maxsegsize = IXL_MAX_DMA_SEG_SIZE,
	.isc_nfl = 1,
	.isc_ntxqs = 1,
	.isc_nrxqs = 1,

	.isc_admin_intrcnt = 1,
	.isc_vendor_info = ixlv_vendor_info_array,
	.isc_driver_version = IXLV_DRIVER_VERSION_STRING,
	.isc_driver = &ixlv_if_driver,
	// TODO: VF driver may not need IFLIB_ADMIN_ALWAYS_RUN
	.isc_flags = IFLIB_NEED_SCRATCH | IFLIB_NEED_ZERO_CSUM,

	.isc_nrxd_min = {IXL_MIN_RING},
	.isc_ntxd_min = {IXL_MIN_RING},
	.isc_nrxd_max = {IXL_MAX_RING},
	.isc_ntxd_max = {IXL_MAX_RING},
	.isc_nrxd_default = {IXL_DEFAULT_RING},
	.isc_ntxd_default = {IXL_DEFAULT_RING},
};

if_shared_ctx_t ixlv_sctx = &ixlv_sctx_init;

/*** Functions ***/
static void *
ixlv_register(device_t dev)
{
	return (ixlv_sctx);
}

static int
ixlv_allocate_pci_resources(struct ixlv_sc *sc)
{
	struct i40e_hw *hw = &sc->hw;
	device_t dev = iflib_get_dev(sc->vsi.ctx);
	int             rid;

	/* Map BAR0 */
	rid = PCIR_BAR(0);
	sc->pci_mem = bus_alloc_resource_any(dev, SYS_RES_MEMORY,
	    &rid, RF_ACTIVE);

	if (!(sc->pci_mem)) {
		device_printf(dev, "Unable to allocate bus resource: PCI memory\n");
		return (ENXIO);
 	}
 
	/* Save off the PCI information */
	hw->vendor_id = pci_get_vendor(dev);
	hw->device_id = pci_get_device(dev);
	hw->revision_id = pci_read_config(dev, PCIR_REVID, 1);
	hw->subsystem_vendor_id =
	    pci_read_config(dev, PCIR_SUBVEND_0, 2);
	hw->subsystem_device_id =
	    pci_read_config(dev, PCIR_SUBDEV_0, 2);

	hw->bus.device = pci_get_slot(dev);
	hw->bus.func = pci_get_function(dev);

	/* Save off register access information */
	sc->osdep.mem_bus_space_tag =
		rman_get_bustag(sc->pci_mem);
	sc->osdep.mem_bus_space_handle =
		rman_get_bushandle(sc->pci_mem);
	sc->osdep.mem_bus_space_size = rman_get_size(sc->pci_mem);
	sc->osdep.flush_reg = I40E_VFGEN_RSTAT;
	sc->osdep.dev = dev;

	sc->hw.hw_addr = (u8 *) &sc->osdep.mem_bus_space_handle;
	sc->hw.back = &sc->osdep;

 	return (0);
}

static int
ixlv_if_attach_pre(if_ctx_t ctx)
{
	device_t dev;
	struct ixlv_sc *sc;
	struct i40e_hw *hw;
	struct ixl_vsi *vsi;
	if_softc_ctx_t scctx;
	int error = 0;

	INIT_DBG_DEV(dev, "begin");

	dev = iflib_get_dev(ctx);
	sc = iflib_get_softc(ctx);

	vsi = &sc->vsi;
	vsi->back = sc;
	sc->dev = dev;
	hw = &sc->hw;

	vsi->dev = dev;
	vsi->hw = &sc->hw;
	//vsi->id = 0;
	vsi->num_vlans = 0;
	vsi->ctx = ctx;
	vsi->media = iflib_get_media(ctx);
	vsi->shared = scctx = iflib_get_softc_ctx(ctx);

	/* Save this tunable */
	vsi->enable_head_writeback = !!(ixlv_enable_head_writeback);

	/* Do PCI setup - map BAR0, etc */
	if (ixlv_allocate_pci_resources(sc)) {
		device_printf(dev, "%s: Allocation of PCI resources failed\n",
		    __func__);
		error = ENXIO;
		goto err_early;
	}

	INIT_DBG_DEV(dev, "Allocated PCI resources and MSIX vectors");

	/*
	 * XXX: This is called by init_shared_code in the PF driver,
	 * but the rest of that function does not support VFs.
	 */
	error = i40e_set_mac_type(hw);
	if (error) {
		device_printf(dev, "%s: set_mac_type failed: %d\n",
		    __func__, error);
		goto err_pci_res;
	}

	error = ixlv_reset_complete(hw);
	if (error) {
		device_printf(dev, "%s: Device is still being reset\n",
		    __func__);
		goto err_pci_res;
	}

	INIT_DBG_DEV(dev, "VF Device is ready for configuration");

	/* Sets up Admin Queue */
	error = ixlv_setup_vc(sc);
	if (error) {
		device_printf(dev, "%s: Error setting up PF comms, %d\n",
		    __func__, error);
		goto err_pci_res;
	}

	INIT_DBG_DEV(dev, "PF API version verified");

	/* Need API version before sending reset message */
	error = ixlv_reset(sc);
	if (error) {
		device_printf(dev, "VF reset failed; reload the driver\n");
		goto err_aq;
	}

	INIT_DBG_DEV(dev, "VF reset complete");

	/* Ask for VF config from PF */
	error = ixlv_vf_config(sc);
	if (error) {
		device_printf(dev, "Error getting configuration from PF: %d\n",
		    error);
		goto err_aq;
	}

	device_printf(dev, "VSIs %d, QPs %d, MSIX %d, RSS sizes: key %d lut %d\n",
	    sc->vf_res->num_vsis,
	    sc->vf_res->num_queue_pairs,
	    sc->vf_res->max_vectors,
	    sc->vf_res->rss_key_size,
	    sc->vf_res->rss_lut_size);
#ifdef IXL_DEBUG
	device_printf(dev, "Offload flags: 0x%b\n",
	    sc->vf_res->vf_offload_flags, IXLV_PRINTF_VF_OFFLOAD_FLAGS);
#endif

	/* got VF config message back from PF, now we can parse it */
	for (int i = 0; i < sc->vf_res->num_vsis; i++) {
		if (sc->vf_res->vsi_res[i].vsi_type == I40E_VSI_SRIOV)
			sc->vsi_res = &sc->vf_res->vsi_res[i];
	}
	if (!sc->vsi_res) {
		device_printf(dev, "%s: no LAN VSI found\n", __func__);
		error = EIO;
		goto err_res_buf;
	}
	vsi->id = sc->vsi_res->vsi_id;

	INIT_DBG_DEV(dev, "Resource Acquisition complete");

	/* If no mac address was assigned just make a random one */
	// TODO: What if the PF doesn't allow us to set our own MAC?
	if (!ixlv_check_ether_addr(hw->mac.addr)) {
		u8 addr[ETHER_ADDR_LEN];
		arc4rand(&addr, sizeof(addr), 0);
		addr[0] &= 0xFE;
		addr[0] |= 0x02;
		bcopy(addr, hw->mac.addr, sizeof(addr));
	}
	bcopy(hw->mac.addr, hw->mac.perm_addr, ETHER_ADDR_LEN);
	iflib_set_mac(ctx, hw->mac.addr);

	/* Allocate filter lists */
	ixlv_init_filters(sc);

	/* Fill out more iflib parameters */
	// TODO: This needs to be set to configured "num-queues" value
	// from iovctl.conf
	scctx->isc_ntxqsets_max = scctx->isc_nrxqsets_max = 16;
	if (vsi->enable_head_writeback) {
		scctx->isc_txqsizes[0] = roundup2(scctx->isc_ntxd[0]
		    * sizeof(struct i40e_tx_desc) + sizeof(u32), DBA_ALIGN);
		scctx->isc_txrx = &ixl_txrx_hwb;
	} else {
		scctx->isc_txqsizes[0] = roundup2(scctx->isc_ntxd[0]
		    * sizeof(struct i40e_tx_desc), DBA_ALIGN);
		scctx->isc_txrx = &ixl_txrx_dwb;
	}
	scctx->isc_rxqsizes[0] = roundup2(scctx->isc_nrxd[0]
	    * sizeof(union i40e_32byte_rx_desc), DBA_ALIGN);
	scctx->isc_msix_bar = PCIR_BAR(IXL_MSIX_BAR);
	scctx->isc_tx_nsegments = IXL_MAX_TX_SEGS;
	scctx->isc_tx_tso_segments_max = IXL_MAX_TSO_SEGS;
	scctx->isc_tx_tso_size_max = IXL_TSO_SIZE;
	scctx->isc_tx_tso_segsize_max = IXL_MAX_DMA_SEG_SIZE;
	// TODO: Probably needs changing
	scctx->isc_rss_table_size = sc->hw.func_caps.rss_table_size;
	scctx->isc_tx_csum_flags = CSUM_OFFLOAD;
	scctx->isc_capabilities = scctx->isc_capenable = IXL_CAPS;

	return (0);

err_res_buf:
	free(sc->vf_res, M_DEVBUF);
err_aq:
	i40e_shutdown_adminq(hw);
err_pci_res:
	ixlv_free_pci_resources(sc);
err_early:
	return (error);
}

static int
ixlv_if_attach_post(if_ctx_t ctx)
{
	device_t dev;
	struct ixlv_sc	*sc;
	struct i40e_hw	*hw;
	struct ixl_vsi *vsi;
	int error = 0;

	INIT_DBG_DEV(dev, "begin");

	dev = iflib_get_dev(ctx);
	sc = iflib_get_softc(ctx);
	vsi = &sc->vsi;
	vsi->ifp = iflib_get_ifp(ctx);
	hw = &sc->hw;

	/* Save off determined number of queues for interface */
	vsi->num_rx_queues = vsi->shared->isc_nrxqsets;
	vsi->num_tx_queues = vsi->shared->isc_ntxqsets;

	/* Setup the stack interface */
	ixlv_setup_interface(dev, sc);

	INIT_DBG_DEV(dev, "Interface setup complete");

	/* Initialize statistics & add sysctls */
	bzero(&sc->vsi.eth_stats, sizeof(struct i40e_eth_stats));
	ixlv_add_sysctls(sc);

	ixl_vc_init_mgr(sc, &sc->vc_mgr);

	/* We want AQ enabled early */
	ixlv_enable_adminq_irq(hw);
	INIT_DBG_DEV(dev, "end");
	return (error);
// TODO: Check if any failures can happen above
#if 0
out:
	free(sc->vf_res, M_DEVBUF);
	i40e_shutdown_adminq(hw);
	ixlv_free_pci_resources(sc);
	ixlv_free_filters(sc);
	INIT_DBG_DEV(dev, "end: error %d", error);
	return (error);
#endif
}

/**
 * XXX: iflib always ignores the return value of detach()
 * -> This means that this isn't allowed to fail
 */
static int
ixlv_if_detach(if_ctx_t ctx)
{
	struct ixlv_sc *sc = iflib_get_softc(ctx);
	struct ixl_vsi *vsi = &sc->vsi;
	struct i40e_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	enum i40e_status_code status;

	INIT_DBG_DEV(dev, "begin");

	/* Remove all the media and link information */
	ifmedia_removeall(vsi->media);

	/* Drain VC mgr */
	callout_drain(&sc->vc_mgr.callout);

	ixlv_disable_adminq_irq(hw);
	status = i40e_shutdown_adminq(&sc->hw);
	if (status != I40E_SUCCESS) {
		device_printf(dev,
		    "i40e_shutdown_adminq() failed with status %s\n",
		    i40e_stat_str(hw, status));
	}

	free(sc->vf_res, M_DEVBUF);
	ixlv_free_pci_resources(sc);
	ixlv_free_filters(sc);

	INIT_DBG_DEV(dev, "end");
	return (0);
}

static int
ixlv_if_shutdown(if_ctx_t ctx)
{
	int error = 0;

	return (error);
}

/* TODO: What is a VF supposed to do in suspend/resume? */
static int
ixlv_if_suspend(if_ctx_t ctx)
{
	int error = 0;

	return (error);
}

static int
ixlv_if_resume(if_ctx_t ctx)
{
	/* Read & clear wake-up registers */

	return (0);
}

/*
** To do a reinit on the VF is unfortunately more complicated
** than a physical device, we must have the PF more or less
** completely recreate our memory, so many things that were
** done only once at attach in traditional drivers now must be
** redone at each reinitialization. This function does that
** 'prelude' so we can then call the normal locked init code.
*/
int
ixlv_reinit_locked(struct ixlv_sc *sc)
{
	struct i40e_hw		*hw = &sc->hw;
	struct ixl_vsi		*vsi = &sc->vsi;
	struct ifnet		*ifp = vsi->ifp;
	struct ixlv_mac_filter  *mf, *mf_temp;
	struct ixlv_vlan_filter	*vf;
	int			error = 0;

	INIT_DBG_IF(ifp, "begin");

	if (ifp->if_drv_flags & IFF_DRV_RUNNING)
		ixlv_stop(sc);

	error = ixlv_reset(sc);

	INIT_DBG_IF(ifp, "VF was reset");

	/* set the state in case we went thru RESET */
	sc->init_state = IXLV_RUNNING;

	/*
	** Resetting the VF drops all filters from hardware;
	** we need to mark them to be re-added in init.
	*/
	SLIST_FOREACH_SAFE(mf, sc->mac_filters, next, mf_temp) {
		if (mf->flags & IXL_FILTER_DEL) {
			SLIST_REMOVE(sc->mac_filters, mf,
			    ixlv_mac_filter, next);
			free(mf, M_DEVBUF);
		} else
			mf->flags |= IXL_FILTER_ADD;
	}
	if (vsi->num_vlans != 0)
		SLIST_FOREACH(vf, sc->vlan_filters, next)
			vf->flags = IXL_FILTER_ADD;
	else { /* clean any stale filters */
		while (!SLIST_EMPTY(sc->vlan_filters)) {
			vf = SLIST_FIRST(sc->vlan_filters);
			SLIST_REMOVE_HEAD(sc->vlan_filters, next);
			free(vf, M_DEVBUF);
		}
	}

	ixlv_enable_adminq_irq(hw);
	return (error);
}

int
ixlv_send_vc_msg(struct ixlv_sc *sc, u32 op)
{
	int error = 0;

	error = ixl_vc_send_cmd(sc, op);
	if (error != 0)
		ixlv_dbg_vc(sc, "Error sending %b: %d\n", op, IXLV_FLAGS, error);

	return (error);
}

static void
ixl_init_cmd_complete(struct ixl_vc_cmd *cmd, void *arg,
	enum i40e_status_code code)
{
	struct ixlv_sc *sc;

	sc = arg;

	/*
	 * Ignore "Adapter Stopped" message as that happens if an ifconfig down
	 * happens while a command is in progress, so we don't print an error
	 * in that case.
	 */
	if (code != I40E_SUCCESS && code != I40E_ERR_ADAPTER_STOPPED) {
		if_printf(sc->vsi.ifp,
		    "Error %s waiting for PF to complete operation %d\n",
		    i40e_stat_str(&sc->hw, code), cmd->request);
	}
}

void
ixlv_if_init(if_ctx_t ctx)
{
	struct ixlv_sc *sc = iflib_get_softc(ctx);
	struct ixl_vsi *vsi = &sc->vsi;
	if_softc_ctx_t scctx = vsi->shared;
	struct i40e_hw *hw = &sc->hw;
	struct ifnet *ifp = iflib_get_ifp(ctx);
	struct ixl_tx_queue *tx_que = vsi->tx_queues;
	struct ixl_rx_queue *rx_que = vsi->rx_queues;
	int error = 0;

	INIT_DBG_IF(ifp, "begin");
	MPASS(sc->vc_mgr.sc == sc);

	/* Do a reinit first if an init has already been done */
	if ((sc->init_state == IXLV_RUNNING) ||
	    (sc->init_state == IXLV_RESET_REQUIRED) ||
	    (sc->init_state == IXLV_RESET_PENDING))
		error = ixlv_reinit_locked(sc);
	/* Don't bother with init if we failed reinit */
	if (error)
		goto init_done;

	/* Remove existing MAC filter if new MAC addr is set */
	if (bcmp(IF_LLADDR(ifp), hw->mac.addr, ETHER_ADDR_LEN) != 0) {
		error = ixlv_del_mac_filter(sc, hw->mac.addr);
		if (error == 0)
			ixlv_send_vc_msg(sc, IXLV_FLAG_AQ_DEL_MAC_FILTER);

		bcopy(tmpaddr, hw->mac.addr, ETH_ALEN);
	}

	error = ixlv_add_mac_filter(sc, hw->mac.addr, 0);
	if (!error || error == EEXIST)
		ixlv_send_vc_msg(sc, IXLV_FLAG_AQ_ADD_MAC_FILTER);
	iflib_set_mac(ctx, hw->mac.addr);

	/* Setup vlan's if needed */
	// ixlv_setup_vlan_filters(sc);

	// TODO: Functionize
	/* Prepare the queues for operation */
	for (int i = 0; i < vsi->num_tx_queues; i++, tx_que++) {
		// TODO: Necessary? Correct?
		ixl_init_tx_ring(vsi, tx_que);
	}
	for (int i = 0; i < vsi->num_rx_queues; i++, rx_que++) {
		struct rx_ring 		*rxr = &rx_que->rxr;

		if (scctx->isc_max_frame_size <= MCLBYTES)
			rxr->mbuf_sz = MCLBYTES;
		else
			rxr->mbuf_sz = MJUMPAGESIZE;
	}

	/* Set initial ITR values */
	ixlv_configure_itr(sc);

	ixlv_send_vc_msg(sc, IXLV_FLAG_AQ_CONFIGURE_QUEUES);

	/* Set up RSS */
	ixlv_config_rss(sc);

	/* Map vectors */
	ixlv_send_vc_msg(sc, IXLV_FLAG_AQ_MAP_VECTORS);

	/* Configure promiscuous mode */
	ixlv_if_promisc_set(ctx, if_getflags(ifp));

	/* Enable queues */
	ixlv_send_vc_msg(sc, IXLV_FLAG_AQ_ENABLE_QUEUES);

	sc->init_state = IXLV_RUNNING;

init_done:
	INIT_DBG_IF(ifp, "end");
	return;
}

/*
 * ixlv_attach() helper function; initalizes the admin queue
 * and attempts to establish contact with the PF by
 * retrying the initial "API version" message several times
 * or until the PF responds.
 */
static int
ixlv_setup_vc(struct ixlv_sc *sc)
{
	struct i40e_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	int error = 0, ret_error = 0, asq_retries = 0;
	bool send_api_ver_retried = 0;

	/* Need to set these AQ paramters before initializing AQ */
	hw->aq.num_arq_entries = IXL_AQ_LEN;
	hw->aq.num_asq_entries = IXL_AQ_LEN;
	hw->aq.arq_buf_size = IXL_AQ_BUF_SZ;
	hw->aq.asq_buf_size = IXL_AQ_BUF_SZ;

	for (int i = 0; i < IXLV_AQ_MAX_ERR; i++) {
		/* Initialize admin queue */
		error = i40e_init_adminq(hw);
		if (error) {
			device_printf(dev, "%s: init_adminq failed: %d\n",
			    __func__, error);
			ret_error = 1;
			continue;
		}

		INIT_DBG_DEV(dev, "Initialized Admin Queue; starting"
		    " send_api_ver attempt %d", i+1);

retry_send:
		/* Send VF's API version */
		error = ixlv_send_api_ver(sc);
		if (error) {
			i40e_shutdown_adminq(hw);
			ret_error = 2;
			device_printf(dev, "%s: unable to send api"
			    " version to PF on attempt %d, error %d\n",
			    __func__, i+1, error);
		}

		asq_retries = 0;
		while (!i40e_asq_done(hw)) {
			if (++asq_retries > IXLV_AQ_MAX_ERR) {
				i40e_shutdown_adminq(hw);
				device_printf(dev, "Admin Queue timeout "
				    "(waiting for send_api_ver), %d more tries...\n",
				    IXLV_AQ_MAX_ERR - (i + 1));
				ret_error = 3;
				break;
			} 
			i40e_msec_pause(10);
		}
		if (asq_retries > IXLV_AQ_MAX_ERR)
			continue;

		INIT_DBG_DEV(dev, "Sent API version message to PF");

		/* Verify that the VF accepts the PF's API version */
		error = ixlv_verify_api_ver(sc);
		if (error == ETIMEDOUT) {
			if (!send_api_ver_retried) {
				/* Resend message, one more time */
				send_api_ver_retried = true;
				device_printf(dev,
				    "%s: Timeout while verifying API version on first"
				    " try!\n", __func__);
				goto retry_send;
			} else {
				device_printf(dev,
				    "%s: Timeout while verifying API version on second"
				    " try!\n", __func__);
				ret_error = 4;
				break;
			}
		}
		if (error) {
			device_printf(dev,
			    "%s: Unable to verify API version,"
			    " error %s\n", __func__, i40e_stat_str(hw, error));
			ret_error = 5;
		}
		break;
	}

	if (ret_error >= 4)
		i40e_shutdown_adminq(hw);
	return (ret_error);
}

/*
 * ixlv_attach() helper function; asks the PF for this VF's
 * configuration, and saves the information if it receives it.
 */
static int
ixlv_vf_config(struct ixlv_sc *sc)
{
	struct i40e_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	int bufsz, error = 0, ret_error = 0;
	int asq_retries, retried = 0;

retry_config:
	error = ixlv_send_vf_config_msg(sc);
	if (error) {
		device_printf(dev,
		    "%s: Unable to send VF config request, attempt %d,"
		    " error %d\n", __func__, retried + 1, error);
		ret_error = 2;
	}

	asq_retries = 0;
	while (!i40e_asq_done(hw)) {
		if (++asq_retries > IXLV_AQ_MAX_ERR) {
			device_printf(dev, "%s: Admin Queue timeout "
			    "(waiting for send_vf_config_msg), attempt %d\n",
			    __func__, retried + 1);
			ret_error = 3;
			goto fail;
		}
		i40e_msec_pause(10);
	}

	INIT_DBG_DEV(dev, "Sent VF config message to PF, attempt %d",
	    retried + 1);

	if (!sc->vf_res) {
		bufsz = sizeof(struct virtchnl_vf_resource) +
		    (I40E_MAX_VF_VSI * sizeof(struct virtchnl_vsi_resource));
		sc->vf_res = malloc(bufsz, M_DEVBUF, M_NOWAIT);
		if (!sc->vf_res) {
			device_printf(dev,
			    "%s: Unable to allocate memory for VF configuration"
			    " message from PF on attempt %d\n", __func__, retried + 1);
			ret_error = 1;
			goto fail;
		}
	}

	/* Check for VF config response */
	error = ixlv_get_vf_config(sc);
	if (error == ETIMEDOUT) {
		/* The 1st time we timeout, send the configuration message again */
		if (!retried) {
			retried++;
			goto retry_config;
		}
		device_printf(dev,
		    "%s: ixlv_get_vf_config() timed out waiting for a response\n",
		    __func__);
	}
	if (error) {
		device_printf(dev,
		    "%s: Unable to get VF configuration from PF after %d tries!\n",
		    __func__, retried + 1);
		ret_error = 4;
	}
	goto done;

fail:
	free(sc->vf_res, M_DEVBUF);
done:
	return (ret_error);
}

static int
ixlv_if_msix_intr_assign(if_ctx_t ctx, int msix)
{
	struct ixlv_sc *sc = iflib_get_softc(ctx);
	struct ixl_vsi *vsi = &sc->vsi;
	struct ixl_rx_queue *rx_que = vsi->rx_queues;
	struct ixl_tx_queue *tx_que = vsi->tx_queues;
	int err, i, rid, vector = 0;
	char buf[16];

	MPASS(vsi->shared->isc_nrxqsets > 0);
	MPASS(vsi->shared->isc_ntxqsets > 0);

	/* Admin Que is vector 0*/
	rid = vector + 1;
	err = iflib_irq_alloc_generic(ctx, &vsi->irq, rid, IFLIB_INTR_ADMIN,
	    ixlv_msix_adminq, sc, 0, "aq");
	if (err) {
		iflib_irq_free(ctx, &vsi->irq);
		device_printf(iflib_get_dev(ctx),
		    "Failed to register Admin Que handler");
		return (err);
	}

	/* Now set up the stations */
	for (i = 0, vector = 1; i < vsi->shared->isc_nrxqsets; i++, vector++, rx_que++) {
		rid = vector + 1;

		snprintf(buf, sizeof(buf), "rxq%d", i);
		err = iflib_irq_alloc_generic(ctx, &rx_que->que_irq, rid,
		    IFLIB_INTR_RX, ixlv_msix_que, rx_que, rx_que->rxr.me, buf);
		/* XXX: Does the driver work as expected if there are fewer num_rx_queues than
		 * what's expected in the iflib context? */
		if (err) {
			device_printf(iflib_get_dev(ctx),
			    "Failed to allocate queue RX int vector %d, err: %d\n", i, err);
			vsi->num_rx_queues = i + 1;
			goto fail;
		}
		rx_que->msix = vector;
	}

	bzero(buf, sizeof(buf));

	for (i = 0; i < vsi->shared->isc_ntxqsets; i++, tx_que++) {
		snprintf(buf, sizeof(buf), "txq%d", i);
		iflib_softirq_alloc_generic(ctx,
		    &vsi->rx_queues[i % vsi->shared->isc_nrxqsets].que_irq,
		    IFLIB_INTR_TX, tx_que, tx_que->txr.me, buf);

		/* TODO: Maybe call a strategy function for this to figure out which
		* interrupts to map Tx queues to. I don't know if there's an immediately
		* better way than this other than a user-supplied map, though. */
		tx_que->msix = (i % vsi->shared->isc_nrxqsets) + 1;
	}

	return (0);
fail:
	iflib_irq_free(ctx, &vsi->irq);
	rx_que = vsi->rx_queues;
	for (int i = 0; i < vsi->num_rx_queues; i++, rx_que++)
		iflib_irq_free(ctx, &rx_que->que_irq);
	return (err);
}

/* Enable all interrupts */
static void
ixlv_if_enable_intr(if_ctx_t ctx)
{
	struct ixlv_sc *sc = iflib_get_softc(ctx);
	struct ixl_vsi *vsi = &sc->vsi;

	ixlv_enable_intr(vsi);
}

/* Disable all interrupts */
static void
ixlv_if_disable_intr(if_ctx_t ctx)
{
	struct ixlv_sc *sc = iflib_get_softc(ctx);
	struct ixl_vsi *vsi = &sc->vsi;

	ixlv_disable_intr(vsi);
}

static int
ixlv_if_rx_queue_intr_enable(if_ctx_t ctx, uint16_t rxqid)
{
	struct ixlv_sc *sc = iflib_get_softc(ctx);
	struct ixl_vsi *vsi = &sc->vsi;
	struct i40e_hw *hw = vsi->hw;
	struct ixl_rx_queue *rx_que = &vsi->rx_queues[rxqid];

	ixlv_enable_queue_irq(hw, rx_que->msix - 1);
	return (0);
}

static int
ixlv_if_tx_queue_intr_enable(if_ctx_t ctx, uint16_t txqid)
{
	struct ixlv_sc *sc = iflib_get_softc(ctx);
	struct ixl_vsi *vsi = &sc->vsi;
	struct i40e_hw *hw = vsi->hw;
	struct ixl_tx_queue *tx_que = &vsi->tx_queues[txqid];

	ixlv_enable_queue_irq(hw, tx_que->msix - 1);
	return (0);
}

static int
ixlv_if_tx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int ntxqs, int ntxqsets)
{
	struct ixlv_sc *sc = iflib_get_softc(ctx);
	struct ixl_vsi *vsi = &sc->vsi;
	if_softc_ctx_t scctx = vsi->shared;
	struct ixl_tx_queue *que;
	int i, j, error = 0;

	MPASS(scctx->isc_ntxqsets > 0);
	MPASS(ntxqs == 1);
	MPASS(scctx->isc_ntxqsets == ntxqsets);

	/* Allocate queue structure memory */
	if (!(vsi->tx_queues =
	    (struct ixl_tx_queue *) malloc(sizeof(struct ixl_tx_queue) *ntxqsets, M_IXLV, M_NOWAIT | M_ZERO))) {
		device_printf(iflib_get_dev(ctx), "Unable to allocate TX ring memory\n");
		return (ENOMEM);
	}

	for (i = 0, que = vsi->tx_queues; i < ntxqsets; i++, que++) {
		struct tx_ring *txr = &que->txr;

		txr->me = i;
		que->vsi = vsi;

		if (!vsi->enable_head_writeback) {
			/* Allocate report status array */
			if (!(txr->tx_rsq = malloc(sizeof(qidx_t) * scctx->isc_ntxd[0], M_IXLV, M_NOWAIT))) {
				device_printf(iflib_get_dev(ctx), "failed to allocate tx_rsq memory\n");
				error = ENOMEM;
				goto fail;
			}
			/* Init report status array */
			for (j = 0; j < scctx->isc_ntxd[0]; j++)
				txr->tx_rsq[j] = QIDX_INVALID;
		}
		/* get the virtual and physical address of the hardware queues */
		txr->tail = I40E_QTX_TAIL1(txr->me);
		txr->tx_base = (struct i40e_tx_desc *)vaddrs[i * ntxqs];
		txr->tx_paddr = paddrs[i * ntxqs];
		txr->que = que;
	}

	return (0);
fail:
	ixlv_if_queues_free(ctx);
	return (error);
}

static int
ixlv_if_rx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int nrxqs, int nrxqsets)
{
	struct ixlv_sc *sc = iflib_get_softc(ctx);
	struct ixl_vsi *vsi = &sc->vsi;
	struct ixl_rx_queue *que;
	int i, error = 0;

	MPASS(scctx->isc_nrxqsets > 0);
	MPASS(nrxqs == 1);
	MPASS(scctx->isc_nrxqsets == nrxqsets);

	/* Allocate queue structure memory */
	if (!(vsi->rx_queues =
	    (struct ixl_rx_queue *) malloc(sizeof(struct ixl_rx_queue) *
	    nrxqsets, M_IXLV, M_NOWAIT | M_ZERO))) {
		device_printf(iflib_get_dev(ctx), "Unable to allocate RX ring memory\n");
		error = ENOMEM;
		goto fail;
	}

	for (i = 0, que = vsi->rx_queues; i < nrxqsets; i++, que++) {
		struct rx_ring *rxr = &que->rxr;

		rxr->me = i;
		que->vsi = vsi;

		/* get the virtual and physical address of the hardware queues */
		rxr->tail = I40E_QRX_TAIL1(rxr->me);
		rxr->rx_base = (union i40e_rx_desc *)vaddrs[i * nrxqs];
		rxr->rx_paddr = paddrs[i * nrxqs];
		rxr->que = que;
	}

	return (0);
fail:
	ixlv_if_queues_free(ctx);
	return (error);
}

static void
ixlv_if_queues_free(if_ctx_t ctx)
{
	struct ixlv_sc *sc = iflib_get_softc(ctx);
	struct ixl_vsi *vsi = &sc->vsi;

	if (vsi->enable_head_writeback) {
		struct ixl_tx_queue *que;
		int i = 0;

		for (i = 0, que = vsi->tx_queues; i < vsi->num_tx_queues; i++, que++) {
			struct tx_ring *txr = &que->txr;
			if (txr->tx_rsq != NULL) {
				free(txr->tx_rsq, M_IXLV);
				txr->tx_rsq = NULL;
			}
		}
	}

	if (vsi->tx_queues != NULL) {
		free(vsi->tx_queues, M_IXLV);
		vsi->tx_queues = NULL;
	}
	if (vsi->rx_queues != NULL) {
		free(vsi->rx_queues, M_IXLV);
		vsi->rx_queues = NULL;
	}
}

// TODO: Implement
static void
ixlv_if_update_admin_status(if_ctx_t ctx)
{
	struct ixlv_sc *sc = iflib_get_softc(ctx);
	struct ixl_vsi *vsi = &sc->vsi;
	//struct ixlv_sc			*sc = vsi->back; 
	//struct i40e_hw			*hw = &sc->hw;
	//struct i40e_arq_event_info	event;
	//i40e_status			ret;
	//u32				loop = 0;
	//u16				opcode
	u16				result = 0;
	//u64				baudrate;

	/* TODO: Split up
	 * - Update admin queue stuff
	 * - Update link status
	 * - Enqueue aq task
	 * - Re-enable admin intr
	 */

/* TODO: Does VF reset need to be handled here? */
#if 0
	if (pf->state & IXL_PF_STATE_EMPR_RESETTING) {
		/* Flag cleared at end of this function */
		ixl_handle_empr_reset(pf);
		return;
	}
#endif

#if 0
	event.buf_len = IXL_AQ_BUF_SZ;
	event.msg_buf = malloc(event.buf_len,
	    M_IXLV, M_NOWAIT | M_ZERO);
	if (!event.msg_buf) {
		device_printf(pf->dev, "%s: Unable to allocate memory for Admin"
		    " Queue event!\n", __func__);
		return;
	}

	/* clean and process any events */
	do {
		ret = i40e_clean_arq_element(hw, &event, &result);
		if (ret)
			break;
		opcode = LE16_TO_CPU(event.desc.opcode);
		ixl_dbg(pf, IXL_DBG_AQ,
		    "Admin Queue event: %#06x\n", opcode);
		switch (opcode) {
		case i40e_aqc_opc_get_link_status:
			ixl_link_event(pf, &event);
			break;
		case i40e_aqc_opc_send_msg_to_pf:
#ifdef PCI_IOV
			ixl_handle_vf_msg(pf, &event);
#endif
			break;
		case i40e_aqc_opc_event_lan_overflow:
			break;
		default:
#ifdef IXL_DEBUG
			printf("AdminQ unknown event %x\n", opcode);
#endif
			break;
		}

	} while (result && (loop++ < IXL_ADM_LIMIT));

	free(event.msg_buf, M_IXLV);
#endif

	/*
	 * If there are still messages to process, reschedule ourselves.
	 * Otherwise, re-enable our interrupt and go to sleep.
	 */
	if (result > 0)
		iflib_admin_intr_deferred(ctx);
	else
		/* TODO: Link/adminq interrupt should be re-enabled in IFDI_LINK_INTR_ENABLE */
		ixlv_enable_intr(vsi);
}

static void
ixlv_if_multi_set(if_ctx_t ctx)
{
	// struct ixlv_sc *sc = iflib_get_softc(ctx);
	// struct ixl_vsi *vsi = &sc->vsi;
	// struct i40e_hw		*hw = vsi->hw;
	// int			mcnt = 0, flags;

	IOCTL_DEBUGOUT("ixl_if_multi_set: begin");

	// TODO: Implement
#if 0
	mcnt = if_multiaddr_count(iflib_get_ifp(ctx), MAX_MULTICAST_ADDR);
	/* delete existing MC filters */
	ixlv_del_multi(vsi);

	if (__predict_false(mcnt == MAX_MULTICAST_ADDR)) {
		// Set promiscuous mode (multicast)
		// TODO: This needs to get handled somehow
#if 0
		ixl_vc_enqueue(&sc->vc_mgr, &sc->add_vlan_cmd,
		    IXLV_FLAG_AQ_CONFIGURE_PROMISC, ixl_init_cmd_complete, sc);
#endif
		return;
	}
	/* (re-)install filters for all mcast addresses */
	mcnt = if_multi_apply(iflib_get_ifp(ctx), ixl_mc_filter_apply, vsi);
	
	if (mcnt > 0)
		ixlv_send_vc_msg(sc, IXLV_FLAG_AQ_ADD_MAC_FILTER);
}

static int
ixlv_if_mtu_set(if_ctx_t ctx, uint32_t mtu)
{
	struct ixlv_sc *sc = iflib_get_softc(ctx);
	struct ixl_vsi *vsi = &sc->vsi;

	IOCTL_DEBUGOUT("ioctl: SIOCSIFMTU (Set Interface MTU)");
	if (mtu > IXL_MAX_FRAME - ETHER_HDR_LEN - ETHER_CRC_LEN -
		ETHER_VLAN_ENCAP_LEN)
		return (EINVAL);

	vsi->shared->isc_max_frame_size = mtu + ETHER_HDR_LEN + ETHER_CRC_LEN +
		ETHER_VLAN_ENCAP_LEN;

	return (0);
}

static void
ixlv_if_media_status(if_ctx_t ctx, struct ifmediareq *ifmr)
{
#ifdef IXL_DEBUG
	struct ifnet *ifp = iflib_get_ifp(ctx);
#endif
	struct ixlv_sc *sc = iflib_get_softc(ctx);

	INIT_DBG_IF(ifp, "begin");

	ixlv_update_link_status(sc);

	ifmr->ifm_status = IFM_AVALID;
	ifmr->ifm_active = IFM_ETHER;

	if (!sc->link_up) {
		INIT_DBG_IF(ifp, "end: link not up");
		return;
	}

	ifmr->ifm_status |= IFM_ACTIVE;
	/* Hardware is always full-duplex */
	ifmr->ifm_active |= IFM_FDX;

	/* Based on the link speed reported by the PF over the AdminQ, choose a
	 * PHY type to report. This isn't 100% correct since we don't really
	 * know the underlying PHY type of the PF, but at least we can report
	 * a valid link speed...
	 */
	switch (sc->link_speed) {
	case VIRTCHNL_LINK_SPEED_100MB:
		ifmr->ifm_active |= IFM_100_TX;
		break;
	case VIRTCHNL_LINK_SPEED_1GB:
		ifmr->ifm_active |= IFM_1000_T;
		break;
	case VIRTCHNL_LINK_SPEED_10GB:
		ifmr->ifm_active |= IFM_10G_SR;
		break;
	case VIRTCHNL_LINK_SPEED_20GB:
	case VIRTCHNL_LINK_SPEED_25GB:
		ifmr->ifm_active |= IFM_25G_SR;
		break;
	case VIRTCHNL_LINK_SPEED_40GB:
		ifmr->ifm_active |= IFM_40G_SR4;
		break;
	default:
		ifmr->ifm_active |= IFM_UNKNOWN;
		break;
	}

	INIT_DBG_IF(ifp, "end");
}

static int
ixlv_if_media_change(if_ctx_t ctx)
{
	struct ifmedia *ifm = iflib_get_media(ctx);

	INIT_DEBUGOUT("ixl_media_change: begin");

	if (IFM_TYPE(ifm->ifm_media) != IFM_ETHER)
		return (EINVAL);

	if_printf(iflib_get_ifp(ctx), "Media change is not supported.\n");
	return (ENODEV);
}

// TODO: Rework
static int
ixlv_if_promisc_set(if_ctx_t ctx, int flags)
{
	struct ixlv_sc *sc = iflib_get_softc(ctx);
	struct ixl_vsi *vsi = &sc->vsi;
	struct ifnet	*ifp = iflib_get_ifp(ctx);
	struct i40e_hw	*hw = vsi->hw;
	int		err;
	bool		uni = FALSE, multi = FALSE;

	if (flags & IFF_ALLMULTI ||
		if_multiaddr_count(ifp, MAX_MULTICAST_ADDR) == MAX_MULTICAST_ADDR)
		multi = TRUE;
	if (flags & IFF_PROMISC)
		sc->promisc_flags |= FLAG_VF_UNICAST_PROMISC;

	ixlv_send_vc_msg(sc, IXLV_FLAG_AQ_CONFIGURE_PROMISC);

	err = i40e_aq_set_vsi_unicast_promiscuous(hw,
	    vsi->seid, uni, NULL, false);
	if (err)
		return (err);
	err = i40e_aq_set_vsi_multicast_promiscuous(hw,
	    vsi->seid, multi, NULL);
	return (err);
}

static void
ixlv_if_timer(if_ctx_t ctx, uint16_t qid)
{
	struct ixlv_sc *sc = iflib_get_softc(ctx);

	if (qid != 0)
		return;

	/* Fire off the adminq task */
	iflib_admin_intr_deferred(ctx);

	/* Update stats */
	ixlv_request_stats(sc);
}

static void
ixlv_if_vlan_register(if_ctx_t ctx, u16 vtag)
{
	struct ixlv_sc *sc = iflib_get_softc(ctx);
	struct ixl_vsi *vsi = &sc->vsi;
	//struct i40e_hw	*hw = vsi->hw;

	if ((vtag == 0) || (vtag > 4095))	/* Invalid */
		return;

	++vsi->num_vlans;
	v = malloc(sizeof(struct ixlv_vlan_filter), M_DEVBUF, M_WAITOK | M_ZERO);
	SLIST_INSERT_HEAD(sc->vlan_filters, v, next);
	v->vlan = vtag;
	v->flags = IXL_FILTER_ADD;

	ixlv_send_vc_msg(sc, IXLV_FLAG_AQ_ADD_VLAN_FILTER);
}

static void
ixlv_if_vlan_unregister(if_ctx_t ctx, u16 vtag)
{
	struct ixlv_sc *sc = iflib_get_softc(ctx);
	struct ixl_vsi *vsi = &sc->vsi;
	//struct i40e_hw	*hw = vsi->hw;

	if ((vtag == 0) || (vtag > 4095))	/* Invalid */
		return;

	SLIST_FOREACH(v, sc->vlan_filters, next) {
		if (v->vlan == vtag) {
			v->flags = IXL_FILTER_DEL;
			++i;
			--vsi->num_vlans;
		}
	}
	if (i)
		ixlv_send_vc_msg(sc, IXLV_FLAG_AQ_DEL_VLAN_FILTER);
}

static uint64_t
ixlv_if_get_counter(if_ctx_t ctx, ift_counter cnt)
{
	struct ixlv_sc *sc = iflib_get_softc(ctx);
	struct ixl_vsi *vsi = &sc->vsi;
	if_t ifp = iflib_get_ifp(ctx);

	switch (cnt) {
	case IFCOUNTER_IPACKETS:
		return (vsi->ipackets);
	case IFCOUNTER_IERRORS:
		return (vsi->ierrors);
	case IFCOUNTER_OPACKETS:
		return (vsi->opackets);
	case IFCOUNTER_OERRORS:
		return (vsi->oerrors);
	case IFCOUNTER_COLLISIONS:
		/* Collisions are by standard impossible in 40G/10G Ethernet */
		return (0);
	case IFCOUNTER_IBYTES:
		return (vsi->ibytes);
	case IFCOUNTER_OBYTES:
		return (vsi->obytes);
	case IFCOUNTER_IMCASTS:
		return (vsi->imcasts);
	case IFCOUNTER_OMCASTS:
		return (vsi->omcasts);
	case IFCOUNTER_IQDROPS:
		return (vsi->iqdrops);
	case IFCOUNTER_OQDROPS:
		return (vsi->oqdrops);
	case IFCOUNTER_NOPROTO:
		return (vsi->noproto);
	default:
		return (if_get_counter_default(ifp, cnt));
	}
}

 
static void
ixlv_free_pci_resources(struct ixlv_sc *sc)
{
	struct ixl_vsi		*vsi = &sc->vsi;
	struct ixl_rx_queue	*rx_que = vsi->rx_queues;
	device_t                dev = sc->dev;

	/* We may get here before stations are setup */
	if (rx_que == NULL)
		goto early;

	/* Release all interrupts */
	iflib_irq_free(vsi->ctx, &vsi->irq);

	for (int i = 0; i < vsi->num_rx_queues; i++, rx_que++)
		iflib_irq_free(vsi->ctx, &rx_que->que_irq);

early:
	if (sc->pci_mem != NULL)
		bus_release_resource(dev, SYS_RES_MEMORY,
		    PCIR_BAR(0), sc->pci_mem);
}


/*
** Requests a VF reset from the PF.
**
** Requires the VF's Admin Queue to be initialized.
*/
static int
ixlv_reset(struct ixlv_sc *sc)
{
	struct i40e_hw	*hw = &sc->hw;
	device_t	dev = sc->dev;
	int		error = 0;

	/* Ask the PF to reset us if we are initiating */
	if (sc->init_state != IXLV_RESET_PENDING)
		ixlv_request_reset(sc);

	i40e_msec_pause(100);
	error = ixlv_reset_complete(hw);
	if (error) {
		device_printf(dev, "%s: VF reset failed\n",
		    __func__);
		return (error);
	}

	error = i40e_shutdown_adminq(hw);
	if (error) {
		device_printf(dev, "%s: shutdown_adminq failed: %d\n",
		    __func__, error);
		return (error);
	}

	error = i40e_init_adminq(hw);
	if (error) {
		device_printf(dev, "%s: init_adminq failed: %d\n",
		    __func__, error);
		return(error);
	}

	return (0);
}

static int
ixlv_reset_complete(struct i40e_hw *hw)
{
	u32 reg;

	/* Wait up to ~10 seconds */
	for (int i = 0; i < 100; i++) {
		reg = rd32(hw, I40E_VFGEN_RSTAT) &
		    I40E_VFGEN_RSTAT_VFR_STATE_MASK;

                if ((reg == VIRTCHNL_VFR_VFACTIVE) ||
		    (reg == VIRTCHNL_VFR_COMPLETED))
			return (0);
		i40e_msec_pause(100);
	}

	return (EBUSY);
}

static void
ixlv_setup_interface(device_t dev, struct ixlv_sc *sc)
{
	struct ixl_vsi *vsi = &sc->vsi;
	if_ctx_t ctx = vsi->ctx;
	struct ifnet *ifp = iflib_get_ifp(ctx);
	uint64_t cap;

	INIT_DBG_DEV(dev, "begin");

	/* initialize fast path functions */
	cap = IXL_CAPS;
	if_setifheaderlen(ifp, sizeof(struct ether_vlan_header));
	if_setcapabilitiesbit(ifp, cap, 0);
	if_setcapenable(ifp, if_getcapabilities(ifp));
	vsi->shared->isc_max_frame_size =
	    ifp->if_mtu + ETHER_HDR_LEN + ETHER_CRC_LEN
	    + ETHER_VLAN_ENCAP_LEN;
#if __FreeBSD_version >= 1100000
	if_setbaudrate(ifp, IF_Gbps(40));
#else
	if_initbaudrate(ifp, IF_Gbps(40));
#endif

	/* Media types based on reported link speed over AdminQ */
	ifmedia_add(vsi->media, IFM_ETHER | IFM_100_TX, 0, NULL);
	ifmedia_add(vsi->media, IFM_ETHER | IFM_1000_T, 0, NULL);
	ifmedia_add(vsi->media, IFM_ETHER | IFM_10G_SR, 0, NULL);
	ifmedia_add(vsi->media, IFM_ETHER | IFM_25G_SR, 0, NULL);
	ifmedia_add(vsi->media, IFM_ETHER | IFM_40G_SR4, 0, NULL);

	ifmedia_add(vsi->media, IFM_ETHER | IFM_AUTO, 0, NULL);
	ifmedia_set(vsi->media, IFM_ETHER | IFM_AUTO);
}

#if 0
/*
** This routine is run via an vlan config EVENT,
** it enables us to use the HW Filter table since
** we can get the vlan id. This just creates the
** entry in the soft version of the VFTA, init will
** repopulate the real table.
*/
static void
ixlv_register_vlan(void *arg, struct ifnet *ifp, u16 vtag)
{
	struct ixl_vsi		*vsi = arg;
	struct ixlv_sc		*sc = vsi->back;
	struct ixlv_vlan_filter	*v;


	if (ifp->if_softc != arg)   /* Not our event */
		return;

	if ((vtag == 0) || (vtag > 4095))	/* Invalid */
		return;

	/* Sanity check - make sure it doesn't already exist */
	SLIST_FOREACH(v, sc->vlan_filters, next) {
		if (v->vlan == vtag)
			return;
	}

	mtx_lock(&sc->mtx);
	++vsi->num_vlans;
	v = malloc(sizeof(struct ixlv_vlan_filter), M_DEVBUF, M_NOWAIT | M_ZERO);
	SLIST_INSERT_HEAD(sc->vlan_filters, v, next);
	v->vlan = vtag;
	v->flags = IXL_FILTER_ADD;
	ixl_vc_enqueue(&sc->vc_mgr, &sc->add_vlan_cmd,
	    IXLV_FLAG_AQ_ADD_VLAN_FILTER, ixl_init_cmd_complete, sc);
	mtx_unlock(&sc->mtx);
	return;
}

/*
** This routine is run via an vlan
** unconfig EVENT, remove our entry
** in the soft vfta.
*/
static void
ixlv_unregister_vlan(void *arg, struct ifnet *ifp, u16 vtag)
{
	struct ixl_vsi		*vsi = arg;
	struct ixlv_sc		*sc = vsi->back;
	struct ixlv_vlan_filter	*v;
	int			i = 0;
	
	if (ifp->if_softc != arg)
		return;

	if ((vtag == 0) || (vtag > 4095))	/* Invalid */
		return;

	mtx_lock(&sc->mtx);
	SLIST_FOREACH(v, sc->vlan_filters, next) {
		if (v->vlan == vtag) {
			v->flags = IXL_FILTER_DEL;
			++i;
			--vsi->num_vlans;
		}
	}
	if (i)
		ixl_vc_enqueue(&sc->vc_mgr, &sc->del_vlan_cmd,
		    IXLV_FLAG_AQ_DEL_VLAN_FILTER, ixl_init_cmd_complete, sc);
	mtx_unlock(&sc->mtx);
	return;
}
#endif

/*
** Get a new filter and add it to the mac filter list.
*/
static struct ixlv_mac_filter *
ixlv_get_mac_filter(struct ixlv_sc *sc)
{
	struct ixlv_mac_filter	*f;

	f = malloc(sizeof(struct ixlv_mac_filter),
	    M_DEVBUF, M_NOWAIT | M_ZERO);
	if (f)
		SLIST_INSERT_HEAD(sc->mac_filters, f, next);

	return (f);
}

/*
** Find the filter with matching MAC address
*/
static struct ixlv_mac_filter *
ixlv_find_mac_filter(struct ixlv_sc *sc, u8 *macaddr)
{
	struct ixlv_mac_filter	*f;
	bool				match = FALSE;

	SLIST_FOREACH(f, sc->mac_filters, next) {
		if (cmp_etheraddr(f->macaddr, macaddr)) {
			match = TRUE;
			break;
		}
	}	

	if (!match)
		f = NULL;
	return (f);
}

/*
** Admin Queue interrupt handler
*/
static int
ixlv_msix_adminq(void *arg)
{
	struct ixlv_sc	*sc = arg;
	struct i40e_hw	*hw = &sc->hw;
	// device_t	dev = sc->dev;
	u32		reg, mask;
	bool		do_task = FALSE;

	++sc->admin_irq;

        reg = rd32(hw, I40E_VFINT_ICR01);
        mask = rd32(hw, I40E_VFINT_ICR0_ENA1);

        reg = rd32(hw, I40E_VFINT_DYN_CTL01);
        reg |= I40E_VFINT_DYN_CTL01_CLEARPBA_MASK;
        wr32(hw, I40E_VFINT_DYN_CTL01, reg);

	/* Check on the cause */
	if (reg & I40E_VFINT_ICR0_ADMINQ_MASK)
		do_task = TRUE;

	if (do_task)
		iflib_admin_intr_deferred(sc->vsi.ctx);
	else
		ixlv_enable_adminq_irq(hw);

	return (FILTER_HANDLED);
}

void
ixlv_enable_intr(struct ixl_vsi *vsi)
{
	struct i40e_hw *hw = vsi->hw;
	struct ixl_rx_queue *que = vsi->rx_queues;

	ixlv_enable_adminq_irq(hw);
	for (int i = 0; i < vsi->num_rx_queues; i++, que++)
		ixlv_enable_queue_irq(hw, que->rxr.me);
}

void
ixlv_disable_intr(struct ixl_vsi *vsi)
{
        struct i40e_hw *hw = vsi->hw;
        struct ixl_rx_queue *que = vsi->rx_queues;

	ixlv_disable_adminq_irq(hw);
	for (int i = 0; i < vsi->num_rx_queues; i++, que++)
		ixlv_disable_queue_irq(hw, que->rxr.me);
}

static void
ixlv_disable_adminq_irq(struct i40e_hw *hw)
{
	wr32(hw, I40E_VFINT_DYN_CTL01, 0);
	wr32(hw, I40E_VFINT_ICR0_ENA1, 0);
	/* flush */
	rd32(hw, I40E_VFGEN_RSTAT);
}

static void
ixlv_enable_adminq_irq(struct i40e_hw *hw)
{
	wr32(hw, I40E_VFINT_DYN_CTL01,
	    I40E_VFINT_DYN_CTL01_INTENA_MASK |
	    I40E_VFINT_DYN_CTL01_ITR_INDX_MASK);
	wr32(hw, I40E_VFINT_ICR0_ENA1, I40E_VFINT_ICR0_ENA1_ADMINQ_MASK);
	/* flush */
	rd32(hw, I40E_VFGEN_RSTAT);
}

static void
ixlv_enable_queue_irq(struct i40e_hw *hw, int id)
{
	u32		reg;

	reg = I40E_VFINT_DYN_CTLN1_INTENA_MASK |
	    I40E_VFINT_DYN_CTLN1_CLEARPBA_MASK |
	    I40E_VFINT_DYN_CTLN1_ITR_INDX_MASK;
	wr32(hw, I40E_VFINT_DYN_CTLN1(id), reg);
}

static void
ixlv_disable_queue_irq(struct i40e_hw *hw, int id)
{
	wr32(hw, I40E_VFINT_DYN_CTLN1(id),
	    I40E_VFINT_DYN_CTLN1_ITR_INDX_MASK);
	rd32(hw, I40E_VFGEN_RSTAT);
}

/*
 * Get initial ITR values from tunable values.
 */
static void
ixlv_configure_itr(struct ixlv_sc *sc)
{
	struct i40e_hw		*hw = &sc->hw;
	struct ixl_vsi		*vsi = &sc->vsi;
	struct ixl_rx_queue	*rx_que = vsi->rx_queues;

	vsi->rx_itr_setting = ixlv_rx_itr;
	//vsi->tx_itr_setting = ixlv_tx_itr;

	for (int i = 0; i < vsi->num_rx_queues; i++, rx_que++) {
		struct rx_ring 	*rxr = &rx_que->rxr;

		wr32(hw, I40E_VFINT_ITRN1(IXL_RX_ITR, i),
		    vsi->rx_itr_setting);
		rxr->itr = vsi->rx_itr_setting;
		rxr->latency = IXL_AVE_LATENCY;

#if 0
		struct tx_ring	*txr = &que->txr;
		wr32(hw, I40E_VFINT_ITRN1(IXL_TX_ITR, i),
		    vsi->tx_itr_setting);
		txr->itr = vsi->tx_itr_setting;
		txr->latency = IXL_AVE_LATENCY;
#endif
	}
}

/*
** Provide a update to the queue RX
** interrupt moderation value.
*/
static void
ixlv_set_queue_rx_itr(struct ixl_rx_queue *que)
{
	struct ixl_vsi	*vsi = que->vsi;
	struct i40e_hw	*hw = vsi->hw;
	struct rx_ring	*rxr = &que->rxr;
	//u16		rx_itr;
	//u16		rx_latency = 0;
	//int		rx_bytes;

	/* Idle, do nothing */
	if (rxr->bytes == 0)
		return;

#if 0
	if (sc->ixlv_dynamic_rx_itr) {
		rx_bytes = rxr->bytes/rxr->itr;
		rx_itr = rxr->itr;

		/* Adjust latency range */
		switch (rxr->latency) {
		case IXL_LOW_LATENCY:
			if (rx_bytes > 10) {
				rx_latency = IXL_AVE_LATENCY;
				rx_itr = IXL_ITR_20K;
			}
			break;
		case IXL_AVE_LATENCY:
			if (rx_bytes > 20) {
				rx_latency = IXL_BULK_LATENCY;
				rx_itr = IXL_ITR_8K;
			} else if (rx_bytes <= 10) {
				rx_latency = IXL_LOW_LATENCY;
				rx_itr = IXL_ITR_100K;
			}
			break;
		case IXL_BULK_LATENCY:
			if (rx_bytes <= 20) {
				rx_latency = IXL_AVE_LATENCY;
				rx_itr = IXL_ITR_20K;
			}
			break;
       		 }

		rxr->latency = rx_latency;

		if (rx_itr != rxr->itr) {
			/* do an exponential smoothing */
			rx_itr = (10 * rx_itr * rxr->itr) /
			    ((9 * rx_itr) + rxr->itr);
			rxr->itr = min(rx_itr, IXL_MAX_ITR);
			wr32(hw, I40E_VFINT_ITRN1(IXL_RX_ITR,
			    que->rxr.me), rxr->itr);
		}
	} else { /* We may have have toggled to non-dynamic */
#endif
		if (vsi->rx_itr_setting & IXL_ITR_DYNAMIC)
			vsi->rx_itr_setting = ixlv_rx_itr;
		/* Update the hardware if needed */
		if (rxr->itr != vsi->rx_itr_setting) {
			rxr->itr = vsi->rx_itr_setting;
			wr32(hw, I40E_VFINT_ITRN1(IXL_RX_ITR,
			    que->rxr.me), rxr->itr);
		}
#if 0
	}
	rxr->bytes = 0;
	rxr->packets = 0;
#endif
}


#if 0
/*
** Provide a update to the queue TX
** interrupt moderation value.
*/
static void
ixlv_set_queue_tx_itr(struct ixl_tx_queue *que)
{
	struct ixl_vsi	*vsi = que->vsi;
	struct i40e_hw	*hw = vsi->hw;
	struct tx_ring	*txr = &que->txr;
#if 0
	u16		tx_itr;
	u16		tx_latency = 0;
	int		tx_bytes;
#endif

	/* Idle, do nothing */
	if (txr->bytes == 0)
		return;

#if 0
	if (ixlv_dynamic_tx_itr) {
		tx_bytes = txr->bytes/txr->itr;
		tx_itr = txr->itr;

		switch (txr->latency) {
		case IXL_LOW_LATENCY:
			if (tx_bytes > 10) {
				tx_latency = IXL_AVE_LATENCY;
				tx_itr = IXL_ITR_20K;
			}
			break;
		case IXL_AVE_LATENCY:
			if (tx_bytes > 20) {
				tx_latency = IXL_BULK_LATENCY;
				tx_itr = IXL_ITR_8K;
			} else if (tx_bytes <= 10) {
				tx_latency = IXL_LOW_LATENCY;
				tx_itr = IXL_ITR_100K;
			}
			break;
		case IXL_BULK_LATENCY:
			if (tx_bytes <= 20) {
				tx_latency = IXL_AVE_LATENCY;
				tx_itr = IXL_ITR_20K;
			}
			break;
		}

		txr->latency = tx_latency;

		if (tx_itr != txr->itr) {
       	         /* do an exponential smoothing */
			tx_itr = (10 * tx_itr * txr->itr) /
			    ((9 * tx_itr) + txr->itr);
			txr->itr = min(tx_itr, IXL_MAX_ITR);
			wr32(hw, I40E_VFINT_ITRN1(IXL_TX_ITR,
			    que->txr.me), txr->itr);
		}

	} else { /* We may have have toggled to non-dynamic */
#endif
		if (vsi->tx_itr_setting & IXL_ITR_DYNAMIC)
			vsi->tx_itr_setting = ixlv_tx_itr;
		/* Update the hardware if needed */
		if (txr->itr != vsi->tx_itr_setting) {
			txr->itr = vsi->tx_itr_setting;
			wr32(hw, I40E_VFINT_ITRN1(IXL_TX_ITR,
			    que->txr.me), txr->itr);
		}
#if 0
	}
	txr->bytes = 0;
	txr->packets = 0;
#endif
}
#endif

#if 0
/*
**
** MSIX Interrupt Handlers and Tasklets
**
*/
static void
ixlv_handle_que(void *context, int pending)
{
	struct ixl_queue *que = context;
	struct ixl_vsi *vsi = que->vsi;
	struct i40e_hw  *hw = vsi->hw;
	struct tx_ring  *txr = &que->txr;
	struct ifnet    *ifp = vsi->ifp;
	bool		more;

	if (ifp->if_drv_flags & IFF_DRV_RUNNING) {
		more = ixl_rxeof(que, IXL_RX_LIMIT);
		mtx_lock(&txr->mtx);
		ixl_txeof(que);
		if (!drbr_empty(ifp, txr->br))
			ixl_mq_start_locked(ifp, txr);
		mtx_unlock(&txr->mtx);
		if (more) {
			taskqueue_enqueue(que->tq, &que->task);
			return;
		}
	}

	/* Reenable this interrupt - hmmm */
	ixlv_enable_queue_irq(hw, que->me);
	return;
}
#endif


static int
ixlv_msix_que(void *arg)
{
	struct ixl_rx_queue *rx_que = arg;

	++rx_que->irqs;

	ixlv_set_queue_rx_itr(rx_que);
	// ixlv_set_queue_tx_itr(que);

	return (FILTER_SCHEDULE_THREAD);
}

#if 0
/*********************************************************************
 *  Multicast Initialization
 *
 *  This routine is called by init to reset a fresh state.
 *
 **********************************************************************/

static void
ixlv_init_multi(struct ixl_vsi *vsi)
{
	struct ixlv_mac_filter *f;
	struct ixlv_sc	*sc = vsi->back;
	int			mcnt = 0;

	IOCTL_DBG_IF(vsi->ifp, "begin");

	/* First clear any multicast filters */
	SLIST_FOREACH(f, sc->mac_filters, next) {
		if ((f->flags & IXL_FILTER_USED)
		    && (f->flags & IXL_FILTER_MC)) {
			f->flags |= IXL_FILTER_DEL;
			mcnt++;
		}
	}
	if (mcnt > 0)
		ixlv_send_vc_msg(sc, IXLV_FLAG_AQ_DEL_MAC_FILTER);
}

/*
** Note: this routine updates the OS on the link state
**	the real check of the hardware only happens with
**	a link interrupt.
*/
void
ixlv_update_link_status(struct ixlv_sc *sc)
{
	struct ixl_vsi *vsi = &sc->vsi;
	struct ifnet *ifp = vsi->ifp;

	if (sc->link_up){ 
		if (vsi->link_active == FALSE) {
			if (bootverbose)
				if_printf(ifp, "Link is Up, %s\n",
				    ixlv_vc_speed_to_string(sc->link_speed));
			vsi->link_active = TRUE;
			if_link_state_change(ifp, LINK_STATE_UP);
		}
	} else { /* Link down */
		if (vsi->link_active == TRUE) {
			if (bootverbose)
				if_printf(ifp, "Link is Down\n");
			if_link_state_change(ifp, LINK_STATE_DOWN);
			vsi->link_active = FALSE;
		}
	}
}

/*********************************************************************
 *
 *  This routine disables all traffic on the adapter by issuing a
 *  global reset on the MAC and deallocates TX/RX buffers.
 *
 **********************************************************************/

static void
ixlv_stop(struct ixlv_sc *sc)
{
	struct ifnet *ifp;
	int start;

	ifp = sc->vsi.ifp;
	INIT_DBG_IF(ifp, "begin");

	ixl_vc_flush(&sc->vc_mgr);
	ixlv_disable_queues(sc);

	start = ticks;
	while ((ifp->if_drv_flags & IFF_DRV_RUNNING) &&
	    ((ticks - start) < hz/10))
		ixlv_do_adminq_locked(sc);

	ixlv_send_vc_msg(sc, IXLV_FLAG_AQ_DISABLE_QUEUES);

	INIT_DBG_IF(ifp, "end");
}

static void
ixlv_if_stop(if_ctx_t ctx)
{
	struct ixlv_sc *sc = iflib_get_softc(ctx);

	ixlv_stop(sc);
}

static void
ixlv_config_rss_reg(struct ixlv_sc *sc)
{
	struct i40e_hw	*hw = &sc->hw;
	struct ixl_vsi	*vsi = &sc->vsi;
	u32		lut = 0;
	u64		set_hena = 0, hena;
	int		i, j, que_id;
	u32		rss_seed[IXL_RSS_KEY_SIZE_REG];
#ifdef RSS
	u32		rss_hash_config;
#endif
        
	/* Don't set up RSS if using a single queue */
	if (vsi->num_rx_queues == 1) {
		wr32(hw, I40E_VFQF_HENA(0), 0);
		wr32(hw, I40E_VFQF_HENA(1), 0);
		ixl_flush(hw);
		return;
	}

#ifdef RSS
	/* Fetch the configured RSS key */
	rss_getkey((uint8_t *) &rss_seed);
#else
	ixl_get_default_rss_key(rss_seed);
#endif

	/* Fill out hash function seed */
	for (i = 0; i < IXL_RSS_KEY_SIZE_REG; i++)
                wr32(hw, I40E_VFQF_HKEY(i), rss_seed[i]);

	/* Enable PCTYPES for RSS: */
#ifdef RSS
	rss_hash_config = rss_gethashconfig();
	if (rss_hash_config & RSS_HASHTYPE_RSS_IPV4)
                set_hena |= ((u64)1 << I40E_FILTER_PCTYPE_NONF_IPV4_OTHER);
	if (rss_hash_config & RSS_HASHTYPE_RSS_TCP_IPV4)
                set_hena |= ((u64)1 << I40E_FILTER_PCTYPE_NONF_IPV4_TCP);
	if (rss_hash_config & RSS_HASHTYPE_RSS_UDP_IPV4)
                set_hena |= ((u64)1 << I40E_FILTER_PCTYPE_NONF_IPV4_UDP);
	if (rss_hash_config & RSS_HASHTYPE_RSS_IPV6)
                set_hena |= ((u64)1 << I40E_FILTER_PCTYPE_NONF_IPV6_OTHER);
	if (rss_hash_config & RSS_HASHTYPE_RSS_IPV6_EX)
		set_hena |= ((u64)1 << I40E_FILTER_PCTYPE_FRAG_IPV6);
	if (rss_hash_config & RSS_HASHTYPE_RSS_TCP_IPV6)
                set_hena |= ((u64)1 << I40E_FILTER_PCTYPE_NONF_IPV6_TCP);
        if (rss_hash_config & RSS_HASHTYPE_RSS_UDP_IPV6)
                set_hena |= ((u64)1 << I40E_FILTER_PCTYPE_NONF_IPV6_UDP);
#else
	set_hena = IXL_DEFAULT_RSS_HENA_XL710;
#endif
	hena = (u64)rd32(hw, I40E_VFQF_HENA(0)) |
	    ((u64)rd32(hw, I40E_VFQF_HENA(1)) << 32);
	hena |= set_hena;
	wr32(hw, I40E_VFQF_HENA(0), (u32)hena);
	wr32(hw, I40E_VFQF_HENA(1), (u32)(hena >> 32));

	/* Populate the LUT with max no. of queues in round robin fashion */
	for (i = 0, j = 0; i < IXL_RSS_VSI_LUT_SIZE; i++, j++) {
                if (j == vsi->num_rx_queues)
                        j = 0;
#ifdef RSS
		/*
		 * Fetch the RSS bucket id for the given indirection entry.
		 * Cap it at the number of configured buckets (which is
		 * num_queues.)
		 */
		que_id = rss_get_indirection_to_bucket(i);
		que_id = que_id % vsi->num_queues;
#else
		que_id = j;
#endif
                /* lut = 4-byte sliding window of 4 lut entries */
                lut = (lut << 8) | (que_id & IXL_RSS_VF_LUT_ENTRY_MASK);
                /* On i = 3, we have 4 entries in lut; write to the register */
                if ((i & 3) == 3) {
                        wr32(hw, I40E_VFQF_HLUT(i >> 2), lut);
			DDPRINTF(sc->dev, "HLUT(%2d): %#010x", i, lut);
		}
        }
	ixl_flush(hw);
}

static void
ixlv_config_rss_pf(struct ixlv_sc *sc)
{
	ixlv_send_vc_msg(sc, IXLV_FLAG_AQ_CONFIG_RSS_KEY);

	ixlv_send_vc_msg(sc, IXLV_FLAG_AQ_SET_RSS_HENA);

	ixlv_send_vc_msg(sc, IXLV_FLAG_AQ_CONFIG_RSS_LUT);
}

/*
** ixlv_config_rss - setup RSS 
**
** RSS keys and table are cleared on VF reset.
*/
static void
ixlv_config_rss(struct ixlv_sc *sc)
{
	if (sc->vf_res->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_RSS_REG) {
		DDPRINTF(sc->dev, "Setting up RSS using VF registers...");
		ixlv_config_rss_reg(sc);
	} else if (sc->vf_res->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_RSS_PF) {
		DDPRINTF(sc->dev, "Setting up RSS using messages to PF...");
		ixlv_config_rss_pf(sc);
	} else
		device_printf(sc->dev, "VF does not support RSS capability sent by PF.\n");
}

#if 0
/*
** This routine refreshes vlan filters, called by init
** it scans the filter table and then updates the AQ
*/
static void
ixlv_setup_vlan_filters(struct ixlv_sc *sc)
{
	struct ixl_vsi			*vsi = &sc->vsi;
	struct ixlv_vlan_filter	*f;
	int				cnt = 0;

	if (vsi->num_vlans == 0)
		return;
	/*
	** Scan the filter table for vlan entries,
	** and if found call for the AQ update.
	*/
	SLIST_FOREACH(f, sc->vlan_filters, next)
                if (f->flags & IXL_FILTER_ADD)
			cnt++;
	if (cnt > 0)
		ixl_vc_enqueue(&sc->vc_mgr, &sc->add_vlan_cmd,
		    IXLV_FLAG_AQ_ADD_VLAN_FILTER, ixl_init_cmd_complete, sc);
}
#endif

/*
** This routine adds new MAC filters to the sc's list;
** these are later added in hardware by sending a virtual
** channel message.
*/
static int
ixlv_add_mac_filter(struct ixlv_sc *sc, u8 *macaddr, u16 flags)
{
	struct ixlv_mac_filter	*f;

	/* Does one already exist? */
	f = ixlv_find_mac_filter(sc, macaddr);
	if (f != NULL) {
		IDPRINTF(sc->vsi.ifp, "exists: " MAC_FORMAT,
		    MAC_FORMAT_ARGS(macaddr));
		return (EEXIST);
	}

	/* If not, get a new empty filter */
	f = ixlv_get_mac_filter(sc);
	if (f == NULL) {
		if_printf(sc->vsi.ifp, "%s: no filters available!!\n",
		    __func__);
		return (ENOMEM);
	}

	IDPRINTF(sc->vsi.ifp, "marked: " MAC_FORMAT,
	    MAC_FORMAT_ARGS(macaddr));

	bcopy(macaddr, f->macaddr, ETHER_ADDR_LEN);
	f->flags |= (IXL_FILTER_ADD | IXL_FILTER_USED);
	f->flags |= flags;
	return (0);
}

/*
** Marks a MAC filter for deletion.
*/
static int
ixlv_del_mac_filter(struct ixlv_sc *sc, u8 *macaddr)
{
	struct ixlv_mac_filter	*f;

	f = ixlv_find_mac_filter(sc, macaddr);
	if (f == NULL)
		return (ENOENT);

	f->flags |= IXL_FILTER_DEL;
	return (0);
}

static void
ixlv_do_adminq_locked(struct ixlv_sc *sc)
{
	struct i40e_hw			*hw = &sc->hw;
	struct i40e_arq_event_info	event;
	struct virtchnl_msg	*v_msg;
	device_t			dev = sc->dev;
	u16				result = 0;
	u32				reg, oldreg;
	i40e_status			ret;
	bool				aq_error = false;

	event.buf_len = IXL_AQ_BUF_SZ;
        event.msg_buf = sc->aq_buffer;
	v_msg = (struct virtchnl_msg *)&event.desc;

	do {
		ret = i40e_clean_arq_element(hw, &event, &result);
		if (ret)
			break;
		ixlv_vc_completion(sc, v_msg->v_opcode,
		    v_msg->v_retval, event.msg_buf, event.msg_len);
		if (result != 0)
			bzero(event.msg_buf, IXL_AQ_BUF_SZ);
	} while (result);

	/* check for Admin queue errors */
	oldreg = reg = rd32(hw, hw->aq.arq.len);
	if (reg & I40E_VF_ARQLEN1_ARQVFE_MASK) {
		device_printf(dev, "ARQ VF Error detected\n");
		reg &= ~I40E_VF_ARQLEN1_ARQVFE_MASK;
		aq_error = true;
	}
	if (reg & I40E_VF_ARQLEN1_ARQOVFL_MASK) {
		device_printf(dev, "ARQ Overflow Error detected\n");
		reg &= ~I40E_VF_ARQLEN1_ARQOVFL_MASK;
		aq_error = true;
	}
	if (reg & I40E_VF_ARQLEN1_ARQCRIT_MASK) {
		device_printf(dev, "ARQ Critical Error detected\n");
		reg &= ~I40E_VF_ARQLEN1_ARQCRIT_MASK;
		aq_error = true;
	}
	if (oldreg != reg)
		wr32(hw, hw->aq.arq.len, reg);

	oldreg = reg = rd32(hw, hw->aq.asq.len);
	if (reg & I40E_VF_ATQLEN1_ATQVFE_MASK) {
		device_printf(dev, "ASQ VF Error detected\n");
		reg &= ~I40E_VF_ATQLEN1_ATQVFE_MASK;
		aq_error = true;
	}
	if (reg & I40E_VF_ATQLEN1_ATQOVFL_MASK) {
		device_printf(dev, "ASQ Overflow Error detected\n");
		reg &= ~I40E_VF_ATQLEN1_ATQOVFL_MASK;
		aq_error = true;
	}
	if (reg & I40E_VF_ATQLEN1_ATQCRIT_MASK) {
		device_printf(dev, "ASQ Critical Error detected\n");
		reg &= ~I40E_VF_ATQLEN1_ATQCRIT_MASK;
		aq_error = true;
	}
	if (oldreg != reg)
		wr32(hw, hw->aq.asq.len, reg);

	if (aq_error) {
		/* Need to reset adapter */
		device_printf(dev, "WARNING: Resetting!\n");
		sc->init_state = IXLV_RESET_REQUIRED;
		ixlv_stop(sc);
		// TODO: Make stop/init calls match
		ixlv_if_init(sc->vsi.ctx);
	}
	ixlv_enable_adminq_irq(hw);
}

static void
ixlv_add_sysctls(struct ixlv_sc *sc)
{
	device_t dev = sc->dev;
	struct ixl_vsi *vsi = &sc->vsi;
	struct i40e_eth_stats *es = &vsi->eth_stats;

	struct sysctl_ctx_list *ctx = device_get_sysctl_ctx(dev);
	struct sysctl_oid *tree = device_get_sysctl_tree(dev);
	struct sysctl_oid_list *child = SYSCTL_CHILDREN(tree);

	struct sysctl_oid *vsi_node; // *queue_node;
	struct sysctl_oid_list *vsi_list; // *queue_list;

#define QUEUE_NAME_LEN 32
	//char queue_namebuf[QUEUE_NAME_LEN];

#if 0
	struct ixl_queue *queues = vsi->queues;
	struct tX_ring *txr;
	struct rx_ring *rxr;
#endif

	/* Driver statistics sysctls */
	SYSCTL_ADD_UQUAD(ctx, child, OID_AUTO, "watchdog_events",
			CTLFLAG_RD, &sc->watchdog_events,
			"Watchdog timeouts");
	SYSCTL_ADD_UQUAD(ctx, child, OID_AUTO, "admin_irq",
			CTLFLAG_RD, &sc->admin_irq,
			"Admin Queue IRQ Handled");

	SYSCTL_ADD_PROC(ctx, child, OID_AUTO, "current_speed",
			CTLTYPE_STRING | CTLFLAG_RD,
			sc, 0, ixlv_sysctl_current_speed,
			"A", "Current Port Speed");

	/* VSI statistics sysctls */
	vsi_node = SYSCTL_ADD_NODE(ctx, child, OID_AUTO, "vsi",
				   CTLFLAG_RD, NULL, "VSI-specific statistics");
	vsi_list = SYSCTL_CHILDREN(vsi_node);

	struct ixl_sysctl_info ctls[] =
	{
		{&es->rx_bytes, "good_octets_rcvd", "Good Octets Received"},
		{&es->rx_unicast, "ucast_pkts_rcvd",
			"Unicast Packets Received"},
		{&es->rx_multicast, "mcast_pkts_rcvd",
			"Multicast Packets Received"},
		{&es->rx_broadcast, "bcast_pkts_rcvd",
			"Broadcast Packets Received"},
		{&es->rx_discards, "rx_discards", "Discarded RX packets"},
		{&es->rx_unknown_protocol, "rx_unknown_proto", "RX unknown protocol packets"},
		{&es->tx_bytes, "good_octets_txd", "Good Octets Transmitted"},
		{&es->tx_unicast, "ucast_pkts_txd", "Unicast Packets Transmitted"},
		{&es->tx_multicast, "mcast_pkts_txd",
			"Multicast Packets Transmitted"},
		{&es->tx_broadcast, "bcast_pkts_txd",
			"Broadcast Packets Transmitted"},
		{&es->tx_errors, "tx_errors", "TX packet errors"},
		// end
		{0,0,0}
	};
	struct ixl_sysctl_info *entry = ctls;
	while (entry->stat != NULL)
	{
		SYSCTL_ADD_QUAD(ctx, child, OID_AUTO, entry->name,
				CTLFLAG_RD, entry->stat,
				entry->description);
		entry++;
	}

#if 0
	/* Queue sysctls */
	for (int q = 0; q < vsi->num_queues; q++) {
		snprintf(queue_namebuf, QUEUE_NAME_LEN, "que%d", q);
		queue_node = SYSCTL_ADD_NODE(ctx, vsi_list, OID_AUTO, queue_namebuf,
					     CTLFLAG_RD, NULL, "Queue Name");
		queue_list = SYSCTL_CHILDREN(queue_node);

		txr = &(queues[q].txr);
		rxr = &(queues[q].rxr);

		SYSCTL_ADD_QUAD(ctx, queue_list, OID_AUTO, "mbuf_defrag_failed",
				CTLFLAG_RD, &(queues[q].mbuf_defrag_failed),
				"m_defrag() failed");
		SYSCTL_ADD_QUAD(ctx, queue_list, OID_AUTO, "dropped",
				CTLFLAG_RD, &(queues[q].dropped_pkts),
				"Driver dropped packets");
		SYSCTL_ADD_QUAD(ctx, queue_list, OID_AUTO, "irqs",
				CTLFLAG_RD, &(queues[q].irqs),
				"irqs on this queue");
		SYSCTL_ADD_QUAD(ctx, queue_list, OID_AUTO, "tso_tx",
				CTLFLAG_RD, &(queues[q].tso),
				"TSO");
		SYSCTL_ADD_QUAD(ctx, queue_list, OID_AUTO, "tx_dmamap_failed",
				CTLFLAG_RD, &(queues[q].tx_dmamap_failed),
				"Driver tx dma failure in xmit");
		SYSCTL_ADD_QUAD(ctx, queue_list, OID_AUTO, "no_desc_avail",
				CTLFLAG_RD, &(txr->no_desc),
				"Queue No Descriptor Available");
		SYSCTL_ADD_QUAD(ctx, queue_list, OID_AUTO, "tx_packets",
				CTLFLAG_RD, &(txr->total_packets),
				"Queue Packets Transmitted");
		SYSCTL_ADD_QUAD(ctx, queue_list, OID_AUTO, "tx_bytes",
				CTLFLAG_RD, &(txr->tx_bytes),
				"Queue Bytes Transmitted");
		SYSCTL_ADD_QUAD(ctx, queue_list, OID_AUTO, "rx_packets",
				CTLFLAG_RD, &(rxr->rx_packets),
				"Queue Packets Received");
		SYSCTL_ADD_QUAD(ctx, queue_list, OID_AUTO, "rx_bytes",
				CTLFLAG_RD, &(rxr->rx_bytes),
				"Queue Bytes Received");
		SYSCTL_ADD_UINT(ctx, queue_list, OID_AUTO, "rx_itr",
				CTLFLAG_RD, &(rxr->itr), 0,
				"Queue Rx ITR Interval");
		SYSCTL_ADD_UINT(ctx, queue_list, OID_AUTO, "tx_itr",
				CTLFLAG_RD, &(txr->itr), 0,
				"Queue Tx ITR Interval");

#ifdef IXL_DEBUG
		/* Examine queue state */
		SYSCTL_ADD_PROC(ctx, queue_list, OID_AUTO, "qtx_head", 
				CTLTYPE_UINT | CTLFLAG_RD, &queues[q],
				sizeof(struct ixl_queue),
				ixlv_sysctl_qtx_tail_handler, "IU",
				"Queue Transmit Descriptor Tail");
		SYSCTL_ADD_PROC(ctx, queue_list, OID_AUTO, "qrx_head", 
				CTLTYPE_UINT | CTLFLAG_RD, &queues[q],
				sizeof(struct ixl_queue),
				ixlv_sysctl_qrx_tail_handler, "IU",
				"Queue Receive Descriptor Tail");
		SYSCTL_ADD_INT(ctx, queue_list, OID_AUTO, "watchdog_timer",
				CTLFLAG_RD, &(txr.watchdog_timer), 0,
				"Ticks before watchdog event is triggered");
#endif
	}
#endif
}

static void
ixlv_init_filters(struct ixlv_sc *sc)
{
	sc->mac_filters = malloc(sizeof(struct ixlv_mac_filter),
	    M_DEVBUF, M_NOWAIT | M_ZERO);
	SLIST_INIT(sc->mac_filters);
	sc->vlan_filters = malloc(sizeof(struct ixlv_vlan_filter),
	    M_DEVBUF, M_NOWAIT | M_ZERO);
	SLIST_INIT(sc->vlan_filters);
}

static void
ixlv_free_filters(struct ixlv_sc *sc)
{
	struct ixlv_mac_filter *f;
	struct ixlv_vlan_filter *v;

	while (!SLIST_EMPTY(sc->mac_filters)) {
		f = SLIST_FIRST(sc->mac_filters);
		SLIST_REMOVE_HEAD(sc->mac_filters, next);
		free(f, M_DEVBUF);
	}
	free(sc->mac_filters, M_DEVBUF);
	while (!SLIST_EMPTY(sc->vlan_filters)) {
		v = SLIST_FIRST(sc->vlan_filters);
		SLIST_REMOVE_HEAD(sc->vlan_filters, next);
		free(v, M_DEVBUF);
	}
	free(sc->vlan_filters, M_DEVBUF);
}

static char *
ixlv_vc_speed_to_string(enum virtchnl_link_speed link_speed)
{
	int index;

	char *speeds[] = {
		"Unknown",
		"100 Mbps",
		"1 Gbps",
		"10 Gbps",
		"40 Gbps",
		"20 Gbps",
		"25 Gbps",
	};

	switch (link_speed) {
	case VIRTCHNL_LINK_SPEED_100MB:
		index = 1;
		break;
	case VIRTCHNL_LINK_SPEED_1GB:
		index = 2;
		break;
	case VIRTCHNL_LINK_SPEED_10GB:
		index = 3;
		break;
	case VIRTCHNL_LINK_SPEED_40GB:
		index = 4;
		break;
	case VIRTCHNL_LINK_SPEED_20GB:
		index = 5;
		break;
	case VIRTCHNL_LINK_SPEED_25GB:
		index = 6;
		break;
	case VIRTCHNL_LINK_SPEED_UNKNOWN:
	default:
		index = 0;
		break;
	}

	return speeds[index];
}

static int
ixlv_sysctl_current_speed(SYSCTL_HANDLER_ARGS)
{
	struct ixlv_sc *sc = (struct ixlv_sc *)arg1;
	int error = 0;

	error = sysctl_handle_string(oidp,
	  ixlv_vc_speed_to_string(sc->link_speed),
	  8, req);
	return (error);
}

#ifdef IXL_DEBUG
/**
 * ixlv_sysctl_qtx_tail_handler
 * Retrieves I40E_QTX_TAIL1 value from hardware
 * for a sysctl.
 */
static int 
ixlv_sysctl_qtx_tail_handler(SYSCTL_HANDLER_ARGS)
{
	struct ixl_queue *que;
	int error;
	u32 val;

	que = ((struct ixl_queue *)oidp->oid_arg1);
	if (!que) return 0;

	val = rd32(que->vsi->hw, que->txr.tail);
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr)
		return error;
	return (0);
}

/**
 * ixlv_sysctl_qrx_tail_handler
 * Retrieves I40E_QRX_TAIL1 value from hardware
 * for a sysctl.
 */
static int 
ixlv_sysctl_qrx_tail_handler(SYSCTL_HANDLER_ARGS)
{
	struct ixl_queue *que;
	int error;
	u32 val;

	que = ((struct ixl_queue *)oidp->oid_arg1);
	if (!que) return 0;

	val = rd32(que->vsi->hw, que->rxr.tail);
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr)
		return error;
	return (0);
}
#endif

