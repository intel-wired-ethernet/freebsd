#$FreeBSD$

.PATH:  ${SRCTOP}/sys/dev/ixl

KMOD    = if_ixl
SRCS    = device_if.h bus_if.h pci_if.h ifdi_if.h
SRCS    += opt_inet.h opt_inet6.h opt_rss.h opt_ixl.h opt_iflib.h
SRCS    += if_ixl.c ixl_pf_main.c ixl_pf_qmgr.c ixl_txrx.c ixl_pf_i2c.c i40e_osdep.c

# Shared source
SRCS    += i40e_common.c i40e_nvm.c i40e_adminq.c i40e_lan_hmc.c i40e_hmc.c i40e_dcb.c

CFLAGS	+= -DPCI_IOV
SRCS 	+= pci_iov_if.h ixl_pf_iov.c


CFLAGS	+= -DINVARIANTS -DINVARIANTS_SUPPORT -DWITNESS
.if 0
.if !defined(KERNBUILDDIR)
.if defined(PCI_IOV)
CFLAGS	+= -DPCI_IOV
SRCS 	+= pci_iov_if.h ixl_pf_iov.c
.endif

.if defined(INVARIANTS)
opt_global.h:
	echo "#define INVARIANTS_SUPPORT 1" >> ${.TARGET}
	echo "#define INVARIANTS 1" >> ${.TARGET}
	echo "INVARIANTS defined"
CFLAGS += -include opt_global.h
.endif
.endif
.endif

# Debug messages / sysctls
# CFLAGS += -DIXL_DEBUG

#CFLAGS	+= -DIXL_IW
#SRCS	+= ixl_iw.c

.include <bsd.kmod.mk>
