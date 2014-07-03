/* implementations of byte-at-a-time virtual read/writes for long mode that
   never cause faults/exceptions and maybe do not affect TLB content */

#define NEED_CPU_REG_SHORTCUTS 1
#include "bochs.h"
#include "cpu.h"
#define LOG_THIS BX_CPU_THIS_PTR

    Bit8u BX_CPP_AttrRegparmN(2)
BX_CPU_C::read_virtual_byte_64_nofail(unsigned s, Bit64u offset, uint8_t *error)
{
    Bit8u data;
    Bit64u laddr = get_laddr64(s, offset); // this is safe

    if (! IsCanonical(laddr)) {
        *error = 1;
        return 0;
    }

    access_read_linear_nofail(laddr, 1, 0, BX_READ, (void *) &data, error);
    return data;
}

int BX_CPU_C::access_read_linear_nofail(bx_address laddr, unsigned len, unsigned curr_pl, unsigned xlate_rw, void *data, uint8_t *error)
{
    BX_ASSERT(xlate_rw == BX_READ || xlate_rw == BX_RW); // this is safe

    Bit32u pageOffset = PAGE_OFFSET(laddr); // this is safe

    bx_TLB_entry *tlbEntry = BX_TLB_ENTRY_OF(laddr); // this is safe

    /* next line DOES THE PAGE TABLE WALK */
    BX_CPU_THIS_PTR address_xlation.paddress1 = translate_linear(tlbEntry, laddr, (curr_pl == 3), xlate_rw);
    BX_CPU_THIS_PTR address_xlation.pages     = 1;
    access_read_physical(BX_CPU_THIS_PTR address_xlation.paddress1, len, data);
    /* previous line SHOULD BE SAFE */

    return 0;
}



bx_phy_address BX_CPU_C::translate_linear_nofail(bx_TLB_entry *tlbEntry, bx_address laddr, unsigned user, unsigned rw)
{
    Bit32u combined_access = 0x06;
    Bit32u lpf_mask = 0xfff; // 4K pages

#if BX_SUPPORT_X86_64
    if (! long_mode()) laddr &= 0xffffffff;
#endif

    bx_phy_address paddress, ppf, poffset = PAGE_OFFSET(laddr);
    unsigned isWrite = rw & 1; // write or r-m-w
    unsigned isExecute = (rw == BX_EXECUTE);

    bx_address lpf = LPFOf(laddr);

    if(BX_CPU_THIS_PTR cr0.get_PG())
    {
        BX_DEBUG(("page walk for address 0x" FMT_LIN_ADDRX, laddr));

#if BX_CPU_LEVEL >= 6
#if BX_SUPPORT_X86_64
        if (long_mode())
            paddress = translate_linear_long_mode(laddr, lpf_mask, combined_access, user, rw);
        else
#endif
            if (BX_CPU_THIS_PTR cr4.get_PAE())
                paddress = translate_linear_PAE(laddr, lpf_mask, combined_access, user, rw);
            else
#endif 
                paddress = translate_linear_legacy(laddr, lpf_mask, combined_access, user, rw);

#if BX_CPU_LEVEL >= 5
        if (lpf_mask > 0xfff)
            BX_CPU_THIS_PTR TLB.split_large = 1;
#endif
    }
    else {
        // no paging
        paddress = (bx_phy_address) laddr;
    }

    // Calculate physical memory address and fill in TLB cache entry
#if BX_SUPPORT_VMX >= 2
    if (BX_CPU_THIS_PTR in_vmx_guest) {
        if (SECONDARY_VMEXEC_CONTROL(VMX_VM_EXEC_CTRL3_EPT_ENABLE)) {
            paddress = translate_guest_physical(paddress, laddr, 1, 0, rw);
        }
    }
#endif
#if BX_SUPPORT_SVM
    if (BX_CPU_THIS_PTR in_svm_guest && SVM_NESTED_PAGING_ENABLED) {
        paddress = nested_walk(paddress, rw, 0);
    }
#endif
    paddress = A20ADDR(paddress);
    return paddress;
}
