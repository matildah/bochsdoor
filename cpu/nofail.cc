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
    Bit32u combined_access = 0x06;
    Bit32u lpf_mask = 0xfff; // 4K pages
    bx_phy_address paddress, ppf, poffset = PAGE_OFFSET(laddr);

    paddress = translate_linear_long_mode_nofail(laddr, lpf_mask, combined_access, user, xlate_rw);
    paddress = A20ADDR(paddress);
    access_read_physical(paddress, len, data);

    return 0;
}


bx_phy_address BX_CPU_C::translate_linear_long_mode_nofail(bx_address laddr, Bit32u &lpf_mask, Bit32u &combined_access, unsigned user, unsigned rw)
{
  bx_phy_address entry_addr[4];
  bx_phy_address ppf = BX_CPU_THIS_PTR cr3 & BX_CR3_PAGING_MASK;
  Bit64u entry[4];
  bx_bool nx_fault = 0;
  int leaf;

  Bit64u offset_mask = BX_CONST64(0x0000ffffffffffff);
  lpf_mask = 0xfff;
  combined_access = 0x06;

  Bit64u reserved = PAGING_PAE_RESERVED_BITS;
  if (! BX_CPU_THIS_PTR efer.get_NXE())
    reserved |= PAGE_DIRECTORY_NX_BIT;

  for (leaf = BX_LEVEL_PML4;; --leaf) {
    entry_addr[leaf] = ppf + ((laddr >> (9 + 9*leaf)) & 0xff8);
#if BX_SUPPORT_VMX >= 2
    if (BX_CPU_THIS_PTR in_vmx_guest) {
      if (SECONDARY_VMEXEC_CONTROL(VMX_VM_EXEC_CTRL3_EPT_ENABLE))
        entry_addr[leaf] = translate_guest_physical(entry_addr[leaf], laddr, 1, 1, BX_READ);
    }
#endif
#if BX_SUPPORT_SVM
    if (BX_CPU_THIS_PTR in_svm_guest && SVM_NESTED_PAGING_ENABLED) {
      entry_addr[leaf] = nested_walk(entry_addr[leaf], BX_RW, 1);
    }
#endif
    access_read_physical(entry_addr[leaf], 8, &entry[leaf]);
    BX_NOTIFY_PHY_MEMORY_ACCESS(entry_addr[leaf], 8, BX_READ, (BX_PTE_ACCESS + leaf), (Bit8u*)(&entry[leaf]));
    offset_mask >>= 9;

    Bit64u curr_entry = entry[leaf];
    int fault = check_entry_PAE(bx_paging_level[leaf], curr_entry, reserved, rw, &nx_fault);
    if (fault >= 0)
      page_fault(fault, laddr, user, rw);

    combined_access &= curr_entry; // U/S and R/W
    ppf = curr_entry & BX_CONST64(0x000ffffffffff000);

    if (leaf == BX_LEVEL_PTE) break;

    if (curr_entry & 0x80) {
      if (leaf > (BX_LEVEL_PDE + !!bx_cpuid_support_1g_paging())) {
        BX_DEBUG(("PAE %s: PS bit set !", bx_paging_level[leaf]));
        page_fault(ERROR_RESERVED | ERROR_PROTECTION, laddr, user, rw);
      }

      ppf &= BX_CONST64(0x000fffffffffe000);
      if (ppf & offset_mask) {
         BX_DEBUG(("PAE %s: reserved bit is set: 0x" FMT_ADDRX64, bx_paging_level[leaf], curr_entry));
         page_fault(ERROR_RESERVED | ERROR_PROTECTION, laddr, user, rw);
      }

      lpf_mask = (Bit32u) offset_mask;
      break;
    }
  }

  bx_bool isWrite = (rw & 1); // write or r-m-w

  unsigned priv_index = (BX_CPU_THIS_PTR cr0.get_WP() << 4) | // bit 4
                        (user<<3) |                           // bit 3
                        (combined_access | isWrite);          // bit 2,1,0

  if (!priv_check[priv_index] || nx_fault)
    page_fault(ERROR_PROTECTION, laddr, user, rw);

  if (BX_CPU_THIS_PTR cr4.get_SMEP() && rw == BX_EXECUTE && !user) {
    if (combined_access & 0x4) // User page
      page_fault(ERROR_PROTECTION, laddr, user, rw);
  }

  // SMAP protections are disabled if EFLAGS.AC=1
  if (BX_CPU_THIS_PTR cr4.get_SMAP() && ! BX_CPU_THIS_PTR get_AC() && rw != BX_EXECUTE && ! user) {
    if (combined_access & 0x4) // User page
      page_fault(ERROR_PROTECTION, laddr, user, rw);
  }

  if (BX_CPU_THIS_PTR cr4.get_PGE())
    combined_access |= (entry[leaf] & 0x100); // G

  // Update A/D bits if needed
  update_access_dirty_PAE(entry_addr, entry, BX_LEVEL_PML4, leaf, isWrite);

  return ppf | (laddr & offset_mask);
}
