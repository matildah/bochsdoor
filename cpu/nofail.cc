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
