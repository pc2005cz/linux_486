// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Software execution of x86 opcodes
 *
 * Copyright (c) 2021, Marcos Del Sol Vives <marcos@orca.pet>
 */

#include <linux/uaccess.h>

#include <asm/insn.h>
#include <asm/insn-eval.h>
#include <asm/soft86.h>

static bool cmov_check_condition(struct insn *insn, struct pt_regs *regs)
{
	bool result, invert;
	int condition, flags;

	/*
	 * Bits 3-1 of the second opcode byte specify the condition.
	 *
	 * Bit 0 of the second opcode byte is a flag - if set, the result must
	 * be inverted.
	 */
	condition = (insn->opcode.bytes[1] >> 1) & 0x7;
	invert = insn->opcode.bytes[1] & 1;

	flags = regs->flags;
	switch (condition) {
	case 0:
		/*
		 * 0F 40 CMOVO
		 * 0F 41 CMOVNO
		 */
		result = flags & X86_EFLAGS_OF;
		break;

	case 1:
		/*
		 * 0F 42 CMOVC/CMOVNAE
		 * 0F 43 CMOVNC/CMOVNB
		 */
		result = flags & X86_EFLAGS_CF;
		break;

	case 2:
		/*
		 * 0F 44 CMOVE/CMOVZ
		 * 0F 45 CMOVNE/CMOVNZ
		 */
		result = flags & X86_EFLAGS_ZF;
		break;

	case 3:
		/*
		 * 0F 46 CMOVNA/CMOVBE
		 * 0F 47 CMOVA/CMOVNBE
		 */
		result = (flags & X86_EFLAGS_CF) ||
			 (flags & X86_EFLAGS_ZF);
		break;

	case 4:
		/*
		 * 0F 48 CMOVS
		 * 0F 49 CMOVNS
		 */
		result = flags & X86_EFLAGS_SF;
		break;

	case 5:
		/*
		 * 0F 4A CMOVP
		 * 0F 4B CMOVNP
		 */
		result = flags & X86_EFLAGS_PF;
		break;

	case 6:
		/*
		 * 0F 4C CMOVL/CMOVNGE
		 * 0F 4D CMOVNL/CMOVGE
		 */
		result = !!(flags & X86_EFLAGS_SF) !=
			 !!(flags & X86_EFLAGS_OF);
		break;

	case 7:
		/*
		 * 0F 4E CMOVLE/CMOVNG
		 * 0F 4F CMOVNLE/CMOVG
		 */
		result = (flags & X86_EFLAGS_ZF) ||
			 !!(flags & X86_EFLAGS_SF) !=
			 !!(flags & X86_EFLAGS_OF);
		break;
	}

	if (invert)
		result = !result;

	return result;
}

static bool cmov_do_move(struct insn *insn, struct pt_regs *regs)
{
	int reg_off, rm_off;
	void __user *src;
	unsigned char *reg_bytes;

	reg_bytes = (unsigned char *)regs;

	/* Destination, from the REG part of the ModRM */
	reg_off = insn_get_modrm_reg_off(insn, regs);
	if (reg_off < 0)
		return false;

	/* Register to register move */
	if (X86_MODRM_MOD(insn->modrm.value) == 3) {
		rm_off = insn_get_modrm_rm_off(insn, regs);
		if (rm_off < 0)
			return false;

		memcpy(reg_bytes + reg_off, reg_bytes + rm_off,
		       insn->addr_bytes);
	} else {
		/* Source from the RM part of the ModRM */
		src = insn_get_addr_ref(insn, regs);
		if (src == (void __user *)-1L)
			return false;

		if (copy_from_user(reg_bytes + reg_off, src,
	+				   insn->addr_bytes) != 0)
			return false;
	}

	return true;
}

static bool cmov_execute(struct insn *insn, struct pt_regs *regs)
{
	/* CMOV is only supported for 16 and 32-bit registers */
	if (insn->addr_bytes != 2 && insn->addr_bytes != 4)
		return false;

	/* If condition is met, execute the move */
	if (cmov_check_condition(insn, regs)) {
		/* Return false if the operands were invalid */
		if (!cmov_do_move(insn, regs))
			return false;
	}

	return true;
}

bool soft86_execute(struct pt_regs *regs)
{
	int nr_copied;
	unsigned char buf[MAX_INSN_SIZE];
	struct insn insn;
	bool ret;

	/* Read from userspace */
	nr_copied = insn_fetch_from_user(regs, buf);
	if (!nr_copied)
		return false;

	/* Attempt to decode it */
	if (!insn_decode_from_regs(&insn, regs, buf, nr_copied))
		return false;

	/* 0x0F is the two byte opcode escape */
	if (insn.opcode.bytes[0] != 0x0F)
		return false;

	switch (insn.opcode.bytes[1]) {
	case 0x1F:
		/* NOPL, so do nothing */
		ret = true;
		break;

	case 0x40 ... 0x4F:
		/* CMOVxx */
		ret = cmov_execute(&insn, regs);
		break;
	}

	/* Increment the instruction pointer if succeeded */
	if (ret)
		regs->ip += insn.length;

	return ret;
}

