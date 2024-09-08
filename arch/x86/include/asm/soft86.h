/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _ASM_X86_SOFT86_H
#define _ASM_X86_SOFT86_H

/*
 * Software execution of x86 opcodes
 *
 * Copyright (C) 2021, Marcos Del Sol Vives <marcos@orca.pet>
 */

#include <linux/types.h>
#include <asm/ptrace.h>

#ifdef CONFIG_X86_INSN_EMU
bool soft86_execute(struct pt_regs *regs);
#else
static inline bool soft86_execute(struct pt_regs *regs)
{
	return false;
}
#endif

#endif /* _ASM_X86_SOFT86_H */
