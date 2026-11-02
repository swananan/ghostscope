#if defined(__aarch64__)
.text
.globl unsupported_cfi_inline_caller
.type unsupported_cfi_inline_caller, %function
unsupported_cfi_inline_caller:
.cfi_startproc
str x30, [sp, #-16]!
.cfi_def_cfa_offset 16
.cfi_offset 30, -16
.cfi_register 30, 19
bl unsupported_cfi_inline_leaf

ldr x30, [sp], #16
.cfi_def_cfa sp, 0
.cfi_restore 30
ret
.cfi_endproc
.size unsupported_cfi_inline_caller, .-unsupported_cfi_inline_caller
.text
.globl unsupported_cfi_tail_caller
.type unsupported_cfi_tail_caller, %function
unsupported_cfi_tail_caller:
.cfi_startproc
str x30, [sp, #-16]!
.cfi_def_cfa_offset 16
.cfi_offset 30, -16
.cfi_register 30, 19
bl unsupported_cfi_tail_level_3

ldr x30, [sp], #16
.cfi_def_cfa sp, 0
.cfi_restore 30
ret
.cfi_endproc
.size unsupported_cfi_tail_caller, .-unsupported_cfi_tail_caller

.section .note.GNU-stack,"",%progbits
#else
	.text
	.globl unsupported_cfi_inline_caller
	.type unsupported_cfi_inline_caller, @function
unsupported_cfi_inline_caller:
	.cfi_startproc
	subq $8, %rsp
	.cfi_def_cfa_offset 16
	.cfi_register %rip, %rbx
	call unsupported_cfi_inline_leaf
	addq $8, %rsp
	.cfi_def_cfa_offset 8
	.cfi_restore %rip
	ret
	.cfi_endproc
	.size unsupported_cfi_inline_caller, .-unsupported_cfi_inline_caller

	.globl unsupported_cfi_tail_caller
	.type unsupported_cfi_tail_caller, @function
unsupported_cfi_tail_caller:
	.cfi_startproc
	subq $8, %rsp
	.cfi_def_cfa_offset 16
	.cfi_register %rip, %rbx
	call unsupported_cfi_tail_level_3
	addq $8, %rsp
	.cfi_def_cfa_offset 8
	.cfi_restore %rip
	ret
	.cfi_endproc
	.size unsupported_cfi_tail_caller, .-unsupported_cfi_tail_caller

	.section .note.GNU-stack,"",@progbits
#endif
