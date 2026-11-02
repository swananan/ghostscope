#if defined(__aarch64__)
.text
.globl register_ra_caller
.type register_ra_caller, %function
register_ra_caller:
.cfi_startproc
stp x29, x30, [sp, #-16]!
.cfi_def_cfa_offset 16
.cfi_offset 29, -16
.cfi_offset 30, -8
mov x29, x30
.cfi_register 30, 29
bl register_ra_leaf

ldp x29, x30, [sp], #16
.cfi_restore 29
.cfi_def_cfa sp, 0
.cfi_restore 30
ret
.cfi_endproc
.size register_ra_caller, .-register_ra_caller

.section .note.GNU-stack,"",%progbits
#else
	.text
	.globl register_ra_caller
	.type register_ra_caller, @function
register_ra_caller:
	.cfi_startproc
	pushq %rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq 8(%rsp), %rbp
	.cfi_register %rip, %rbp
	call register_ra_leaf
	popq %rbp
	.cfi_restore %rbp
	.cfi_def_cfa_offset 8
	.cfi_restore %rip
	ret
	.cfi_endproc
	.size register_ra_caller, .-register_ra_caller

	.section .note.GNU-stack,"",@progbits
#endif
