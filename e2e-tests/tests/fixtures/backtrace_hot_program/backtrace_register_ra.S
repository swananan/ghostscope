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
