	.text
	.globl undefined_ra_inline_caller
	.type undefined_ra_inline_caller, @function
undefined_ra_inline_caller:
	.cfi_startproc
	subq $8, %rsp
	.cfi_def_cfa_offset 16
	.cfi_undefined %rip
	call undefined_ra_inline_leaf
	addq $8, %rsp
	.cfi_def_cfa_offset 8
	.cfi_restore %rip
	ret
	.cfi_endproc
	.size undefined_ra_inline_caller, .-undefined_ra_inline_caller

	.globl undefined_ra_tail_caller
	.type undefined_ra_tail_caller, @function
undefined_ra_tail_caller:
	.cfi_startproc
	subq $8, %rsp
	.cfi_def_cfa_offset 16
	.cfi_undefined %rip
	call undefined_ra_tail_level_4
	addq $8, %rsp
	.cfi_def_cfa_offset 8
	.cfi_restore %rip
	ret
	.cfi_endproc
	.size undefined_ra_tail_caller, .-undefined_ra_tail_caller

	.section .note.GNU-stack,"",@progbits
