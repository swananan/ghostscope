	.text
	.globl undefined_rbp_inline_caller
	.type undefined_rbp_inline_caller, @function
undefined_rbp_inline_caller:
	.cfi_startproc
	subq $8, %rsp
	.cfi_def_cfa_offset 16
	.cfi_undefined %rbp
	call undefined_rbp_inline_leaf
	addq $8, %rsp
	.cfi_def_cfa_offset 8
	.cfi_restore %rbp
	ret
	.cfi_endproc
	.size undefined_rbp_inline_caller, .-undefined_rbp_inline_caller

	.globl undefined_rbp_inline_outer
	.type undefined_rbp_inline_outer, @function
undefined_rbp_inline_outer:
	.cfi_startproc
	pushq %rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq %rsp, %rbp
	.cfi_def_cfa_register %rbp
	call undefined_rbp_inline_caller
	leave
	.cfi_def_cfa %rsp, 8
	.cfi_restore %rbp
	ret
	.cfi_endproc
	.size undefined_rbp_inline_outer, .-undefined_rbp_inline_outer

	.globl undefined_rbp_ra_inline_caller
	.type undefined_rbp_ra_inline_caller, @function
undefined_rbp_ra_inline_caller:
	.cfi_startproc
	subq $8, %rsp
	.cfi_def_cfa_offset 16
	.cfi_undefined %rbp
	call undefined_rbp_ra_inline_leaf
	addq $8, %rsp
	.cfi_def_cfa_offset 8
	.cfi_restore %rbp
	ret
	.cfi_endproc
	.size undefined_rbp_ra_inline_caller, .-undefined_rbp_ra_inline_caller

	.globl undefined_rbp_ra_inline_outer
	.type undefined_rbp_ra_inline_outer, @function
undefined_rbp_ra_inline_outer:
	.cfi_startproc
	subq $8, %rsp
	.cfi_def_cfa_offset 16
	.cfi_register %rip, %rbp
	call undefined_rbp_ra_inline_caller
	addq $8, %rsp
	.cfi_def_cfa_offset 8
	.cfi_restore %rip
	ret
	.cfi_endproc
	.size undefined_rbp_ra_inline_outer, .-undefined_rbp_ra_inline_outer

	.globl undefined_rbp_tail_caller
	.type undefined_rbp_tail_caller, @function
undefined_rbp_tail_caller:
	.cfi_startproc
	subq $8, %rsp
	.cfi_def_cfa_offset 16
	.cfi_undefined %rbp
	call undefined_rbp_tail_level_2
	addq $8, %rsp
	.cfi_def_cfa_offset 8
	.cfi_restore %rbp
	ret
	.cfi_endproc
	.size undefined_rbp_tail_caller, .-undefined_rbp_tail_caller

	.globl undefined_rbp_tail_outer
	.type undefined_rbp_tail_outer, @function
undefined_rbp_tail_outer:
	.cfi_startproc
	pushq %rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq %rsp, %rbp
	.cfi_def_cfa_register %rbp
	call undefined_rbp_tail_caller
	leave
	.cfi_def_cfa %rsp, 8
	.cfi_restore %rbp
	ret
	.cfi_endproc
	.size undefined_rbp_tail_outer, .-undefined_rbp_tail_outer

	.section .note.GNU-stack,"",@progbits
