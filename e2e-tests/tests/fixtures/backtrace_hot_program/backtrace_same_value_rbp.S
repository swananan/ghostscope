	.text
	.globl same_value_rbp_caller
	.type same_value_rbp_caller, @function
same_value_rbp_caller:
	.cfi_startproc
	# The outer frame arranges RSP=RBP+16 before this call. Keep its RBP
	# unchanged while using it as this frame's CFA base.
	.cfi_def_cfa %rbp, 16
	.cfi_offset %rip, -8
	.cfi_same_value %rbp
	subq $8, %rsp
	# A shape-based RBP recovery reads this poison value instead of honoring
	# DW_CFA_same_value, so the following outer-frame unwind fails.
	movq $1, (%rsp)
	call same_value_rbp_leaf
	addq $8, %rsp
	ret
	.cfi_endproc
	.size same_value_rbp_caller, .-same_value_rbp_caller

	.globl same_value_rbp_outer
	.type same_value_rbp_outer, @function
same_value_rbp_outer:
	.cfi_startproc
	pushq %rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	subq $32, %rsp
	.cfi_def_cfa_offset 48
	movq %rsp, %rbp
	.cfi_def_cfa %rbp, 48
	# Put the caller's entry RSP at RBP+8 while retaining ABI call alignment.
	addq $16, %rsp
	call same_value_rbp_caller
	leaq 40(%rbp), %rsp
	.cfi_def_cfa %rsp, 8
	movq -8(%rsp), %rbp
	.cfi_restore %rbp
	ret
	.cfi_endproc
	.size same_value_rbp_outer, .-same_value_rbp_outer

	.section .note.GNU-stack,"",@progbits
