#if defined(__aarch64__)
.text
.globl zero_rbp_tail_boundary
.type zero_rbp_tail_boundary, %function
zero_rbp_tail_boundary:
.cfi_startproc
stp x29, x30, [sp, #-16]!
.cfi_def_cfa_offset 16
.cfi_offset 29, -16
.cfi_offset 30, -8
mov x29, xzr
.cfi_register 30, 29
bl zero_rbp_tail_level_4

ldp x29, x30, [sp], #16
.cfi_restore 29
.cfi_def_cfa sp, 0
.cfi_restore 30
ret
.cfi_endproc
.size zero_rbp_tail_boundary, .-zero_rbp_tail_boundary

.section .note.GNU-stack,"",%progbits
#else
	.text
	.globl zero_rbp_tail_boundary
	.type zero_rbp_tail_boundary, @function
zero_rbp_tail_boundary:
	.cfi_startproc
	pushq %rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	# RBP is available even though its value is zero. The return-address rule
	# uses it to terminate this synthetic stack cleanly at a tail-call boundary.
	xorl %ebp, %ebp
	.cfi_register %rip, %rbp
	call zero_rbp_tail_level_4
	.cfi_restore %rip
	popq %rbp
	.cfi_restore %rbp
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
	.size zero_rbp_tail_boundary, .-zero_rbp_tail_boundary

	.section .note.GNU-stack,"",@progbits
#endif
