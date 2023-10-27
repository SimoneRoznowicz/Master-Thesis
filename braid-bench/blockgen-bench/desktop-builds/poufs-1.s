	.text
	.file	"poufs.8f3a7672-cgu.0"
	.section	".text._ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h3675e32b8b504c35E","ax",@progbits
	.p2align	4, 0x90
	.type	_ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h3675e32b8b504c35E,@function
_ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h3675e32b8b504c35E:
	.cfi_startproc
	pushq	%rax
	.cfi_def_cfa_offset 16
	movq	(%rdi), %rdi
	callq	_ZN3std10sys_common9backtrace28__rust_begin_short_backtrace17hc9eae246da2e969bE
	xorl	%eax, %eax
	popq	%rcx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end0:
	.size	_ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h3675e32b8b504c35E, .Lfunc_end0-_ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h3675e32b8b504c35E
	.cfi_endproc

	.section	".text._ZN4core3ptr28drop_in_place$LT$$RF$i64$GT$17h97f0ca4d384d7cbeE","ax",@progbits
	.p2align	4, 0x90
	.type	_ZN4core3ptr28drop_in_place$LT$$RF$i64$GT$17h97f0ca4d384d7cbeE,@function
_ZN4core3ptr28drop_in_place$LT$$RF$i64$GT$17h97f0ca4d384d7cbeE:
	.cfi_startproc
	retq
.Lfunc_end1:
	.size	_ZN4core3ptr28drop_in_place$LT$$RF$i64$GT$17h97f0ca4d384d7cbeE, .Lfunc_end1-_ZN4core3ptr28drop_in_place$LT$$RF$i64$GT$17h97f0ca4d384d7cbeE
	.cfi_endproc

	.section	".text._ZN4core3ptr68drop_in_place$LT$alloc..vec..Vec$LT$$u5b$i64$u3b$$u20$1$u5d$$GT$$GT$17hded603570404b0c7E","ax",@progbits
	.p2align	4, 0x90
	.type	_ZN4core3ptr68drop_in_place$LT$alloc..vec..Vec$LT$$u5b$i64$u3b$$u20$1$u5d$$GT$$GT$17hded603570404b0c7E,@function
_ZN4core3ptr68drop_in_place$LT$alloc..vec..Vec$LT$$u5b$i64$u3b$$u20$1$u5d$$GT$$GT$17hded603570404b0c7E:
	.cfi_startproc
	movq	8(%rdi), %rsi
	testq	%rsi, %rsi
	je	.LBB2_3
	movq	(%rdi), %rdi
	testq	%rdi, %rdi
	je	.LBB2_3
	shlq	$3, %rsi
	testq	%rsi, %rsi
	je	.LBB2_3
	movl	$8, %edx
	jmpq	*__rust_dealloc@GOTPCREL(%rip)
.LBB2_3:
	retq
.Lfunc_end2:
	.size	_ZN4core3ptr68drop_in_place$LT$alloc..vec..Vec$LT$$u5b$i64$u3b$$u20$1$u5d$$GT$$GT$17hded603570404b0c7E, .Lfunc_end2-_ZN4core3ptr68drop_in_place$LT$alloc..vec..Vec$LT$$u5b$i64$u3b$$u20$1$u5d$$GT$$GT$17hded603570404b0c7E
	.cfi_endproc

	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4
.LCPI3_0:
	.quad	65536
	.quad	65536
	.section	.text._ZN5poufs5block13compute_group17h1045228d1de64904E,"ax",@progbits
	.p2align	4, 0x90
	.type	_ZN5poufs5block13compute_group17h1045228d1de64904E,@function
_ZN5poufs5block13compute_group17h1045228d1de64904E:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%r13
	.cfi_def_cfa_offset 40
	pushq	%r12
	.cfi_def_cfa_offset 48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	subq	$72, %rsp
	.cfi_def_cfa_offset 128
	.cfi_offset %rbx, -56
	.cfi_offset %r12, -48
	.cfi_offset %r13, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	%rsi, %r14
	movq	%rdi, %r13
	movl	$524288, %edi
	movl	$8, %esi
	callq	*__rust_alloc@GOTPCREL(%rip)
	testq	%rax, %rax
	je	.LBB3_68
	movl	$524288, %edx
	movq	%rax, %r15
	movq	%rax, (%r13)
	movq	%rax, %rdi
	xorl	%esi, %esi
	callq	*memset@GOTPCREL(%rip)
	leaq	(%r14,%r14), %rax
	vmovaps	.LCPI3_0(%rip), %xmm0
	movq	$-1, %r12
	movl	$1, %ebp
	movq	$-1, %r11
	xorl	%r9d, %r9d
	xorl	%ebx, %ebx
	movq	%r13, 40(%rsp)
	xorq	%r14, %rax
	addq	%r14, %rax
	xorq	%r14, %rax
	addq	%r14, %rax
	xorq	%r14, %rax
	addq	%r14, %rax
	xorq	%r14, %rax
	addq	%r14, %rax
	vmovups	%xmm0, 8(%r13)
	xorq	%r14, %rax
	addq	%r14, %rax
	xorq	%r14, %rax
	addq	%r14, %rax
	xorq	%r14, %rax
	addq	%r14, %rax
	xorq	%r14, %rax
	addq	%r14, %rax
	rorxq	$45, %rax, %rdi
	movq	%rdi, 32(%rsp)
	jmp	.LBB3_6
.LBB3_2:
	movq	40(%rsp), %r13
	movq	56(%rsp), %r9
.LBB3_3:
	movq	%rax, %r15
	movq	32(%rsp), %rdi
	movq	48(%rsp), %rbx
	movl	$1, %ebp
.LBB3_5:
	incq	%r11
	cmpq	$17, %rbx
	je	.LBB3_65
.LBB3_6:
	movq	%rbx, %rcx
	movq	%r9, %r10
	incq	%rbx
	shlxq	%rcx, %rbp, %r9
	cmpq	%r10, %r9
	jbe	.LBB3_5
	testq	%rcx, %rcx
	je	.LBB3_60
	movl	%ecx, %eax
	andl	$7, %eax
	leaq	-1(%rcx), %rdx
	movq	%rbx, 48(%rsp)
	movq	%r9, 56(%rsp)
	movq	%rcx, 8(%rsp)
	movq	%rax, 16(%rsp)
	movq	(%r13), %rax
	movl	%r9d, %r13d
	movq	%rdx, 24(%rsp)
	movq	%r10, %rdx
	notq	%rdx
	subl	%r10d, %r13d
	addq	%r9, %rdx
	andq	$3, %r13
	movq	%rdx, 64(%rsp)
	je	.LBB3_20
	movabsq	$9223372036854775800, %rdx
	movq	%rcx, %r9
	xorl	%r8d, %r8d
	movq	%r11, %rcx
	andq	%rdx, %r9
	.p2align	4, 0x90
.LBB3_10:
	cmpq	$7, 24(%rsp)
	leaq	57826(%r10), %rbp
	jae	.LBB3_12
	movq	%r14, %rbx
	xorl	%esi, %esi
	jmp	.LBB3_14
	.p2align	4, 0x90
.LBB3_12:
	movq	%r14, %rbx
	xorl	%esi, %esi
	.p2align	4, 0x90
.LBB3_13:
	movl	%esi, %edi
	addq	$8, %rsi
	shlxq	%rdi, %r12, %rdx
	addl	%ebp, %edx
	movzwl	%dx, %edx
	addq	(%rax,%rdx,8), %rbx
	leal	1(%rdi), %edx
	shlxq	%rdx, %r12, %rdx
	addl	%ebp, %edx
	movzwl	%dx, %edx
	xorq	(%rax,%rdx,8), %rbx
	leal	2(%rdi), %edx
	shlxq	%rdx, %r12, %rdx
	addl	%ebp, %edx
	movzwl	%dx, %edx
	addq	(%rax,%rdx,8), %rbx
	leal	3(%rdi), %edx
	shlxq	%rdx, %r12, %rdx
	addl	%ebp, %edx
	movzwl	%dx, %edx
	xorq	(%rax,%rdx,8), %rbx
	leal	4(%rdi), %edx
	shlxq	%rdx, %r12, %rdx
	addl	%ebp, %edx
	movzwl	%dx, %edx
	addq	(%rax,%rdx,8), %rbx
	leal	5(%rdi), %edx
	shlxq	%rdx, %r12, %rdx
	addl	%ebp, %edx
	movzwl	%dx, %edx
	xorq	(%rax,%rdx,8), %rbx
	leal	6(%rdi), %edx
	shlxq	%rdx, %r12, %rdx
	addl	%ebp, %edx
	movzwl	%dx, %edx
	addq	(%rax,%rdx,8), %rbx
	leal	7(%rdi), %edx
	shlxq	%rdx, %r12, %rdx
	addl	%ebp, %edx
	movzwl	%dx, %edx
	xorq	(%rax,%rdx,8), %rbx
	cmpq	%r9, %rsi
	jne	.LBB3_13
.LBB3_14:
	testb	$7, 8(%rsp)
	movq	%rbx, %rdx
	je	.LBB3_17
	movq	16(%rsp), %rdi
	.p2align	4, 0x90
.LBB3_16:
	shlxq	%rsi, %r12, %rdx
	addl	%ebp, %edx
	movzwl	%dx, %edx
	movq	(%rax,%rdx,8), %rdx
	movq	%rdx, %r11
	xorq	%rbx, %r11
	addq	%rbx, %rdx
	testb	$1, %sil
	leaq	1(%rsi), %rsi
	cmovneq	%r11, %rdx
	decq	%rdi
	movq	%rdx, %rbx
	jne	.LBB3_16
.LBB3_17:
	incq	%r10
	movzwl	%bp, %esi
	movq	%rcx, %r11
	movq	%rcx, %rdi
	.p2align	4, 0x90
.LBB3_18:
	incq	%rdi
	movq	%rdx, %rbp
	xorq	%r14, %rbp
	addq	%r14, %rdx
	testb	$1, %dil
	cmovneq	%rbp, %rdx
	cmpq	$16, %rdi
	jb	.LBB3_18
	rorxq	$45, %rdx, %rdx
	incq	%r8
	movq	%rdx, (%r15,%rsi,8)
	cmpq	%r13, %r8
	jne	.LBB3_10
.LBB3_20:
	cmpq	$3, 64(%rsp)
	jb	.LBB3_2
	movq	8(%rsp), %r8
	movq	40(%rsp), %r13
	movq	56(%rsp), %r9
	movabsq	$9223372036854775800, %rdx
	andq	%rdx, %r8
	.p2align	4, 0x90
.LBB3_22:
	cmpq	$7, 24(%rsp)
	leaq	57826(%r10), %rbp
	jae	.LBB3_24
	movq	%r14, %rbx
	xorl	%esi, %esi
	jmp	.LBB3_26
	.p2align	4, 0x90
.LBB3_24:
	movq	%r14, %rbx
	xorl	%esi, %esi
	.p2align	4, 0x90
.LBB3_25:
	movl	%esi, %edx
	addq	$8, %rsi
	shlxq	%rdx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	addq	(%rax,%rcx,8), %rbx
	leal	1(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	xorq	(%rax,%rcx,8), %rbx
	leal	2(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	addq	(%rax,%rcx,8), %rbx
	leal	3(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	xorq	(%rax,%rcx,8), %rbx
	leal	4(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	addq	(%rax,%rcx,8), %rbx
	leal	5(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	xorq	(%rax,%rcx,8), %rbx
	leal	6(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	addq	(%rax,%rcx,8), %rbx
	leal	7(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	xorq	(%rax,%rcx,8), %rbx
	cmpq	%r8, %rsi
	jne	.LBB3_25
.LBB3_26:
	testb	$7, 8(%rsp)
	movq	%rbx, %rdx
	je	.LBB3_29
	movq	16(%rsp), %rdi
	.p2align	4, 0x90
.LBB3_28:
	shlxq	%rsi, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	movq	(%rax,%rcx,8), %rdx
	movq	%rdx, %rcx
	xorq	%rbx, %rcx
	addq	%rbx, %rdx
	testb	$1, %sil
	leaq	1(%rsi), %rsi
	cmovneq	%rcx, %rdx
	decq	%rdi
	movq	%rdx, %rbx
	jne	.LBB3_28
.LBB3_29:
	movzwl	%bp, %esi
	movq	%r11, %rdi
	.p2align	4, 0x90
.LBB3_30:
	incq	%rdi
	movq	%rdx, %rcx
	xorq	%r14, %rcx
	addq	%r14, %rdx
	testb	$1, %dil
	cmovneq	%rcx, %rdx
	cmpq	$16, %rdi
	jb	.LBB3_30
	cmpq	$7, 24(%rsp)
	leaq	57827(%r10), %rbp
	rorxq	$45, %rdx, %rdx
	movq	%rdx, (%r15,%rsi,8)
	jae	.LBB3_33
	movq	%r14, %rbx
	xorl	%esi, %esi
	jmp	.LBB3_35
	.p2align	4, 0x90
.LBB3_33:
	movq	%r14, %rbx
	xorl	%esi, %esi
	.p2align	4, 0x90
.LBB3_34:
	movl	%esi, %edx
	addq	$8, %rsi
	shlxq	%rdx, %r12, %rdi
	addl	%ebp, %edi
	movzwl	%di, %edi
	addq	(%rax,%rdi,8), %rbx
	leal	1(%rdx), %edi
	shlxq	%rdi, %r12, %rdi
	addl	%ebp, %edi
	movzwl	%di, %edi
	xorq	(%rax,%rdi,8), %rbx
	leal	2(%rdx), %edi
	shlxq	%rdi, %r12, %rdi
	addl	%ebp, %edi
	movzwl	%di, %edi
	addq	(%rax,%rdi,8), %rbx
	leal	3(%rdx), %edi
	shlxq	%rdi, %r12, %rdi
	addl	%ebp, %edi
	movzwl	%di, %edi
	xorq	(%rax,%rdi,8), %rbx
	leal	4(%rdx), %edi
	shlxq	%rdi, %r12, %rdi
	addl	%ebp, %edi
	movzwl	%di, %edi
	addq	(%rax,%rdi,8), %rbx
	leal	5(%rdx), %edi
	shlxq	%rdi, %r12, %rdi
	addl	%ebp, %edi
	movzwl	%di, %edi
	xorq	(%rax,%rdi,8), %rbx
	leal	6(%rdx), %edi
	addl	$7, %edx
	shlxq	%rdi, %r12, %rdi
	shlxq	%rdx, %r12, %rdx
	addl	%ebp, %edi
	addl	%ebp, %edx
	movzwl	%di, %edi
	movzwl	%dx, %edx
	addq	(%rax,%rdi,8), %rbx
	xorq	(%rax,%rdx,8), %rbx
	cmpq	%r8, %rsi
	jne	.LBB3_34
.LBB3_35:
	testb	$7, 8(%rsp)
	movq	%rbx, %rdx
	je	.LBB3_38
	movq	16(%rsp), %rdi
	.p2align	4, 0x90
.LBB3_37:
	shlxq	%rsi, %r12, %rdx
	addl	%ebp, %edx
	movzwl	%dx, %edx
	movq	(%rax,%rdx,8), %rdx
	movq	%rdx, %rcx
	xorq	%rbx, %rcx
	addq	%rbx, %rdx
	testb	$1, %sil
	leaq	1(%rsi), %rsi
	cmovneq	%rcx, %rdx
	decq	%rdi
	movq	%rdx, %rbx
	jne	.LBB3_37
.LBB3_38:
	movzwl	%bp, %esi
	movq	%r11, %rdi
	.p2align	4, 0x90
.LBB3_39:
	incq	%rdi
	movq	%rdx, %rcx
	xorq	%r14, %rcx
	addq	%r14, %rdx
	testb	$1, %dil
	cmovneq	%rcx, %rdx
	cmpq	$16, %rdi
	jb	.LBB3_39
	cmpq	$7, 24(%rsp)
	leaq	57828(%r10), %rbp
	rorxq	$45, %rdx, %rcx
	movq	%rcx, (%r15,%rsi,8)
	jae	.LBB3_42
	movq	%r14, %rbx
	xorl	%esi, %esi
	jmp	.LBB3_44
	.p2align	4, 0x90
.LBB3_42:
	movq	%r14, %rbx
	xorl	%esi, %esi
	.p2align	4, 0x90
.LBB3_43:
	movl	%esi, %edx
	addq	$8, %rsi
	shlxq	%rdx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	addq	(%rax,%rcx,8), %rbx
	leal	1(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	xorq	(%rax,%rcx,8), %rbx
	leal	2(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	addq	(%rax,%rcx,8), %rbx
	leal	3(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	xorq	(%rax,%rcx,8), %rbx
	leal	4(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	addq	(%rax,%rcx,8), %rbx
	leal	5(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	xorq	(%rax,%rcx,8), %rbx
	leal	6(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	addq	(%rax,%rcx,8), %rbx
	leal	7(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	xorq	(%rax,%rcx,8), %rbx
	cmpq	%r8, %rsi
	jne	.LBB3_43
.LBB3_44:
	testb	$7, 8(%rsp)
	movq	%rbx, %rdx
	je	.LBB3_47
	movq	16(%rsp), %rdi
	.p2align	4, 0x90
.LBB3_46:
	shlxq	%rsi, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	movq	(%rax,%rcx,8), %rdx
	movq	%rdx, %rcx
	xorq	%rbx, %rcx
	addq	%rbx, %rdx
	testb	$1, %sil
	leaq	1(%rsi), %rsi
	cmovneq	%rcx, %rdx
	decq	%rdi
	movq	%rdx, %rbx
	jne	.LBB3_46
.LBB3_47:
	movzwl	%bp, %esi
	movq	%r11, %rdi
	.p2align	4, 0x90
.LBB3_48:
	incq	%rdi
	movq	%rdx, %rcx
	xorq	%r14, %rcx
	addq	%r14, %rdx
	testb	$1, %dil
	cmovneq	%rcx, %rdx
	cmpq	$16, %rdi
	jb	.LBB3_48
	cmpq	$7, 24(%rsp)
	leaq	57829(%r10), %rbp
	rorxq	$45, %rdx, %rcx
	movq	%rcx, (%r15,%rsi,8)
	jae	.LBB3_51
	movq	%r14, %rbx
	xorl	%esi, %esi
	jmp	.LBB3_53
	.p2align	4, 0x90
.LBB3_51:
	movq	%r14, %rbx
	xorl	%esi, %esi
	.p2align	4, 0x90
.LBB3_52:
	movl	%esi, %edx
	addq	$8, %rsi
	shlxq	%rdx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	addq	(%rax,%rcx,8), %rbx
	leal	1(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	xorq	(%rax,%rcx,8), %rbx
	leal	2(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	addq	(%rax,%rcx,8), %rbx
	leal	3(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	xorq	(%rax,%rcx,8), %rbx
	leal	4(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	addq	(%rax,%rcx,8), %rbx
	leal	5(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	xorq	(%rax,%rcx,8), %rbx
	leal	6(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	addq	(%rax,%rcx,8), %rbx
	leal	7(%rdx), %ecx
	shlxq	%rcx, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	xorq	(%rax,%rcx,8), %rbx
	cmpq	%r8, %rsi
	jne	.LBB3_52
.LBB3_53:
	testb	$7, 8(%rsp)
	movq	%rbx, %rdx
	je	.LBB3_56
	movq	16(%rsp), %rdi
	.p2align	4, 0x90
.LBB3_55:
	shlxq	%rsi, %r12, %rcx
	addl	%ebp, %ecx
	movzwl	%cx, %ecx
	movq	(%rax,%rcx,8), %rdx
	movq	%rdx, %rcx
	xorq	%rbx, %rcx
	addq	%rbx, %rdx
	testb	$1, %sil
	leaq	1(%rsi), %rsi
	cmovneq	%rcx, %rdx
	decq	%rdi
	movq	%rdx, %rbx
	jne	.LBB3_55
.LBB3_56:
	addq	$4, %r10
	movzwl	%bp, %esi
	movq	%r11, %rdi
	.p2align	4, 0x90
.LBB3_57:
	incq	%rdi
	movq	%rdx, %rcx
	xorq	%r14, %rcx
	addq	%r14, %rdx
	testb	$1, %dil
	cmovneq	%rcx, %rdx
	cmpq	$16, %rdi
	jb	.LBB3_57
	rorxq	$45, %rdx, %rcx
	movq	%rcx, (%r15,%rsi,8)
	cmpq	%r9, %r10
	jne	.LBB3_22
	jmp	.LBB3_3
.LBB3_60:
	movl	%r9d, %edx
	movq	%r10, %rax
	notq	%rax
	subl	%r10d, %edx
	addq	%r9, %rax
	andq	$7, %rdx
	je	.LBB3_62
	.p2align	4, 0x90
.LBB3_61:
	leal	57826(%r10), %esi
	incq	%r10
	decq	%rdx
	movzwl	%si, %esi
	movq	%rdi, (%r15,%rsi,8)
	jne	.LBB3_61
.LBB3_62:
	cmpq	$7, %rax
	jb	.LBB3_5
	movq	%r9, %rax
	negq	%rax
	addq	$57833, %r10
	.p2align	4, 0x90
.LBB3_64:
	leal	-7(%r10), %ecx
	leaq	8(%rax,%r10), %rdx
	movzwl	%cx, %ecx
	movq	%rdi, (%r15,%rcx,8)
	leal	-6(%r10), %ecx
	movzwl	%cx, %ecx
	movq	%rdi, (%r15,%rcx,8)
	leal	-5(%r10), %ecx
	movzwl	%cx, %ecx
	movq	%rdi, (%r15,%rcx,8)
	leal	-4(%r10), %ecx
	movzwl	%cx, %ecx
	movq	%rdi, (%r15,%rcx,8)
	leal	-3(%r10), %ecx
	movzwl	%cx, %ecx
	movq	%rdi, (%r15,%rcx,8)
	leal	-2(%r10), %ecx
	movzwl	%cx, %ecx
	movq	%rdi, (%r15,%rcx,8)
	leal	-1(%r10), %ecx
	movzwl	%cx, %ecx
	movq	%rdi, (%r15,%rcx,8)
	movzwl	%r10w, %ecx
	addq	$8, %r10
	movq	%rdi, (%r15,%rcx,8)
	cmpq	$57833, %rdx
	jne	.LBB3_64
	jmp	.LBB3_5
.LBB3_65:
	movq	(%r13), %rax
	movl	$123367, %ecx
	.p2align	4, 0x90
.LBB3_66:
	leal	-6(%rcx), %esi
	leal	-7(%rcx), %ebp
	leal	-9(%rcx), %r10d
	leal	-13(%rcx), %edi
	leal	-37(%rcx), %ebx
	leal	-5(%rcx), %r15d
	leal	-34(%rcx), %edx
	movzwl	%si, %r9d
	andl	$65534, %ebp
	andl	$65534, %r10d
	andl	$65534, %edi
	andl	$65534, %ebx
	andl	$65534, %r15d
	movzwl	%dx, %edx
	movq	(%rax,%r9,8), %rsi
	addq	%r14, %rsi
	xorq	(%rax,%rbp,8), %rsi
	addq	(%rax,%r10,8), %rsi
	xorq	(%rax,%rdi,8), %rsi
	leal	-21(%rcx), %edi
	andl	$65534, %edi
	addq	(%rax,%rdi,8), %rsi
	leal	-69(%rcx), %edi
	xorq	(%rax,%rbx,8), %rsi
	leal	-133(%rcx), %ebx
	andl	$65534, %edi
	addq	(%rax,%rdi,8), %rsi
	leal	-261(%rcx), %edi
	andl	$65534, %ebx
	xorq	(%rax,%rbx,8), %rsi
	leal	-517(%rcx), %ebx
	andl	$65534, %edi
	addq	(%rax,%rdi,8), %rsi
	leal	-1029(%rcx), %edi
	andl	$65534, %ebx
	xorq	(%rax,%rbx,8), %rsi
	leal	-2053(%rcx), %ebx
	andl	$65534, %edi
	addq	(%rax,%rdi,8), %rsi
	leal	-4101(%rcx), %edi
	andl	$65534, %ebx
	xorq	(%rax,%rbx,8), %rsi
	leal	-8197(%rcx), %ebx
	andl	$65534, %edi
	addq	(%rax,%rdi,8), %rsi
	leal	-16389(%rcx), %edi
	andl	$65534, %ebx
	xorq	(%rax,%rbx,8), %rsi
	leal	-32773(%rcx), %ebx
	andl	$65534, %edi
	addq	(%rax,%rdi,8), %rsi
	andl	$65534, %ebx
	leal	-4(%rcx), %edi
	xorq	(%rax,%rbx,8), %rsi
	leal	-8(%rcx), %ebx
	movzwl	%di, %r11d
	leal	-11(%rcx), %edi
	addq	(%rax,%r15,8), %rsi
	movzwl	%bx, %r8d
	leal	-12(%rcx), %ebx
	andl	$65534, %edi
	movzwl	%bx, %ebx
	rorxq	$45, %rsi, %rsi
	movq	%rsi, (%rax,%r15,8)
	addq	%r14, %rsi
	xorq	(%rax,%r9,8), %rsi
	addq	(%rax,%r8,8), %rsi
	xorq	(%rax,%rbx,8), %rsi
	leal	-20(%rcx), %ebx
	movzwl	%bx, %ebx
	addq	(%rax,%rbx,8), %rsi
	leal	-36(%rcx), %ebx
	movzwl	%bx, %ebx
	xorq	(%rax,%rbx,8), %rsi
	leal	-68(%rcx), %ebx
	movzwl	%bx, %ebx
	addq	(%rax,%rbx,8), %rsi
	leal	-132(%rcx), %ebx
	movzwl	%bx, %ebx
	xorq	(%rax,%rbx,8), %rsi
	leal	-260(%rcx), %ebx
	movzwl	%bx, %ebx
	addq	(%rax,%rbx,8), %rsi
	leal	-516(%rcx), %ebx
	movzwl	%bx, %ebx
	xorq	(%rax,%rbx,8), %rsi
	leal	-1028(%rcx), %ebx
	movzwl	%bx, %ebx
	addq	(%rax,%rbx,8), %rsi
	leal	-2052(%rcx), %ebx
	movzwl	%bx, %ebx
	xorq	(%rax,%rbx,8), %rsi
	leal	-4100(%rcx), %ebx
	movzwl	%bx, %ebx
	addq	(%rax,%rbx,8), %rsi
	leal	-8196(%rcx), %ebx
	movzwl	%bx, %ebx
	xorq	(%rax,%rbx,8), %rsi
	leal	-16388(%rcx), %ebx
	movzwl	%bx, %ebx
	addq	(%rax,%rbx,8), %rsi
	leal	-32772(%rcx), %ebx
	movzwl	%bx, %ebx
	xorq	(%rax,%rbx,8), %rsi
	addq	(%rax,%r11,8), %rsi
	rorxq	$45, %rsi, %rbx
	leal	-3(%rcx), %esi
	movq	%rbx, (%rax,%r11,8)
	addq	%r14, %rbx
	andl	$65534, %esi
	xorq	(%rax,%r15,8), %rbx
	addq	(%rax,%rbp,8), %rbx
	leal	-35(%rcx), %ebp
	xorq	(%rax,%rdi,8), %rbx
	leal	-19(%rcx), %edi
	andl	$65534, %ebp
	andl	$65534, %edi
	addq	(%rax,%rdi,8), %rbx
	leal	-67(%rcx), %edi
	xorq	(%rax,%rbp,8), %rbx
	leal	-131(%rcx), %ebp
	andl	$65534, %edi
	addq	(%rax,%rdi,8), %rbx
	leal	-259(%rcx), %edi
	andl	$65534, %ebp
	xorq	(%rax,%rbp,8), %rbx
	leal	-515(%rcx), %ebp
	andl	$65534, %edi
	addq	(%rax,%rdi,8), %rbx
	leal	-1027(%rcx), %edi
	andl	$65534, %ebp
	xorq	(%rax,%rbp,8), %rbx
	leal	-2051(%rcx), %ebp
	andl	$65534, %edi
	addq	(%rax,%rdi,8), %rbx
	leal	-4099(%rcx), %edi
	andl	$65534, %ebp
	xorq	(%rax,%rbp,8), %rbx
	leal	-8195(%rcx), %ebp
	andl	$65534, %edi
	addq	(%rax,%rdi,8), %rbx
	leal	-16387(%rcx), %edi
	andl	$65534, %ebp
	xorq	(%rax,%rbp,8), %rbx
	leal	-32771(%rcx), %ebp
	andl	$65534, %edi
	addq	(%rax,%rdi,8), %rbx
	andl	$65534, %ebp
	xorq	(%rax,%rbp,8), %rbx
	leal	-10(%rcx), %ebp
	addq	(%rax,%rsi,8), %rbx
	movzwl	%bp, %ebp
	rorxq	$45, %rbx, %rdi
	leal	-2(%rcx), %ebx
	movq	%rdi, (%rax,%rsi,8)
	addq	%r14, %rdi
	xorq	(%rax,%r11,8), %rdi
	addq	(%rax,%r9,8), %rdi
	xorq	(%rax,%rbp,8), %rdi
	leal	-18(%rcx), %ebp
	movzwl	%bp, %ebp
	addq	(%rax,%rbp,8), %rdi
	leal	-130(%rcx), %ebp
	xorq	(%rax,%rdx,8), %rdi
	leal	-66(%rcx), %edx
	movzwl	%bp, %ebp
	movzwl	%dx, %edx
	addq	(%rax,%rdx,8), %rdi
	leal	-258(%rcx), %edx
	xorq	(%rax,%rbp,8), %rdi
	leal	-514(%rcx), %ebp
	movzwl	%dx, %edx
	addq	(%rax,%rdx,8), %rdi
	leal	-1026(%rcx), %edx
	movzwl	%bp, %ebp
	xorq	(%rax,%rbp,8), %rdi
	leal	-2050(%rcx), %ebp
	movzwl	%dx, %edx
	addq	(%rax,%rdx,8), %rdi
	leal	-4098(%rcx), %edx
	movzwl	%bp, %ebp
	xorq	(%rax,%rbp,8), %rdi
	leal	-8194(%rcx), %ebp
	movzwl	%dx, %edx
	addq	(%rax,%rdx,8), %rdi
	leal	-16386(%rcx), %edx
	movzwl	%bp, %ebp
	xorq	(%rax,%rbp,8), %rdi
	leal	-32770(%rcx), %ebp
	movzwl	%dx, %edx
	addq	(%rax,%rdx,8), %rdi
	movzwl	%bp, %ebp
	leal	-17(%rcx), %edx
	xorq	(%rax,%rbp,8), %rdi
	movzwl	%bx, %ebp
	andl	$65534, %edx
	addq	(%rax,%rbp,8), %rdi
	rorxq	$45, %rdi, %rbx
	leal	-1(%rcx), %edi
	movq	%rbx, (%rax,%rbp,8)
	addq	%r14, %rbx
	andl	$65534, %edi
	xorq	(%rax,%rsi,8), %rbx
	leal	-65(%rcx), %esi
	addq	(%rax,%r15,8), %rbx
	andl	$65534, %esi
	xorq	(%rax,%r10,8), %rbx
	addq	(%rax,%rdx,8), %rbx
	leal	-33(%rcx), %edx
	andl	$65534, %edx
	xorq	(%rax,%rdx,8), %rbx
	leal	-129(%rcx), %edx
	addq	(%rax,%rsi,8), %rbx
	leal	-257(%rcx), %esi
	andl	$65534, %edx
	xorq	(%rax,%rdx,8), %rbx
	leal	-513(%rcx), %edx
	andl	$65534, %esi
	addq	(%rax,%rsi,8), %rbx
	leal	-1025(%rcx), %esi
	andl	$65534, %edx
	xorq	(%rax,%rdx,8), %rbx
	leal	-2049(%rcx), %edx
	andl	$65534, %esi
	addq	(%rax,%rsi,8), %rbx
	leal	-4097(%rcx), %esi
	andl	$65534, %edx
	xorq	(%rax,%rdx,8), %rbx
	leal	-8193(%rcx), %edx
	andl	$65534, %esi
	addq	(%rax,%rsi,8), %rbx
	leal	-16385(%rcx), %esi
	andl	$65534, %edx
	xorq	(%rax,%rdx,8), %rbx
	leal	-32769(%rcx), %edx
	andl	$65534, %esi
	addq	(%rax,%rsi,8), %rbx
	andl	$65534, %edx
	leal	-16(%rcx), %esi
	xorq	(%rax,%rdx,8), %rbx
	movzwl	%si, %esi
	addq	(%rax,%rdi,8), %rbx
	rorxq	$45, %rbx, %rdx
	movq	%rdx, (%rax,%rdi,8)
	addq	%r14, %rdx
	xorq	(%rax,%rbp,8), %rdx
	addq	(%rax,%r11,8), %rdx
	xorq	(%rax,%r8,8), %rdx
	addq	(%rax,%rsi,8), %rdx
	leal	-32(%rcx), %esi
	movzwl	%si, %esi
	xorq	(%rax,%rsi,8), %rdx
	leal	-64(%rcx), %esi
	movzwl	%si, %esi
	addq	(%rax,%rsi,8), %rdx
	leal	-128(%rcx), %esi
	movzwl	%si, %esi
	xorq	(%rax,%rsi,8), %rdx
	leal	-256(%rcx), %esi
	movzwl	%si, %esi
	addq	(%rax,%rsi,8), %rdx
	leal	-512(%rcx), %esi
	movzwl	%si, %esi
	xorq	(%rax,%rsi,8), %rdx
	leal	-1024(%rcx), %esi
	movzwl	%si, %esi
	addq	(%rax,%rsi,8), %rdx
	leal	-2048(%rcx), %esi
	movzwl	%si, %esi
	xorq	(%rax,%rsi,8), %rdx
	leal	-4096(%rcx), %esi
	movzwl	%si, %esi
	addq	(%rax,%rsi,8), %rdx
	leal	-8192(%rcx), %esi
	movzwl	%si, %esi
	xorq	(%rax,%rsi,8), %rdx
	leal	-16384(%rcx), %esi
	movzwl	%si, %esi
	addq	(%rax,%rsi,8), %rdx
	leal	-32768(%rcx), %esi
	movzwl	%si, %esi
	xorq	(%rax,%rsi,8), %rdx
	movzwl	%cx, %esi
	addq	$6, %rcx
	addq	(%rax,%rsi,8), %rdx
	rorxq	$45, %rdx, %rdx
	movq	%rdx, (%rax,%rsi,8)
	cmpq	$1114117, %rcx
	jne	.LBB3_66
	addq	$72, %rsp
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%r12
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.LBB3_68:
	.cfi_def_cfa_offset 128
	movl	$524288, %edi
	movl	$8, %esi
	callq	*_ZN5alloc5alloc18handle_alloc_error17hfe0de613579df40dE@GOTPCREL(%rip)
	ud2
.Lfunc_end3:
	.size	_ZN5poufs5block13compute_group17h1045228d1de64904E, .Lfunc_end3-_ZN5poufs5block13compute_group17h1045228d1de64904E
	.cfi_endproc

	.section	.rodata.cst4,"aM",@progbits,4
	.p2align	2
.LCPI4_0:
	.long	0x447a0000
.LCPI4_1:
	.long	0x49800000
.LCPI4_2:
	.long	0x4dfa0000
.LCPI4_3:
	.long	0x49742400
.LCPI4_4:
	.long	0x4b88ffff
	.section	.text._ZN5poufs4main17h035f03ee3a9dc028E,"ax",@progbits
	.p2align	4, 0x90
	.type	_ZN5poufs4main17h035f03ee3a9dc028E,@function
_ZN5poufs4main17h035f03ee3a9dc028E:
.Lfunc_begin0:
	.cfi_startproc
	.cfi_personality 155, DW.ref.rust_eh_personality
	.cfi_lsda 27, .Lexception0
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%r13
	.cfi_def_cfa_offset 40
	pushq	%r12
	.cfi_def_cfa_offset 48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	subq	$104, %rsp
	.cfi_def_cfa_offset 160
	.cfi_offset %rbx, -56
	.cfi_offset %r12, -48
	.cfi_offset %r13, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	_ZN4core3fmt3num3imp54_$LT$impl$u20$core..fmt..Display$u20$for$u20$usize$GT$3fmt17h06d9fc27024febb0E@GOTPCREL(%rip), %rdx
	movq	_ZN3std2io5stdio6_print17hcbc8e5359e4501b6E@GOTPCREL(%rip), %rbp
	leaq	.L__unnamed_1(%rip), %rax
	leaq	.L__unnamed_2(%rip), %rcx
	leaq	56(%rsp), %rbx
	movq	%rsp, %r15
	movq	%r15, %rdi
	movq	%rax, 56(%rsp)
	movq	%rcx, (%rsp)
	movq	$2, 8(%rsp)
	movq	$0, 16(%rsp)
	movq	%rbx, 32(%rsp)
	movq	$1, 40(%rsp)
	movq	%rdx, 64(%rsp)
	callq	*%rbp
	movq	_ZN4core3fmt5float52_$LT$impl$u20$core..fmt..Display$u20$for$u20$f32$GT$3fmt17ha80c19f9318342c9E@GOTPCREL(%rip), %rdx
	leaq	.L__unnamed_3(%rip), %rax
	leaq	.L__unnamed_4(%rip), %rcx
	movq	%rsp, %r14
	movq	%r14, %rdi
	movq	%rax, 56(%rsp)
	movq	%rcx, (%rsp)
	movq	$2, 8(%rsp)
	movq	$0, 16(%rsp)
	movq	%rbx, 32(%rsp)
	movq	$1, 40(%rsp)
	movq	%rdx, 64(%rsp)
	callq	*%rbp
	movq	__rust_dealloc@GOTPCREL(%rip), %r12
	movl	$727, %ebx
	movl	$256, %ebp
	jmp	.LBB4_1
	.p2align	4, 0x90
.LBB4_7:
	decq	%rbp
	je	.LBB4_8
.LBB4_1:
	movq	%r15, %rdi
	movq	%rbx, %rsi
	callq	_ZN5poufs5block13compute_group17h1045228d1de64904E
	movq	16(%rsp), %rsi
	cmpq	$65535, %rsi
	jbe	.LBB4_2
	movq	(%rsp), %rdi
	movq	8(%rsp), %rsi
	movq	524280(%rdi), %rbx
	movq	%rbx, 80(%rsp)
	testq	%rsi, %rsi
	je	.LBB4_7
	shlq	$3, %rsi
	testq	%rsi, %rsi
	je	.LBB4_7
	movl	$8, %edx
	callq	*%r12
	jmp	.LBB4_7
.LBB4_8:
	leaq	.L__unnamed_5(%rip), %rax
	leaq	.L__unnamed_6(%rip), %rcx
	movq	%rsp, %r14
	movq	%r14, %rdi
	movq	%rax, (%rsp)
	movq	$1, 8(%rsp)
	movq	$0, 16(%rsp)
	movq	%rcx, 32(%rsp)
	movq	$0, 40(%rsp)
	callq	*_ZN3std2io5stdio6_print17hcbc8e5359e4501b6E@GOTPCREL(%rip)
	xorl	%r15d, %r15d
	jmp	.LBB4_9
	.p2align	4, 0x90
.LBB4_14:
	leaq	88(%rsp), %rdi
	callq	*_ZN3std4time7Instant7elapsed17h1d42061bc4e5948dE@GOTPCREL(%rip)
	movl	%edx, %ecx
	movq	%rax, %rdx
	movl	$1000000, %eax
	movl	%ecx, %ecx
	imulq	$274877907, %rcx, %rdi
	mulxq	%rax, %rax, %rsi
	shrq	$38, %rdi
	addq	%rax, %rdi
	adcq	$0, %rsi
	shrq	$8, %rdi
	movq	%rsi, %rax
	shlq	$56, %rax
	shrq	$8, %rsi
	orq	%rax, %rdi
	callq	*__floattisf@GOTPCREL(%rip)
	vdivss	.LCPI4_0(%rip), %xmm0, %xmm0
	movq	_ZN4core3fmt5float52_$LT$impl$u20$core..fmt..Display$u20$for$u20$f32$GT$3fmt17ha80c19f9318342c9E@GOTPCREL(%rip), %r13
	movq	_ZN3std2io5stdio6_print17hcbc8e5359e4501b6E@GOTPCREL(%rip), %rbp
	leaq	48(%rsp), %rax
	movl	%r15d, 76(%rsp)
	leaq	.L__unnamed_7(%rip), %r15
	leaq	56(%rsp), %r12
	movq	%r14, %rdi
	movq	%rax, 56(%rsp)
	leaq	.L__unnamed_8(%rip), %rax
	movq	%rax, (%rsp)
	movq	$2, 8(%rsp)
	movq	%r15, 16(%rsp)
	movq	$1, 24(%rsp)
	movq	%r12, 32(%rsp)
	movq	$1, 40(%rsp)
	movq	%r13, 64(%rsp)
	vmovss	%xmm0, 48(%rsp)
	callq	*%rbp
	vmovss	.LCPI4_1(%rip), %xmm0
	vmovss	.LCPI4_2(%rip), %xmm1
	leaq	52(%rsp), %rax
	movq	%r14, %rdi
	vmulss	48(%rsp), %xmm0, %xmm0
	movq	%rax, 56(%rsp)
	leaq	.L__unnamed_9(%rip), %rax
	movq	%r13, 64(%rsp)
	movq	%r12, %r13
	movq	%rax, (%rsp)
	movq	$2, 8(%rsp)
	movq	%r15, 16(%rsp)
	movq	$1, 24(%rsp)
	movq	%r12, 32(%rsp)
	movq	$1, 40(%rsp)
	vdivss	%xmm0, %xmm1, %xmm0
	vmovss	%xmm0, 52(%rsp)
	callq	*%rbp
	vmovss	.LCPI4_3(%rip), %xmm0
	vmovss	.LCPI4_4(%rip), %xmm1
	leaq	52(%rsp), %rax
	movl	76(%rsp), %r15d
	movq	__rust_dealloc@GOTPCREL(%rip), %r12
	movq	%r14, %rdi
	vmulss	48(%rsp), %xmm0, %xmm0
	movq	%rax, 56(%rsp)
	movq	_ZN4core3fmt5float52_$LT$impl$u20$core..fmt..Display$u20$for$u20$f32$GT$3fmt17ha80c19f9318342c9E@GOTPCREL(%rip), %rax
	movq	%rax, 64(%rsp)
	leaq	.L__unnamed_10(%rip), %rax
	movq	%rax, (%rsp)
	leaq	.L__unnamed_7(%rip), %rax
	movq	$2, 8(%rsp)
	movq	%rax, 16(%rsp)
	movq	$1, 24(%rsp)
	movq	%r13, 32(%rsp)
	movq	$1, 40(%rsp)
	vdivss	%xmm0, %xmm1, %xmm0
	vmovss	%xmm0, 52(%rsp)
	callq	*%rbp
	cmpl	$5, %r15d
	je	.LBB4_15
.LBB4_9:
	incl	%r15d
	callq	*_ZN3std4time7Instant3now17h96d387d8dbcab72dE@GOTPCREL(%rip)
	movl	$256, %ebp
	movq	%rax, 88(%rsp)
	movq	%rdx, 96(%rsp)
	jmp	.LBB4_10
	.p2align	4, 0x90
.LBB4_19:
	decq	%rbp
	je	.LBB4_14
.LBB4_10:
	movq	%r14, %rdi
	movq	%rbx, %rsi
	callq	_ZN5poufs5block13compute_group17h1045228d1de64904E
	movq	16(%rsp), %rsi
	cmpq	$65535, %rsi
	jbe	.LBB4_11
	movq	(%rsp), %rdi
	movq	8(%rsp), %rsi
	movq	524280(%rdi), %rbx
	movq	%rbx, 80(%rsp)
	testq	%rsi, %rsi
	je	.LBB4_19
	shlq	$3, %rsi
	testq	%rsi, %rsi
	je	.LBB4_19
	movl	$8, %edx
	callq	*%r12
	jmp	.LBB4_19
.LBB4_15:
	leaq	80(%rsp), %rax
	leaq	_ZN4core5array69_$LT$impl$u20$core..fmt..Debug$u20$for$u20$$u5b$T$u3b$$u20$N$u5d$$GT$3fmt17hdb02d034d79bb30cE(%rip), %rcx
	leaq	.L__unnamed_11(%rip), %rdx
	movq	%rsp, %rdi
	movq	%rax, 56(%rsp)
	movq	%rcx, 64(%rsp)
	leaq	56(%rsp), %rcx
	movq	%rdx, (%rsp)
	movq	$2, 8(%rsp)
	movq	$0, 16(%rsp)
	movq	%rcx, 32(%rsp)
	movq	$1, 40(%rsp)
	callq	*_ZN3std2io5stdio6_print17hcbc8e5359e4501b6E@GOTPCREL(%rip)
	addq	$104, %rsp
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%r12
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.LBB4_11:
	.cfi_def_cfa_offset 160
.Ltmp3:
	leaq	.L__unnamed_12(%rip), %rdx
	movl	$65535, %edi
	callq	*_ZN4core9panicking18panic_bounds_check17h7777e18766a27b0bE@GOTPCREL(%rip)
.Ltmp4:
	jmp	.LBB4_3
.LBB4_2:
.Ltmp0:
	leaq	.L__unnamed_13(%rip), %rdx
	movl	$65535, %edi
	callq	*_ZN4core9panicking18panic_bounds_check17h7777e18766a27b0bE@GOTPCREL(%rip)
.Ltmp1:
.LBB4_3:
	ud2
.LBB4_12:
.Ltmp2:
	jmp	.LBB4_13
.LBB4_20:
.Ltmp5:
.LBB4_13:
	movq	%r14, %rdi
	movq	%rax, %rbx
	callq	_ZN4core3ptr68drop_in_place$LT$alloc..vec..Vec$LT$$u5b$i64$u3b$$u20$1$u5d$$GT$$GT$17hded603570404b0c7E
	movq	%rbx, %rdi
	callq	_Unwind_Resume@PLT
	ud2
.Lfunc_end4:
	.size	_ZN5poufs4main17h035f03ee3a9dc028E, .Lfunc_end4-_ZN5poufs4main17h035f03ee3a9dc028E
	.cfi_endproc
	.section	.gcc_except_table._ZN5poufs4main17h035f03ee3a9dc028E,"a",@progbits
	.p2align	2
GCC_except_table4:
.Lexception0:
	.byte	255
	.byte	255
	.byte	1
	.uleb128 .Lcst_end0-.Lcst_begin0
.Lcst_begin0:
	.uleb128 .Lfunc_begin0-.Lfunc_begin0
	.uleb128 .Ltmp3-.Lfunc_begin0
	.byte	0
	.byte	0
	.uleb128 .Ltmp3-.Lfunc_begin0
	.uleb128 .Ltmp4-.Ltmp3
	.uleb128 .Ltmp5-.Lfunc_begin0
	.byte	0
	.uleb128 .Ltmp0-.Lfunc_begin0
	.uleb128 .Ltmp1-.Ltmp0
	.uleb128 .Ltmp2-.Lfunc_begin0
	.byte	0
	.uleb128 .Ltmp1-.Lfunc_begin0
	.uleb128 .Lfunc_end4-.Ltmp1
	.byte	0
	.byte	0
.Lcst_end0:
	.p2align	2

	.section	".text._ZN4core5array69_$LT$impl$u20$core..fmt..Debug$u20$for$u20$$u5b$T$u3b$$u20$N$u5d$$GT$3fmt17hdb02d034d79bb30cE","ax",@progbits
	.p2align	4, 0x90
	.type	_ZN4core5array69_$LT$impl$u20$core..fmt..Debug$u20$for$u20$$u5b$T$u3b$$u20$N$u5d$$GT$3fmt17hdb02d034d79bb30cE,@function
_ZN4core5array69_$LT$impl$u20$core..fmt..Debug$u20$for$u20$$u5b$T$u3b$$u20$N$u5d$$GT$3fmt17hdb02d034d79bb30cE:
	.cfi_startproc
	pushq	%rbx
	.cfi_def_cfa_offset 16
	subq	$32, %rsp
	.cfi_def_cfa_offset 48
	.cfi_offset %rbx, -16
	movq	%rdi, %rbx
	movq	%rsi, %rdi
	callq	*_ZN4core3fmt9Formatter10debug_list17h9d866824678487fbE@GOTPCREL(%rip)
	movq	%rdx, 24(%rsp)
	movq	%rbx, 8(%rsp)
	leaq	16(%rsp), %rbx
	leaq	.L__unnamed_14(%rip), %rdx
	leaq	8(%rsp), %rsi
	movq	%rax, 16(%rsp)
	movq	%rbx, %rdi
	callq	*_ZN4core3fmt8builders9DebugList5entry17ha30adc12336de69eE@GOTPCREL(%rip)
	movq	%rbx, %rdi
	callq	*_ZN4core3fmt8builders9DebugList6finish17hc84e922fc299916fE@GOTPCREL(%rip)
	addq	$32, %rsp
	.cfi_def_cfa_offset 16
	popq	%rbx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end5:
	.size	_ZN4core5array69_$LT$impl$u20$core..fmt..Debug$u20$for$u20$$u5b$T$u3b$$u20$N$u5d$$GT$3fmt17hdb02d034d79bb30cE, .Lfunc_end5-_ZN4core5array69_$LT$impl$u20$core..fmt..Debug$u20$for$u20$$u5b$T$u3b$$u20$N$u5d$$GT$3fmt17hdb02d034d79bb30cE
	.cfi_endproc

	.section	.text._ZN3std2rt10lang_start17h5855facffa7dcfc1E,"ax",@progbits
	.hidden	_ZN3std2rt10lang_start17h5855facffa7dcfc1E
	.globl	_ZN3std2rt10lang_start17h5855facffa7dcfc1E
	.p2align	4, 0x90
	.type	_ZN3std2rt10lang_start17h5855facffa7dcfc1E,@function
_ZN3std2rt10lang_start17h5855facffa7dcfc1E:
	.cfi_startproc
	pushq	%rax
	.cfi_def_cfa_offset 16
	movq	%rdx, %rcx
	movq	%rsi, %rdx
	leaq	.L__unnamed_15(%rip), %rsi
	movq	%rdi, (%rsp)
	movq	%rsp, %rdi
	callq	*_ZN3std2rt19lang_start_internal17h2ba92edce36c035eE@GOTPCREL(%rip)
	popq	%rcx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end6:
	.size	_ZN3std2rt10lang_start17h5855facffa7dcfc1E, .Lfunc_end6-_ZN3std2rt10lang_start17h5855facffa7dcfc1E
	.cfi_endproc

	.section	".text._ZN3std2rt10lang_start28_$u7b$$u7b$closure$u7d$$u7d$17h6ca21ce1d8230655E","ax",@progbits
	.p2align	4, 0x90
	.type	_ZN3std2rt10lang_start28_$u7b$$u7b$closure$u7d$$u7d$17h6ca21ce1d8230655E,@function
_ZN3std2rt10lang_start28_$u7b$$u7b$closure$u7d$$u7d$17h6ca21ce1d8230655E:
	.cfi_startproc
	pushq	%rax
	.cfi_def_cfa_offset 16
	movq	(%rdi), %rdi
	callq	_ZN3std10sys_common9backtrace28__rust_begin_short_backtrace17hc9eae246da2e969bE
	xorl	%eax, %eax
	popq	%rcx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end7:
	.size	_ZN3std2rt10lang_start28_$u7b$$u7b$closure$u7d$$u7d$17h6ca21ce1d8230655E, .Lfunc_end7-_ZN3std2rt10lang_start28_$u7b$$u7b$closure$u7d$$u7d$17h6ca21ce1d8230655E
	.cfi_endproc

	.section	.text._ZN3std10sys_common9backtrace28__rust_begin_short_backtrace17hc9eae246da2e969bE,"ax",@progbits
	.p2align	4, 0x90
	.type	_ZN3std10sys_common9backtrace28__rust_begin_short_backtrace17hc9eae246da2e969bE,@function
_ZN3std10sys_common9backtrace28__rust_begin_short_backtrace17hc9eae246da2e969bE:
	.cfi_startproc
	pushq	%rax
	.cfi_def_cfa_offset 16
	callq	*%rdi
	#APP
	#NO_APP
	popq	%rax
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end8:
	.size	_ZN3std10sys_common9backtrace28__rust_begin_short_backtrace17hc9eae246da2e969bE, .Lfunc_end8-_ZN3std10sys_common9backtrace28__rust_begin_short_backtrace17hc9eae246da2e969bE
	.cfi_endproc

	.section	".text._ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17h6462c0e29b0783f4E","ax",@progbits
	.p2align	4, 0x90
	.type	_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17h6462c0e29b0783f4E,@function
_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17h6462c0e29b0783f4E:
	.cfi_startproc
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	(%rdi), %r14
	movq	%rsi, %rdi
	movq	%rsi, %rbx
	callq	*_ZN4core3fmt9Formatter15debug_lower_hex17h7679588e717565b5E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB9_1
	movq	%r14, %rdi
	movq	%rbx, %rsi
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*_ZN4core3fmt3num53_$LT$impl$u20$core..fmt..LowerHex$u20$for$u20$i64$GT$3fmt17hb97f823a996d444eE@GOTPCREL(%rip)
.LBB9_1:
	.cfi_def_cfa_offset 32
	movq	%rbx, %rdi
	callq	*_ZN4core3fmt9Formatter15debug_upper_hex17h2038d8f17d26ccdeE@GOTPCREL(%rip)
	movq	%r14, %rdi
	movq	%rbx, %rsi
	addq	$8, %rsp
	testb	%al, %al
	je	.LBB9_4
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*_ZN4core3fmt3num53_$LT$impl$u20$core..fmt..UpperHex$u20$for$u20$i64$GT$3fmt17h1d4d159e2d65c175E@GOTPCREL(%rip)
.LBB9_4:
	.cfi_def_cfa_offset 32
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*_ZN4core3fmt3num3imp52_$LT$impl$u20$core..fmt..Display$u20$for$u20$i64$GT$3fmt17h0dc13840d5ac416fE@GOTPCREL(%rip)
.Lfunc_end9:
	.size	_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17h6462c0e29b0783f4E, .Lfunc_end9-_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17h6462c0e29b0783f4E
	.cfi_endproc

	.section	.text.main,"ax",@progbits
	.globl	main
	.p2align	4, 0x90
	.type	main,@function
main:
	.cfi_startproc
	pushq	%rax
	.cfi_def_cfa_offset 16
	movq	%rsi, %rcx
	movslq	%edi, %rdx
	leaq	_ZN5poufs4main17h035f03ee3a9dc028E(%rip), %rax
	leaq	.L__unnamed_15(%rip), %rsi
	movq	%rsp, %rdi
	movq	%rax, (%rsp)
	callq	*_ZN3std2rt19lang_start_internal17h2ba92edce36c035eE@GOTPCREL(%rip)
	popq	%rcx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end10:
	.size	main, .Lfunc_end10-main
	.cfi_endproc

	.type	.L__unnamed_16,@object
	.section	.rodata..L__unnamed_16,"a",@progbits
.L__unnamed_16:
	.ascii	"Block count per group : "
	.size	.L__unnamed_16, 24

	.type	.L__unnamed_17,@object
	.section	.rodata..L__unnamed_17,"a",@progbits
.L__unnamed_17:
	.byte	10
	.size	.L__unnamed_17, 1

	.type	.L__unnamed_2,@object
	.section	.data.rel.ro..L__unnamed_2,"aw",@progbits
	.p2align	3
.L__unnamed_2:
	.quad	.L__unnamed_16
	.asciz	"\030\000\000\000\000\000\000"
	.quad	.L__unnamed_17
	.asciz	"\001\000\000\000\000\000\000"
	.size	.L__unnamed_2, 32

	.type	.L__unnamed_1,@object
	.section	.rodata.cst8,"aM",@progbits,8
	.p2align	3
.L__unnamed_1:
	.asciz	"\001\000\000\000\000\000\000"
	.size	.L__unnamed_1, 8

	.type	.L__unnamed_18,@object
	.section	.rodata..L__unnamed_18,"a",@progbits
.L__unnamed_18:
	.ascii	"Group size : "
	.size	.L__unnamed_18, 13

	.type	.L__unnamed_19,@object
	.section	.rodata.cst4,"aM",@progbits,4
.L__unnamed_19:
	.ascii	"MiB\n"
	.size	.L__unnamed_19, 4

	.type	.L__unnamed_4,@object
	.section	.data.rel.ro..L__unnamed_4,"aw",@progbits
	.p2align	3
.L__unnamed_4:
	.quad	.L__unnamed_18
	.asciz	"\r\000\000\000\000\000\000"
	.quad	.L__unnamed_19
	.asciz	"\004\000\000\000\000\000\000"
	.size	.L__unnamed_4, 32

	.type	.L__unnamed_3,@object
	.section	.rodata.cst4,"aM",@progbits,4
	.p2align	2
.L__unnamed_3:
	.ascii	"\000\000\000?"
	.size	.L__unnamed_3, 4

	.type	.L__unnamed_20,@object
	.section	.rodata..L__unnamed_20,"a",@progbits
.L__unnamed_20:
	.ascii	"src/main.rs"
	.size	.L__unnamed_20, 11

	.type	.L__unnamed_13,@object
	.section	.data.rel.ro..L__unnamed_13,"aw",@progbits
	.p2align	3
.L__unnamed_13:
	.quad	.L__unnamed_20
	.asciz	"\013\000\000\000\000\000\000\000\027\000\000\000\r\000\000"
	.size	.L__unnamed_13, 24

	.type	.L__unnamed_21,@object
	.section	.rodata..L__unnamed_21,"a",@progbits
.L__unnamed_21:
	.ascii	"Warmup done.\n"
	.size	.L__unnamed_21, 13

	.type	.L__unnamed_5,@object
	.section	.data.rel.ro..L__unnamed_5,"aw",@progbits
	.p2align	3
.L__unnamed_5:
	.quad	.L__unnamed_21
	.asciz	"\r\000\000\000\000\000\000"
	.size	.L__unnamed_5, 16

	.type	.L__unnamed_6,@object
	.section	.rodata..L__unnamed_6,"a",@progbits
	.p2align	3
.L__unnamed_6:
	.size	.L__unnamed_6, 0

	.type	.L__unnamed_12,@object
	.section	.data.rel.ro..L__unnamed_12,"aw",@progbits
	.p2align	3
.L__unnamed_12:
	.quad	.L__unnamed_20
	.asciz	"\013\000\000\000\000\000\000\000\035\000\000\000\021\000\000"
	.size	.L__unnamed_12, 24

	.type	.L__unnamed_22,@object
	.section	.rodata..L__unnamed_22,"a",@progbits
.L__unnamed_22:
	.ascii	"Runtime per block = "
	.size	.L__unnamed_22, 20

	.type	.L__unnamed_23,@object
	.section	.rodata..L__unnamed_23,"a",@progbits
.L__unnamed_23:
	.ascii	"ms\n"
	.size	.L__unnamed_23, 3

	.type	.L__unnamed_8,@object
	.section	.data.rel.ro..L__unnamed_8,"aw",@progbits
	.p2align	3
.L__unnamed_8:
	.quad	.L__unnamed_22
	.asciz	"\024\000\000\000\000\000\000"
	.quad	.L__unnamed_23
	.asciz	"\003\000\000\000\000\000\000"
	.size	.L__unnamed_8, 32

	.type	.L__unnamed_7,@object
	.section	.rodata..L__unnamed_7,"a",@progbits
	.p2align	3
.L__unnamed_7:
	.asciz	"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\002\000\000\000\000\000\000\000\002\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000 \000\000\000\000\000\000\000\003\000\000\000\000\000\000"
	.size	.L__unnamed_7, 56

	.type	.L__unnamed_24,@object
	.section	.rodata..L__unnamed_24,"a",@progbits
.L__unnamed_24:
	.ascii	"Read speed = "
	.size	.L__unnamed_24, 13

	.type	.L__unnamed_25,@object
	.section	.rodata..L__unnamed_25,"a",@progbits
.L__unnamed_25:
	.ascii	"MB/s\n"
	.size	.L__unnamed_25, 5

	.type	.L__unnamed_9,@object
	.section	.data.rel.ro..L__unnamed_9,"aw",@progbits
	.p2align	3
.L__unnamed_9:
	.quad	.L__unnamed_24
	.asciz	"\r\000\000\000\000\000\000"
	.quad	.L__unnamed_25
	.asciz	"\005\000\000\000\000\000\000"
	.size	.L__unnamed_9, 32

	.type	.L__unnamed_26,@object
	.section	.rodata.cst16,"aM",@progbits,16
.L__unnamed_26:
	.ascii	"\"Clock speed\" = "
	.size	.L__unnamed_26, 16

	.type	.L__unnamed_27,@object
	.section	.rodata.cst4,"aM",@progbits,4
.L__unnamed_27:
	.ascii	"GHz\n"
	.size	.L__unnamed_27, 4

	.type	.L__unnamed_10,@object
	.section	.data.rel.ro..L__unnamed_10,"aw",@progbits
	.p2align	3
.L__unnamed_10:
	.quad	.L__unnamed_26
	.asciz	"\020\000\000\000\000\000\000"
	.quad	.L__unnamed_27
	.asciz	"\004\000\000\000\000\000\000"
	.size	.L__unnamed_10, 32

	.type	.L__unnamed_28,@object
	.section	.rodata.cst4,"aM",@progbits,4
.L__unnamed_28:
	.ascii	"x = "
	.size	.L__unnamed_28, 4

	.type	.L__unnamed_11,@object
	.section	.data.rel.ro..L__unnamed_11,"aw",@progbits
	.p2align	3
.L__unnamed_11:
	.quad	.L__unnamed_28
	.asciz	"\004\000\000\000\000\000\000"
	.quad	.L__unnamed_17
	.asciz	"\001\000\000\000\000\000\000"
	.size	.L__unnamed_11, 32

	.type	.L__unnamed_14,@object
	.section	.data.rel.ro..L__unnamed_14,"aw",@progbits
	.p2align	3
.L__unnamed_14:
	.quad	_ZN4core3ptr28drop_in_place$LT$$RF$i64$GT$17h97f0ca4d384d7cbeE
	.asciz	"\b\000\000\000\000\000\000\000\b\000\000\000\000\000\000"
	.quad	_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17h6462c0e29b0783f4E
	.size	.L__unnamed_14, 32

	.type	.L__unnamed_15,@object
	.section	.data.rel.ro..L__unnamed_15,"aw",@progbits
	.p2align	3
.L__unnamed_15:
	.quad	_ZN4core3ptr28drop_in_place$LT$$RF$i64$GT$17h97f0ca4d384d7cbeE
	.asciz	"\b\000\000\000\000\000\000\000\b\000\000\000\000\000\000"
	.quad	_ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h3675e32b8b504c35E
	.quad	_ZN3std2rt10lang_start28_$u7b$$u7b$closure$u7d$$u7d$17h6ca21ce1d8230655E
	.quad	_ZN3std2rt10lang_start28_$u7b$$u7b$closure$u7d$$u7d$17h6ca21ce1d8230655E
	.size	.L__unnamed_15, 48

	.hidden	DW.ref.rust_eh_personality
	.weak	DW.ref.rust_eh_personality
	.section	.data.DW.ref.rust_eh_personality,"aGw",@progbits,DW.ref.rust_eh_personality,comdat
	.p2align	3
	.type	DW.ref.rust_eh_personality,@object
	.size	DW.ref.rust_eh_personality, 8
DW.ref.rust_eh_personality:
	.quad	rust_eh_personality
	.section	".note.GNU-stack","",@progbits
