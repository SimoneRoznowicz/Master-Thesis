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

	.section	".text._ZN4core3ptr68drop_in_place$LT$alloc..vec..Vec$LT$$u5b$i64$u3b$$u20$4$u5d$$GT$$GT$17hd59a4f8a0d76894dE","ax",@progbits
	.p2align	4, 0x90
	.type	_ZN4core3ptr68drop_in_place$LT$alloc..vec..Vec$LT$$u5b$i64$u3b$$u20$4$u5d$$GT$$GT$17hd59a4f8a0d76894dE,@function
_ZN4core3ptr68drop_in_place$LT$alloc..vec..Vec$LT$$u5b$i64$u3b$$u20$4$u5d$$GT$$GT$17hd59a4f8a0d76894dE:
	.cfi_startproc
	movq	8(%rdi), %rsi
	testq	%rsi, %rsi
	je	.LBB2_3
	movq	(%rdi), %rdi
	testq	%rdi, %rdi
	je	.LBB2_3
	shlq	$5, %rsi
	je	.LBB2_3
	movl	$8, %edx
	jmpq	*__rust_dealloc@GOTPCREL(%rip)
.LBB2_3:
	retq
.Lfunc_end2:
	.size	_ZN4core3ptr68drop_in_place$LT$alloc..vec..Vec$LT$$u5b$i64$u3b$$u20$4$u5d$$GT$$GT$17hd59a4f8a0d76894dE, .Lfunc_end2-_ZN4core3ptr68drop_in_place$LT$alloc..vec..Vec$LT$$u5b$i64$u3b$$u20$4$u5d$$GT$$GT$17hd59a4f8a0d76894dE
	.cfi_endproc

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
	subq	$24, %rsp
	.cfi_def_cfa_offset 80
	.cfi_offset %rbx, -56
	.cfi_offset %r12, -48
	.cfi_offset %r13, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	%rsi, (%rsp)
	movq	%rdi, %rbx
	movl	$2097152, %edi
	movl	$8, %esi
	callq	*__rust_alloc@GOTPCREL(%rip)
	testq	%rax, %rax
	je	.LBB3_58
	movl	$1, %edx
	movq	%rax, (%rbx)
	movq	$65536, 8(%rbx)
	vpxor	%xmm0, %xmm0, %xmm0
	movq	%rax, %rcx
	movq	%rbx, %r10
	.p2align	4, 0x90
.LBB3_2:
	vmovdqu	%ymm0, (%rcx)
	vmovdqu	%ymm0, 32(%rcx)
	vmovdqu	%ymm0, 64(%rcx)
	vmovdqu	%ymm0, 96(%rcx)
	vmovdqu	%ymm0, 128(%rcx)
	vmovdqu	%ymm0, 160(%rcx)
	vmovdqu	%ymm0, 192(%rcx)
	vmovdqu	%ymm0, 224(%rcx)
	vmovdqu	%ymm0, 256(%rcx)
	vmovdqu	%ymm0, 288(%rcx)
	vmovdqu	%ymm0, 320(%rcx)
	vmovdqu	%ymm0, 352(%rcx)
	vmovdqu	%ymm0, 384(%rcx)
	vmovdqu	%ymm0, 416(%rcx)
	vmovdqu	%ymm0, 448(%rcx)
	vmovdqu	%ymm0, 480(%rcx)
	vmovdqu	%ymm0, 512(%rcx)
	vmovdqu	%ymm0, 544(%rcx)
	vmovdqu	%ymm0, 576(%rcx)
	vmovdqu	%ymm0, 608(%rcx)
	vmovdqu	%ymm0, 640(%rcx)
	vmovdqu	%ymm0, 672(%rcx)
	vmovdqu	%ymm0, 704(%rcx)
	vmovdqu	%ymm0, 736(%rcx)
	vmovdqu	%ymm0, 768(%rcx)
	vmovdqu	%ymm0, 800(%rcx)
	vmovdqu	%ymm0, 832(%rcx)
	vmovdqu	%ymm0, 864(%rcx)
	vmovdqu	%ymm0, 896(%rcx)
	vmovdqu	%ymm0, 928(%rcx)
	vmovdqu	%ymm0, 960(%rcx)
	vmovdqu	%ymm0, 992(%rcx)
	vmovdqu	%ymm0, 1024(%rcx)
	vmovdqu	%ymm0, 1056(%rcx)
	vmovdqu	%ymm0, 1088(%rcx)
	vmovdqu	%ymm0, 1120(%rcx)
	vmovdqu	%ymm0, 1152(%rcx)
	vmovdqu	%ymm0, 1184(%rcx)
	vmovdqu	%ymm0, 1216(%rcx)
	vmovdqu	%ymm0, 1248(%rcx)
	vmovdqu	%ymm0, 1280(%rcx)
	vmovdqu	%ymm0, 1312(%rcx)
	vmovdqu	%ymm0, 1344(%rcx)
	vmovdqu	%ymm0, 1376(%rcx)
	vmovdqu	%ymm0, 1408(%rcx)
	vmovdqu	%ymm0, 1440(%rcx)
	vmovdqu	%ymm0, 1472(%rcx)
	vmovdqu	%ymm0, 1504(%rcx)
	vmovdqu	%ymm0, 1536(%rcx)
	vmovdqu	%ymm0, 1568(%rcx)
	vmovdqu	%ymm0, 1600(%rcx)
	vmovdqu	%ymm0, 1632(%rcx)
	vmovdqu	%ymm0, 1664(%rcx)
	vmovdqu	%ymm0, 1696(%rcx)
	vmovdqu	%ymm0, 1728(%rcx)
	vmovdqu	%ymm0, 1760(%rcx)
	vmovdqu	%ymm0, 1792(%rcx)
	vmovdqu	%ymm0, 1824(%rcx)
	vmovdqu	%ymm0, 1856(%rcx)
	vmovdqu	%ymm0, 1888(%rcx)
	vmovdqu	%ymm0, 1920(%rcx)
	vmovdqu	%ymm0, 1952(%rcx)
	vmovdqu	%ymm0, 1984(%rcx)
	vmovdqu	%ymm0, 2016(%rcx)
	vmovdqu	%ymm0, 2048(%rcx)
	vmovdqu	%ymm0, 2080(%rcx)
	vmovdqu	%ymm0, 2112(%rcx)
	vmovdqu	%ymm0, 2144(%rcx)
	vmovdqu	%ymm0, 2176(%rcx)
	vmovdqu	%ymm0, 2208(%rcx)
	vmovdqu	%ymm0, 2240(%rcx)
	vmovdqu	%ymm0, 2272(%rcx)
	vmovdqu	%ymm0, 2304(%rcx)
	vmovdqu	%ymm0, 2336(%rcx)
	vmovdqu	%ymm0, 2368(%rcx)
	vmovdqu	%ymm0, 2400(%rcx)
	vmovdqu	%ymm0, 2432(%rcx)
	vmovdqu	%ymm0, 2464(%rcx)
	vmovdqu	%ymm0, 2496(%rcx)
	vmovdqu	%ymm0, 2528(%rcx)
	vmovdqu	%ymm0, 2560(%rcx)
	vmovdqu	%ymm0, 2592(%rcx)
	vmovdqu	%ymm0, 2624(%rcx)
	vmovdqu	%ymm0, 2656(%rcx)
	vmovdqu	%ymm0, 2688(%rcx)
	vmovdqu	%ymm0, 2720(%rcx)
	vmovdqu	%ymm0, 2752(%rcx)
	vmovdqu	%ymm0, 2784(%rcx)
	vmovdqu	%ymm0, 2816(%rcx)
	vmovdqu	%ymm0, 2848(%rcx)
	vmovdqu	%ymm0, 2880(%rcx)
	vmovdqu	%ymm0, 2912(%rcx)
	vmovdqu	%ymm0, 2944(%rcx)
	vmovdqu	%ymm0, 2976(%rcx)
	vmovdqu	%ymm0, 3008(%rcx)
	vmovdqu	%ymm0, 3040(%rcx)
	vmovdqu	%ymm0, 3072(%rcx)
	vmovdqu	%ymm0, 3104(%rcx)
	vmovdqu	%ymm0, 3136(%rcx)
	vmovdqu	%ymm0, 3168(%rcx)
	vmovdqu	%ymm0, 3200(%rcx)
	vmovdqu	%ymm0, 3232(%rcx)
	vmovdqu	%ymm0, 3264(%rcx)
	vmovdqu	%ymm0, 3296(%rcx)
	vmovdqu	%ymm0, 3328(%rcx)
	vmovdqu	%ymm0, 3360(%rcx)
	vmovdqu	%ymm0, 3392(%rcx)
	vmovdqu	%ymm0, 3424(%rcx)
	vmovdqu	%ymm0, 3456(%rcx)
	vmovdqu	%ymm0, 3488(%rcx)
	vmovdqu	%ymm0, 3520(%rcx)
	vmovdqu	%ymm0, 3552(%rcx)
	vmovdqu	%ymm0, 3584(%rcx)
	vmovdqu	%ymm0, 3616(%rcx)
	vmovdqu	%ymm0, 3648(%rcx)
	vmovdqu	%ymm0, 3680(%rcx)
	vmovdqu	%ymm0, 3712(%rcx)
	vmovdqu	%ymm0, 3744(%rcx)
	vmovdqu	%ymm0, 3776(%rcx)
	vmovdqu	%ymm0, 3808(%rcx)
	vmovdqu	%ymm0, 3840(%rcx)
	vmovdqu	%ymm0, 3872(%rcx)
	vmovdqu	%ymm0, 3904(%rcx)
	vmovdqu	%ymm0, 3936(%rcx)
	vmovdqu	%ymm0, 3968(%rcx)
	vmovdqu	%ymm0, 4000(%rcx)
	vmovdqu	%ymm0, 4032(%rcx)
	vmovdqu	%ymm0, 4064(%rcx)
	vmovdqu	%ymm0, 4096(%rcx)
	vmovdqu	%ymm0, 4128(%rcx)
	vmovdqu	%ymm0, 4160(%rcx)
	vmovdqu	%ymm0, 4192(%rcx)
	vmovdqu	%ymm0, 4224(%rcx)
	vmovdqu	%ymm0, 4256(%rcx)
	vmovdqu	%ymm0, 4288(%rcx)
	vmovdqu	%ymm0, 4320(%rcx)
	vmovdqu	%ymm0, 4352(%rcx)
	vmovdqu	%ymm0, 4384(%rcx)
	vmovdqu	%ymm0, 4416(%rcx)
	vmovdqu	%ymm0, 4448(%rcx)
	vmovdqu	%ymm0, 4480(%rcx)
	vmovdqu	%ymm0, 4512(%rcx)
	vmovdqu	%ymm0, 4544(%rcx)
	vmovdqu	%ymm0, 4576(%rcx)
	vmovdqu	%ymm0, 4608(%rcx)
	vmovdqu	%ymm0, 4640(%rcx)
	vmovdqu	%ymm0, 4672(%rcx)
	vmovdqu	%ymm0, 4704(%rcx)
	vmovdqu	%ymm0, 4736(%rcx)
	vmovdqu	%ymm0, 4768(%rcx)
	vmovdqu	%ymm0, 4800(%rcx)
	vmovdqu	%ymm0, 4832(%rcx)
	vmovdqu	%ymm0, 4864(%rcx)
	vmovdqu	%ymm0, 4896(%rcx)
	vmovdqu	%ymm0, 4928(%rcx)
	vmovdqu	%ymm0, 4960(%rcx)
	vmovdqu	%ymm0, 4992(%rcx)
	vmovdqu	%ymm0, 5024(%rcx)
	vmovdqu	%ymm0, 5056(%rcx)
	vmovdqu	%ymm0, 5088(%rcx)
	vmovdqu	%ymm0, 5120(%rcx)
	vmovdqu	%ymm0, 5152(%rcx)
	vmovdqu	%ymm0, 5184(%rcx)
	vmovdqu	%ymm0, 5216(%rcx)
	vmovdqu	%ymm0, 5248(%rcx)
	vmovdqu	%ymm0, 5280(%rcx)
	vmovdqu	%ymm0, 5312(%rcx)
	vmovdqu	%ymm0, 5344(%rcx)
	vmovdqu	%ymm0, 5376(%rcx)
	vmovdqu	%ymm0, 5408(%rcx)
	vmovdqu	%ymm0, 5440(%rcx)
	vmovdqu	%ymm0, 5472(%rcx)
	vmovdqu	%ymm0, 5504(%rcx)
	vmovdqu	%ymm0, 5536(%rcx)
	vmovdqu	%ymm0, 5568(%rcx)
	vmovdqu	%ymm0, 5600(%rcx)
	vmovdqu	%ymm0, 5632(%rcx)
	vmovdqu	%ymm0, 5664(%rcx)
	vmovdqu	%ymm0, 5696(%rcx)
	vmovdqu	%ymm0, 5728(%rcx)
	vmovdqu	%ymm0, 5760(%rcx)
	vmovdqu	%ymm0, 5792(%rcx)
	vmovdqu	%ymm0, 5824(%rcx)
	vmovdqu	%ymm0, 5856(%rcx)
	vmovdqu	%ymm0, 5888(%rcx)
	vmovdqu	%ymm0, 5920(%rcx)
	vmovdqu	%ymm0, 5952(%rcx)
	vmovdqu	%ymm0, 5984(%rcx)
	vmovdqu	%ymm0, 6016(%rcx)
	vmovdqu	%ymm0, 6048(%rcx)
	vmovdqu	%ymm0, 6080(%rcx)
	vmovdqu	%ymm0, 6112(%rcx)
	vmovdqu	%ymm0, 6144(%rcx)
	vmovdqu	%ymm0, 6176(%rcx)
	vmovdqu	%ymm0, 6208(%rcx)
	vmovdqu	%ymm0, 6240(%rcx)
	vmovdqu	%ymm0, 6272(%rcx)
	vmovdqu	%ymm0, 6304(%rcx)
	vmovdqu	%ymm0, 6336(%rcx)
	vmovdqu	%ymm0, 6368(%rcx)
	vmovdqu	%ymm0, 6400(%rcx)
	vmovdqu	%ymm0, 6432(%rcx)
	vmovdqu	%ymm0, 6464(%rcx)
	vmovdqu	%ymm0, 6496(%rcx)
	vmovdqu	%ymm0, 6528(%rcx)
	vmovdqu	%ymm0, 6560(%rcx)
	vmovdqu	%ymm0, 6592(%rcx)
	vmovdqu	%ymm0, 6624(%rcx)
	vmovdqu	%ymm0, 6656(%rcx)
	vmovdqu	%ymm0, 6688(%rcx)
	vmovdqu	%ymm0, 6720(%rcx)
	vmovdqu	%ymm0, 6752(%rcx)
	vmovdqu	%ymm0, 6784(%rcx)
	vmovdqu	%ymm0, 6816(%rcx)
	vmovdqu	%ymm0, 6848(%rcx)
	vmovdqu	%ymm0, 6880(%rcx)
	vmovdqu	%ymm0, 6912(%rcx)
	vmovdqu	%ymm0, 6944(%rcx)
	vmovdqu	%ymm0, 6976(%rcx)
	vmovdqu	%ymm0, 7008(%rcx)
	vmovdqu	%ymm0, 7040(%rcx)
	vmovdqu	%ymm0, 7072(%rcx)
	vmovdqu	%ymm0, 7104(%rcx)
	vmovdqu	%ymm0, 7136(%rcx)
	vmovdqu	%ymm0, 7168(%rcx)
	vmovdqu	%ymm0, 7200(%rcx)
	vmovdqu	%ymm0, 7232(%rcx)
	vmovdqu	%ymm0, 7264(%rcx)
	vmovdqu	%ymm0, 7296(%rcx)
	vmovdqu	%ymm0, 7328(%rcx)
	vmovdqu	%ymm0, 7360(%rcx)
	vmovdqu	%ymm0, 7392(%rcx)
	vmovdqu	%ymm0, 7424(%rcx)
	vmovdqu	%ymm0, 7456(%rcx)
	vmovdqu	%ymm0, 7488(%rcx)
	vmovdqu	%ymm0, 7520(%rcx)
	vmovdqu	%ymm0, 7552(%rcx)
	vmovdqu	%ymm0, 7584(%rcx)
	vmovdqu	%ymm0, 7616(%rcx)
	vmovdqu	%ymm0, 7648(%rcx)
	vmovdqu	%ymm0, 7680(%rcx)
	vmovdqu	%ymm0, 7712(%rcx)
	vmovdqu	%ymm0, 7744(%rcx)
	vmovdqu	%ymm0, 7776(%rcx)
	vmovdqu	%ymm0, 7808(%rcx)
	vmovdqu	%ymm0, 7840(%rcx)
	vmovdqu	%ymm0, 7872(%rcx)
	vmovdqu	%ymm0, 7904(%rcx)
	vmovdqu	%ymm0, 7936(%rcx)
	vmovdqu	%ymm0, 7968(%rcx)
	vmovdqu	%ymm0, 8000(%rcx)
	vmovdqu	%ymm0, 8032(%rcx)
	vmovdqu	%ymm0, 8064(%rcx)
	vmovdqu	%ymm0, 8096(%rcx)
	vmovdqu	%ymm0, 8128(%rcx)
	addq	$255, %rdx
	addq	$8160, %rcx
	cmpq	$65536, %rdx
	jne	.LBB3_2
	movq	$-1, %rdx
	movl	$1, %ebp
	movq	$-1, %r14
	vpxor	%xmm0, %xmm0, %xmm0
	vmovdqu	%ymm0, (%rcx)
	movq	$65536, 16(%r10)
	xorl	%r9d, %r9d
	xorl	%ebx, %ebx
	movq	%r10, 16(%rsp)
	jmp	.LBB3_7
.LBB3_54:
	movq	16(%rsp), %r10
.LBB3_4:
	movq	%rsi, %rax
	movq	8(%rsp), %rbx
	movl	$1, %ebp
.LBB3_6:
	incq	%r14
	cmpq	$17, %rbx
	je	.LBB3_55
.LBB3_7:
	movq	%rbx, %r15
	movq	%r9, %r12
	incq	%rbx
	shlxq	%r15, %rbp, %r9
	cmpq	%r12, %r9
	jbe	.LBB3_6
	movq	(%rsp), %rcx
	vmovdqu	(%rcx), %ymm0
	testq	%r15, %r15
	je	.LBB3_12
	movq	(%r10), %rsi
	movl	%r15d, %r11d
	movl	%r9d, %ecx
	andl	$7, %r11d
	leaq	-1(%r15), %r13
	subl	%r12d, %ecx
	leaq	1(%r12), %r8
	movq	%rbx, 8(%rsp)
	testb	$1, %cl
	je	.LBB3_29
	addq	$57826, %r12
	cmpq	$7, %r13
	jae	.LBB3_17
	xorl	%edi, %edi
	vmovdqa	%ymm0, %ymm1
	jmp	.LBB3_19
.LBB3_12:
	movl	%r9d, %esi
	movq	%r12, %rcx
	notq	%rcx
	subl	%r12d, %esi
	vpaddq	%ymm0, %ymm0, %ymm1
	addq	%r9, %rcx
	andq	$3, %rsi
	je	.LBB3_14
	.p2align	4, 0x90
.LBB3_13:
	vpxor	%ymm0, %ymm1, %ymm2
	leal	57826(%r12), %edi
	incq	%r12
	vpaddq	%ymm0, %ymm2, %ymm2
	movzwl	%di, %edi
	vpxor	%ymm0, %ymm2, %ymm2
	shlq	$5, %rdi
	decq	%rsi
	vpaddq	%ymm0, %ymm2, %ymm2
	vpxor	%ymm0, %ymm2, %ymm2
	vpaddq	%ymm0, %ymm2, %ymm2
	vpxor	%ymm0, %ymm2, %ymm2
	vpaddq	%ymm0, %ymm2, %ymm2
	vpxor	%ymm0, %ymm2, %ymm2
	vpaddq	%ymm0, %ymm2, %ymm2
	vpxor	%ymm0, %ymm2, %ymm2
	vpaddq	%ymm0, %ymm2, %ymm2
	vpxor	%ymm0, %ymm2, %ymm2
	vpaddq	%ymm0, %ymm2, %ymm2
	vpxor	%ymm0, %ymm2, %ymm2
	vpaddq	%ymm0, %ymm2, %ymm2
	vpsrlq	$45, %ymm2, %ymm3
	vpsllq	$19, %ymm2, %ymm2
	vpor	%ymm3, %ymm2, %ymm2
	vmovdqu	%ymm2, (%rax,%rdi)
	jne	.LBB3_13
.LBB3_14:
	cmpq	$3, %rcx
	jb	.LBB3_6
	movq	%r9, %rcx
	negq	%rcx
	addq	$57826, %r12
	.p2align	4, 0x90
.LBB3_16:
	vpxor	%ymm0, %ymm1, %ymm2
	movzwl	%r12w, %esi
	leaq	4(%rcx,%r12), %rdi
	vpaddq	%ymm0, %ymm2, %ymm2
	shlq	$5, %rsi
	vpxor	%ymm0, %ymm2, %ymm2
	vpaddq	%ymm0, %ymm2, %ymm2
	vpxor	%ymm0, %ymm2, %ymm2
	vpaddq	%ymm0, %ymm2, %ymm2
	vpxor	%ymm0, %ymm2, %ymm2
	vpaddq	%ymm0, %ymm2, %ymm2
	vpxor	%ymm0, %ymm2, %ymm2
	vpaddq	%ymm0, %ymm2, %ymm2
	vpxor	%ymm0, %ymm2, %ymm2
	vpaddq	%ymm0, %ymm2, %ymm2
	vpxor	%ymm0, %ymm2, %ymm2
	vpaddq	%ymm0, %ymm2, %ymm2
	vpxor	%ymm0, %ymm2, %ymm2
	vpaddq	%ymm0, %ymm2, %ymm2
	vpsrlq	$45, %ymm2, %ymm3
	vpsllq	$19, %ymm2, %ymm2
	vpor	%ymm3, %ymm2, %ymm2
	vmovdqu	%ymm2, (%rax,%rsi)
	leal	1(%r12), %esi
	movzwl	%si, %esi
	shlq	$5, %rsi
	vmovdqu	%ymm2, (%rax,%rsi)
	leal	2(%r12), %esi
	movzwl	%si, %esi
	shlq	$5, %rsi
	vmovdqu	%ymm2, (%rax,%rsi)
	leal	3(%r12), %esi
	addq	$4, %r12
	movzwl	%si, %esi
	shlq	$5, %rsi
	vmovdqu	%ymm2, (%rax,%rsi)
	cmpq	$57826, %rdi
	jne	.LBB3_16
	jmp	.LBB3_6
.LBB3_17:
	movabsq	$9223372036854775800, %rcx
	movq	%r15, %rbx
	xorl	%edi, %edi
	vmovdqa	%ymm0, %ymm1
	andq	%rcx, %rbx
	.p2align	4, 0x90
.LBB3_18:
	movl	%edi, %ebp
	addq	$8, %rdi
	shlxq	%rbp, %rdx, %rcx
	addl	%r12d, %ecx
	movzwl	%cx, %ecx
	shlq	$5, %rcx
	vpaddq	(%rsi,%rcx), %ymm1, %ymm1
	leal	1(%rbp), %ecx
	shlxq	%rcx, %rdx, %rcx
	addl	%r12d, %ecx
	movzwl	%cx, %ecx
	shlq	$5, %rcx
	vpxor	(%rsi,%rcx), %ymm1, %ymm1
	leal	2(%rbp), %ecx
	shlxq	%rcx, %rdx, %rcx
	addl	%r12d, %ecx
	movzwl	%cx, %ecx
	shlq	$5, %rcx
	vpaddq	(%rsi,%rcx), %ymm1, %ymm1
	leal	3(%rbp), %ecx
	shlxq	%rcx, %rdx, %rcx
	addl	%r12d, %ecx
	movzwl	%cx, %ecx
	shlq	$5, %rcx
	vpxor	(%rsi,%rcx), %ymm1, %ymm1
	leal	4(%rbp), %ecx
	shlxq	%rcx, %rdx, %rcx
	addl	%r12d, %ecx
	movzwl	%cx, %ecx
	shlq	$5, %rcx
	vpaddq	(%rsi,%rcx), %ymm1, %ymm1
	leal	5(%rbp), %ecx
	shlxq	%rcx, %rdx, %rcx
	addl	%r12d, %ecx
	movzwl	%cx, %ecx
	shlq	$5, %rcx
	vpxor	(%rsi,%rcx), %ymm1, %ymm1
	leal	6(%rbp), %ecx
	shlxq	%rcx, %rdx, %rcx
	addl	%r12d, %ecx
	movzwl	%cx, %ecx
	shlq	$5, %rcx
	vpaddq	(%rsi,%rcx), %ymm1, %ymm1
	leal	7(%rbp), %ecx
	shlxq	%rcx, %rdx, %rcx
	addl	%r12d, %ecx
	movzwl	%cx, %ecx
	shlq	$5, %rcx
	vpxor	(%rsi,%rcx), %ymm1, %ymm1
	cmpq	%rbx, %rdi
	jne	.LBB3_18
.LBB3_19:
	testb	$7, %r15b
	je	.LBB3_24
	movq	%r11, %rcx
	jmp	.LBB3_22
	.p2align	4, 0x90
.LBB3_21:
	vpxor	%ymm1, %ymm2, %ymm1
	incq	%rdi
	decq	%rcx
	je	.LBB3_24
.LBB3_22:
	shlxq	%rdi, %rdx, %rbx
	addl	%r12d, %ebx
	movzwl	%bx, %ebx
	shlq	$5, %rbx
	vmovdqu	(%rsi,%rbx), %ymm2
	testb	$1, %dil
	jne	.LBB3_21
	vpaddq	%ymm1, %ymm2, %ymm1
	incq	%rdi
	decq	%rcx
	jne	.LBB3_22
.LBB3_24:
	movzwl	%r12w, %ecx
	movq	%r14, %rdi
	jmp	.LBB3_26
	.p2align	4, 0x90
.LBB3_25:
	vpxor	%ymm0, %ymm1, %ymm1
	cmpq	$16, %rdi
	jae	.LBB3_28
.LBB3_26:
	incq	%rdi
	testb	$1, %dil
	jne	.LBB3_25
	vpaddq	%ymm0, %ymm1, %ymm1
	cmpq	$16, %rdi
	jb	.LBB3_26
.LBB3_28:
	vpsrlq	$45, %ymm1, %ymm2
	vpsllq	$19, %ymm1, %ymm1
	shlq	$5, %rcx
	movq	%r8, %r12
	vpor	%ymm2, %ymm1, %ymm1
	vmovdqu	%ymm1, (%rax,%rcx)
.LBB3_29:
	cmpq	%r8, %r9
	je	.LBB3_4
	movabsq	$9223372036854775800, %rcx
	movq	%r15, %r10
	andq	%rcx, %r10
	jmp	.LBB3_32
	.p2align	4, 0x90
.LBB3_31:
	vpsrlq	$45, %ymm1, %ymm2
	vpsllq	$19, %ymm1, %ymm1
	shlq	$5, %rcx
	vpor	%ymm2, %ymm1, %ymm1
	vmovdqu	%ymm1, (%rax,%rcx)
	cmpq	%r9, %r12
	je	.LBB3_54
.LBB3_32:
	leaq	57826(%r12), %rdi
	xorl	%ebx, %ebx
	vmovdqa	%ymm0, %ymm1
	cmpq	$7, %r13
	jb	.LBB3_34
	.p2align	4, 0x90
.LBB3_33:
	movl	%ebx, %ecx
	addq	$8, %rbx
	shlxq	%rcx, %rdx, %rbp
	addl	%edi, %ebp
	movzwl	%bp, %ebp
	shlq	$5, %rbp
	vpaddq	(%rsi,%rbp), %ymm1, %ymm1
	leal	1(%rcx), %ebp
	shlxq	%rbp, %rdx, %rbp
	addl	%edi, %ebp
	movzwl	%bp, %ebp
	shlq	$5, %rbp
	vpxor	(%rsi,%rbp), %ymm1, %ymm1
	leal	2(%rcx), %ebp
	shlxq	%rbp, %rdx, %rbp
	addl	%edi, %ebp
	movzwl	%bp, %ebp
	shlq	$5, %rbp
	vpaddq	(%rsi,%rbp), %ymm1, %ymm1
	leal	3(%rcx), %ebp
	shlxq	%rbp, %rdx, %rbp
	addl	%edi, %ebp
	movzwl	%bp, %ebp
	shlq	$5, %rbp
	vpxor	(%rsi,%rbp), %ymm1, %ymm1
	leal	4(%rcx), %ebp
	shlxq	%rbp, %rdx, %rbp
	addl	%edi, %ebp
	movzwl	%bp, %ebp
	shlq	$5, %rbp
	vpaddq	(%rsi,%rbp), %ymm1, %ymm1
	leal	5(%rcx), %ebp
	shlxq	%rbp, %rdx, %rbp
	addl	%edi, %ebp
	movzwl	%bp, %ebp
	shlq	$5, %rbp
	vpxor	(%rsi,%rbp), %ymm1, %ymm1
	leal	6(%rcx), %ebp
	addl	$7, %ecx
	shlxq	%rbp, %rdx, %rbp
	shlxq	%rcx, %rdx, %rcx
	addl	%edi, %ebp
	addl	%edi, %ecx
	movzwl	%bp, %ebp
	movzwl	%cx, %ecx
	shlq	$5, %rbp
	shlq	$5, %rcx
	vpaddq	(%rsi,%rbp), %ymm1, %ymm1
	vpxor	(%rsi,%rcx), %ymm1, %ymm1
	cmpq	%r10, %rbx
	jne	.LBB3_33
.LBB3_34:
	testb	$7, %r15b
	je	.LBB3_39
	movq	%r11, %rcx
	jmp	.LBB3_37
	.p2align	4, 0x90
.LBB3_36:
	vpxor	%ymm1, %ymm2, %ymm1
	incq	%rbx
	decq	%rcx
	je	.LBB3_39
.LBB3_37:
	shlxq	%rbx, %rdx, %rbp
	addl	%edi, %ebp
	movzwl	%bp, %ebp
	shlq	$5, %rbp
	vmovdqu	(%rsi,%rbp), %ymm2
	testb	$1, %bl
	jne	.LBB3_36
	vpaddq	%ymm1, %ymm2, %ymm1
	incq	%rbx
	decq	%rcx
	jne	.LBB3_37
.LBB3_39:
	movzwl	%di, %ecx
	movq	%r14, %rdi
	jmp	.LBB3_41
	.p2align	4, 0x90
.LBB3_40:
	vpxor	%ymm0, %ymm1, %ymm1
	cmpq	$16, %rdi
	jae	.LBB3_43
.LBB3_41:
	incq	%rdi
	testb	$1, %dil
	jne	.LBB3_40
	vpaddq	%ymm0, %ymm1, %ymm1
	cmpq	$16, %rdi
	jb	.LBB3_41
.LBB3_43:
	vpsrlq	$45, %ymm1, %ymm2
	vpsllq	$19, %ymm1, %ymm1
	shlq	$5, %rcx
	leaq	57827(%r12), %r8
	xorl	%edi, %edi
	vpor	%ymm2, %ymm1, %ymm1
	vmovdqu	%ymm1, (%rax,%rcx)
	vmovdqa	%ymm0, %ymm1
	cmpq	$7, %r13
	jb	.LBB3_45
	.p2align	4, 0x90
.LBB3_44:
	movl	%edi, %ebx
	addq	$8, %rdi
	shlxq	%rbx, %rdx, %rcx
	addl	%r8d, %ecx
	movzwl	%cx, %ecx
	shlq	$5, %rcx
	vpaddq	(%rsi,%rcx), %ymm1, %ymm1
	leal	1(%rbx), %ecx
	shlxq	%rcx, %rdx, %rcx
	addl	%r8d, %ecx
	movzwl	%cx, %ecx
	shlq	$5, %rcx
	vpxor	(%rsi,%rcx), %ymm1, %ymm1
	leal	2(%rbx), %ecx
	shlxq	%rcx, %rdx, %rcx
	addl	%r8d, %ecx
	movzwl	%cx, %ecx
	shlq	$5, %rcx
	vpaddq	(%rsi,%rcx), %ymm1, %ymm1
	leal	3(%rbx), %ecx
	shlxq	%rcx, %rdx, %rcx
	addl	%r8d, %ecx
	movzwl	%cx, %ecx
	shlq	$5, %rcx
	vpxor	(%rsi,%rcx), %ymm1, %ymm1
	leal	4(%rbx), %ecx
	shlxq	%rcx, %rdx, %rcx
	addl	%r8d, %ecx
	movzwl	%cx, %ecx
	shlq	$5, %rcx
	vpaddq	(%rsi,%rcx), %ymm1, %ymm1
	leal	5(%rbx), %ecx
	shlxq	%rcx, %rdx, %rcx
	addl	%r8d, %ecx
	movzwl	%cx, %ecx
	shlq	$5, %rcx
	vpxor	(%rsi,%rcx), %ymm1, %ymm1
	leal	6(%rbx), %ecx
	shlxq	%rcx, %rdx, %rcx
	addl	%r8d, %ecx
	movzwl	%cx, %ecx
	shlq	$5, %rcx
	vpaddq	(%rsi,%rcx), %ymm1, %ymm1
	leal	7(%rbx), %ecx
	shlxq	%rcx, %rdx, %rcx
	addl	%r8d, %ecx
	movzwl	%cx, %ecx
	shlq	$5, %rcx
	vpxor	(%rsi,%rcx), %ymm1, %ymm1
	cmpq	%r10, %rdi
	jne	.LBB3_44
.LBB3_45:
	testb	$7, %r15b
	je	.LBB3_50
	movq	%r11, %rcx
	jmp	.LBB3_48
	.p2align	4, 0x90
.LBB3_47:
	vpxor	%ymm1, %ymm2, %ymm1
	incq	%rdi
	decq	%rcx
	je	.LBB3_50
.LBB3_48:
	shlxq	%rdi, %rdx, %rbx
	addl	%r8d, %ebx
	movzwl	%bx, %ebx
	shlq	$5, %rbx
	vmovdqu	(%rsi,%rbx), %ymm2
	testb	$1, %dil
	jne	.LBB3_47
	vpaddq	%ymm1, %ymm2, %ymm1
	incq	%rdi
	decq	%rcx
	jne	.LBB3_48
.LBB3_50:
	addq	$2, %r12
	movzwl	%r8w, %ecx
	movq	%r14, %rdi
	jmp	.LBB3_52
	.p2align	4, 0x90
.LBB3_51:
	vpxor	%ymm0, %ymm1, %ymm1
	cmpq	$16, %rdi
	jae	.LBB3_31
.LBB3_52:
	incq	%rdi
	testb	$1, %dil
	jne	.LBB3_51
	vpaddq	%ymm0, %ymm1, %ymm1
	cmpq	$16, %rdi
	jb	.LBB3_52
	jmp	.LBB3_31
.LBB3_55:
	movq	(%rsp), %rax
	movl	$123364, %ecx
	vmovdqu	(%rax), %ymm0
	movq	(%r10), %rax
	.p2align	4, 0x90
.LBB3_56:
	leal	-3(%rcx), %edx
	leal	-6(%rcx), %ebp
	leal	-10(%rcx), %ebx
	leal	-2(%rcx), %edi
	movzwl	%dx, %esi
	leal	-4(%rcx), %edx
	movzwl	%bp, %ebp
	movzwl	%bx, %ebx
	movzwl	%di, %edi
	movzwl	%dx, %edx
	shlq	$5, %rsi
	shlq	$5, %rbp
	shlq	$5, %rbx
	shlq	$5, %rdi
	vpaddq	(%rax,%rsi), %ymm0, %ymm1
	shlq	$5, %rdx
	vpxor	(%rax,%rdx), %ymm1, %ymm1
	vpaddq	(%rax,%rbp), %ymm1, %ymm1
	leal	-18(%rcx), %ebp
	movzwl	%bp, %ebp
	vpxor	(%rax,%rbx), %ymm1, %ymm1
	leal	-34(%rcx), %ebx
	shlq	$5, %rbp
	vpaddq	(%rax,%rbp), %ymm1, %ymm1
	movzwl	%bx, %ebp
	leal	-66(%rcx), %ebx
	shlq	$5, %rbp
	movzwl	%bx, %ebx
	vpxor	(%rax,%rbp), %ymm1, %ymm1
	leal	-130(%rcx), %ebp
	shlq	$5, %rbx
	movzwl	%bp, %ebp
	vpaddq	(%rax,%rbx), %ymm1, %ymm1
	leal	-258(%rcx), %ebx
	shlq	$5, %rbp
	vpxor	(%rax,%rbp), %ymm1, %ymm1
	movzwl	%bx, %ebp
	leal	-514(%rcx), %ebx
	shlq	$5, %rbp
	movzwl	%bx, %ebx
	vpaddq	(%rax,%rbp), %ymm1, %ymm1
	leal	-1026(%rcx), %ebp
	shlq	$5, %rbx
	movzwl	%bp, %ebp
	vpxor	(%rax,%rbx), %ymm1, %ymm1
	leal	-2050(%rcx), %ebx
	shlq	$5, %rbp
	vpaddq	(%rax,%rbp), %ymm1, %ymm1
	movzwl	%bx, %ebp
	leal	-4098(%rcx), %ebx
	shlq	$5, %rbp
	movzwl	%bx, %ebx
	vpxor	(%rax,%rbp), %ymm1, %ymm1
	leal	-8194(%rcx), %ebp
	shlq	$5, %rbx
	movzwl	%bp, %ebp
	vpaddq	(%rax,%rbx), %ymm1, %ymm1
	leal	-16386(%rcx), %ebx
	shlq	$5, %rbp
	vpxor	(%rax,%rbp), %ymm1, %ymm1
	movzwl	%bx, %ebp
	leal	-32770(%rcx), %ebx
	movzwl	%bx, %ebx
	shlq	$5, %rbp
	vpaddq	(%rax,%rbp), %ymm1, %ymm1
	shlq	$5, %rbx
	leal	-1(%rcx), %ebp
	vpxor	(%rax,%rbx), %ymm1, %ymm1
	leal	-5(%rcx), %ebx
	vpaddq	(%rax,%rdi), %ymm1, %ymm1
	vpsrlq	$45, %ymm1, %ymm2
	vpsllq	$19, %ymm1, %ymm1
	vpor	%ymm2, %ymm1, %ymm1
	vmovdqu	%ymm1, (%rax,%rdi)
	vpaddq	%ymm0, %ymm1, %ymm1
	vpxor	(%rax,%rsi), %ymm1, %ymm1
	movzwl	%bx, %esi
	leal	-9(%rcx), %ebx
	shlq	$5, %rsi
	movzwl	%bx, %ebx
	vpaddq	(%rax,%rsi), %ymm1, %ymm1
	leal	-17(%rcx), %esi
	shlq	$5, %rbx
	movzwl	%si, %esi
	vpxor	(%rax,%rbx), %ymm1, %ymm1
	leal	-33(%rcx), %ebx
	shlq	$5, %rsi
	vpaddq	(%rax,%rsi), %ymm1, %ymm1
	movzwl	%bx, %esi
	leal	-65(%rcx), %ebx
	shlq	$5, %rsi
	movzwl	%bx, %ebx
	vpxor	(%rax,%rsi), %ymm1, %ymm1
	leal	-129(%rcx), %esi
	shlq	$5, %rbx
	movzwl	%si, %esi
	vpaddq	(%rax,%rbx), %ymm1, %ymm1
	leal	-257(%rcx), %ebx
	shlq	$5, %rsi
	vpxor	(%rax,%rsi), %ymm1, %ymm1
	movzwl	%bx, %esi
	leal	-513(%rcx), %ebx
	shlq	$5, %rsi
	movzwl	%bx, %ebx
	vpaddq	(%rax,%rsi), %ymm1, %ymm1
	leal	-1025(%rcx), %esi
	shlq	$5, %rbx
	movzwl	%si, %esi
	vpxor	(%rax,%rbx), %ymm1, %ymm1
	leal	-2049(%rcx), %ebx
	shlq	$5, %rsi
	vpaddq	(%rax,%rsi), %ymm1, %ymm1
	movzwl	%bx, %esi
	leal	-4097(%rcx), %ebx
	shlq	$5, %rsi
	movzwl	%bx, %ebx
	vpxor	(%rax,%rsi), %ymm1, %ymm1
	leal	-8193(%rcx), %esi
	shlq	$5, %rbx
	movzwl	%si, %esi
	vpaddq	(%rax,%rbx), %ymm1, %ymm1
	leal	-16385(%rcx), %ebx
	shlq	$5, %rsi
	vpxor	(%rax,%rsi), %ymm1, %ymm1
	movzwl	%bx, %esi
	leal	-32769(%rcx), %ebx
	movzwl	%bx, %ebx
	shlq	$5, %rsi
	vpaddq	(%rax,%rsi), %ymm1, %ymm1
	movzwl	%bp, %esi
	shlq	$5, %rbx
	vpxor	(%rax,%rbx), %ymm1, %ymm1
	shlq	$5, %rsi
	vpaddq	(%rax,%rsi), %ymm1, %ymm1
	vpsrlq	$45, %ymm1, %ymm2
	vpsllq	$19, %ymm1, %ymm1
	vpor	%ymm2, %ymm1, %ymm1
	vmovdqu	%ymm1, (%rax,%rsi)
	vpaddq	%ymm0, %ymm1, %ymm1
	leal	-8(%rcx), %esi
	vpxor	(%rax,%rdi), %ymm1, %ymm1
	vpaddq	(%rax,%rdx), %ymm1, %ymm1
	movzwl	%si, %edx
	leal	-16(%rcx), %esi
	shlq	$5, %rdx
	movzwl	%si, %esi
	vpxor	(%rax,%rdx), %ymm1, %ymm1
	leal	-32(%rcx), %edx
	shlq	$5, %rsi
	movzwl	%dx, %edx
	vpaddq	(%rax,%rsi), %ymm1, %ymm1
	leal	-64(%rcx), %esi
	shlq	$5, %rdx
	vpxor	(%rax,%rdx), %ymm1, %ymm1
	movzwl	%si, %edx
	leal	-128(%rcx), %esi
	shlq	$5, %rdx
	movzwl	%si, %esi
	vpaddq	(%rax,%rdx), %ymm1, %ymm1
	leal	-256(%rcx), %edx
	shlq	$5, %rsi
	movzwl	%dx, %edx
	vpxor	(%rax,%rsi), %ymm1, %ymm1
	leal	-512(%rcx), %esi
	shlq	$5, %rdx
	vpaddq	(%rax,%rdx), %ymm1, %ymm1
	movzwl	%si, %edx
	leal	-1024(%rcx), %esi
	shlq	$5, %rdx
	movzwl	%si, %esi
	vpxor	(%rax,%rdx), %ymm1, %ymm1
	leal	-2048(%rcx), %edx
	shlq	$5, %rsi
	movzwl	%dx, %edx
	vpaddq	(%rax,%rsi), %ymm1, %ymm1
	leal	-4096(%rcx), %esi
	shlq	$5, %rdx
	vpxor	(%rax,%rdx), %ymm1, %ymm1
	movzwl	%si, %edx
	leal	-8192(%rcx), %esi
	shlq	$5, %rdx
	movzwl	%si, %esi
	vpaddq	(%rax,%rdx), %ymm1, %ymm1
	leal	-16384(%rcx), %edx
	shlq	$5, %rsi
	movzwl	%dx, %edx
	vpxor	(%rax,%rsi), %ymm1, %ymm1
	leal	-32768(%rcx), %esi
	shlq	$5, %rdx
	vpaddq	(%rax,%rdx), %ymm1, %ymm1
	movzwl	%si, %edx
	shlq	$5, %rdx
	vpxor	(%rax,%rdx), %ymm1, %ymm1
	movzwl	%cx, %edx
	addq	$3, %rcx
	shlq	$5, %rdx
	vpaddq	(%rax,%rdx), %ymm1, %ymm1
	vpsrlq	$45, %ymm1, %ymm2
	vpsllq	$19, %ymm1, %ymm1
	vpor	%ymm2, %ymm1, %ymm1
	vmovdqu	%ymm1, (%rax,%rdx)
	cmpq	$1114114, %rcx
	jne	.LBB3_56
	addq	$24, %rsp
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
	vzeroupper
	retq
.LBB3_58:
	.cfi_def_cfa_offset 80
	movl	$2097152, %edi
	movl	$8, %esi
	callq	*_ZN5alloc5alloc18handle_alloc_error17hfe0de613579df40dE@GOTPCREL(%rip)
	ud2
.Lfunc_end3:
	.size	_ZN5poufs5block13compute_group17h1045228d1de64904E, .Lfunc_end3-_ZN5poufs5block13compute_group17h1045228d1de64904E
	.cfi_endproc

	.section	.rodata.cst32,"aM",@progbits,32
	.p2align	5
.LCPI4_0:
	.quad	727
	.quad	728
	.quad	729
	.quad	730
	.section	.rodata.cst4,"aM",@progbits,4
	.p2align	2
.LCPI4_1:
	.long	0x447a0000
.LCPI4_2:
	.long	0x49800000
.LCPI4_3:
	.long	0x4efa0000
.LCPI4_4:
	.long	0x49742400
.LCPI4_5:
	.long	0x4c88ffff
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
	subq	$168, %rsp
	.cfi_def_cfa_offset 224
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
	leaq	16(%rsp), %r14
	leaq	112(%rsp), %rbx
	movq	%rax, 112(%rsp)
	movq	%rcx, 16(%rsp)
	movq	$2, 24(%rsp)
	movq	$0, 32(%rsp)
	movq	%rbx, 48(%rsp)
	movq	%r14, %rdi
	movq	$1, 56(%rsp)
	movq	%rdx, 120(%rsp)
	callq	*%rbp
	movq	_ZN4core3fmt5float52_$LT$impl$u20$core..fmt..Display$u20$for$u20$f32$GT$3fmt17ha80c19f9318342c9E@GOTPCREL(%rip), %rdx
	leaq	.L__unnamed_3(%rip), %rax
	leaq	.L__unnamed_4(%rip), %rcx
	leaq	16(%rsp), %rdi
	movq	%rax, 112(%rsp)
	movq	%rcx, 16(%rsp)
	movq	$2, 24(%rsp)
	movq	$0, 32(%rsp)
	movq	%rbx, 48(%rsp)
	movq	$1, 56(%rsp)
	movq	%rdx, 120(%rsp)
	callq	*%rbp
	vmovaps	.LCPI4_0(%rip), %ymm0
	movq	__rust_dealloc@GOTPCREL(%rip), %r12
	movl	$256, %ebp
	leaq	80(%rsp), %rbx
	vmovups	%ymm0, 112(%rsp)
	jmp	.LBB4_1
	.p2align	4, 0x90
.LBB4_7:
	decq	%rbp
	je	.LBB4_8
.LBB4_1:
	vmovups	112(%rsp), %ymm0
	movq	%rbx, %rdi
	movq	%r14, %rsi
	vmovups	%ymm0, 16(%rsp)
	vzeroupper
	callq	_ZN5poufs5block13compute_group17h1045228d1de64904E
	movq	96(%rsp), %rsi
	cmpq	$65535, %rsi
	jbe	.LBB4_2
	movq	80(%rsp), %rdi
	movq	88(%rsp), %rsi
	vmovups	2097120(%rdi), %ymm0
	vmovups	%ymm0, 112(%rsp)
	testq	%rsi, %rsi
	je	.LBB4_7
	shlq	$5, %rsi
	je	.LBB4_7
	movl	$8, %edx
	vzeroupper
	callq	*%r12
	jmp	.LBB4_7
.LBB4_8:
	leaq	.L__unnamed_5(%rip), %rax
	leaq	16(%rsp), %r14
	leaq	.L__unnamed_6(%rip), %rcx
	movq	%rax, 16(%rsp)
	movq	$1, 24(%rsp)
	movq	$0, 32(%rsp)
	movq	%rcx, 48(%rsp)
	movq	%r14, %rdi
	movq	$0, 56(%rsp)
	vzeroupper
	callq	*_ZN3std2io5stdio6_print17hcbc8e5359e4501b6E@GOTPCREL(%rip)
	leaq	80(%rsp), %rbx
	xorl	%r15d, %r15d
	jmp	.LBB4_9
	.p2align	4, 0x90
.LBB4_14:
	leaq	152(%rsp), %rdi
	vzeroupper
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
	vdivss	.LCPI4_1(%rip), %xmm0, %xmm0
	movq	_ZN4core3fmt5float52_$LT$impl$u20$core..fmt..Display$u20$for$u20$f32$GT$3fmt17ha80c19f9318342c9E@GOTPCREL(%rip), %r13
	movq	_ZN3std2io5stdio6_print17hcbc8e5359e4501b6E@GOTPCREL(%rip), %rbp
	leaq	12(%rsp), %rax
	movq	%r14, %rdi
	movl	%r15d, 108(%rsp)
	movq	%rax, 80(%rsp)
	leaq	.L__unnamed_7(%rip), %rax
	movq	%rax, 16(%rsp)
	leaq	.L__unnamed_8(%rip), %rax
	movq	$2, 24(%rsp)
	movq	%rax, 32(%rsp)
	movq	$1, 40(%rsp)
	movq	%rbx, 48(%rsp)
	movq	%rax, %r15
	movq	$1, 56(%rsp)
	movq	%r13, 88(%rsp)
	vmovss	%xmm0, 12(%rsp)
	callq	*%rbp
	vmovss	.LCPI4_2(%rip), %xmm0
	vmovss	.LCPI4_3(%rip), %xmm1
	leaq	76(%rsp), %r12
	leaq	.L__unnamed_9(%rip), %rax
	movq	%r14, %rdi
	vmulss	12(%rsp), %xmm0, %xmm0
	movq	%r12, 80(%rsp)
	movq	%rax, 16(%rsp)
	movq	$2, 24(%rsp)
	movq	%r15, 32(%rsp)
	movq	$1, 40(%rsp)
	movq	%rbx, 48(%rsp)
	movq	%r13, 88(%rsp)
	movq	$1, 56(%rsp)
	vdivss	%xmm0, %xmm1, %xmm0
	vmovss	%xmm0, 76(%rsp)
	callq	*%rbp
	vmovss	.LCPI4_4(%rip), %xmm0
	vmovss	.LCPI4_5(%rip), %xmm1
	leaq	.L__unnamed_10(%rip), %rax
	movq	%r12, 80(%rsp)
	movq	__rust_dealloc@GOTPCREL(%rip), %r12
	movq	%r13, 88(%rsp)
	movq	%r14, %rdi
	vmulss	12(%rsp), %xmm0, %xmm0
	movq	%rax, 16(%rsp)
	movq	$2, 24(%rsp)
	movq	%r15, 32(%rsp)
	movl	108(%rsp), %r15d
	movq	$1, 40(%rsp)
	movq	%rbx, 48(%rsp)
	movq	$1, 56(%rsp)
	vdivss	%xmm0, %xmm1, %xmm0
	vmovss	%xmm0, 76(%rsp)
	callq	*%rbp
	cmpl	$5, %r15d
	je	.LBB4_15
.LBB4_9:
	incl	%r15d
	callq	*_ZN3std4time7Instant3now17h96d387d8dbcab72dE@GOTPCREL(%rip)
	movl	$256, %ebp
	movq	%rax, 152(%rsp)
	movq	%rdx, 160(%rsp)
	jmp	.LBB4_10
	.p2align	4, 0x90
.LBB4_19:
	decq	%rbp
	je	.LBB4_14
.LBB4_10:
	vmovups	112(%rsp), %ymm0
	movq	%rbx, %rdi
	movq	%r14, %rsi
	vmovups	%ymm0, 16(%rsp)
	vzeroupper
	callq	_ZN5poufs5block13compute_group17h1045228d1de64904E
	movq	96(%rsp), %rsi
	cmpq	$65535, %rsi
	jbe	.LBB4_11
	movq	80(%rsp), %rdi
	movq	88(%rsp), %rsi
	vmovups	2097120(%rdi), %ymm0
	vmovups	%ymm0, 112(%rsp)
	testq	%rsi, %rsi
	je	.LBB4_19
	shlq	$5, %rsi
	je	.LBB4_19
	movl	$8, %edx
	vzeroupper
	callq	*%r12
	jmp	.LBB4_19
.LBB4_15:
	leaq	112(%rsp), %rax
	leaq	_ZN4core5array69_$LT$impl$u20$core..fmt..Debug$u20$for$u20$$u5b$T$u3b$$u20$N$u5d$$GT$3fmt17h783f7a899adb6690E(%rip), %rcx
	leaq	.L__unnamed_11(%rip), %rdx
	leaq	16(%rsp), %rdi
	movq	%rax, 80(%rsp)
	movq	%rcx, 88(%rsp)
	leaq	80(%rsp), %rcx
	movq	%rdx, 16(%rsp)
	movq	$2, 24(%rsp)
	movq	$0, 32(%rsp)
	movq	%rcx, 48(%rsp)
	movq	$1, 56(%rsp)
	callq	*_ZN3std2io5stdio6_print17hcbc8e5359e4501b6E@GOTPCREL(%rip)
	addq	$168, %rsp
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
	.cfi_def_cfa_offset 224
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
	movq	%rbx, %rdi
	movq	%rax, %r14
	callq	_ZN4core3ptr68drop_in_place$LT$alloc..vec..Vec$LT$$u5b$i64$u3b$$u20$4$u5d$$GT$$GT$17hd59a4f8a0d76894dE
	movq	%r14, %rdi
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

	.section	".text._ZN4core5array69_$LT$impl$u20$core..fmt..Debug$u20$for$u20$$u5b$T$u3b$$u20$N$u5d$$GT$3fmt17h783f7a899adb6690E","ax",@progbits
	.p2align	4, 0x90
	.type	_ZN4core5array69_$LT$impl$u20$core..fmt..Debug$u20$for$u20$$u5b$T$u3b$$u20$N$u5d$$GT$3fmt17h783f7a899adb6690E,@function
_ZN4core5array69_$LT$impl$u20$core..fmt..Debug$u20$for$u20$$u5b$T$u3b$$u20$N$u5d$$GT$3fmt17h783f7a899adb6690E:
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
	subq	$24, %rsp
	.cfi_def_cfa_offset 80
	.cfi_offset %rbx, -56
	.cfi_offset %r12, -48
	.cfi_offset %r13, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	%rdi, %rbx
	movq	%rsi, %rdi
	callq	*_ZN4core3fmt9Formatter10debug_list17h9d866824678487fbE@GOTPCREL(%rip)
	movq	_ZN4core3fmt8builders9DebugList5entry17ha30adc12336de69eE@GOTPCREL(%rip), %r15
	movq	%rdx, 16(%rsp)
	leaq	8(%rsp), %r14
	leaq	.L__unnamed_14(%rip), %rdx
	movq	%rsp, %r12
	movq	%rax, 8(%rsp)
	leaq	8(%rbx), %r13
	movq	%rbx, (%rsp)
	movq	%r12, %rsi
	movq	%r14, %rdi
	callq	*%r15
	leaq	.L__unnamed_14(%rip), %rdx
	leaq	16(%rbx), %rbp
	movq	%r13, (%rsp)
	movq	%r14, %rdi
	movq	%r12, %rsi
	callq	*%r15
	leaq	.L__unnamed_14(%rip), %rdx
	movq	%rbp, (%rsp)
	addq	$24, %rbx
	movq	%r14, %rdi
	movq	%r12, %rsi
	movq	%rdx, %rbp
	callq	*%r15
	movq	%rbx, (%rsp)
	movq	%r14, %rdi
	movq	%r12, %rsi
	movq	%rbp, %rdx
	callq	*%r15
	movq	%r14, %rdi
	callq	*_ZN4core3fmt8builders9DebugList6finish17hc84e922fc299916fE@GOTPCREL(%rip)
	addq	$24, %rsp
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
.Lfunc_end5:
	.size	_ZN4core5array69_$LT$impl$u20$core..fmt..Debug$u20$for$u20$$u5b$T$u3b$$u20$N$u5d$$GT$3fmt17h783f7a899adb6690E, .Lfunc_end5-_ZN4core5array69_$LT$impl$u20$core..fmt..Debug$u20$for$u20$$u5b$T$u3b$$u20$N$u5d$$GT$3fmt17h783f7a899adb6690E
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
	.asciz	"\004\000\000\000\000\000\000"
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
	.ascii	"\000\000\000@"
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

	.type	.L__unnamed_7,@object
	.section	.data.rel.ro..L__unnamed_7,"aw",@progbits
	.p2align	3
.L__unnamed_7:
	.quad	.L__unnamed_22
	.asciz	"\024\000\000\000\000\000\000"
	.quad	.L__unnamed_23
	.asciz	"\003\000\000\000\000\000\000"
	.size	.L__unnamed_7, 32

	.type	.L__unnamed_8,@object
	.section	.rodata..L__unnamed_8,"a",@progbits
	.p2align	3
.L__unnamed_8:
	.asciz	"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\002\000\000\000\000\000\000\000\002\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000 \000\000\000\000\000\000\000\003\000\000\000\000\000\000"
	.size	.L__unnamed_8, 56

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
