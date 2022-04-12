struct ldst_filter {
	u32 mask;
	u32 arm_code;
	char *name;
	int (*handler)(struct ldst_filter *, u32, struct pt_regs*);
};

static int ldst_default(struct ldst_filter *f, u32 insn, struct pt_regs *regs)
{
	pr_alert("instruction :%x(%s) is not implemented.\n", insn, f->name);
	return 1;
}

/*
 * |------+-----+-----+-----+-----+-----------------------------------------|
 * | op0  | op1 | op2 | op3 | op4 | Decode group                            |
 * |------+-----+-----+-----+-----+-----------------------------------------|
 * | xx10 | -   |  00 | -   | -   | Load/store no-allocate pair (offset)    |
 * | xx10 | -   |  01 | -   | -   | Load/store register pair (post-indexed) |
 * | xx10 | -   |  10 | -   | -   | Load/store register pair (offset)       |
 * | xx10 | -   |  11 | -   | -   | Load/store register pair (pre-indexed)  |
 * |------+-----+-----+-----+-----+-----------------------------------------|
 */
static int ldst_type_pair(struct ldst_filter *f, u32 insn, struct pt_regs *regs)
{
	/* The bit 26 is used for SIMD only, please see the spec */
	if (insn & BIT(26))
		return align_ldst_pair_simdfp(insn, regs);
	else
		return align_ldst_pair(insn, regs);
}

/*
 * |------+-----+-----+--------+-----+----------------------------------------------|
 * | op0  | op1 | op2 |    op3 | op4 | Decode group                                 |
 * |------+-----+-----+--------+-----+----------------------------------------------|
 * | xx11 | -   |  0x | 0xxxxx |  00 | Load/store register (unscaled immediate)     |
 * | xx11 | -   |  0x | 0xxxxx |  01 | Load/store register (immediate post-indexed) |
 * | xx11 | -   |  0x | 0xxxxx |  11 | Load/store register (immediate pre-indexed)  |
 * | xx11 | -   |  1x |      - |   - | Load/store register (unsigned immediate)     |
 * |------+-----+-----+--------+-----+----------------------------------------------|
 */
static int ldst_type_imm(struct ldst_filter *f, u32 insn, struct pt_regs *regs)
{
	/* The bit 26 is used for SIMD only, please see the spec */
	if (insn & BIT(26))
		return align_ldst_imm_simdfp(insn, regs);
	else
		return align_ldst_imm(insn, regs);
}

/*
 * |------+-----+-----+--------+-----+---------------------------------------|
 * | op0  | op1 | op2 |    op3 | op4 |                                       |
 * |------+-----+-----+--------+-----+---------------------------------------|
 * | xx11 | -   |  0x | 1xxxxx |  10 | Load/store register (register offset) |
 * |------+-----+-----+--------+-----+---------------------------------------|
 */
static int ldst_type_regoff(struct ldst_filter *f, u32 insn, struct pt_regs *regs)
{
	/* The bit 26 is used for SIMD only, please see the spec */
	if (insn & BIT(26))
		return align_ldst_regoff_simdfp(insn, regs);
	else
		return align_ldst_regoff(insn, regs);
}

/*
 * |------+-----+-----+--------+-----+-------------------------------------------|
 * | op0  | op1 | op2 |    op3 | op4 |                                           |
 * |------+-----+-----+--------+-----+-------------------------------------------|
 * | 0x00 |   1 |  10 | x00000 |   - | Advanced SIMD load/store single structure |
 * | 0x00 |   1 |  11 |      - |   - | Advanced SIMD load/store single structure |
 * |      |     |     |        |     |   (post-indexed)                          |
 * |------+-----+-----+--------+-----+-------------------------------------------|
 */
static int ldst_type_vector_single(struct ldst_filter *f, u32 insn, struct pt_regs *regs)
{
	return align_ldst_vector_single(insn, regs);
}

/* Please see the C4.1.66 */
static const struct ldst_filter ldst_filters[] = {
	{
		.mask           = BIT(31) | GENMASK(29, 28) | BIT(26)
					| GENMASK(24, 23) | BIT(21),
		.arm_code       = BIT(21),
		.name           = "Compare and swap pair",
		.handler        = ldst_default,
	}, {
		.mask           = BIT(31) | GENMASK(29, 28) | BIT(26)
					| GENMASK(24, 23) | GENMASK(21, 16),
		.arm_code       = BIT(26),
		.name           = "Advanced SIMD load/store multiple structures",
		.handler        = ldst_default,
	}, {
		.mask           = BIT(31) | GENMASK(29, 28) | BIT(26)
					| GENMASK(24, 23) | BIT(21),
		.arm_code       = BIT(26) | BIT(23),
		.name           = "Advanced SIMD load/store multiple structures(post-indexed)",
		.handler        = ldst_default,
	}, {
		.mask           = BIT(31) | GENMASK(29, 28) | BIT(26)
					| GENMASK(24, 23) | GENMASK(20, 16),
		.arm_code       = BIT(26) | BIT(24),
		.name           = "Advanced SIMD load/store single structures",
		.handler        = ldst_type_vector_single,
	}, {
		.mask           = BIT(31) | GENMASK(29, 28) | BIT(26) | GENMASK(24, 23),
		.arm_code       = BIT(26) | BIT(24) | BIT(23),
		.name           = "Advanced SIMD load/store single structures(post-indexed)",
		.handler        = ldst_type_vector_single,
	}, {
		.mask           = GENMASK(31, 28) | BIT(26) | BIT(24) | BIT(21),
		.arm_code       = BIT(31) | BIT(30) | BIT(28) | BIT(24) | BIT(21),
		.name           = "Load/store memory tags",
		.handler        = ldst_default,
	}, {
		.mask           = BIT(31) | GENMASK(29, 28) | BIT(26)
					| GENMASK(24, 23) | BIT(21),
		.arm_code       = BIT(31) | BIT(21),
		.name           = "Load/store exclusive pair",
		.handler        = ldst_default,
	}, {
		.mask           = GENMASK(29, 28) | BIT(26) | GENMASK(24, 23) | BIT(21),
		.arm_code       = 0,
		.name           = "Load/store exclusive register",
		.handler        = ldst_default,
	}, {
		.mask           = GENMASK(29, 28) | BIT(26) | GENMASK(24, 23) | BIT(21),
		.arm_code       = BIT(23),
		.name           = "Load/store ordered",
		.handler        = ldst_default,
	}, {
		.mask           = GENMASK(29, 28) | BIT(26) | GENMASK(24, 23) | BIT(21),
		.arm_code       = BIT(23) | BIT(21),
		.name           = "Compare and swap",
		.handler        = ldst_default,
	}, {
		.mask           = GENMASK(29, 28) | BIT(26) | BIT(24) | BIT(21) |
					GENMASK(11, 10),
		.arm_code       = BIT(28) | BIT(24),
		.name           = "LDAPR/STLR(unscaled immediate)",
		.handler        = ldst_default,
	}, {
		.mask           = GENMASK(29, 28) | BIT(24),
		.arm_code       = BIT(28),
		.name           = "Load register(literal)",
		.handler        = ldst_default,
	}, {
		.mask           = GENMASK(29, 28) | BIT(24) | BIT(21) | GENMASK(11, 10),
		.arm_code       = BIT(28) | BIT(10),
		.name           = "Memory Copy and Memory Set",
		.handler        = ldst_default,
	}, {
		.mask           = GENMASK(29, 28) | GENMASK(24, 23),
		.arm_code       = BIT(29),
		.name           = "Load/store no-allocate pair(offset)",
		.handler        = ldst_type_pair,
	}, {
		.mask           = GENMASK(29, 28) | GENMASK(24, 23),
		.arm_code       = BIT(29) | BIT(23),
		.name           = "Load/store register pair(post-indexed)",
		.handler        = ldst_type_pair,
	}, {
		.mask           = GENMASK(29, 28) | GENMASK(24, 23),
		.arm_code       = BIT(29) | BIT(24),
		.name           = "Load/store register pair(offset)",
		.handler        = ldst_type_pair,
	}, {
		.mask           = GENMASK(29, 28) | GENMASK(24, 23),
		.arm_code       = BIT(29) | BIT(24) | BIT(23),
		.name           = "Load/store register pair(pre-indexed)",
		.handler        = ldst_type_pair,
	}, {
		.mask           = GENMASK(29, 28) | BIT(24) | BIT(21) | GENMASK(11, 10),
		.arm_code       = BIT(29) | BIT(28),
		.name           = "Load/store register (unscaled immediate)",
		.handler        = ldst_type_imm,
	}, {
		.mask           = GENMASK(29, 28) | BIT(24) | BIT(21) | GENMASK(11, 10),
		.arm_code       = BIT(29) | BIT(28) | BIT(10),
		.name           = "Load/store register (immediate post-indexed)",
		.handler        = ldst_type_imm,
	}, {
		.mask           = GENMASK(29, 28) | BIT(24) | BIT(21) | GENMASK(11, 10),
		.arm_code       = BIT(29) | BIT(28) | BIT(11),
		.name           = "Load/store register (unprivileged)",
		.handler        = ldst_default,
	}, {
		.mask           = GENMASK(29, 28) | BIT(24) | BIT(21) | GENMASK(11, 10),
		.arm_code       = BIT(29) | BIT(28) | BIT(11) | BIT(10),
		.name           = "Load/store register (immediate pre-indexed)",
		.handler        = ldst_type_imm,
	}, {
		.mask           = GENMASK(29, 28) | BIT(24) | BIT(21) | GENMASK(11, 10),
		.arm_code       = BIT(29) | BIT(28) | BIT(21),
		.name           = "Atomic memory operation",
		.handler        = ldst_default,
	}, {
		.mask           = GENMASK(29, 28) | BIT(24) | BIT(21) | GENMASK(11, 10),
		.arm_code       = BIT(29) | BIT(28) | BIT(21) | BIT(11),
		.name           = "Load/store register (register offset)",
		.handler        = ldst_type_regoff,
	}, {
		.mask           = GENMASK(29, 28) | BIT(24) | BIT(21) | BIT(10),
		.arm_code       = BIT(29) | BIT(28) | BIT(21) | BIT(10),
		.name           = "Load/store register (pac)",
		.handler        = ldst_default,
	}, {
		.mask           = GENMASK(29, 28) | BIT(24),
		.arm_code       = BIT(29) | BIT(28) | BIT(24),
		.name           = "Load/store register (unsigned immediate)",
		.handler        = ldst_type_imm,
	},
};

/* Return 0 on success, return 1 on failure. */
static int align_ldst_new(u32 insn, struct pt_regs *regs)
{
	int i;
	struct ldst_filter *f;

	for (i = 0; i < ARRAY_SIZE(ldst_filters); i++) {
		f = (struct ldst_filter *)&ldst_filters[i];

		/* Find the correct hander */
		if ((f->mask & insn) == f->arm_code) {
			pr_debug("insn:%x, (%s)\n", insn, f->name);
			return f->handler(f, insn, regs);
		}
	}

	return 1;
}
