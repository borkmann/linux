#ifndef __LINUX_BPF_H__
#define __LINUX_BPF_H__

#include <stdarg.h>

#include <linux/atomic.h>
#include <linux/refcount.h>
#include <linux/compat.h>
#include <linux/skbuff.h>
#include <linux/linkage.h>
#include <linux/printk.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/cryptohash.h>
#include <linux/set_memory.h>
#include <linux/file.h>
#include <linux/percpu.h>
#include <linux/err.h>
#include <linux/rbtree_latch.h>

#include <net/sch_generic.h>

#include <uapi/linux/filter.h>
#include <uapi/linux/bpf.h>

struct sock;
struct sk_buff;
struct seccomp_data;
struct perf_event;

/* ArgX, context and stack frame pointer register positions. Note,
 * Arg1, Arg2, Arg3, etc are used as argument mappings of function
 * calls in BPF_CALL instruction.
 */
#define BPF_REG_ARG1	BPF_REG_1
#define BPF_REG_ARG2	BPF_REG_2
#define BPF_REG_ARG3	BPF_REG_3
#define BPF_REG_ARG4	BPF_REG_4
#define BPF_REG_ARG5	BPF_REG_5
#define BPF_REG_CTX	BPF_REG_6
#define BPF_REG_FP	BPF_REG_10

/* Additional register mappings for converted user programs. */
#define BPF_REG_A	BPF_REG_0
#define BPF_REG_X	BPF_REG_7
#define BPF_REG_TMP	BPF_REG_8

/* Kernel hidden auxiliary/helper register for hardening step.
 * Only used by eBPF JITs. It's nothing more than a temporary
 * register that JITs use internally, only that here it's part
 * of eBPF instructions that have been rewritten for blinding
 * constants. See JIT pre-step in bpf_jit_blind_constants().
 */
#define BPF_REG_AX		MAX_BPF_REG
#define MAX_BPF_JIT_REG		(MAX_BPF_REG + 1)

/* unused opcode to mark special call to bpf_tail_call() helper */
#define BPF_TAIL_CALL	0xf0

/* As per nm, we expose JITed images as text (code) section for
 * kallsyms. That way, tools like perf can find it to match
 * addresses.
 */
#define BPF_SYM_ELF_TYPE	't'

/* BPF program can access up to 512 bytes of stack space. */
#define MAX_BPF_STACK	512

/* Maximum number of nesting tail calls. */
#define MAX_BPF_TAIL_CALL_CNT	32

/* Helper macros for filter block array initializers. */

/* ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */

#define BPF_ALU64_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_ALU32_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

/* ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */

#define BPF_ALU64_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_ALU32_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Endianess conversion, cpu_to_{l,b}e(), {l,b}e_to_cpu() */

#define BPF_ENDIAN(TYPE, DST, LEN)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_END | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = LEN })

/* Short form of mov, dst_reg = src_reg */

#define BPF_MOV64_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_MOV32_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

/* Short form of mov, dst_reg = imm32 */

#define BPF_MOV64_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_MOV32_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* BPF_LD_IMM64 macro encodes single 'load 64-bit immediate' insn */
#define BPF_LD_IMM64(DST, IMM)					\
	BPF_LD_IMM64_RAW(DST, 0, IMM)

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_DW | BPF_IMM,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = (__u32) (IMM) }),			\
	((struct bpf_insn) {					\
		.code  = 0, /* zero is reserved opcode */	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((__u64) (IMM)) >> 32 })

/* pseudo BPF_LD_IMM64 insn used to refer to process-local map_fd */
#define BPF_LD_MAP_FD(DST, MAP_FD)				\
	BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)

/* Short form of mov based on type, BPF_X: dst_reg = src_reg, BPF_K: dst_reg = imm32 */

#define BPF_MOV64_RAW(TYPE, DST, SRC, IMM)			\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_MOV32_RAW(TYPE, DST, SRC, IMM)			\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })

/* Direct packet access, R0 = *(uint *) (skb->data + imm32) */

#define BPF_LD_ABS(SIZE, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS,	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Indirect packet access, R0 = *(uint *) (skb->data + src_reg + imm32) */

#define BPF_LD_IND(SIZE, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_IND,	\
		.dst_reg = 0,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })

/* Memory load, dst_reg = *(uint *) (src_reg + off16) */

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = src_reg */

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Atomic memory add, *(uint *)(dst_reg + off16) += src_reg */

#define BPF_STX_XADD(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_XADD,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = imm32 */

#define BPF_ST_MEM(SIZE, DST, OFF, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Conditional jumps against registers, if (dst_reg 'op' src_reg) goto pc + off16 */

#define BPF_JMP_REG(OP, DST, SRC, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc + off16 */

#define BPF_JMP_IMM(OP, DST, IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Unconditional jumps, goto pc + off16 */

#define BPF_JMP_A(OFF)						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_JA,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Function call */

#define BPF_EMIT_CALL(FUNC)					\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_CALL,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((FUNC) - __bpf_call_base) })

/* Raw code statement block */

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)			\
	((struct bpf_insn) {					\
		.code  = CODE,					\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Program exit */

#define BPF_EXIT_INSN()						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_EXIT,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = 0 })

/* Internal classic blocks for direct assignment */

#define __BPF_STMT(CODE, K)					\
	((struct sock_filter) BPF_STMT(CODE, K))

#define __BPF_JUMP(CODE, K, JT, JF)				\
	((struct sock_filter) BPF_JUMP(CODE, K, JT, JF))

#define bytes_to_bpf_size(bytes)				\
({								\
	int bpf_size = -EINVAL;					\
								\
	if (bytes == sizeof(u8))				\
		bpf_size = BPF_B;				\
	else if (bytes == sizeof(u16))				\
		bpf_size = BPF_H;				\
	else if (bytes == sizeof(u32))				\
		bpf_size = BPF_W;				\
	else if (bytes == sizeof(u64))				\
		bpf_size = BPF_DW;				\
								\
	bpf_size;						\
})

#define bpf_size_to_bytes(bpf_size)				\
({								\
	int bytes = -EINVAL;					\
								\
	if (bpf_size == BPF_B)					\
		bytes = sizeof(u8);				\
	else if (bpf_size == BPF_H)				\
		bytes = sizeof(u16);				\
	else if (bpf_size == BPF_W)				\
		bytes = sizeof(u32);				\
	else if (bpf_size == BPF_DW)				\
		bytes = sizeof(u64);				\
								\
	bytes;							\
})

#define BPF_SIZEOF(type)					\
	({							\
		const int __size = bytes_to_bpf_size(sizeof(type)); \
		BUILD_BUG_ON(__size < 0);			\
		__size;						\
	})

#define BPF_FIELD_SIZEOF(type, field)				\
	({							\
		const int __size = bytes_to_bpf_size(FIELD_SIZEOF(type, field)); \
		BUILD_BUG_ON(__size < 0);			\
		__size;						\
	})

#define BPF_LDST_BYTES(insn)					\
	({							\
		const int __size = bpf_size_to_bytes(BPF_SIZE(insn->code)); \
		WARN_ON(__size < 0);				\
		__size;						\
	})

#define __BPF_MAP_0(m, v, ...) v
#define __BPF_MAP_1(m, v, t, a, ...) m(t, a)
#define __BPF_MAP_2(m, v, t, a, ...) m(t, a), __BPF_MAP_1(m, v, __VA_ARGS__)
#define __BPF_MAP_3(m, v, t, a, ...) m(t, a), __BPF_MAP_2(m, v, __VA_ARGS__)
#define __BPF_MAP_4(m, v, t, a, ...) m(t, a), __BPF_MAP_3(m, v, __VA_ARGS__)
#define __BPF_MAP_5(m, v, t, a, ...) m(t, a), __BPF_MAP_4(m, v, __VA_ARGS__)

#define __BPF_REG_0(...) __BPF_PAD(5)
#define __BPF_REG_1(...) __BPF_MAP(1, __VA_ARGS__), __BPF_PAD(4)
#define __BPF_REG_2(...) __BPF_MAP(2, __VA_ARGS__), __BPF_PAD(3)
#define __BPF_REG_3(...) __BPF_MAP(3, __VA_ARGS__), __BPF_PAD(2)
#define __BPF_REG_4(...) __BPF_MAP(4, __VA_ARGS__), __BPF_PAD(1)
#define __BPF_REG_5(...) __BPF_MAP(5, __VA_ARGS__)

#define __BPF_MAP(n, ...) __BPF_MAP_##n(__VA_ARGS__)
#define __BPF_REG(n, ...) __BPF_REG_##n(__VA_ARGS__)

#define __BPF_CAST(t, a)						       \
	(__force t)							       \
	(__force							       \
	 typeof(__builtin_choose_expr(sizeof(t) == sizeof(unsigned long),      \
				      (unsigned long)0, (t)0))) a
#define __BPF_V void
#define __BPF_N

#define __BPF_DECL_ARGS(t, a) t   a
#define __BPF_DECL_REGS(t, a) u64 a

#define __BPF_PAD(n)							       \
	__BPF_MAP(n, __BPF_DECL_ARGS, __BPF_N, u64, __ur_1, u64, __ur_2,       \
		  u64, __ur_3, u64, __ur_4, u64, __ur_5)

#define BPF_CALL_x(x, name, ...)					       \
	static __always_inline						       \
	u64 ____##name(__BPF_MAP(x, __BPF_DECL_ARGS, __BPF_V, __VA_ARGS__));   \
	u64 name(__BPF_REG(x, __BPF_DECL_REGS, __BPF_N, __VA_ARGS__));	       \
	u64 name(__BPF_REG(x, __BPF_DECL_REGS, __BPF_N, __VA_ARGS__))	       \
	{								       \
		return ____##name(__BPF_MAP(x,__BPF_CAST,__BPF_N,__VA_ARGS__));\
	}								       \
	static __always_inline						       \
	u64 ____##name(__BPF_MAP(x, __BPF_DECL_ARGS, __BPF_V, __VA_ARGS__))

#define BPF_CALL_0(name, ...)	BPF_CALL_x(0, name, __VA_ARGS__)
#define BPF_CALL_1(name, ...)	BPF_CALL_x(1, name, __VA_ARGS__)
#define BPF_CALL_2(name, ...)	BPF_CALL_x(2, name, __VA_ARGS__)
#define BPF_CALL_3(name, ...)	BPF_CALL_x(3, name, __VA_ARGS__)
#define BPF_CALL_4(name, ...)	BPF_CALL_x(4, name, __VA_ARGS__)
#define BPF_CALL_5(name, ...)	BPF_CALL_x(5, name, __VA_ARGS__)

#define bpf_ctx_range(TYPE, MEMBER)						\
	offsetof(TYPE, MEMBER) ... offsetofend(TYPE, MEMBER) - 1
#define bpf_ctx_range_till(TYPE, MEMBER1, MEMBER2)				\
	offsetof(TYPE, MEMBER1) ... offsetofend(TYPE, MEMBER2) - 1

#define bpf_target_off(TYPE, MEMBER, SIZE, PTR_SIZE)				\
	({									\
		BUILD_BUG_ON(FIELD_SIZEOF(TYPE, MEMBER) != (SIZE));		\
		*(PTR_SIZE) = (SIZE);						\
		offsetof(TYPE, MEMBER);						\
	})

#ifdef CONFIG_COMPAT
/* A struct sock_filter is architecture independent. */
struct compat_sock_fprog {
	u16		len;
	compat_uptr_t	filter;	/* struct sock_filter * */
};
#endif

struct sock_fprog_kern {
	u16			len;
	struct sock_filter	*filter;
};

struct bpf_binary_header {
	unsigned int pages;
	u8 image[];
};

struct bpf_map;

struct bpf_map_ops {
	/* Funcs callable from userspace (via syscall). */
	struct bpf_map *(*map_alloc)(union bpf_attr *attr);
	void (*map_release)(struct bpf_map *map, struct file *map_file);
	void (*map_free)(struct bpf_map *map);
	int (*map_get_next_key)(struct bpf_map *map, void *key, void *next_key);

	/* Funcs callable from userspace and from eBPF programs. */
	void *(*map_lookup_elem)(struct bpf_map *map, void *key);
	int (*map_update_elem)(struct bpf_map *map, void *key, void *value, u64 flags);
	int (*map_delete_elem)(struct bpf_map *map, void *key);

	/* Funcs called by prog_array and perf_event_array map. */
	void *(*map_fd_get_ptr)(struct bpf_map *map, struct file *map_file, int fd);
	void (*map_fd_put_ptr)(void *ptr);
	u32 (*map_gen_lookup)(struct bpf_map *map, struct bpf_insn *insn_buf);
	u32 (*map_fd_sys_lookup_elem)(void *ptr);
};

struct bpf_verifier_ops {
	/* Return BPF function prototype for verification. */
	const struct bpf_func_proto *(*get_func_proto)(enum bpf_func_id func_id);

	/* Return true if 'size' wide access at offset 'off' within
	 * bpf_context with 'type' (read or write) is allowed.
	 */
	bool (*is_valid_access)(int off, int size, enum bpf_access_type type,
				struct bpf_insn_access_aux *info);
	int (*gen_prologue)(struct bpf_insn *insn, bool direct_write,
			    const struct bpf_prog *prog);
	u32 (*convert_ctx_access)(enum bpf_access_type type,
				  const struct bpf_insn *src,
				  struct bpf_insn *dst,
				  struct bpf_prog *prog, u32 *target_size);
	int (*test_run)(struct bpf_prog *prog, const union bpf_attr *kattr,
			union bpf_attr __user *uattr);
};

struct bpf_map {
	atomic_t		refcnt;
	enum bpf_map_type	map_type;
	u32			key_size;
	u32			value_size;
	u32			max_entries;
	u32			map_flags;
	u32			pages;
	u32			id;		/* Unique identifier */
	struct user_struct	*user;		/* Map owner for charging */
	const struct bpf_map_ops *ops;
	struct work_struct	work;
	atomic_t		usercnt;	/* References in user space */
	struct bpf_map		*inner_map_meta; /* Meta data for map in map */
};

/* Read-write auxillary data for slow-path operations. */
struct bpf_prog_aux {
	atomic_t		refcnt;
	u32			used_map_cnt;
	u32			max_ctx_offset;	/* Ctx access tracking (tracing) */
	u32			stack_depth;	/* Max used stack space */
	u32			id;		/* Unique identifier */
	struct latch_tree_node	ksym_tnode;	/* kallsym linkage */
	struct list_head	ksym_lnode;	/* kallsym linkage */
	const struct bpf_verifier_ops *ops;
	struct bpf_map		**used_maps;	/* Maps used in the prog */
	struct bpf_prog		*prog;		/* Backref to prog */
	struct user_struct	*user;		/* Prog owner for charging */
	union {
		struct work_struct work;
		struct rcu_head	rcu;
	};
};

struct bpf_prog {
	u16			pages;		/* Number of allocated pages */
	kmemcheck_bitfield_begin(meta);
	u16			jited:1,	/* Is our filter JIT'ed? */
				locked:1,	/* Program image locked? */
				gpl_compatible:1, /* Is filter GPL compatible? */
				cb_access:1,	/* Is control block accessed? */
				dst_needed:1;	/* Do we need dst entry? */
	kmemcheck_bitfield_end(meta);
	enum bpf_prog_type	type;		/* Type of BPF program */
	u32			len;		/* Number of filter blocks */
	u32			jited_len;	/* Size of jited insns in bytes */
	u8			tag[BPF_TAG_SIZE];
	struct bpf_prog_aux	*aux;		/* Auxiliary fields */
	struct sock_fprog_kern	*orig_prog;	/* Original BPF program */
	unsigned int		(*bpf_func)(const void *ctx,
					    const struct bpf_insn *insn);
	/* Instructions for interpreter */
	union {
		struct sock_filter	insns[0];
		struct bpf_insn		insnsi[0];
	};
};

/* Function argument constraints. */
enum bpf_arg_type {
	ARG_DONTCARE	= 0,	/* Unused argument in helper function. */
	ARG_CONST_MAP_PTR,	/* Const argument used as pointer to BPF map. */
	ARG_PTR_TO_MAP_KEY,	/* Pointer to stack used as map key. */
	ARG_PTR_TO_MAP_VALUE,	/* Pointer to stack used as map value. */
	ARG_PTR_TO_MEM,		/* Pointer to valid memory (stack, packet, map value). */
	ARG_PTR_TO_UNINIT_MEM,	/* Pointer to memory does not need to be initialized,
				 * Helper function must fill all bytes or clear
				 * them in error case.
				 */
	ARG_CONST_SIZE,		/* Number of bytes accessed from memory. */
	ARG_CONST_SIZE_OR_ZERO,	/* Number of bytes accessed from memory or 0. */
	ARG_PTR_TO_CTX,		/* Pointer to context. */
	ARG_ANYTHING,		/* Any (initialized) argument is ok. */
};

/* Type of values returned from helper functions. */
enum bpf_return_type {
	RET_INTEGER,			/* Function returns integer. */
	RET_VOID,			/* Function doesn't return anything. */
	RET_PTR_TO_MAP_VALUE_OR_NULL,	/* Returns a pointer to map elem value or NULL. */
};

enum bpf_access_type {
	BPF_READ	= 1,
	BPF_WRITE	= 2,
};

/* BPF function prototype used by verifier to allow BPF_CALLs
 * from programs to in-kernel helper functions and for adjusting
 * imm32 field in BPF_CALL instructions after verifying.
 */
struct bpf_func_proto {
	u64 (*func)(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
	bool gpl_only;
	bool pkt_access;
	enum bpf_return_type ret_type;
	enum bpf_arg_type arg1_type;
	enum bpf_arg_type arg2_type;
	enum bpf_arg_type arg3_type;
	enum bpf_arg_type arg4_type;
	enum bpf_arg_type arg5_type;
};

/* Types of values stored in eBPF registers for the verifier. */

/* Pointer types represent:
 *  pointer
 *  pointer + imm
 *  pointer + (u16) var
 *  pointer + (u16) var + imm
 *  if (range > 0) then [ptr, ptr + range - off) is safe to access
 *  if (id > 0) means that some 'var' was added
 *  if (off > 0) means that 'imm' was added
 */
enum bpf_reg_type {
	NOT_INIT	= 0,	/* Nothing was written into register. */
	SCALAR_VALUE,		/* Reg doesn't contain a valid pointer. */
	PTR_TO_CTX,		/* Reg points to bpf_context. */
	CONST_PTR_TO_MAP,	/* Reg points to struct bpf_map. */
	PTR_TO_MAP_VALUE,	/* Reg points to map element value. */
	PTR_TO_MAP_VALUE_OR_NULL, /* Points to map elem value or NULL. */
	PTR_TO_STACK,		/* Reg == frame_pointer + offset. */
	PTR_TO_PACKET,		/* Reg points to {skb,xdp}->data. */
	PTR_TO_PACKET_END,	/* {skb,xdp}->data + headlen. */
};

/* BPF context is intentionally undefined structure. Pointer
 * to bpf_context is the first argument to eBPF programs, e.g.
 * for socket filters it's equal to 'struct sk_buff *'.
 */
struct bpf_context;

/* The information passed from prog-specific *_is_valid_access
 * back to the verifier.
 */
struct bpf_insn_access_aux {
	enum bpf_reg_type reg_type;
	int ctx_field_size;
};

static inline void
bpf_ctx_record_field_size(struct bpf_insn_access_aux *aux, u32 size)
{
	aux->ctx_field_size = size;
}

struct bpf_event_entry {
	struct perf_event *event;
	struct file *perf_file;
	struct file *map_file;
	struct rcu_head rcu;
};

struct sk_filter {
	refcount_t	refcnt;
	struct rcu_head	rcu;
	struct bpf_prog	*prog;
};

#define BPF_PROG_RUN(filter, ctx)  (*filter->bpf_func)(ctx, filter->insnsi)

#define BPF_SKB_CB_LEN QDISC_CB_PRIV_LEN

struct bpf_skb_data_end {
	struct qdisc_skb_cb qdisc_cb;
	void *data_end;
};

struct xdp_buff {
	void *data;
	void *data_end;
	void *data_hard_start;
};

/* compute the linear packet data range [data, data_end) which
 * will be accessed by cls_bpf, act_bpf and lwt programs
 */
static inline void bpf_compute_data_end(struct sk_buff *skb)
{
	struct bpf_skb_data_end *cb = (struct bpf_skb_data_end *)skb->cb;

	BUILD_BUG_ON(sizeof(*cb) > FIELD_SIZEOF(struct sk_buff, cb));
	cb->data_end = skb->data + skb_headlen(skb);
}

static inline u8 *bpf_skb_cb(struct sk_buff *skb)
{
	/* eBPF programs may read/write skb->cb[] area to transfer meta
	 * data between tail calls. Since this also needs to work with
	 * tc, that scratch memory is mapped to qdisc_skb_cb's data area.
	 *
	 * In some socket filter cases, the cb unfortunately needs to be
	 * saved/restored so that protocol specific skb->cb[] data won't
	 * be lost. In any case, due to unpriviledged eBPF programs
	 * attached to sockets, we need to clear the bpf_skb_cb() area
	 * to not leak previous contents to user space.
	 */
	BUILD_BUG_ON(FIELD_SIZEOF(struct __sk_buff, cb) != BPF_SKB_CB_LEN);
	BUILD_BUG_ON(FIELD_SIZEOF(struct __sk_buff, cb) !=
		     FIELD_SIZEOF(struct qdisc_skb_cb, data));

	return qdisc_skb_cb(skb)->data;
}

static inline u32 bpf_prog_run_save_cb(const struct bpf_prog *prog,
				       struct sk_buff *skb)
{
	u8 *cb_data = bpf_skb_cb(skb);
	u8 cb_saved[BPF_SKB_CB_LEN];
	u32 res;

	if (unlikely(prog->cb_access)) {
		memcpy(cb_saved, cb_data, sizeof(cb_saved));
		memset(cb_data, 0, sizeof(cb_saved));
	}

	res = BPF_PROG_RUN(prog, skb);

	if (unlikely(prog->cb_access))
		memcpy(cb_data, cb_saved, sizeof(cb_saved));

	return res;
}

static inline u32 bpf_prog_run_clear_cb(const struct bpf_prog *prog,
					struct sk_buff *skb)
{
	u8 *cb_data = bpf_skb_cb(skb);

	if (unlikely(prog->cb_access))
		memset(cb_data, 0, BPF_SKB_CB_LEN);

	return BPF_PROG_RUN(prog, skb);
}

static __always_inline u32 bpf_prog_run_xdp(const struct bpf_prog *prog,
					    struct xdp_buff *xdp)
{
	/* Caller needs to hold rcu_read_lock() (!), otherwise program
	 * can be released while still running, or map elements could be
	 * freed early while still having concurrent users. XDP fastpath
	 * already takes rcu_read_lock() when fetching the program, so
	 * it's not necessary here anymore.
	 */
	return BPF_PROG_RUN(prog, xdp);
}

static inline u32 bpf_prog_insn_size(const struct bpf_prog *prog)
{
	return prog->len * sizeof(struct bpf_insn);
}

static inline u32 bpf_prog_tag_scratch_size(const struct bpf_prog *prog)
{
	return round_up(bpf_prog_insn_size(prog) +
			sizeof(__be64) + 1, SHA_MESSAGE_BYTES);
}

static inline unsigned int bpf_prog_size(unsigned int proglen)
{
	return max(sizeof(struct bpf_prog),
		   offsetof(struct bpf_prog, insns[proglen]));
}

static inline bool bpf_prog_was_classic(const struct bpf_prog *prog)
{
	/* When classic BPF programs have been loaded and the arch
	 * does not have a classic BPF JIT (anymore), they have been
	 * converted via bpf_migrate_filter() to eBPF and thus always
	 * have an unspec program type.
	 */
	return prog->type == BPF_PROG_TYPE_UNSPEC;
}

static inline bool
bpf_ctx_narrow_access_ok(u32 off, u32 size, const u32 size_default)
{
	bool off_ok;
#ifdef __LITTLE_ENDIAN
	off_ok = (off & (size_default - 1)) == 0;
#else
	off_ok = (off & (size_default - 1)) + size == size_default;
#endif
	return off_ok && size <= size_default && (size & (size - 1)) == 0;
}

#define bpf_classic_proglen(fprog) (fprog->len * sizeof(fprog->filter[0]))

#ifdef CONFIG_ARCH_HAS_SET_MEMORY
static inline void bpf_prog_lock_ro(struct bpf_prog *fp)
{
	fp->locked = 1;
	WARN_ON_ONCE(set_memory_ro((unsigned long)fp, fp->pages));
}

static inline void bpf_prog_unlock_ro(struct bpf_prog *fp)
{
	if (fp->locked) {
		WARN_ON_ONCE(set_memory_rw((unsigned long)fp, fp->pages));
		/* In case set_memory_rw() fails, we want to be the first
		 * to crash here instead of some random place later on.
		 */
		fp->locked = 0;
	}
}

static inline void bpf_jit_binary_lock_ro(struct bpf_binary_header *hdr)
{
	WARN_ON_ONCE(set_memory_ro((unsigned long)hdr, hdr->pages));
}

static inline void bpf_jit_binary_unlock_ro(struct bpf_binary_header *hdr)
{
	WARN_ON_ONCE(set_memory_rw((unsigned long)hdr, hdr->pages));
}
#else
static inline void bpf_prog_lock_ro(struct bpf_prog *fp)
{
}

static inline void bpf_prog_unlock_ro(struct bpf_prog *fp)
{
}

static inline void bpf_jit_binary_lock_ro(struct bpf_binary_header *hdr)
{
}

static inline void bpf_jit_binary_unlock_ro(struct bpf_binary_header *hdr)
{
}
#endif /* CONFIG_ARCH_HAS_SET_MEMORY */

static inline struct bpf_binary_header *
bpf_jit_binary_hdr(const struct bpf_prog *fp)
{
	unsigned long real_start = (unsigned long)fp->bpf_func;
	unsigned long addr = real_start & PAGE_MASK;

	return (void *)addr;
}

int sk_filter_trim_cap(struct sock *sk, struct sk_buff *skb, unsigned int cap);
static inline int sk_filter(struct sock *sk, struct sk_buff *skb)
{
	return sk_filter_trim_cap(sk, skb, 1);
}

struct bpf_prog *bpf_prog_select_runtime(struct bpf_prog *fp, int *err);
void bpf_prog_free(struct bpf_prog *fp);

struct bpf_prog *bpf_prog_alloc(unsigned int size, gfp_t gfp_extra_flags);
struct bpf_prog *bpf_prog_realloc(struct bpf_prog *fp_old, unsigned int size,
				  gfp_t gfp_extra_flags);
void __bpf_prog_free(struct bpf_prog *fp);

static inline void bpf_prog_unlock_free(struct bpf_prog *fp)
{
	bpf_prog_unlock_ro(fp);
	__bpf_prog_free(fp);
}

struct bpf_array {
	struct bpf_map map;
	u32 elem_size;
	/* 'Ownership' of prog_array is claimed by the first program that is
	 * going to use this map or by the first program which FD is stored
	 * in the map to make sure that all callers and callees have the same
	 * prog_type and JITed flag.
	 */
	enum bpf_prog_type owner_prog_type;
	bool owner_jited;
	union {
		char value[0] __aligned(8);
		void *ptrs[0] __aligned(8);
		void __percpu *pptrs[0] __aligned(8);
	};
};

bool bpf_prog_array_compatible(struct bpf_array *array, const struct bpf_prog *fp);
int bpf_prog_calc_tag(struct bpf_prog *fp);
void bpf_user_rnd_init_once(void);
const struct bpf_func_proto *bpf_get_trace_printk_proto(void);

typedef unsigned long (*bpf_ctx_copy_t)(void *dst, const void *src,
					unsigned long off, unsigned long len);

u64 bpf_event_output(struct bpf_map *map, u64 flags, void *meta, u64 meta_size,
		     void *ctx, u64 ctx_size, bpf_ctx_copy_t ctx_copy);

typedef int (*bpf_aux_classic_check_t)(struct sock_filter *filter,
				       unsigned int flen);

int bpf_prog_create(struct bpf_prog **pfp, struct sock_fprog_kern *fprog);
int bpf_prog_create_from_user(struct bpf_prog **pfp, struct sock_fprog *fprog,
			      bpf_aux_classic_check_t trans, bool save_orig);
void bpf_prog_destroy(struct bpf_prog *fp);

int bpf_prog_test_run_xdp(struct bpf_prog *prog, const union bpf_attr *kattr,
			  union bpf_attr __user *uattr);
int bpf_prog_test_run_skb(struct bpf_prog *prog, const union bpf_attr *kattr,
			  union bpf_attr __user *uattr);

int sk_attach_filter(struct sock_fprog *fprog, struct sock *sk);
int sk_attach_bpf(u32 ufd, struct sock *sk);
int sk_reuseport_attach_filter(struct sock_fprog *fprog, struct sock *sk);
int sk_reuseport_attach_bpf(u32 ufd, struct sock *sk);
int sk_detach_filter(struct sock *sk);
int sk_get_filter(struct sock *sk, struct sock_filter __user *filter,
		  unsigned int len);

bool sk_filter_charge(struct sock *sk, struct sk_filter *fp);
void sk_filter_uncharge(struct sock *sk, struct sk_filter *fp);

u64 __bpf_call_base(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);

struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog);
void bpf_jit_compile(struct bpf_prog *prog);
bool bpf_helper_changes_pkt_data(void *func);

#ifdef CONFIG_BPF_SYSCALL
DECLARE_PER_CPU(int, bpf_prog_active);

#define BPF_PROG_TYPE(_id, _ops) \
	extern const struct bpf_verifier_ops _ops;
#define BPF_MAP_TYPE(_id, _ops) \
	extern const struct bpf_map_ops _ops;
#include <linux/bpf_types.h>
#undef BPF_PROG_TYPE
#undef BPF_MAP_TYPE

struct bpf_prog *bpf_prog_get(u32 ufd);
struct bpf_prog *bpf_prog_get_type(u32 ufd, enum bpf_prog_type type);
struct bpf_prog * __must_check bpf_prog_add(struct bpf_prog *prog, int i);
void bpf_prog_sub(struct bpf_prog *prog, int i);
struct bpf_prog * __must_check bpf_prog_inc(struct bpf_prog *prog);
void bpf_prog_put(struct bpf_prog *prog);
int __bpf_prog_charge(struct user_struct *user, u32 pages);
void __bpf_prog_uncharge(struct user_struct *user, u32 pages);

struct bpf_map *bpf_map_get_with_uref(u32 ufd);
struct bpf_map *__bpf_map_get(struct fd f);
struct bpf_map * __must_check bpf_map_inc(struct bpf_map *map, bool uref);
void bpf_map_put_with_uref(struct bpf_map *map);
void bpf_map_put(struct bpf_map *map);
int bpf_map_precharge_memlock(u32 pages);
void *bpf_map_area_alloc(size_t size);
void bpf_map_area_free(void *base);

extern int sysctl_unprivileged_bpf_disabled;

int bpf_map_new_fd(struct bpf_map *map);
int bpf_prog_new_fd(struct bpf_prog *prog);

int bpf_obj_pin_user(u32 ufd, const char __user *pathname);
int bpf_obj_get_user(const char __user *pathname);

int bpf_percpu_hash_copy(struct bpf_map *map, void *key, void *value);
int bpf_percpu_array_copy(struct bpf_map *map, void *key, void *value);
int bpf_percpu_hash_update(struct bpf_map *map, void *key, void *value,
			   u64 flags);
int bpf_percpu_array_update(struct bpf_map *map, void *key, void *value,
			    u64 flags);

int bpf_stackmap_copy(struct bpf_map *map, void *key, void *value);

int bpf_fd_array_map_update_elem(struct bpf_map *map, struct file *map_file,
				 void *key, void *value, u64 map_flags);
int bpf_fd_array_map_lookup_elem(struct bpf_map *map, void *key, u32 *value);
void bpf_fd_array_map_clear(struct bpf_map *map);
int bpf_fd_htab_map_update_elem(struct bpf_map *map, struct file *map_file,
				void *key, void *value, u64 map_flags);
int bpf_fd_htab_map_lookup_elem(struct bpf_map *map, void *key, u32 *value);

/* memcpy that is used with 8-byte aligned pointers, power-of-8 size and
 * forced to use 'long' read/writes to try to atomically copy long counters.
 * Best-effort only.  No barriers here, since it _will_ race with concurrent
 * updates from BPF programs. Called from bpf syscall and mostly used with
 * size 8 or 16 bytes, so ask compiler to inline it.
 */
static inline void bpf_long_memcpy(void *dst, const void *src, u32 size)
{
	const long *lsrc = src;
	long *ldst = dst;

	size /= sizeof(long);
	while (size--)
		*ldst++ = *lsrc++;
}

/* Verify correctness of eBPF program. */
int bpf_check(struct bpf_prog **fp, union bpf_attr *attr);

/* Map specifics */
struct net_device  *__dev_map_lookup_elem(struct bpf_map *map, u32 key);
void __dev_map_insert_ctx(struct bpf_map *map, u32 index);
void __dev_map_flush(struct bpf_map *map);
#else
static inline struct bpf_prog *bpf_prog_get(u32 ufd)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline struct bpf_prog *bpf_prog_get_type(u32 ufd,
						 enum bpf_prog_type type)
{
	return ERR_PTR(-EOPNOTSUPP);
}
static inline struct bpf_prog * __must_check bpf_prog_add(struct bpf_prog *prog,
							  int i)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void bpf_prog_sub(struct bpf_prog *prog, int i)
{
}

static inline void bpf_prog_put(struct bpf_prog *prog)
{
}

static inline struct bpf_prog * __must_check bpf_prog_inc(struct bpf_prog *prog)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline int __bpf_prog_charge(struct user_struct *user, u32 pages)
{
	return 0;
}

static inline void __bpf_prog_uncharge(struct user_struct *user, u32 pages)
{
}

static inline struct net_device  *__dev_map_lookup_elem(struct bpf_map *map,
						       u32 key)
{
	return NULL;
}

static inline void __dev_map_insert_ctx(struct bpf_map *map, u32 index)
{
}

static inline void __dev_map_flush(struct bpf_map *map)
{
}
#endif /* CONFIG_BPF_SYSCALL */

struct bpf_prog *bpf_patch_insn_single(struct bpf_prog *prog, u32 off,
				       const struct bpf_insn *patch, u32 len);

/* The pair of xdp_do_redirect and xdp_do_flush_map MUST be called in the
 * same cpu context. Further for best results no more than a single map
 * for the do_redirect/do_flush pair should be used. This limitation is
 * because we only track one map and force a flush when the map changes.
 * This does not appear to be a real limitation for existing software.
 */
int xdp_do_generic_redirect(struct net_device *dev, struct sk_buff *skb);
int xdp_do_redirect(struct net_device *dev,
		    struct xdp_buff *xdp,
		    struct bpf_prog *prog);
void xdp_do_flush_map(void);

void bpf_warn_invalid_xdp_action(u32 act);
void bpf_warn_invalid_xdp_redirect(u32 ifindex);

#ifdef CONFIG_BPF_JIT
extern int bpf_jit_enable;
extern int bpf_jit_harden;
extern int bpf_jit_kallsyms;

typedef void (*bpf_jit_fill_hole_t)(void *area, unsigned int size);

struct bpf_binary_header *
bpf_jit_binary_alloc(unsigned int proglen, u8 **image_ptr,
		     unsigned int alignment,
		     bpf_jit_fill_hole_t bpf_fill_ill_insns);
void bpf_jit_binary_free(struct bpf_binary_header *hdr);

void bpf_jit_free(struct bpf_prog *fp);

struct bpf_prog *bpf_jit_blind_constants(struct bpf_prog *fp);
void bpf_jit_prog_release_other(struct bpf_prog *fp, struct bpf_prog *fp_other);

static inline void bpf_jit_dump(unsigned int flen, unsigned int proglen,
				u32 pass, void *image)
{
	pr_err("flen=%u proglen=%u pass=%u image=%pK from=%s pid=%d\n", flen,
	       proglen, pass, image, current->comm, task_pid_nr(current));

	if (image)
		print_hex_dump(KERN_ERR, "JIT code: ", DUMP_PREFIX_OFFSET,
			       16, 1, image, proglen, false);
}

static inline bool bpf_jit_is_ebpf(void)
{
# ifdef CONFIG_HAVE_EBPF_JIT
	return true;
# else
	return false;
# endif
}

static inline bool ebpf_jit_enabled(void)
{
	return bpf_jit_enable && bpf_jit_is_ebpf();
}

static inline bool bpf_prog_ebpf_jited(const struct bpf_prog *fp)
{
	return fp->jited && bpf_jit_is_ebpf();
}

static inline bool bpf_jit_blinding_enabled(void)
{
	/* These are the prerequisites, should someone ever have the
	 * idea to call blinding outside of them, we make sure to
	 * bail out.
	 */
	if (!bpf_jit_is_ebpf())
		return false;
	if (!bpf_jit_enable)
		return false;
	if (!bpf_jit_harden)
		return false;
	if (bpf_jit_harden == 1 && capable(CAP_SYS_ADMIN))
		return false;

	return true;
}

static inline bool bpf_jit_kallsyms_enabled(void)
{
	/* There are a couple of corner cases where kallsyms should
	 * not be enabled f.e. on hardening.
	 */
	if (bpf_jit_harden)
		return false;
	if (!bpf_jit_kallsyms)
		return false;
	if (bpf_jit_kallsyms == 1)
		return true;

	return false;
}

const char *__bpf_address_lookup(unsigned long addr, unsigned long *size,
				 unsigned long *off, char *sym);
bool is_bpf_text_address(unsigned long addr);
int bpf_get_kallsym(unsigned int symnum, unsigned long *value, char *type,
		    char *sym);

static inline const char *
bpf_address_lookup(unsigned long addr, unsigned long *size,
		   unsigned long *off, char **modname, char *sym)
{
	const char *ret = __bpf_address_lookup(addr, size, off, sym);

	if (ret && modname)
		*modname = NULL;
	return ret;
}

void bpf_prog_kallsyms_add(struct bpf_prog *fp);
void bpf_prog_kallsyms_del(struct bpf_prog *fp);

#else /* CONFIG_BPF_JIT */

static inline bool ebpf_jit_enabled(void)
{
	return false;
}

static inline bool bpf_prog_ebpf_jited(const struct bpf_prog *fp)
{
	return false;
}

static inline void bpf_jit_free(struct bpf_prog *fp)
{
	bpf_prog_unlock_free(fp);
}

static inline bool bpf_jit_kallsyms_enabled(void)
{
	return false;
}

static inline const char *
__bpf_address_lookup(unsigned long addr, unsigned long *size,
		     unsigned long *off, char *sym)
{
	return NULL;
}

static inline bool is_bpf_text_address(unsigned long addr)
{
	return false;
}

static inline int bpf_get_kallsym(unsigned int symnum, unsigned long *value,
				  char *type, char *sym)
{
	return -ERANGE;
}

static inline const char *
bpf_address_lookup(unsigned long addr, unsigned long *size,
		   unsigned long *off, char **modname, char *sym)
{
	return NULL;
}

static inline void bpf_prog_kallsyms_add(struct bpf_prog *fp)
{
}

static inline void bpf_prog_kallsyms_del(struct bpf_prog *fp)
{
}
#endif /* CONFIG_BPF_JIT */

#define BPF_ANC		BIT(15)

static inline bool bpf_needs_clear_a(const struct sock_filter *first)
{
	switch (first->code) {
	case BPF_RET | BPF_K:
	case BPF_LD | BPF_W | BPF_LEN:
		return false;

	case BPF_LD | BPF_W | BPF_ABS:
	case BPF_LD | BPF_H | BPF_ABS:
	case BPF_LD | BPF_B | BPF_ABS:
		if (first->k == SKF_AD_OFF + SKF_AD_ALU_XOR_X)
			return true;
		return false;

	default:
		return true;
	}
}

static inline u16 bpf_anc_helper(const struct sock_filter *ftest)
{
	BUG_ON(ftest->code & BPF_ANC);

	switch (ftest->code) {
	case BPF_LD | BPF_W | BPF_ABS:
	case BPF_LD | BPF_H | BPF_ABS:
	case BPF_LD | BPF_B | BPF_ABS:
#define BPF_ANCILLARY(CODE)	case SKF_AD_OFF + SKF_AD_##CODE:	\
				return BPF_ANC | SKF_AD_##CODE
		switch (ftest->k) {
		BPF_ANCILLARY(PROTOCOL);
		BPF_ANCILLARY(PKTTYPE);
		BPF_ANCILLARY(IFINDEX);
		BPF_ANCILLARY(NLATTR);
		BPF_ANCILLARY(NLATTR_NEST);
		BPF_ANCILLARY(MARK);
		BPF_ANCILLARY(QUEUE);
		BPF_ANCILLARY(HATYPE);
		BPF_ANCILLARY(RXHASH);
		BPF_ANCILLARY(CPU);
		BPF_ANCILLARY(ALU_XOR_X);
		BPF_ANCILLARY(VLAN_TAG);
		BPF_ANCILLARY(VLAN_TAG_PRESENT);
		BPF_ANCILLARY(PAY_OFFSET);
		BPF_ANCILLARY(RANDOM);
		BPF_ANCILLARY(VLAN_TPID);
		}
		/* Fallthrough. */
	default:
		return ftest->code;
	}
}

void *bpf_internal_load_pointer_neg_helper(const struct sk_buff *skb,
					   int k, unsigned int size);

static inline void *bpf_load_pointer(const struct sk_buff *skb, int k,
				     unsigned int size, void *buffer)
{
	if (k >= 0)
		return skb_header_pointer(skb, k, size, buffer);

	return bpf_internal_load_pointer_neg_helper(skb, k, size);
}

static inline int bpf_tell_extensions(void)
{
	return SKF_AD_MAX;
}

struct bpf_sock_ops_kern {
	struct	sock *sk;
	u32	op;
	union {
		u32 reply;
		u32 replylong[4];
	};
};

/* Verifier prototypes for helper functions called from eBPF programs. */
extern const struct bpf_func_proto bpf_map_lookup_elem_proto;
extern const struct bpf_func_proto bpf_map_update_elem_proto;
extern const struct bpf_func_proto bpf_map_delete_elem_proto;

extern const struct bpf_func_proto bpf_get_prandom_u32_proto;
extern const struct bpf_func_proto bpf_get_smp_processor_id_proto;
extern const struct bpf_func_proto bpf_get_numa_node_id_proto;
extern const struct bpf_func_proto bpf_tail_call_proto;
extern const struct bpf_func_proto bpf_ktime_get_ns_proto;
extern const struct bpf_func_proto bpf_get_current_pid_tgid_proto;
extern const struct bpf_func_proto bpf_get_current_uid_gid_proto;
extern const struct bpf_func_proto bpf_get_current_comm_proto;
extern const struct bpf_func_proto bpf_skb_vlan_push_proto;
extern const struct bpf_func_proto bpf_skb_vlan_pop_proto;
extern const struct bpf_func_proto bpf_get_stackid_proto;

/* Shared helper prototypes. */
u64 bpf_tail_call(u64 ctx, u64 r2, u64 index, u64 r4, u64 r5);
u64 bpf_get_stackid(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
u64 bpf_user_rnd_u32(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);

#endif /* __LINUX_BPF_H__ */
