/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _XT_SO_H
# define _XT_SO_H

# ifndef DECLARE_BITMAP
#  define DIV_ROUND_UP(n, d)	(((n) + (d) - 1) / (d))
#  define BITS_PER_BYTE		8
#  define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#  define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]

#  ifndef __WORDSIZE
#   define __WORDSIZE (__SIZEOF_LONG__ * 8)
#  endif

#  ifndef BITS_PER_LONG
#   define BITS_PER_LONG __WORDSIZE
#  endif

#  define BIT_MASK(nr)		(1UL << ((nr) % BITS_PER_LONG))
#  define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
# endif

enum {
	F_SO_MATCH	= 1 << 0,
	F_SO_MATCH_INV	= 1 << 1,
	F_SO_LEVEL	= 1 << 2,
	F_SO_LEVEL_INV	= 1 << 3,
	F_SO_CATEG	= 1 << 4,
	F_SO_CATEG_INV	= 1 << 5,
	F_SO_DOI	= 1 << 6,
	F_SO_DOI_INV	= 1 << 7,
	F_SO_UNLBL	= 1 << 8,
	F_SO_CIPSO	= 1 << 9,
	F_SO_ASTRA	= 1 << 10,
};

#define LEVELS_NUM	(256 + 1) /* plus level zero */
struct so_info {
	uint32_t flags;
	/* allowed levels - at least one should be present */
	DECLARE_BITMAP(level_bitmap, LEVELS_NUM);
	/* categories bit-masks are 1-based, as in network */
	/* required categoreis - all should be present */
	uint64_t categ;
	/* doi restriction for CIPSO */
	uint32_t doi;
};

# ifndef __KERNEL__
static inline void set_bit(int nr, unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

	*p |= mask;
}

static inline int get_bit(int nr, unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

	return (*p & mask) != 0;
}
# endif
#endif /* _XT_SO_H */
