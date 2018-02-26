/*
 * Iptables match for selecting security labels
 *
 * Copyright (C) 2018 vt@altlinux.org
 *
 * This code is released under the GNU GPL v2, 1991
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <asm/unaligned.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/bitrev.h>
#include <linux/netfilter/x_tables.h>
#include <net/cipso_ipv4.h>
#include "xt_so.h"

#define XT_SO_VERSION VERSION
MODULE_AUTHOR("<vt@altlinux.org>");
MODULE_DESCRIPTION("iptables match for selecting security labels");
MODULE_LICENSE("GPL");
MODULE_VERSION(XT_SO_VERSION);
MODULE_ALIAS("ipt_so");

static unsigned int debug __read_mostly = 0;
module_param(debug, uint, 0664);
MODULE_PARM_DESC(debug, "debug level");

/* Extract rfc1108 packed flags into array. */
static int unpack_rfc1108_bits(const uint8_t *data, size_t len, uint8_t *out, size_t size)
{
	unsigned int i;
	unsigned int acc = 0;
	unsigned int bits = 0;

	for (i = 0; i < len; i++) {
		const uint8_t b = data[i];

		if ((b >> 1) && !size) {
			/* `acc` could accumulate big amount of zero bits that
			 * could exceed its size if turned to significant bits,
			 * instaerror if significant bits are incoming and
			 * output buffer is already chocked */
			return -1;
		}
		acc |= (b >> 1) << bits;
		bits += 7;
		while (bits >= 8) {
			/* any significant bits exceeding output buffer will
			 * trigger a error */
			if (size) {
				*out++ = acc & 0xff;
				size--;
				acc >>= 8;
				bits -= 8;
			} else if (acc) {
				/* not triggering error on zero `acc` will allow
				 * to accumulate insignificant zero bits */
				return -1;
			}
		}
		if (!(b & 1))
			break;
	}
	/* garbage behind uncontinued byte until option end is silently
	 * discarded */
	while (acc) {
		if (size) {
			*out++ = acc & 0xff;
			size--;
			acc >>= 8;
			bits -= 8;
		} else
			return -1;
	}
	/* higher bits that is not presented in the input assumed to be zeros */
	while (size) {
		*out++ = 0;
		size--;
	}

	return 0;
}

/* Copy variable len (bit-)array filling another with sanity checks
 * and stripping insignificant bits if need. */
static int copy_msb0_bits(const uint8_t *data, size_t len, uint8_t *out, size_t size)
{
	unsigned int i;

	for (i = 0; i < len; i++) {
		const uint8_t b = data[i];

		if (size) {
			*out++ = b;
			size--;
		} else if (b)
			return 1;
	}
	while (size) {
		*out++ = 0;
		size--;
	}
	return 0;
}

static uint64_t bitrev64(uint64_t x)
{
	return ((uint64_t)bitrev32(x) << 32) |
		(uint64_t)bitrev32(x >> 32);
}

/* Extract level and categories from RFC 1108 Basic Security label */
/* Label in RFC 1108 is originally encoded as:
 * [0]   130 = IPOPT_SEC
 * [1]   length >= 3
 * [2]   classification level (lower value is higher secrecy) [4 levels]
 * [3].. protection authority flags (msb0)
 *       * lsb of each byte since [3] is flag of presence of next byte
 *
 * Astra mod:
 * [0]   130 = IPOPT_SEC
 * [1]   length >= 4
 * [2]   classification level is Unclassified (0b10101011)
 * [3]   level (higher value higher secrecy) [256 levels]
 * [4].. categories (lsb0)
 *       * lsb of each byte since [3] is flag of presence of next byte
 *
 */
static int parse_rfc1108_astra(const uint8_t *data, uint16_t len, uint8_t *level, uint64_t *categories)
{
	uint8_t parsec[9];

	if (data[1] < 3)
		return 0;
	if (data[2] != 0b10101011) /* Unclassified */
		return 0;
	/* Astra allows 64-bit of category flags */
	if (data[1] < 4)
		return 0;

	if (unpack_rfc1108_bits(&data[3], len - 3, parsec, sizeof(parsec)))
		return 0;

	*level = parsec[0];
	*categories = get_unaligned_le64(&parsec[1]);
	if (debug > 1)
		pr_devel(": astra level=%u categories=%llx\n", *level, *categories);

	return 1;
}

#define CIPSO_V4_OPT_LEN_MAX          40
#define CIPSO_V4_HDR_LEN              6
#define CIPSO_V4_TAG_RBM_BLEN         4
#define CIPSO_V4_OPT_LEN (CIPSO_V4_HDR_LEN + CIPSO_V4_TAG_RBM_BLEN)

/* Extract level and categories from cipso option. */
/* CIPSO option is encoded like this:
 * [0]     134 = IPOPT_CIPSO
 * [1]     length <= 40
 * [2..5]  DOI >= 1
 * tags:
 *  [6]    tag type (1 for bitmap)
 *  [7]    length of tag (4..34)
 *  [8]    empty alignment byte
 *  [9]    sensitivity level
 *  [10..] categories bitmap (msb0-be) (0..30 octets)
 * [another tag...]
 */
static int parse_cipso(const uint8_t *data, uint16_t len, uint8_t *level,
    uint64_t *categories, uint32_t *doi)
{
	if (data[1] <= CIPSO_V4_HDR_LEN || data[1] > CIPSO_V4_OPT_LEN_MAX)
		return 0;
	*doi = get_unaligned_be32(&data[2]);
	data += CIPSO_V4_HDR_LEN;
	len  -= CIPSO_V4_HDR_LEN;
	/* parse tags */
	while (len > 0) {
		if (len < CIPSO_V4_TAG_RBM_BLEN
		    || data[1] < CIPSO_V4_TAG_RBM_BLEN
		    || data[1] > len)
			return 0;
		*level = data[3];

		if (data[0] == CIPSO_V4_TAG_RBITMAP) {
			if (copy_msb0_bits(&data[4], data[1] - 3,
				    (uint8_t *)categories, sizeof(*categories)))
				return 0;
			*categories = bitrev64(be64_to_cpu(*categories));
			break;
		} else {
			/* two other tag types are not supported */
			return 0;
		}
	}
	if (debug > 1)
		pr_devel(": cipso level=%u categories=%llx\n", *level, *categories);
	return 1;
}

static bool
so_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct so_info *info = par->targinfo;
	const struct iphdr *iph = ip_hdr(skb);
	const uint8_t *data = (const void *)iph + sizeof(struct iphdr);
	uint16_t len = ip_hdrlen(skb) - sizeof(struct iphdr);
	uint8_t level       = 0;
	uint64_t categories = 0;
	size_t opt_len;
	int    sec_err = -1; /* sec option never seen */

	while (len >= 2) {
		if (data[IPOPT_OPTVAL] == IPOPT_END)
			break;
		else if (data[IPOPT_OPTVAL] == IPOPT_NOOP) {
			--len;
			++data;
			continue;
		}
		opt_len = data[IPOPT_OLEN];

		/* invalid option length */
		if (opt_len < 2 || opt_len > len)
			goto pproblem;

		if (data[IPOPT_OPTVAL] == IPOPT_SEC) {
			/* multiple security options are not allowed */
			if (sec_err != -1)
				goto pproblem;
			if (debug > 1)
				pr_devel("option astra %#x[%x] %*ph\n",
				    data[IPOPT_OPTVAL], data[IPOPT_OLEN],
				    len, data);
			if (!(info->flags & F_SO_ASTRA))
				goto mismatch;
			sec_err = !parse_rfc1108_astra(data, len, &level,
			    &categories);
			if (sec_err)
				goto pproblem;
		} else if (data[IPOPT_OPTVAL] == IPOPT_CIPSO) {
			uint32_t doi;

			if (sec_err != -1)
				goto pproblem;
			if (debug > 1)
				pr_devel("option cipso %#x[%x] %*ph\n",
				    data[IPOPT_OPTVAL], data[IPOPT_OLEN],
				    len, data);
			if (!(info->flags & F_SO_CIPSO))
				goto mismatch;
			sec_err = !parse_cipso(data, len, &level, &categories,
			    &doi);
			if (sec_err)
				goto pproblem;
			if (info->flags & F_SO_DOI) {
				if ((info->doi != doi)
				    == !(info->flags & F_SO_DOI_INV)) {
					if (debug > 1)
						pr_devel("DOI mismatch %u vs %s%u\n",
						    doi, 
						    (info->flags & F_SO_DOI_INV)? "!" : "",
						    info->doi);
					goto mismatch;
				}
			}
		}
		len  -= opt_len;
		data += opt_len;
	}

	if (sec_err == -1) {
		if (!(info->flags & F_SO_UNLBL))
			goto mismatch;
	}
	if (info->flags & F_SO_LEVEL) {
		if (!test_bit(level, info->level_bitmap)
		    == !(info->flags & F_SO_LEVEL_INV)) {
			if (debug > 1)
				pr_devel("Level is not allowed %u\n", level);
			goto mismatch;
		}
	}
	if (info->flags & F_SO_CATEG) {
		if ((info->categ != categories)
		    == !(info->flags & F_SO_CATEG_INV)) {
			if (debug > 1)
				pr_devel("Category mismatch %llx vs %s%llx\n",
				    categories,
				    (info->flags & F_SO_DOI_INV)? "!" : "",
				    info->categ);
			goto mismatch;
		}
	}

	return true ^ !!(info->flags & F_SO_MATCH_INV);
mismatch:
	return false ^ !!(info->flags & F_SO_MATCH_INV);
pproblem:
	par->hotdrop = true;
	return false;
}

static struct xt_match so_mt_reg __read_mostly = {
	.name      = "so",
	.family    = NFPROTO_IPV4,
	.match     = so_mt,
	.matchsize = sizeof(struct so_info),
	.me        = THIS_MODULE,
};

static int __init so_init(void)
{
	pr_info("loading " XT_SO_VERSION ", debug=%d\n", debug);
	return xt_register_match(&so_mt_reg);
}

static void __exit so_exit(void)
{
	xt_unregister_match(&so_mt_reg);
	pr_info("unloaded\n");
}

module_init(so_init);
module_exit(so_exit);
