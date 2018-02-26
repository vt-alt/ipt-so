/*
 * Iptables match for selecting security labels
 *
 * Copyright (C) 2018 vt@altlinux.org
 *
 * This code is released under the GNU GPL v2, 1991
 */

#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xtables.h>
#include <netinet/ether.h>
#include "xt_so.h"

enum {
	O_SO_MATCH = 0,
	O_SO_MISMATCH,
	O_SO_PROTO,
	O_SO_LEVEL,
	O_SO_CATEG,
	O_SO_DOI,
};

static const struct xt_option_entry so_mt_opts[] = {
	{.name = "so-match-all", .id = O_SO_MATCH, .flags = XTOPT_INVERT},
	{.name = "so-mismatch", .id = O_SO_MISMATCH},
	{.name = "so-proto", .id = O_SO_PROTO,
		.type = XTTYPE_STRING, .flags = XTOPT_INVERT},
	{.name = "so-level", .id = O_SO_LEVEL,
		.type = XTTYPE_STRING, .flags = XTOPT_INVERT},
	{.name = "so-categ", .id = O_SO_CATEG,
		.type = XTTYPE_STRING, .flags = XTOPT_INVERT},
	{.name = "so-doi", .id = O_SO_DOI,
		.type = XTTYPE_UINT32, .flags = XTOPT_PUT|XTOPT_INVERT,
		XTOPT_POINTER(struct so_info, doi)},
	XTOPT_TABLEEND
};

static void so_mt_help(void)
{
	printf(
"so match options:\n"
"  --so-mismatch             Trigger match if any parameter does not match\n"
"                            You should use this option to `-j DROP`.\n"
"  --so-match-all            Trigger match if all options match.\n"
" [!] --so-proto cipso,astra,unlbl Set required security label protocols\n"
"                            (default=any).\n"
" [!] --so-level n[,n...]    Set security levels to match (any will match).\n"
" [!] --so-categ n[,n...]    Set required security categories (exact match).\n"
" [!] --so-doi n             Set required CIPSO DOI.\n"
	);
}

static uint16_t parse_level(const char *level)
{
	unsigned int num;

	if (xtables_strtoui(level, NULL, &num, 0, UINT8_MAX))
		return num;

	xtables_error(PARAMETER_PROBLEM, "invalid level `%s' specified", level);
}

static void parse_levels(const char *levelstring, struct so_info *info)
{
	char *buffer = strdup(levelstring);
	char *cp, *next;

	if (!buffer)
		xtables_error(OTHER_PROBLEM, "strdup failed");
	for (cp = buffer; cp; cp = next) {
		uint16_t level;

		next = strchr(cp, ',');
		if (next)
			*next++ = '\0';
		level = parse_level(cp);
		set_bit(level, info->level_bitmap);
	}
	free(buffer);
}

static uint16_t parse_categ(const char *level)
{
	unsigned int num;

	if (xtables_strtoui(level, NULL, &num, 0, 64))
		return num;

	xtables_error(PARAMETER_PROBLEM, "invalid category `%s' specified",
	    level);
}

static void parse_categs(const char *categories, uint64_t *categout)
{
	char *buffer = strdup(categories);
	char *cp, *next;
	int have_cat0 = 0;

	if (!buffer)
		xtables_error(OTHER_PROBLEM, "strdup failed");
	for (cp = buffer; cp; cp = next) {
		uint16_t cat;

		next = strchr(cp, ',');
		if (next)
			*next++ = '\0';
		cat = parse_categ(cp);
		/* category 1 is bit0, thus, category 0 is no category */
		if (!cat)
			have_cat0 = 1;
		else {
			uint64_t ocat = *categout;

			*categout |= 1ULL << (cat - 1);
			if (*categout == ocat)
				xtables_error(OTHER_PROBLEM,
				    "--so-categ: duplicated gategory %d", cat);
		}
	}
	free(buffer);

	if (have_cat0 && *categout)
		xtables_error(OTHER_PROBLEM, "--so-categ: category 0 ca not be combined with other categories");
}

static uint32_t parse_protos(const char *protostring)
{
	char *buffer = strdup(protostring);
	char *cp, *next;
	uint32_t flags = 0;

	if (!buffer)
		xtables_error(OTHER_PROBLEM, "strdup failed");
	for (cp = buffer; cp; cp = next) {
		next = strchr(cp, ',');
		if (next)
			*next++ = '\0';

		if (!strcmp(cp, "cipso"))
			flags |= F_SO_CIPSO;
		else if (!strcmp(cp, "astra"))
			flags |= F_SO_ASTRA;
		else if (!strcmp(cp, "unlbl") || !strcmp(cp, "unlabeled"))
			flags |= F_SO_UNLBL;
		else if (!strcmp(cp, "any"))
			flags |= F_SO_CIPSO|F_SO_ASTRA|F_SO_UNLBL;
		else if (!strcmp(cp, "lbl") || !strcmp(cp, "labeled"))
			flags |= F_SO_CIPSO|F_SO_ASTRA;
		else
			xtables_error(OTHER_PROBLEM,
			    "unknown --so-proto, allowed values `cipso,astra,unlbl'");
	}
	free(buffer);
	return flags;
}

static void so_mt_parse(struct xt_option_call *cb)

{
	struct so_info *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_SO_LEVEL:
		parse_levels(cb->arg, info);
		info->flags |= F_SO_LEVEL;
		if (cb->invert)
			info->flags |= F_SO_LEVEL_INV;
		break;
	case O_SO_CATEG:
		parse_categs(cb->arg, &info->categ);
		info->flags |= F_SO_CATEG;
		if (cb->invert)
			info->flags |= F_SO_CATEG_INV;
		break;
	case O_SO_DOI:
		info->flags |= F_SO_DOI;
		if (cb->invert)
			info->flags |= F_SO_DOI_INV;
		break;
	case O_SO_PROTO:
		info->flags = parse_protos(cb->arg);
		if (cb->invert)
			info->flags ^= parse_protos("any");
		break;
	case O_SO_MATCH:
		info->flags |= F_SO_MATCH;
		if (cb->invert)
			info->flags |= F_SO_MATCH_INV;
		break;
	case O_SO_MISMATCH:
		info->flags |= F_SO_MATCH_INV;
	}
}

static void so_mt_init(struct xt_entry_match *match)
{
	struct so_info *info = (void *)match->data;

	memset(info, 0, sizeof(*info));
	info->flags |= parse_protos("any");
}

static void so_mt_check(struct xt_fcheck_call *cb)
{
	struct so_info *info = cb->data;
	
	if (!(info->flags & (F_SO_MATCH|F_SO_MATCH_INV)))
		xtables_error(OTHER_PROBLEM,
		    "specify --so-match-all or --so-mismatch explicitly");
	if (!(info->flags & parse_protos("any")))
		xtables_error(OTHER_PROBLEM,
		    "--so-proto does not select any packets");
	if (!(info->flags & F_SO_CIPSO))
		if (info->flags & F_SO_DOI)
			xtables_error(OTHER_PROBLEM,
			    "--so-doi requires --so-proto cipso|any to be used");
}

static void categ_print(uint64_t category)
{
	int i;
	char separ = ' ';

	for (i = 0; i < 64; i++) {
		if (category & (1ULL << i)) {
			printf("%c%d", separ, i + 1); /* 1-based */
			separ = ',';
		}
	}
	if (!category)
		printf(" 0");
}

static void so_mt_save(const void *ip,
    const struct xt_entry_match *match)
{
	struct so_info *info = (void *)match->data;
	int i;

	if ((info->flags & parse_protos("any")) != parse_protos("any")) {
		printf(" --so-proto");
		char separ = ' ';

		if (info->flags & F_SO_UNLBL) {
			printf("%cunlbl", separ);
			separ = ',';
		}
		if (info->flags & F_SO_CIPSO) {
			printf("%ccipso", separ);
			separ = ',';
		}
		if (info->flags & F_SO_ASTRA)
			printf("%castra", separ);
	}
	if (info->flags & F_SO_DOI && info->flags & F_SO_CIPSO) {
		printf(" --so-doi %u", info->doi);
	}
	if (info->flags & F_SO_LEVEL) {
		char separ = ' ';
		if (info->flags & F_SO_LEVEL_INV)
			printf(" !");
		printf(" --so-level");
		for (i = 0; i <= UINT8_MAX; i++) {
			if (get_bit(i, info->level_bitmap)) {
				printf("%c%d", separ, i);
				separ = ',';
			}
		}
	}
	if (info->flags & F_SO_CATEG) {
		if (info->flags & F_SO_CATEG_INV)
			printf(" !");
		printf(" --so-categ");
		categ_print(info->categ);
	}
	if (info->flags & F_SO_MATCH_INV)
		printf(" --so-mismatch");
	else
		printf(" --so-match-all");
}

static void so_mt_print(const void *ip,
    const struct xt_entry_match *match, int numeric)
{
	printf(" -m so");
	so_mt_save(ip, match);
}

static struct xtables_match so_mt_reg = {
	.version	= XTABLES_VERSION,
	.name		= "so",
	.family		= NFPROTO_IPV4,
	.size		= XT_ALIGN(sizeof(struct so_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct so_info)),
	.help		= so_mt_help,
	.init		= so_mt_init,
	.print		= so_mt_print,
	.save		= so_mt_save,
	.x6_parse	= so_mt_parse,
	.x6_fcheck	= so_mt_check,
	.x6_options	= so_mt_opts,
};

static __attribute__((constructor)) void so_mt_ldr(void)
{
	xtables_register_match(&so_mt_reg);
}

