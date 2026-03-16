/*
 * mutate.c — Mutation engine for libfathom
 *
 * Implements 7 mutation strategies with weighted random selection
 * and adaptive boosting for strategies that find new coverage.
 */

#include "mutate.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ── Interesting values ──────────────────────────────────────────────── */

static const int8_t interesting_8[] = {
    0, 1, 0x7F, (int8_t)0x80, (int8_t)0xFF,
};

static const int16_t interesting_16[] = {
    0, 1, 0x7F, (int16_t)0x80, (int16_t)0xFF,
    (int16_t)0x100, 0x7FFF, (int16_t)0x8000, (int16_t)0xFFFF,
};

static const int32_t interesting_32[] = {
    0, 1, 0x7F, (int32_t)0x80, (int32_t)0xFF,
    (int32_t)0x100, 0x7FFF, (int32_t)0x8000, (int32_t)0xFFFF,
    (int32_t)0x10000, 0x7FFFFFFF, (int32_t)0x80000000, (int32_t)0xFFFFFFFF,
};

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

/* ── Random helpers ──────────────────────────────────────────────────── */

static uint32_t rand_below(uint32_t limit)
{
    if (limit <= 1)
        return 0;
    return (uint32_t)(rand() % limit);
}

/* ── Strategy: bitflip ───────────────────────────────────────────────── */

static void mutate_bitflip(uint8_t *buf, size_t len)
{
    if (len == 0)
        return;

    uint32_t count = 1 + rand_below(4);  /* flip 1-4 bits */
    for (uint32_t i = 0; i < count; i++) {
        size_t byte_pos = rand_below((uint32_t)len);
        uint8_t bit = 1u << rand_below(8);
        buf[byte_pos] ^= bit;
    }
}

/* ── Strategy: byteflip ─────────────────────────────────────────────── */

static void mutate_byteflip(uint8_t *buf, size_t len)
{
    if (len == 0)
        return;

    uint32_t count = 1 + rand_below(4);  /* flip 1-4 bytes */
    for (uint32_t i = 0; i < count; i++) {
        size_t pos = rand_below((uint32_t)len);
        buf[pos] ^= 0xFF;
    }
}

/* ── Strategy: arithmetic ────────────────────────────────────────────── */

static void mutate_arith(uint8_t *buf, size_t len)
{
    if (len == 0)
        return;

    size_t pos = rand_below((uint32_t)len);
    int32_t delta = (int32_t)(rand_below(FATHOM_ARITH_MAX * 2 + 1))
                    - FATHOM_ARITH_MAX;
    if (delta == 0)
        delta = 1;

    /* Choose byte or word granularity. */
    uint32_t width = rand_below(3);  /* 0 = byte, 1 = word16, 2 = dword32 */

    if (width == 0 || len < 2) {
        /* Byte arithmetic. */
        buf[pos] = (uint8_t)(buf[pos] + delta);
    } else if (width == 1 || len < 4) {
        /* 16-bit arithmetic. */
        if (pos + 1 >= len)
            pos = len - 2;
        uint16_t val;
        memcpy(&val, buf + pos, 2);
        val = (uint16_t)(val + delta);
        memcpy(buf + pos, &val, 2);
    } else {
        /* 32-bit arithmetic. */
        if (pos + 3 >= len)
            pos = len - 4;
        uint32_t val;
        memcpy(&val, buf + pos, 4);
        val = (uint32_t)(val + delta);
        memcpy(buf + pos, &val, 4);
    }
}

/* ── Strategy: interesting values ────────────────────────────────────── */

static void mutate_interesting(uint8_t *buf, size_t len)
{
    if (len == 0)
        return;

    uint32_t width = rand_below(3);  /* 0 = 8-bit, 1 = 16-bit, 2 = 32-bit */

    if (width == 0 || len < 2) {
        size_t pos = rand_below((uint32_t)len);
        int8_t val = interesting_8[rand_below(ARRAY_LEN(interesting_8))];
        buf[pos] = (uint8_t)val;
    } else if (width == 1 || len < 4) {
        size_t pos = rand_below((uint32_t)(len - 1));
        int16_t val = interesting_16[rand_below(ARRAY_LEN(interesting_16))];
        memcpy(buf + pos, &val, 2);
    } else {
        size_t pos = rand_below((uint32_t)(len - 3));
        int32_t val = interesting_32[rand_below(ARRAY_LEN(interesting_32))];
        memcpy(buf + pos, &val, 4);
    }
}

/* ── Strategy: dictionary ────────────────────────────────────────────── */

static void mutate_dictionary(uint8_t *buf, size_t *len, size_t max_len,
                              const fathom_dict_t *dict)
{
    if (!dict || dict->count == 0 || *len == 0)
        return;

    const fathom_dict_entry_t *ent =
        &dict->entries[rand_below((uint32_t)dict->count)];

    if (ent->len == 0)
        return;

    /* 50/50: overwrite at random position or insert. */
    if (rand_below(2) == 0) {
        /* Overwrite mode: place token at a random position. */
        if (ent->len > *len) {
            /* Token bigger than buffer — truncate what we write. */
            size_t copy = *len;
            memcpy(buf, ent->data, copy);
        } else {
            size_t pos = rand_below((uint32_t)(*len - ent->len + 1));
            memcpy(buf + pos, ent->data, ent->len);
        }
    } else {
        /* Insert mode: splice token in, growing the buffer. */
        size_t new_len = *len + ent->len;
        if (new_len > max_len)
            new_len = max_len;
        size_t actual_insert = new_len - *len;
        if (actual_insert == 0) {
            /* No room to insert; fall back to overwrite. */
            if (ent->len <= *len) {
                size_t pos = rand_below((uint32_t)(*len - ent->len + 1));
                memcpy(buf + pos, ent->data, ent->len);
            }
            return;
        }
        size_t pos = rand_below((uint32_t)(*len + 1));
        /* Shift tail right. */
        memmove(buf + pos + actual_insert, buf + pos, *len - pos);
        /* Copy as much of the token as fits. */
        size_t copy = actual_insert < ent->len ? actual_insert : ent->len;
        memcpy(buf + pos, ent->data, copy);
        *len = new_len;
    }
}

/* ── Strategy: havoc ─────────────────────────────────────────────────── */

static void mutate_havoc(uint8_t *buf, size_t *len, size_t max_len,
                         const fathom_dict_t *dict)
{
    uint32_t rounds = FATHOM_HAVOC_MIN +
                      rand_below(FATHOM_HAVOC_MAX - FATHOM_HAVOC_MIN + 1);

    for (uint32_t i = 0; i < rounds; i++) {
        /* Pick an atomic mutation (everything except havoc and splice). */
        uint32_t which = rand_below(5);
        switch (which) {
        case 0: mutate_bitflip(buf, *len);                    break;
        case 1: mutate_byteflip(buf, *len);                   break;
        case 2: mutate_arith(buf, *len);                      break;
        case 3: mutate_interesting(buf, *len);                 break;
        case 4: mutate_dictionary(buf, len, max_len, dict);   break;
        }
    }
}

/* ── Strategy: splice ────────────────────────────────────────────────── */

static void mutate_splice(uint8_t *buf, size_t *len, size_t max_len,
                          const uint8_t *splice, size_t splice_len)
{
    if (!splice || splice_len == 0 || *len == 0)
        return;

    /* Pick a random midpoint in the current buffer. */
    size_t mid = 1 + rand_below((uint32_t)(*len > 1 ? *len - 1 : 1));

    /* Pick a random midpoint in the splice donor. */
    size_t smid = 1 + rand_below((uint32_t)(splice_len > 1 ? splice_len - 1 : 1));

    /* Take buf[0..mid) + splice[smid..splice_len). */
    size_t tail = splice_len - smid;
    size_t new_len = mid + tail;
    if (new_len > max_len)
        new_len = max_len;
    size_t copy = new_len > mid ? new_len - mid : 0;
    if (copy > 0)
        memcpy(buf + mid, splice + smid, copy);
    *len = new_len;
}

/* ── Weighted selection ──────────────────────────────────────────────── */

static fathom_mutation_t pick_strategy(const fathom_mutator_t *mut,
                                       bool have_splice,
                                       bool have_dict)
{
    double total = 0.0;
    for (int i = 0; i < FATHOM_MUT_COUNT; i++) {
        if (i == FATHOM_MUT_SPLICE && !have_splice)
            continue;
        if (i == FATHOM_MUT_DICTIONARY && !have_dict)
            continue;
        total += mut->weights[i];
    }

    if (total <= 0.0) {
        /* Fallback: uniform random among valid strategies. */
        int valid[FATHOM_MUT_COUNT];
        int n = 0;
        for (int i = 0; i < FATHOM_MUT_COUNT; i++) {
            if (i == FATHOM_MUT_SPLICE && !have_splice) continue;
            if (i == FATHOM_MUT_DICTIONARY && !have_dict) continue;
            valid[n++] = i;
        }
        return (fathom_mutation_t)valid[rand_below((uint32_t)n)];
    }

    double r = ((double)rand() / (double)RAND_MAX) * total;
    double cum = 0.0;
    for (int i = 0; i < FATHOM_MUT_COUNT; i++) {
        if (i == FATHOM_MUT_SPLICE && !have_splice)
            continue;
        if (i == FATHOM_MUT_DICTIONARY && !have_dict)
            continue;
        cum += mut->weights[i];
        if (r <= cum)
            return (fathom_mutation_t)i;
    }

    /* Rounding fallback. */
    return FATHOM_MUT_BITFLIP;
}

/* ── Dictionary helpers ──────────────────────────────────────────────── */

/*
 * Parse a single hex escape (\xHH) from *p, advancing *p past it.
 * Returns the decoded byte, or -1 on malformed input.
 */
static int parse_hex_escape(const char **p)
{
    const char *s = *p;
    if (s[0] != '\\' || s[1] != 'x')
        return -1;
    char hi = s[2], lo = s[3];
    if (!isxdigit((unsigned char)hi) || !isxdigit((unsigned char)lo))
        return -1;

    unsigned int val = 0;
    char hex[3] = { hi, lo, '\0' };
    sscanf(hex, "%x", &val);
    *p = s + 4;
    return (int)val;
}

/*
 * Parse a dictionary line. Supported formats:
 *   "string"           — quoted literal (C-style escapes: \n \t \r \\ \")
 *   \xHH\xHH...       — hex-escaped bytes
 *   name="string"      — named token (the name= prefix is skipped)
 *
 * Returns the decoded data in out (caller-allocated), sets *out_len,
 * and returns 0 on success, -1 on skip/comment/empty.
 */
static int parse_dict_line(const char *line, uint8_t *out, size_t out_cap,
                           size_t *out_len)
{
    /* Skip leading whitespace. */
    while (*line && isspace((unsigned char)*line))
        line++;

    /* Skip blank lines and comments. */
    if (*line == '\0' || *line == '#')
        return -1;

    /* Skip optional name= prefix. */
    const char *eq = strchr(line, '=');
    if (eq) {
        /* Verify it looks like name="..." */
        const char *q = eq + 1;
        while (*q && isspace((unsigned char)*q))
            q++;
        if (*q == '"')
            line = eq + 1;
    }

    /* Skip whitespace again. */
    while (*line && isspace((unsigned char)*line))
        line++;

    size_t n = 0;

    if (*line == '"') {
        /* Quoted string: parse until closing quote. */
        line++;
        while (*line && *line != '"' && n < out_cap) {
            if (*line == '\\') {
                line++;
                switch (*line) {
                case 'n':  out[n++] = '\n'; line++; break;
                case 't':  out[n++] = '\t'; line++; break;
                case 'r':  out[n++] = '\r'; line++; break;
                case '\\': out[n++] = '\\'; line++; break;
                case '"':  out[n++] = '"';  line++; break;
                case '0':  out[n++] = '\0'; line++; break;
                case 'x': {
                    /* Back up so parse_hex_escape sees \x. */
                    line--;
                    int val = parse_hex_escape(&line);
                    if (val >= 0)
                        out[n++] = (uint8_t)val;
                    break;
                }
                default:
                    /* Unknown escape: keep literal. */
                    out[n++] = (uint8_t)*line++;
                    break;
                }
            } else {
                out[n++] = (uint8_t)*line++;
            }
        }
    } else if (*line == '\\' && *(line + 1) == 'x') {
        /* Hex-escaped sequence. */
        while (*line == '\\' && *(line + 1) == 'x' && n < out_cap) {
            int val = parse_hex_escape(&line);
            if (val < 0)
                break;
            out[n++] = (uint8_t)val;
        }
    } else {
        /* Raw string: take the whole line as a token. */
        size_t slen = strlen(line);
        /* Trim trailing whitespace. */
        while (slen > 0 && isspace((unsigned char)line[slen - 1]))
            slen--;
        if (slen == 0)
            return -1;
        size_t copy = slen < out_cap ? slen : out_cap;
        memcpy(out, line, copy);
        n = copy;
    }

    if (n == 0)
        return -1;

    *out_len = n;
    return 0;
}

/* ── Public API: Dictionary ──────────────────────────────────────────── */

void fathom_dict_init(fathom_dict_t *dict)
{
    memset(dict, 0, sizeof(*dict));
}

void fathom_dict_destroy(fathom_dict_t *dict)
{
    if (!dict)
        return;
    for (size_t i = 0; i < dict->count; i++)
        free(dict->entries[i].data);
    free(dict->entries);
    memset(dict, 0, sizeof(*dict));
}

int fathom_dict_add(fathom_dict_t *dict, const uint8_t *data, size_t len)
{
    if (!data || len == 0)
        return -1;

    if (dict->count >= dict->capacity) {
        size_t new_cap = dict->capacity ? dict->capacity * 2 : 16;
        fathom_dict_entry_t *tmp = realloc(dict->entries,
                                           new_cap * sizeof(*tmp));
        if (!tmp)
            return -1;
        dict->entries  = tmp;
        dict->capacity = new_cap;
    }

    uint8_t *copy = malloc(len);
    if (!copy)
        return -1;
    memcpy(copy, data, len);

    dict->entries[dict->count].data = copy;
    dict->entries[dict->count].len  = len;
    dict->count++;
    return 0;
}

int fathom_dict_load(fathom_dict_t *dict, const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "fathom: dict open %s: %s\n", path, strerror(errno));
        return -1;
    }

    char line[1024];
    uint8_t buf[FATHOM_DICT_MAX_ENTRY];
    int added = 0;

    while (fgets(line, (int)sizeof(line), fp)) {
        /* Strip trailing newline. */
        size_t slen = strlen(line);
        if (slen > 0 && line[slen - 1] == '\n')
            line[--slen] = '\0';
        if (slen > 0 && line[slen - 1] == '\r')
            line[--slen] = '\0';

        size_t out_len = 0;
        if (parse_dict_line(line, buf, sizeof(buf), &out_len) == 0) {
            if (fathom_dict_add(dict, buf, out_len) == 0)
                added++;
        }
    }

    fclose(fp);
    return added;
}

/* ── Public API: Mutator ─────────────────────────────────────────────── */

void fathom_mutator_init(fathom_mutator_t *mut, fathom_dict_t *dict)
{
    memset(mut, 0, sizeof(*mut));
    mut->dict = dict;

    /* Equal initial weights. */
    for (int i = 0; i < FATHOM_MUT_COUNT; i++)
        mut->weights[i] = 1.0;

    /* Seed PRNG from /dev/urandom; fall back to time. */
    unsigned int seed;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        if (read(fd, &seed, sizeof(seed)) != sizeof(seed))
            seed = (unsigned int)time(NULL) ^ (unsigned int)getpid();
        close(fd);
    } else {
        seed = (unsigned int)time(NULL) ^ (unsigned int)getpid();
    }
    srand(seed);
}

int fathom_mutate(fathom_mutator_t *mut, uint8_t *buf, size_t *len,
                  size_t max_len, const uint8_t *splice, size_t splice_len)
{
    if (!mut || !buf || !len)
        return -1;

    bool have_splice = (splice != NULL && splice_len > 0);
    bool have_dict   = (mut->dict != NULL && mut->dict->count > 0);

    fathom_mutation_t which = pick_strategy(mut, have_splice, have_dict);
    mut->uses[which]++;

    switch (which) {
    case FATHOM_MUT_BITFLIP:
        mutate_bitflip(buf, *len);
        break;
    case FATHOM_MUT_BYTEFLIP:
        mutate_byteflip(buf, *len);
        break;
    case FATHOM_MUT_ARITH:
        mutate_arith(buf, *len);
        break;
    case FATHOM_MUT_INTERESTING:
        mutate_interesting(buf, *len);
        break;
    case FATHOM_MUT_DICTIONARY:
        mutate_dictionary(buf, len, max_len, mut->dict);
        break;
    case FATHOM_MUT_HAVOC:
        mutate_havoc(buf, len, max_len, mut->dict);
        break;
    case FATHOM_MUT_SPLICE:
        mutate_splice(buf, len, max_len, splice, splice_len);
        break;
    case FATHOM_MUT_COUNT:
        /* Not a real strategy. */
        break;
    }

    return (int)which;
}

void fathom_mutator_reward(fathom_mutator_t *mut, fathom_mutation_t which)
{
    if (!mut || which < 0 || which >= FATHOM_MUT_COUNT)
        return;

    mut->hits[which]++;

    /*
     * Adaptive weights: decay all weights toward the minimum, then
     * boost the rewarded strategy.  This keeps successful strategies
     * dominant while preventing starvation of others.
     */
    for (int i = 0; i < FATHOM_MUT_COUNT; i++) {
        mut->weights[i] *= FATHOM_WEIGHT_DECAY;
        if (mut->weights[i] < FATHOM_WEIGHT_MIN)
            mut->weights[i] = FATHOM_WEIGHT_MIN;
    }

    mut->weights[which] *= FATHOM_WEIGHT_BONUS;
}
