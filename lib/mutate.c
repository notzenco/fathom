/*
 * mutate.c — Mutation engine for libfathom
 *
 * Implements the mutation strategies of fathom_mutation_t with weighted
 * random selection and adaptive boosting for strategies that find new
 * coverage.  Multi-byte values are written in either byte order, since
 * file formats and protocols are often big-endian.
 */

#include "mutate.h"
#include "osdep.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static const int64_t interesting_64[] = {
    0, 1, -1, 0x7F, 0xFF, 0x7FFF, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFFLL,
    0x100000000LL, INT64_MAX, INT64_MIN,
};

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

/* ── Random helpers ──────────────────────────────────────────────────── */

/* xorshift64*: fast, seedable, and identical on every platform. */
static uint64_t rng_next(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static uint32_t rand_below(uint64_t *rng, uint32_t limit)
{
    if (limit <= 1)
        return 0;
    return (uint32_t)((rng_next(rng) >> 32) % limit);
}

uint32_t fathom_rand_below(fathom_mutator_t *mut, uint32_t limit)
{
    return rand_below(&mut->rng, limit);
}

/* Write the low `width` bytes of v at p, little- or big-endian. */
static void put_int(uint8_t *p, uint64_t v, size_t width, bool big)
{
    for (size_t i = 0; i < width; i++)
        p[big ? width - 1 - i : i] = (uint8_t)(v >> (8 * i));
}

static uint64_t get_int(const uint8_t *p, size_t width, bool big)
{
    uint64_t v = 0;
    for (size_t i = 0; i < width; i++)
        v |= (uint64_t)p[big ? width - 1 - i : i] << (8 * i);
    return v;
}

/* Largest of 1, 2, 4, 8 bytes that fits len, chosen at random. */
static size_t pick_width(uint64_t *rng, size_t len)
{
    size_t w = (size_t)1 << rand_below(rng, 4);
    while (w > len)
        w >>= 1;
    return w;
}

/* Chunk length for insert/delete/clone: mostly small, sometimes large. */
static size_t block_len(uint64_t *rng, size_t limit)
{
    if (limit <= 1)
        return limit;
    size_t cap = rand_below(rng, 4) == 0 ? limit : (limit < 32 ? limit : 32);
    return 1 + rand_below(rng, (uint32_t)cap);
}

/* ── Strategy: bitflip ───────────────────────────────────────────────── */

static void mutate_bitflip(uint64_t *rng, uint8_t *buf, size_t len)
{
    if (len == 0)
        return;

    uint32_t count = 1 + rand_below(rng, 4);  /* flip 1-4 bits */
    for (uint32_t i = 0; i < count; i++) {
        size_t byte_pos = rand_below(rng, (uint32_t)len);
        uint8_t bit = 1u << rand_below(rng, 8);
        buf[byte_pos] ^= bit;
    }
}

/* ── Strategy: byteflip ─────────────────────────────────────────────── */

static void mutate_byteflip(uint64_t *rng, uint8_t *buf, size_t len)
{
    if (len == 0)
        return;

    uint32_t count = 1 + rand_below(rng, 4);  /* flip 1-4 bytes */
    for (uint32_t i = 0; i < count; i++) {
        size_t pos = rand_below(rng, (uint32_t)len);
        buf[pos] ^= 0xFF;
    }
}

/* ── Strategy: arithmetic ────────────────────────────────────────────── */

static void mutate_arith(uint64_t *rng, uint8_t *buf, size_t len)
{
    if (len == 0)
        return;

    size_t width = pick_width(rng, len);
    size_t pos = rand_below(rng, (uint32_t)(len - width + 1));
    bool big = width > 1 && rand_below(rng, 2);
    int64_t delta = (int64_t)rand_below(rng, FATHOM_ARITH_MAX * 2 + 1) - FATHOM_ARITH_MAX;
    if (delta == 0)
        delta = 1;
    put_int(buf + pos, get_int(buf + pos, width, big) + (uint64_t)delta, width, big);
}

/* ── Strategy: interesting values ────────────────────────────────────── */

static void mutate_interesting(uint64_t *rng, uint8_t *buf, size_t len)
{
    if (len == 0)
        return;

    size_t width = pick_width(rng, len);
    size_t pos = rand_below(rng, (uint32_t)(len - width + 1));
    bool big = width > 1 && rand_below(rng, 2);
    uint64_t v;
    switch (width) {
    case 1:  v = (uint64_t)interesting_8[rand_below(rng, ARRAY_LEN(interesting_8))];   break;
    case 2:  v = (uint64_t)interesting_16[rand_below(rng, ARRAY_LEN(interesting_16))]; break;
    case 4:  v = (uint64_t)interesting_32[rand_below(rng, ARRAY_LEN(interesting_32))]; break;
    default: v = (uint64_t)interesting_64[rand_below(rng, ARRAY_LEN(interesting_64))]; break;
    }
    put_int(buf + pos, v, width, big);
}

/* ── Strategies: insert, delete, clone ───────────────────────────────── */

static void mutate_insert(uint64_t *rng, uint8_t *buf, size_t *len, size_t max_len)
{
    if (*len >= max_len)
        return;
    size_t n = block_len(rng, max_len - *len);
    size_t pos = rand_below(rng, (uint32_t)(*len + 1));
    memmove(buf + pos + n, buf + pos, *len - pos);

    /* Copy an existing chunk (repeating structure) 3 times in 4, else random bytes. */
    if (*len >= n && rand_below(rng, 4) != 0) {
        size_t src = rand_below(rng, (uint32_t)(*len - n + 1));
        if (src >= pos)
            src += n;   /* the source moved with the tail */
        memmove(buf + pos, buf + src, n);
    } else if (rand_below(rng, 2)) {
        memset(buf + pos, (int)rand_below(rng, 256), n);
    } else {
        for (size_t i = 0; i < n; i++)
            buf[pos + i] = (uint8_t)rand_below(rng, 256);
    }
    *len += n;
}

static void mutate_delete(uint64_t *rng, uint8_t *buf, size_t *len)
{
    if (*len < 2)
        return;
    size_t n = block_len(rng, *len - 1);
    size_t pos = rand_below(rng, (uint32_t)(*len - n + 1));
    memmove(buf + pos, buf + pos + n, *len - pos - n);
    *len -= n;
}

static void mutate_clone(uint64_t *rng, uint8_t *buf, size_t len)
{
    if (len < 2)
        return;
    size_t n = block_len(rng, len - 1);
    size_t src = rand_below(rng, (uint32_t)(len - n + 1));
    size_t dst = rand_below(rng, (uint32_t)(len - n + 1));
    if (dst == src)
        dst = (dst + 1) % (len - n + 1);
    memmove(buf + dst, buf + src, n);
}

/* ── Strategy: dictionary ────────────────────────────────────────────── */

static void mutate_dictionary(uint64_t *rng, uint8_t *buf, size_t *len, size_t max_len,
                              const fathom_dict_t *dict)
{
    if (!dict || dict->count == 0 || *len == 0)
        return;

    const fathom_dict_entry_t *ent =
        &dict->entries[rand_below(rng, (uint32_t)dict->count)];

    if (ent->len == 0)
        return;

    /* 50/50: overwrite at random position or insert. */
    if (rand_below(rng, 2) == 0) {
        /* Overwrite mode: place token at a random position. */
        if (ent->len > *len) {
            /* Token bigger than buffer — truncate what we write. */
            size_t copy = *len;
            memcpy(buf, ent->data, copy);
        } else {
            size_t pos = rand_below(rng, (uint32_t)(*len - ent->len + 1));
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
                size_t pos = rand_below(rng, (uint32_t)(*len - ent->len + 1));
                memcpy(buf + pos, ent->data, ent->len);
            }
            return;
        }
        size_t pos = rand_below(rng, (uint32_t)(*len + 1));
        /* Shift tail right. */
        memmove(buf + pos + actual_insert, buf + pos, *len - pos);
        /* Copy as much of the token as fits. */
        size_t copy = actual_insert < ent->len ? actual_insert : ent->len;
        memcpy(buf + pos, ent->data, copy);
        *len = new_len;
    }
}

/* ── Strategy: havoc ─────────────────────────────────────────────────── */

static void mutate_havoc(uint64_t *rng, uint8_t *buf, size_t *len, size_t max_len,
                         const fathom_dict_t *dict)
{
    uint32_t rounds = FATHOM_HAVOC_MIN +
                      rand_below(rng, FATHOM_HAVOC_MAX - FATHOM_HAVOC_MIN + 1);

    for (uint32_t i = 0; i < rounds; i++) {
        /* Pick an atomic mutation (everything except havoc and splice). */
        switch (rand_below(rng, 9)) {
        case 0: mutate_bitflip(rng, buf, *len);                    break;
        case 1: mutate_byteflip(rng, buf, *len);                   break;
        case 2: mutate_arith(rng, buf, *len);                      break;
        case 3: mutate_interesting(rng, buf, *len);                break;
        case 4: mutate_dictionary(rng, buf, len, max_len, dict);   break;
        case 5: mutate_insert(rng, buf, len, max_len);             break;
        case 6: mutate_delete(rng, buf, len);                      break;
        case 7: mutate_clone(rng, buf, *len);                      break;
        default:
            if (*len)   /* set a random byte to a different random value */
                buf[rand_below(rng, (uint32_t)*len)] ^= (uint8_t)(1 + rand_below(rng, 255));
            break;
        }
    }
}

/* ── Strategy: splice ────────────────────────────────────────────────── */

static void mutate_splice(uint64_t *rng, uint8_t *buf, size_t *len, size_t max_len,
                          const uint8_t *splice, size_t splice_len)
{
    if (!splice || splice_len == 0 || *len == 0)
        return;

    /* Pick a random midpoint in the current buffer. */
    size_t mid = 1 + rand_below(rng, (uint32_t)(*len > 1 ? *len - 1 : 1));

    /* Pick a random midpoint in the splice donor. */
    size_t smid = 1 + rand_below(rng, (uint32_t)(splice_len > 1 ? splice_len - 1 : 1));

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

static fathom_mutation_t pick_strategy(fathom_mutator_t *mut,
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
        return (fathom_mutation_t)valid[rand_below(&mut->rng, (uint32_t)n)];
    }

    double r = (double)(rng_next(&mut->rng) >> 11) / 9007199254740992.0 * total;
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

    fathom_mutator_seed(mut, fathom_entropy());
}

void fathom_mutator_seed(fathom_mutator_t *mut, uint64_t seed)
{
    /* splitmix64 scramble so small seeds still give a well-mixed state. */
    seed += 0x9E3779B97F4A7C15ULL;
    seed = (seed ^ (seed >> 30)) * 0xBF58476D1CE4E5B9ULL;
    seed = (seed ^ (seed >> 27)) * 0x94D049BB133111EBULL;
    seed ^= seed >> 31;
    mut->rng = seed ? seed : 1;
}

int fathom_mutate(fathom_mutator_t *mut, uint8_t *buf, size_t *len,
                  size_t max_len, const uint8_t *splice, size_t splice_len)
{
    if (!mut || !buf || !len)
        return -1;

    /* Every strategy edits existing bytes, so an empty input would never change. */
    if (*len == 0 && max_len > 0) {
        size_t n = 1 + rand_below(&mut->rng, 8);
        if (n > max_len)
            n = max_len;
        for (size_t i = 0; i < n; i++)
            buf[i] = (uint8_t)rand_below(&mut->rng, 256);
        *len = n;
    }

    bool have_splice = (splice != NULL && splice_len > 0);
    bool have_dict   = (mut->dict != NULL && mut->dict->count > 0) ||
                       (mut->frontier != NULL && mut->frontier->count > 0);

    fathom_mutation_t which = pick_strategy(mut, have_splice, have_dict);
    mut->uses[which]++;
    uint64_t *rng = &mut->rng;
    fathom_dict_t *dict = mut->dict;
    if (mut->frontier && mut->frontier->count && rand_below(rng, 2) == 0)
        dict = mut->frontier;

    switch (which) {
    case FATHOM_MUT_BITFLIP:
        mutate_bitflip(rng, buf, *len);
        break;
    case FATHOM_MUT_BYTEFLIP:
        mutate_byteflip(rng, buf, *len);
        break;
    case FATHOM_MUT_ARITH:
        mutate_arith(rng, buf, *len);
        break;
    case FATHOM_MUT_INTERESTING:
        mutate_interesting(rng, buf, *len);
        break;
    case FATHOM_MUT_DICTIONARY:
        mutate_dictionary(rng, buf, len, max_len, dict);
        break;
    case FATHOM_MUT_HAVOC:
        mutate_havoc(rng, buf, len, max_len, dict);
        break;
    case FATHOM_MUT_SPLICE:
        mutate_splice(rng, buf, len, max_len, splice, splice_len);
        break;
    case FATHOM_MUT_INSERT:
        mutate_insert(rng, buf, len, max_len);
        break;
    case FATHOM_MUT_DELETE:
        mutate_delete(rng, buf, len);
        break;
    case FATHOM_MUT_CLONE:
        mutate_clone(rng, buf, *len);
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

int fathom_dict_add_constant(fathom_dict_t *dict, int64_t v)
{
    if (v == 0 || v == 1 || v == -1)
        return 0;   /* already covered by the interesting-values strategy */

    size_t width = (v >= -128 && v <= 255) ? 1
                 : (v >= -32768 && v <= 65535) ? 2
                 : (v >= INT32_MIN && v <= (int64_t)UINT32_MAX) ? 4 : 8;

    /* Little-endian for native integers, big-endian for file and wire formats. */
    int added = 0;
    for (int big = 0; big < (width > 1 ? 2 : 1); big++) {
        uint8_t bytes[8];
        put_int(bytes, (uint64_t)v, width, big);
        bool dup = false;
        for (size_t e = 0; e < dict->count && !dup; e++)
            dup = dict->entries[e].len == width &&
                  memcmp(dict->entries[e].data, bytes, width) == 0;
        if (dup)
            continue;
        if (fathom_dict_add(dict, bytes, width) < 0)
            return -1;
        added = 1;
    }
    return added;
}

/* ── Deterministic stage ─────────────────────────────────────────────── */

#define DET_ARITH 16

enum { DET_BITFLIP, DET_ARITH8, DET_INT8, DET_INT16, DET_INT32, DET_DONE };

bool fathom_det_next(fathom_det_t *d, const uint8_t *in, size_t len, uint8_t *out)
{
    for (;;) {
        memcpy(out, in, len);
        switch (d->stage) {
        case DET_BITFLIP:
            if (d->pos < len * 8) {
                out[d->pos / 8] ^= (uint8_t)(1u << (d->pos % 8));
                d->pos++;
                return true;
            }
            break;
        case DET_ARITH8:
            if (d->pos < len) {
                /* k: 0..15 add 1..16, 16..31 subtract 1..16 */
                int delta = d->k < DET_ARITH ? (int)d->k + 1 : -(int)(d->k - DET_ARITH + 1);
                out[d->pos] = (uint8_t)(out[d->pos] + delta);
                if (++d->k == 2 * DET_ARITH) {
                    d->k = 0;
                    d->pos++;
                }
                return true;
            }
            break;
        case DET_INT8:
            if (d->pos < len) {
                out[d->pos] = (uint8_t)interesting_8[d->k];
                if (++d->k == ARRAY_LEN(interesting_8)) {
                    d->k = 0;
                    d->pos++;
                }
                return true;
            }
            break;
        case DET_INT16:
        case DET_INT32: {
            size_t w = d->stage == DET_INT16 ? 2 : 4;
            size_t nv = w == 2 ? ARRAY_LEN(interesting_16) : ARRAY_LEN(interesting_32);
            if (len >= w && d->pos <= len - w) {
                uint64_t v = w == 2 ? (uint64_t)(uint16_t)interesting_16[d->k / 2]
                                    : (uint64_t)(uint32_t)interesting_32[d->k / 2];
                put_int(out + d->pos, v, w, d->k % 2);   /* each value in both orders */
                if (++d->k == 2 * nv) {
                    d->k = 0;
                    d->pos++;
                }
                return true;
            }
            break;
        }
        default:
            return false;
        }
        d->stage++;
        d->pos = 0;
        d->k = 0;
    }
}
