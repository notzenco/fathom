/*
 * test_util.h — Portable helpers shared by the unit tests
 *
 * Tests run from the repository root (`make test`), so fixture and
 * target paths are relative to it.
 */

#ifndef FATHOM_TEST_UTIL_H
#define FATHOM_TEST_UTIL_H

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "osdep.h"

#ifdef _WIN32
#include <direct.h>
#define TU_EXE ".exe"
#else
#include <unistd.h>
#define TU_EXE ""
#endif

#define FIXTURE(name) "tests/fixtures/" name
#define TARGET(name)  "tests/targets/" name TU_EXE

static inline int tu_dir_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && (st.st_mode & S_IFDIR);
}

static inline int tu_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && (st.st_mode & S_IFREG);
}

/* Create a fresh, empty directory under the system temp dir. */
static inline int tu_make_tmpdir(char *buf, size_t cap, const char *tag)
{
    for (int attempt = 0; attempt < 100; attempt++) {
        snprintf(buf, cap, "%s/fathom-%s-%08x", fathom_tmpdir(), tag,
                 (unsigned)(fathom_entropy() & 0xffffffffu));
        if (!tu_dir_exists(buf) && fathom_mkdir(buf) == 0)
            return 0;
    }
    return -1;
}

/* Remove a directory tree (files and sub-directories only, no links). */
static inline void tu_rm_tree(const char *path)
{
    DIR *d = opendir(path);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
                continue;
            char child[4096];
            int n = snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            if (n < 0 || (size_t)n >= sizeof(child))
                continue;
            if (tu_dir_exists(child))
                tu_rm_tree(child);
            else
                remove(child);
        }
        closedir(d);
    }
#ifdef _WIN32
    _rmdir(path);
#else
    rmdir(path);
#endif
}

/* Count regular files in a directory (non-recursive, skipping dot files). */
static inline int tu_count_files(const char *dirpath)
{
    DIR *d = opendir(dirpath);
    if (!d)
        return -1;
    int n = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.')
            continue;
        char path[4096];
        int len = snprintf(path, sizeof(path), "%s/%s", dirpath, ent->d_name);
        if (len > 0 && (size_t)len < sizeof(path) && tu_file_exists(path))
            n++;
    }
    closedir(d);
    return n;
}

#endif /* FATHOM_TEST_UTIL_H */
