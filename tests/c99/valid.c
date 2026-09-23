#include "wolftrust/static_assert.h"

#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ != 199901L)
#error "ISO C99 is required"
#endif

struct wt_c99_probe {
    int first;
    int second;
};

WT_STATIC_ASSERT(sizeof(struct wt_c99_probe) >= 2 * sizeof(int),
                 "probe layout");

int wt_c99_probe(void)
{
    const struct wt_c99_probe probe = { .first = 1, .second = 2 };
    return probe.first + probe.second;
}
