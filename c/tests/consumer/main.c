/* An app of the C API, from the package or the source: it links, and the
 * library is the header's. */
#include <lantern/lantern.h>

#include <stdio.h>
#include <string.h>

int main(void)
{
    uint8_t digest[32];
    char short_form[20];
    lantern_sha256((const uint8_t*)"abc", 3, digest);
    lantern_short_form(digest, short_form);
    printf("Lantern C API %u (%s), draft %s: %s\n", (unsigned)lantern_version(), lantern_version_string(),
        lantern_spec_draft(), short_form);
    return lantern_version() >= LANTERN_C_API_VERSION && strcmp(short_form, "BA78 16BF 8F01 CFEA") == 0 ? 0 : 1;
}
