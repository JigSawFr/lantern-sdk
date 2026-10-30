/* lantern.h alone, as C11 and C17 with every warning: it declares what it
 * uses, and its structs are what the ABI policy says. */
#include <lantern/lantern.h>

#include <stddef.h>

/* struct_size first, in every struct an app passes by pointer */
_Static_assert(offsetof(lantern_client_config, struct_size) == 0, "struct_size first");
_Static_assert(offsetof(lantern_error, struct_size) == 0, "struct_size first");
_Static_assert(offsetof(lantern_allocator, struct_size) == 0, "struct_size first");
_Static_assert(sizeof(lantern_status) == 4 && sizeof(lantern_code) == 4, "fixed-size enums");
_Static_assert(sizeof(lantern_str) == 2 * sizeof(void*), "a pointer and a size");

int lantern_header_check_c(void);
int lantern_header_check_c(void)
{
    lantern_apps_query query = LANTERN_INIT(lantern_apps_query);
    return (int)query.struct_size + LANTERN_C_API_VERSION;
}
