// lantern.h as C++23, with the C++ library's warnings: extern "C", and
// LANTERN_INIT as a C++ expression.
#include <lantern/lantern.h>

#include <cstddef>
#include <type_traits>

static_assert(std::is_standard_layout_v<lantern_client_config>);
static_assert(std::is_trivially_copyable_v<lantern_error>);
static_assert(offsetof(lantern_client_config, struct_size) == 0);

int lantern_header_check_cpp();
int lantern_header_check_cpp()
{
    const auto query = LANTERN_INIT(lantern_apps_query);
    return static_cast<int>(query.struct_size) + static_cast<int>(lantern_version() == 0);
}
