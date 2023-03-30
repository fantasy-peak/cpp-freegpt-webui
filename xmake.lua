set_project("cpp-freegpt-webui")
set_version("0.0.1", {build = "%Y%m%d%H%M"})
set_xmakever("2.7.8")

add_repositories("my_private_repo https://github.com/fantasy-peak/xmake-repo.git")

add_requires("openssl", {system = false})
add_requires("fmt", "yaml_cpp_struct", "nlohmann_json", "spdlog", "inja")
add_requires("boost", "plusaes", "tl_expected", "resource_pool")

set_languages("c++23")
set_policy("check.auto_ignore_flags", false)
add_cxflags("-O2 -Wall -Wextra -pedantic-errors -Wno-missing-field-initializers -Wno-ignored-qualifiers")
add_includedirs("include")

target("cpp-freegpt-webui")
    set_kind("binary")
    add_files("src/*.cpp")
    add_packages("openssl", "fmt", "yaml_cpp_struct", "nlohmann_json", "spdlog", "boost", "inja", "tl_expected", "resource_pool", "plusaes")
    add_syslinks("pthread")
target_end()
