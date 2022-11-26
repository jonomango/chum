# zydis
option(ZYDIS_BUILD_EXAMPLES "" OFF)
option(ZYDIS_BUILD_TOOLS    "" OFF)
option(ZYDIS_BUILD_DOXYGEN  "" OFF)
add_subdirectory(zydis)

# pe-builder
add_subdirectory(pe-builder)
