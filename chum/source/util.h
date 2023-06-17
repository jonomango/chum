#pragma once

#include <vector>
#include <cstdint>

namespace chum {

// Return the raw contents of a file.
std::vector<std::uint8_t> read_file_to_buffer(char const* path);

} // namespace chum

