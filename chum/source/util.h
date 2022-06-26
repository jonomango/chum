#pragma once

#include <vector>

namespace chum {

// Return the raw contents of a file.
std::vector<std::uint8_t> read_file_to_buffer(char const* path);

} // namespace chum

