#pragma once

#include <Zydis/Zydis.h>
#include <vector>

namespace chum {

// This is a database that contains the code and data that makes up an
// x86-64 binary.
class binary {
public:
  // Initialize the current binary by disassembling the provided PE image.
  bool disassemble(char const* path);

private:
  // Return the raw contents of a file.
  static std::vector<std::uint8_t> read_file_to_buffer(char const* path);
};

} // namespace chum

