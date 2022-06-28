#include "disassembler.h"
#include "util.h"

namespace chum {

// Load a chum::binary from an x86-64 PE file. This tries to fully disassemble
// the image and identify all the code and data that it is composed of.
std::optional<binary> load(char const* const path) {
  auto const file_buffer = read_file_to_buffer(path);
  if (file_buffer.empty())
    return {};

  return binary();
}

} // namespace chum

