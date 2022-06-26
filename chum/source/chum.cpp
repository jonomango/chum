#include "chum.h"
#include <fstream>

namespace chum {

// Initialize the current binary by disassembling the provided PE image.
bool binary::disassemble(char const* const path) {
  auto const file_buffer = read_file_to_buffer(path);
  if (file_buffer.empty())
    return false;

  struct disassembler_context {

  } ctx;

  return true;
}

// Return the raw contents of a file.
std::vector<std::uint8_t> binary::read_file_to_buffer(char const* const path) {
  // Try to open the file.
  std::ifstream file(path, std::ios::binary);
  if (!file)
    return {};

  // Get the size of the file and resize the vector as needed.
  file.seekg(0, file.end);
  std::vector<std::uint8_t> contents(file.tellg());
  file.seekg(0, file.beg);

  // Read the contents.
  file.read(reinterpret_cast<char*>(contents.data()), contents.size());

  return contents;
}

} // namespace chum

