#include "util.h"

#include <fstream>

namespace chum {

// Return the raw contents of a file.
std::vector<std::uint8_t> read_file_to_buffer(char const* const path) {
  // Try to open the file.
  std::ifstream file(path, std::ios::binary);
  if (!file)
    return {};

  // Get the size of the file and resize the vector as needed.
  file.seekg(0, file.end);
  std::vector<std::uint8_t> contents(file.tellg());
  file.seekg(0, file.beg);

  // Copy the file contents into the vector.
  file.read(reinterpret_cast<char*>(contents.data()), contents.size());

  return contents;
}

} // namespace chum

