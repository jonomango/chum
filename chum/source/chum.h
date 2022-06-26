#pragma once

#include "block.h"

#include <vector>

#include <Zydis/Zydis.h>

namespace chum {

// This is a database that contains the code and data that makes up an
// x86-64 binary.
class binary {
public:
  // Create an empty binary.
  binary();

  // Initialize the current binary with a 64-bit PE image.
  bool load(char const* path);

  // Print the contents of this binary, for debugging purposes.
  void print() const;

  // Create and initialize a new data block.
  data_block& create_data_block(std::uint32_t size, std::uint32_t alignment = 1);

private:
  ZydisDecoder decoder_;

  // Every piece of data that makes up this binary.
  std::vector<data_block> data_blocks_;
};

} // namespace chum

