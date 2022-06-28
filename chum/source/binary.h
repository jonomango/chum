#pragma once

#include "block.h"
#include "symbol.h"

#include <vector>

#include <Zydis/Zydis.h>

namespace chum {

// This is a database that contains the code and data that makes up an
// x86-64 binary.
class binary {
public:
  // Create an empty binary.
  binary();

  // Free any resources.
  ~binary();

  // Move constructor.
  binary(binary&& other);

  // Move assignment operator.
  binary& operator=(binary&& other);

  // Prevent copying.
  binary(binary const&) = delete;
  binary& operator=(binary const&) = delete;

  // Print the contents of this binary, for debugging purposes.
  void print();

  // Create a new symbol that is assigned a unique symbol ID.
  symbol* create_symbol(symbol_type type, char const* name = nullptr);

  // Create a zero-initialized data block of the specified size and alignment.
  data_block* create_data_block(
    std::uint32_t size, std::uint32_t alignment = 1);

  // Create and initialize a new data block from a raw blob of data.
  data_block* create_data_block(void const* data,
    std::uint32_t size, std::uint32_t alignment = 1);

  // Create a new basic block for the specific code symbol. This block
  // contains zero instructions upon creation.
  basic_block* create_basic_block(symbol_id sym_id);

private:
  ZydisDecoder decoder_;
  ZydisFormatter formatter_;

  // Every symbol that makes up this binary. These are accessed with symbol IDs.
  std::vector<symbol*> symbols_ = {};

  // Every piece of data that makes up this binary.
  std::vector<data_block*> data_blocks_ = {};

  // Every piece of code that makes up this binary.
  std::vector<basic_block*> basic_blocks_ = {};
};

} // namespace chum

