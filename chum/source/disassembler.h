#pragma once

#include "binary.h"

#include <optional>

namespace chum {

// This is essentially a wrapper over a chum::binary that was produced from
// an x86-64 PE file. This contains additional features for analyzing the
// original image that the chum::binary class does not contain (since it
// contains no PE-related information).
class disassembled_binary {
  friend class disassembler;
public:
  // Print the contents of this binary, for debugging purposes.
  void print();

  // TODO: Duplicate the full chum::binary interface.

  // Get the underlying chum::binary. Prefer to use the functions in
  // disassembled_binary, rather than directly accessing the underlying
  // binary, since these functions have been modified to keep track of
  // internal state which may fail to be updated.
  binary& underlying_binary();

  // Get the symbol that an RVA points to.
  symbol* rva_to_symbol(std::uint32_t rva);

private:
  binary binary_ = {};
};

// Try to disassemble an x86-64 PE file.
std::optional<disassembled_binary> disassemble(char const* path);

} // namespace chum

