#pragma once

#include "binary.h"

#include <optional>

namespace chum {

// This is essentially a wrapper over a chum::binary that was produced from
// an x86-64 PE file. This contains additional features for analyzing the
// original image that the chum::binary class does not contain (since it
// contains no PE-related information).
class disassembled_binary : public binary {
  friend class disassembler;
public:
  // Get the symbol that an RVA points to.
  symbol* rva_to_symbol(std::uint32_t rva);

private:
  // This maps every RVA to its associated symbol (if it has one).
  // TODO: This consumes a HUGE amount of memory. Is this worth it?
  // TODO: Optimize to use symbol IDs (although at the cost of 1 indirection).
  std::vector<symbol*> rva_to_sym_ = {};
};

// Try to disassemble an x86-64 PE file.
std::optional<disassembled_binary> disassemble(char const* path);

} // namespace chum

