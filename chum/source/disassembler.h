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
};

// Try to disassemble an x86-64 PE file.
std::optional<disassembled_binary> disassemble(char const* path);

} // namespace chum

