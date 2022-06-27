#pragma once

#include <cstdint>

namespace chum {

// This represents an x86-64 instruction, except any memory references are
// modified to use symbols instead.
struct instruction {
  // This is the length, in bytes, of the raw instruction. This value will
  // never exceed 15.
  std::uint8_t length : 4;

  // This is a variable-length array that contains the raw instruction bytes.
  // TODO: Actually make this variable-length...
  std::uint8_t bytes[15];
};

} // namespace chum

