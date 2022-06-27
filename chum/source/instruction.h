#pragma once

#include <cstdint>

namespace chum {

struct instruction {
  // This is the length, in bytes, of the raw instruction. This value will
  // never exceed 15.
  std::uint8_t length : 4;

  // This is a variable-length array that contains the raw instruction bytes.
  std::uint8_t bytes[1];
};

} // namespace chum

