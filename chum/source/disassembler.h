#pragma once

#include "binary.h"

#include <optional>

namespace chum {

// Load a chum::binary from an x86-64 PE file. This tries to fully disassemble
// the image and identify all the code and data that it is composed of.
std::optional<binary> load(char const* path);

} // namespace chum

