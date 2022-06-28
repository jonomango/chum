#include "disassembler.h"
#include "util.h"

#include <Windows.h>

namespace chum {

// Print the contents of this binary, for debugging purposes.
void disassembled_binary::print() {
  binary_.print();
}

// Get the underlying chum::binary. Prefer to use the functions in
// disassembled_binary, rather than directly accessing the underlying
// binary, since these functions have been modified to keep track of
// internal state which may fail to be updated.
binary& disassembled_binary::underlying_binary() {
  return binary_;
}

// Get the symbol that an RVA points to.
symbol* disassembled_binary::rva_to_symbol(std::uint32_t const rva) {
  return nullptr;
}

// This is an internal structure that is used to produce a disassembled
// binary. I don't really like how this is structured, but I couldn't find
// a better solution.
class disassembler {
public:
  // This is the binary that is being produced.
  disassembled_binary bin = {};

public:
  // Initialize various structures in the disassembler. This function should
  // only be called ONCE for each instantiation.
  bool initialize(char const* const path) {
    file_buffer_ = read_file_to_buffer(path);
    if (file_buffer_.empty())
      return false;

    dos_header_ = reinterpret_cast<PIMAGE_DOS_HEADER>(&file_buffer_[0]);
    if (dos_header_->e_magic != IMAGE_DOS_SIGNATURE)
      return false;

    nt_header_ = reinterpret_cast<PIMAGE_NT_HEADERS>(
      &file_buffer_[dos_header_->e_lfanew]);
    if (nt_header_->Signature != IMAGE_NT_SIGNATURE)
      return false;

    // Make sure we're dealing with a 64-bit PE image.
    if (nt_header_->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
      return false;

    sections_ = reinterpret_cast<PIMAGE_SECTION_HEADER>(nt_header_ + 1);

    return true;
  }

private:
  // The raw file contents.
  std::vector<std::uint8_t> file_buffer_ = {};

  // Pointers into the file buffer for commonly used PE structures.
  PIMAGE_DOS_HEADER     dos_header_;
  PIMAGE_NT_HEADERS     nt_header_;
  PIMAGE_SECTION_HEADER sections_;
};

// Disassemble an x86-64 PE file.
std::optional<disassembled_binary> disassemble(char const* const path) {
  disassembler dasm = {};

  // Initialize the disassembler.
  if (!dasm.initialize(path))
    return {};

  return dasm.bin;
}

} // namespace chum

