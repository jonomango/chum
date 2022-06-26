#include "chum.h"
#include "util.h"

#include <fstream>
#include <cassert>
#include <Windows.h>

namespace chum {

// Create an empty binary.
binary::binary() {
  // Initialize the Zydis decoder for x86-64.
  assert(ZYAN_SUCCESS(ZydisDecoderInit(&decoder_,
    ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)));
}

// Initialize the current binary with a 64-bit PE image.
bool binary::load(char const* const path) {
  // Default-initialize this object again, in-case it was modified before
  // load was called.
  *this = binary();

  auto file_buffer = read_file_to_buffer(path);
  if (file_buffer.empty())
    return false;

  auto const dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(&file_buffer[0]);
  if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    return false;

  auto const nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(
    &file_buffer[dos_header->e_lfanew]);
  if (nt_header->Signature != IMAGE_NT_SIGNATURE)
    return false;

  // Make sure we're dealing with a 64-bit PE image.
  if (nt_header->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    return false;

  auto const sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(nt_header + 1);

  // Create a data block for each data section.
  for (std::size_t i = 0; i < nt_header->FileHeader.NumberOfSections; ++i) {
    auto const& section = sections[i];

    // Ignore executable sections.
    if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
      continue;

    assert(section.Characteristics & IMAGE_SCN_MEM_READ);

    auto& db = create_data_block(min(section.SizeOfRawData,
      section.Misc.VirtualSize), nt_header->OptionalHeader.SectionAlignment);

    // Copy the data from file.
    std::memcpy(db.bytes.data(), &file_buffer[section.PointerToRawData],
      db.bytes.size());

    // Can we write to this section?
    db.read_only = !(section.Characteristics & IMAGE_SCN_MEM_WRITE);
  }

  return true;
}

// Print the contents of this binary, for debugging purposes.
void binary::print() const {
  std::printf("[+] Data blocks:\n");

  for (std::size_t i = 0; i < data_blocks_.size(); ++i) {
    auto const& db = data_blocks_[i];

    std::printf("[+]   Block %zd:\n", i);
    std::printf("[+]     Size      = 0x%zX.\n", db.bytes.size());
    std::printf("[+]     Alignment = 0x%X.\n", db.alignment);
    std::printf("[+]     Read-only = %s.\n", db.read_only ? "true" : "false");
  }
}

// Create and initialize a new data block.
data_block& binary::create_data_block(
    std::uint32_t const size, std::uint32_t const alignment) {
  auto& db = data_blocks_.emplace_back();
  db.bytes     = std::vector<std::uint8_t>(size, 0);
  db.alignment = alignment;
  db.read_only = false;
  return db;
}

} // namespace chum

