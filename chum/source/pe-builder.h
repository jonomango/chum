#pragma once

#include <vector>

#include <Windows.h>

namespace chum {

class binary;

class pe_builder {
public:
  pe_builder(binary const& bin)
    : bin_(bin) {}

  // Try to create a PE image at the specified path.
  bool create(char const* path) const;

  // Create and return the raw contents of a PE image. An empty vector is
  // returned on failure.
  std::vector<std::uint8_t> create() const;

private:
  // Fill out most of the stuff in the NT header.
  void write_nt_header(PIMAGE_NT_HEADERS nt_header) const;

  // Get a pointer to a section header in the vector of bytes.
  static PIMAGE_SECTION_HEADER section_header(
    std::vector<std::uint8_t>& vec, std::size_t idx);

  // Append padding to the vector of bytes.
  static void append_padding(std::vector<std::uint8_t>& vec,
    std::size_t count, std::uint8_t value = 0);

  // Align an integer up to the specified alignment.
  static std::uint64_t align_integer(std::uint64_t value, std::uint64_t alignment);

private:
  binary const& bin_;

  // TODO: Pass options like this to the PE builder.
  static constexpr std::uint32_t file_alignment = 0x200;
  static constexpr std::uint64_t image_base = 0x140000000;
};

} // namespace chum

