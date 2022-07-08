#pragma once

#include "binary.h"

#include <optional>

namespace chum {

struct rva_data_block_entry {
  // This is the RVA to the start of the data block.
  std::uint32_t rva = 0;

  // This is the data block that is found at the specified RVA.
  data_block* db = nullptr;
};

// This contains information about a specific RVA.
struct rva_map_entry {
  // If the blink is 0, this is the symbol that this RVA lands in.
  symbol_id sym_id = null_symbol_id;

  // If non-zero, this is the number of bytes to the previous RVA entry.
  std::uint32_t blink = 0;
};

// This is essentially a wrapper over a chum::binary that was produced from
// an x86-64 PE file. This contains additional features for analyzing the
// original image that the chum::binary class does not contain (since it
// contains no PE-related information).
class disassembled_binary : public binary {
  friend class disassembler;
public:
  // Get the symbol that an RVA points to.
  symbol* rva_to_symbol(std::uint32_t rva) const;

  // Get the data block at the specified RVA.
  data_block* rva_to_db(std::uint32_t rva) const;

  // Get the data block that contains the specified RVA.
  data_block* rva_to_containing_db(std::uint32_t rva,
    std::uint32_t* offset = nullptr) const;

  // Get the basic block at the specified RVA.
  basic_block* rva_to_bb(std::uint32_t rva) const;

  // Get the basic block at the specified RVA, which includes any addresses
  // that point to an instruction in the basic block.
  basic_block* rva_to_containing_bb(std::uint32_t rva,
    std::uint32_t* offset = nullptr) const;

private:
  // Insert the specified data block into the RVA to data block map.
  void insert_data_block_in_rva_map(std::uint32_t rva, data_block* db);

private:
  // This is a map that contains RVAs and their associated metadata.
  std::vector<rva_map_entry> rva_map_ = {};

  // This is a map that links RVAs to data blocks. This vector will always
  // be sorted by RVA, to allow for quick lookup.
  std::vector<rva_data_block_entry> rva_data_block_map_ = {};
};

// Try to disassemble an x86-64 PE file.
std::optional<disassembled_binary> disassemble(char const* path);

} // namespace chum

