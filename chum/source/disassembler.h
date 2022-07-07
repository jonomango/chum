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

// This is essentially a wrapper over a chum::binary that was produced from
// an x86-64 PE file. This contains additional features for analyzing the
// original image that the chum::binary class does not contain (since it
// contains no PE-related information).
class disassembled_binary : public binary {
  friend class disassembler;
public:
  // Get the symbol that an RVA points to.
  symbol* rva_to_symbol(std::uint32_t rva);

  // Get the closest symbol that contains the specified RVA. For example,
  // if the specified RVA lands inside of a basic block, then the basic
  // block's symbol would be returned.
  symbol* rva_to_containing_symbol(std::uint32_t rva);

  // Get the data block at the specified RVA.
  data_block* rva_to_db(std::uint32_t rva) const;

  // Get the data block that contains the specified RVA.
  data_block* rva_to_containing_db(std::uint32_t rva, std::uint32_t* offset = nullptr) const;

private:
  // Insert the specified data block into the RVA to data block map.
  void insert_data_block_in_rva_map(std::uint32_t rva, data_block* db);

private:
  // This is a map that links RVAs to data blocks. This vector will always
  // be sorted by RVA, to allow quick lookup.
  std::vector<rva_data_block_entry> rva_data_block_map_ = {};
};

// Try to disassemble an x86-64 PE file.
std::optional<disassembled_binary> disassemble(char const* path);

} // namespace chum

