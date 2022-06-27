#pragma once

#include "block.h"
#include "symbol.h"

#include <vector>
#include <Windows.h>

#include <Zydis/Zydis.h>

namespace chum {

// This is a database that contains the code and data that makes up an
// x86-64 binary.
class binary {
public:
  // Create an empty binary.
  binary();

  // Initialize the current binary with a 64-bit PE image.
  bool load(char const* path);

  // Print the contents of this binary, for debugging purposes.
  void print();

  // Create a new basic block that contains no instructions.
  basic_block* create_basic_block();

  // Create a new data block with uninitialized data.
  data_block* create_data_block(std::uint32_t size, std::uint32_t alignment = 1);

  // Create a new symbol.
  symbol* create_symbol(symbol_type type, char const* name = nullptr);

private:
  struct db_map_entry {
    std::uint32_t rva;
    std::uint32_t size;
    data_block* db;
  };

  struct disassembler_context {
    // Raw file contents.
    std::vector<std::uint8_t> file_buffer;

    // Pointers to various PE structures in the file.
    PIMAGE_DOS_HEADER     dos_header;
    PIMAGE_NT_HEADERS     nt_header;
    PIMAGE_SECTION_HEADER sections;

    // This maps every RVA to its associated symbol (if it has one).
    std::vector<symbol*> rva_to_sym;

    // This is used for finding which data block an RVA is contained in.
    std::vector<db_map_entry> db_map;
  };

  // Initialize the disassembler context.
  static bool init_disassembler_context(disassembler_context& ctx, char const* path);

  // Convert an RVA to its corresponding file offset by iterating over every
  // PE section.
  static std::uint32_t rva_to_file_offset(
      disassembler_context const& ctx, std::uint32_t rva);

  // Get the data block map entry that the specified RVA lands in, or
  // nullptr if not found.
  static db_map_entry const* rva_to_db_map_entry(
      disassembler_context const& ctx, std::uint32_t rva);

  // Create data blocks for every PE section.
  void create_section_data_blocks(disassembler_context& ctx);

  // Create data symbols for every PE import.
  void create_import_symbols(disassembler_context& ctx);

  // Generate the basic blocks for this binary.
  bool disassemble(disassembler_context& ctx);

private:
  ZydisDecoder decoder_;
  ZydisFormatter formatter_;

  // Every symbol that makes up this binary. These are accessed with symbol IDs.
  std::vector<symbol*> symbols_;

  // Every piece of data that makes up this binary.
  std::vector<data_block*> data_blocks_;

  // Every piece of code that makes up this binary.
  std::vector<basic_block*> basic_blocks_;
};

} // namespace chum

