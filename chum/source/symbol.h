#pragma once

#include <string>

namespace chum {

// The different types of symbols that exist. Might be useful to add symbol
// aliases as well, which would point to another symbol.
enum class symbol_type {
  invalid,

  // A code symbol points to the start of a basic block.
  code,

  // A data symbol points to a location inside of a data block.
  data,

  // An import symbol points to a location inside of an import table.
  import
};

// Get the string representation of a symbol type.
inline constexpr char const* serialize_symbol_type(symbol_type const type) {
  switch (type) {
  case symbol_type::code:   return "code";
  case symbol_type::data:   return "data";
  case symbol_type::import: return "import";
  default: return "invalid";
  }
}

// A symbol ID is essentially a handle to a symbol that can be used to
// quickly lookup the associated symbol.
using symbol_id = std::uint32_t;

// This symbol will NEVER point to meaningful data.
inline constexpr symbol_id null_symbol_id = 0;

// A symbol represents a memory address that is not known until link-time.
// TODO: support exporting symbols.
struct symbol {
  // The symbol ID pointing to this symbol.
  symbol_id id = null_symbol_id;

  // The symbol type.
  symbol_type type = symbol_type::invalid;

  union {
    // Valid only for code symbols.
    struct basic_block* bb;

    // Valid only for data symbols.
    struct {
      struct data_block* db;

      // This is the offset of the data from the start of the data block.
      std::uint32_t db_offset;
    };

    // Valid only for import symbols.
    struct import_routine* ir;
  };

  // An optional name for this symbol.
  std::string name = "";
};

} // namespace chum

