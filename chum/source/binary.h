#pragma once

#include "block.h"
#include "symbol.h"
#include "imports.h"

#include <vector>
#include <tuple>

#include <Zydis/Zydis.h>

namespace chum {

// This is a database that contains the code and data that makes up an
// x86-64 binary.
class binary {
public:
  // Create an empty binary.
  binary();

  // Free any resources.
  ~binary();

  // Move constructor.
  binary(binary&& other);

  // Move assignment operator.
  binary& operator=(binary&& other);

  // Prevent copying.
  binary(binary const&) = delete;
  binary& operator=(binary const&) = delete;

  // Print the contents of this binary, for debugging purposes.
  void print(bool verbose = false);

  // Create a new PE file from this binary.
  bool create(char const* path) const;

  // Get the entrypoint of this binary, if it exists.
  basic_block* entrypoint() const;

  // Set the entrypoint of this binary.
  void entrypoint(basic_block* bb);

  // Create a new symbol that is assigned a unique symbol ID.
  symbol* create_symbol(symbol_type type, char const* name = nullptr);

  // Get a symbol from its ID.
  symbol* get_symbol(symbol_id sym_id) const;

  // Get every symbol.
  std::vector<symbol*>& symbols();

  // Get every symbol.
  std::vector<symbol*> const& symbols() const;

  // Create a zero-initialized data block of the specified size and alignment.
  data_block* create_data_block(
    std::uint32_t size, std::uint32_t alignment = 1);

  // Create and initialize a new data block from a raw blob of data.
  data_block* create_data_block(void const* data,
    std::uint32_t size, std::uint32_t alignment = 1);

  // Get every data block.
  std::vector<data_block*>& data_blocks();

  // Get every data block.
  std::vector<data_block*> const& data_blocks() const;

  // Create a new basic block for the specific code symbol. This block
  // contains zero instructions upon creation. This function also updates
  // the specified symbol so that it points to the newly created block.
  basic_block* create_basic_block(symbol_id sym_id);

  // Create a new basic block, as well as a new code symbol that points
  // to this block. This block contains zero instructions upon creation.
  basic_block* create_basic_block(char const* name = nullptr);

  // Get every basic block.
  std::vector<basic_block*>& basic_blocks();

  // Get every basic block.
  std::vector<basic_block*> const& basic_blocks() const;

  // Create an empty import module.
  import_module* create_import_module(char const* name);

  // Get an import routine.
  import_routine* get_import_routine(
    char const* module_name, char const* routine_name) const;

  // Get an import routine. If the routine could not be found, create the
  // routine.
  import_routine* get_or_create_import_routine(
    char const* module_name, char const* routine_name);

public:
  // Create a new instruction.
  template <typename... Args>
  instruction instr(Args&&... args) const;

private:
  // This is a helper function for instr() that serializes a single item
  // into the instruction that is currently being built.
  template <std::size_t Idx, typename... Args>
  void instr_push_item(instruction& instr, std::tuple<Args...> const& tuple) const;

  // This is another helper function for serializing integer types, since
  // it is done so often.
  template <typename T>
  void instr_push_integer(instruction& instr, T const& value) const;

private:
  // ---------------
  // Remember to add any new members to the move constructor/assignment operator!
  // ---------------

  ZydisDecoder decoder_ = {};
  ZydisFormatter formatter_ = {};

  // This is an optional pointer to the entrypoint of this binary.
  basic_block* entrypoint_ = nullptr;

  // Most of these containers need to store pointers to the contained
  // structures since they require stability. We dont want to invalidate
  // any existing pointers whenever an insertion/deletion occurs.

  // Every symbol that makes up this binary. These are accessed with symbol IDs.
  std::vector<symbol*> symbols_ = {};

  // Every piece of data that makes up this binary.
  std::vector<data_block*> data_blocks_ = {};

  // Every piece of code that makes up this binary.
  std::vector<basic_block*> basic_blocks_ = {};

  // These are imports from external modules.
  std::vector<import_module*> import_modules_ = {};
};

// Create a new instruction.
template <typename... Args>
instruction binary::instr(Args&&... args) const {
  instruction new_instr = { 0 };
  instr_push_item<0>(new_instr, std::make_tuple(std::forward<Args>(args)...));
  return new_instr;
}

// This is a helper function for instr() that serializes a single item
// into the instruction that is currently being built.
template <std::size_t Idx, typename... Args>
void binary::instr_push_item(instruction& instr,
    std::tuple<Args...> const& tuple) const {
  if constexpr (Idx < sizeof...(Args)) {
    // The current item that we are pushing to the instruction.
    auto const item = std::get<Idx>(tuple);
    using item_type = std::remove_const_t<decltype(item)>;

    static_assert(std::is_integral_v<item_type>  ||
      std::is_same_v<item_type, symbol_id>       ||
      std::is_same_v<item_type, symbol*>         ||
      std::is_same_v<item_type, basic_block*>    ||
      std::is_same_v<item_type, import_routine*> ||
      std::is_same_v<item_type, char const*>);

    // Integral types should be converted to bytes.
    if constexpr (std::is_integral_v<item_type>)
      instr_push_integer(instr, item);
    else if constexpr (std::is_same_v<item_type, symbol_id>)
      instr_push_integer(instr, item.value);
    else if constexpr (std::is_same_v<item_type, symbol*>)
      instr_push_integer(instr, item->id.value);
    else if constexpr (std::is_same_v<item_type, basic_block*>)
      instr_push_integer(instr, item->sym_id.value);
    else if constexpr (std::is_same_v<item_type, import_routine*>)
      instr_push_integer(instr, item->sym_id.value);
    // C-style strings are assumed to be a null-terminated array of bytes.
    else if constexpr (std::is_same_v<item_type, char const*>) {
      for (std::size_t i = 0; item[i]; ++i)
        instr.bytes[instr.length++] = item[i];
    }

    // Push the next item in the tuple.
    instr_push_item<Idx + 1>(instr, tuple);
  }
}

// This is another helper function for serializing integer types, since
// it is done so often.
template <typename T>
void binary::instr_push_integer(instruction& instr, T const& value) const {
  // We need the integer to be unsigned so that we can safely do bitwise
  // operations on it (specifically, right-shift).
  auto unsigned_value = static_cast<std::make_unsigned_t<T>>(value);

  // Copy each byte, making sure to account for endianness.
  for (std::size_t i = 0; i < sizeof(value); ++i) {
    instr.bytes[instr.length++] = unsigned_value & 0xFF;
    unsigned_value >>= 8;
  }
}

} // namespace chum

