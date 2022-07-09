#include "chum.h"

#include <chrono>

void transform(chum::binary& bin) {
  auto const entrypoint = bin.entrypoint();
  if (!entrypoint)
    return;

  // Allocate a data block to hold a string.
  auto const hello_world_db = bin.create_data_block("Hello world!", 13);
  hello_world_db->read_only = true;

  // Create a symbol to the string.
  auto const hello_world_sym = bin.create_symbol(
    chum::symbol_type::data, "hello_world_str");
  hello_world_sym->db = hello_world_db;
  hello_world_sym->db_offset = 0;

  // Import the MessageBoxA routine.
  auto const message_box_symid = bin.get_or_create_import_routine(
    "user32.dll", "MessageBoxA")->sym_id;

  // Create a basic block that opens a message box.
  auto const block = bin.create_basic_block("instrumentation_block");
  block->push(bin.instr("\x48\x31\xC9"));                  // xor rcx, rcx
  block->push(bin.instr("\x48\x8D\x15", hello_world_sym)); // lea rdx, hello_world
  block->push(bin.instr("\xC3"));                          // ret

  // Insert a CALL to our instrumentation block.
  entrypoint->insert(bin.instr("\xE8", block));
}

#include <tuple>
#include <iostream>

template <std::size_t Idx, typename... Args>
constexpr void instr_push_item(chum::instruction& instr, std::tuple<Args...> const& tuple) {
  if constexpr (Idx < sizeof...(Args)) {
    // The current item that we are pushing to the instruction.
    auto const item = std::get<Idx>(tuple);
    using item_type = std::remove_const_t<decltype(item)>;

    static_assert(std::is_integral_v<item_type> ||
      std::is_same_v<item_type, char const*> ||
      std::is_same_v<item_type, chum::symbol_id>);

    // Integral types should be converted to bytes.
    if constexpr (std::is_integral_v<item_type>) {
      // We need the integer to be unsigned so that we can safely do bitwise
      // operations on it (specifically, right-shift).
      auto unsigned_item = static_cast<std::make_unsigned_t<item_type>>(item);

      // Copy each byte, making sure to account for endianness.
      for (std::size_t i = 0; i < sizeof(item); ++i) {
        instr.bytes[instr.length++] = unsigned_item & 0xFF;
        unsigned_item >>= 8;
      }
    }
    // C-style strings are assumed to be a null-terminated array of bytes.
    else if constexpr (std::is_same_v<item_type, char const*>) {
      for (std::size_t i = 0; item[i]; ++i)
        instr.bytes[instr.length++] = item[i];
    }
    // Symbol IDs should be encoded as unsigned 32-bit integers.
    else if constexpr (std::is_same_v<item_type, chum::symbol_id>) {
      for (std::size_t i = 0; i < 4; ++i)
        instr.bytes[instr.length++] = (item.value >> (8 * i)) & 0xFF;
    }

    // Push the next item in the tuple.
    instr_push_item<Idx + 1>(instr, tuple);
  }
}

template <typename... Args>
constexpr chum::instruction instr(Args&&... args) {
  chum::instruction instr = { 0 };
  instr_push_item<0>(instr, std::make_tuple(std::forward<Args>(args)...));
  return instr;
}

int main() {
  auto const start_time = std::chrono::high_resolution_clock::now();

  //auto bin = chum::disassemble("C:\\Users\\realj\\Desktop\\dxgkrnl (lizerd).sys");
  //auto bin = chum::disassemble("C:\\Users\\realj\\Desktop\\kernel32.dll");
  //auto bin = chum::disassemble("hello-world-x64.dll");
  auto bin = chum::disassemble("hello-world-x64-min.dll");
  //auto bin = chum::disassemble("split-block-1030.dll");

  auto const end_time = std::chrono::high_resolution_clock::now();

  std::printf("[+] Time elapsed: %zums.\n",
    std::chrono::duration_cast<std::chrono::milliseconds>(
    end_time - start_time).count());

  if (!bin) {
    std::printf("[!] Failed to disassemble binary.\n");
    return 0;
  }

  std::printf("[+] Disassembled binary.\n");

  constexpr auto instruction = instr("\x12\x34", 0x56ui8, 0x1234ui16, chum::symbol_id{ 0x69 });
  //constexpr auto instruction = instr(0x56ui8, 0x1234ui16);

  for (std::size_t i = 0; i < instruction.length; ++i)
    std::printf("%X ", instruction.bytes[i]);
  std::printf("\n");

  transform(*bin);

  bin->print(true);
}

