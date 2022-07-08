#include "chum.h"

#include <chrono>

void transform(chum::binary& bin) {
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
  auto const ibb = bin.create_basic_block("instrumentation_block");

  // xor rcx, rcx
  ibb->push({ 3, { 0x48, 0x31, 0xC9 } });
  // lea rdx, hello_world
  ibb->push({ 7, { 0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00 } });
  // ret
  ibb->push({ 1, { 0xC3 } });

  auto const entrypoint = bin.entrypoint();
  if (!entrypoint)
    return;

  // Insert a CALL to our instrumentation function.
  entrypoint->insert(chum::instruction::call(ibb));
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

  transform(*bin);

  bin->print(true);
}

