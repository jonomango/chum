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
  auto const message_box = bin.get_or_create_import_routine(
    "user32.dll", "MessageBoxA");

  // Create a basic block that opens a message box.
  auto const block = bin.create_basic_block("jono_block");
  block->push(bin.instr("\x48\x83\xEC\x20"));              // sub rsp, 0x20
  block->push(bin.instr("\x48\x31\xC9"));                  // xor rcx, rcx
  block->push(bin.instr("\x48\x8D\x15", hello_world_sym)); // lea rdx, hello_world
  block->push(bin.instr("\x4D\x31\xC0"));                  // xor r8, r8
  block->push(bin.instr("\x45\x31\xC9"));                  // xor r9d, r9d
  block->push(bin.instr("\xFF\x15", message_box));         // call message_box
  block->push(bin.instr("\x48\x83\xC4\x20"));              // add rsp, 0x20
  block->push(bin.instr("\xC3"));                          // ret

  // Insert a CALL to our instrumentation block at the start of the entrypoint.
  entrypoint->insert(bin.instr("\xE8", block));
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

