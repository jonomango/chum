#include "chum.h"
#include "util.h"

#include <fstream>
#include <cassert>
#include <queue>

namespace chum {

// Create an empty binary.
binary::binary() {
  // Initialize the Zydis decoder for x86-64.
  assert(ZYAN_SUCCESS(ZydisDecoderInit(&decoder_,
    ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)));

  // Initialize the Zydis formatter.
  assert(ZYAN_SUCCESS(ZydisFormatterInit(&formatter_,
    ZYDIS_FORMATTER_STYLE_INTEL)));

  // This makes it so that relative instructions are shown as RIP+X instead
  // of using an absolute address.
  ZydisFormatterSetProperty(&formatter_,
    ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_BRANCHES, true);
  ZydisFormatterSetProperty(&formatter_,
    ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_RIPREL, true);
}

// Initialize the current binary with a 64-bit PE image.
bool binary::load(char const* const path) {
  // Default-initialize this object again, in-case it was modified before
  // load was called.
  *this = binary();

  disassembler_context ctx;
  if (!init_disassembler_context(ctx, path))
    return false;

  // Create the invalid symbol at index 0.
  auto const null_symbol = create_symbol(symbol_type::invalid, "<null>");
  assert(null_symbol->id == null_symbol_id);

  // Create the section data blocks before disassembling.
  create_section_data_blocks(ctx);

  return disassemble(ctx);
}

// Print the contents of this binary, for debugging purposes.
void binary::print() const {
  std::printf("[+] Symbols:\n");
  for (auto const sym : symbols_) {
    std::printf("[+]   ID: %-6u Type: %-8s",
      sym->id, serialize_symbol_type(sym->type));

    // Print the name, if it exists.
    if (!sym->name.empty())
      std::printf(" Name: %s\n", sym->name.c_str());
    else
      std::printf("\n");
  }

  std::printf("[+]\n[+] Data blocks:\n");
  for (std::size_t i = 0; i < data_blocks_.size(); ++i) {
    auto const db = data_blocks_[i];

    std::printf("[+]   #%-4zu Size: 0x%-8zX Alignment: 0x%-5X Read-only: %s\n",
      i, db->bytes.size(), db->alignment, db->read_only ? "true" : "false");
  }

  std::printf("[+]\n[+] Basic blocks:\n");
  for (std::size_t i = 0; i < basic_blocks_.size(); ++i) {
    auto const bb = basic_blocks_[i];

    std::printf("[+]   #%-4zd Symbol: %-6u Instruction count: %-4zu",
      i, bb->sym_id, bb->instructions.size());

    // Print the fallthrough target symbol ID, if it exists.
    if (bb->fallthrough_target)
      std::printf(" Fallthrough symbol: %-6u\n", bb->fallthrough_target->sym_id);
    else
      std::printf("\n");
  }
}

// Create a new basic block that contains no instructions.
basic_block* binary::create_basic_block() {
  auto const bb = basic_blocks_.emplace_back(new basic_block);

  return bb;
}

// Create a new data block with uninitialized data.
data_block* binary::create_data_block(
    std::uint32_t const size, std::uint32_t const alignment) {
  auto const db = data_blocks_.emplace_back(new data_block);
  db->bytes     = std::vector<std::uint8_t>(size, 0);
  db->alignment = alignment;
  db->read_only = false;
  return db;
}

// Create a new symbol.
symbol* binary::create_symbol(
    symbol_type const type, char const* const name) {
  auto const sym = symbols_.emplace_back(new symbol);
  sym->id        = static_cast<symbol_id>(symbols_.size() - 1);
  sym->type      = type;
  sym->name      = name ? name : "";
  return sym;
}

// Initialize the disassembler context.
bool binary::init_disassembler_context(
    disassembler_context& ctx, char const* const path) {
  ctx.file_buffer = read_file_to_buffer(path);
  if (ctx.file_buffer.empty())
    return false;

  ctx.dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(&ctx.file_buffer[0]);
  if (ctx.dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    return false;

  ctx.nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(
    &ctx.file_buffer[ctx.dos_header->e_lfanew]);
  if (ctx.nt_header->Signature != IMAGE_NT_SIGNATURE)
    return false;

  // Make sure we're dealing with a 64-bit PE image.
  if (ctx.nt_header->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    return false;

  ctx.sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(ctx.nt_header + 1);

  // Allocate the table so that any RVA can fit.
  ctx.rva_to_sym = std::vector<symbol*>(
    ctx.nt_header->OptionalHeader.SizeOfImage, nullptr);

  return true;
}

// Create data blocks for every PE section.
void binary::create_section_data_blocks(disassembler_context& ctx) {
  for (std::size_t i = 0; i < ctx.nt_header->FileHeader.NumberOfSections; ++i) {
    auto const& section = ctx.sections[i];

    // Ignore executable sections.
    if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
      continue;

    assert(section.Characteristics & IMAGE_SCN_MEM_READ);

    auto const db = create_data_block(min(section.SizeOfRawData,
      section.Misc.VirtualSize), ctx.nt_header->OptionalHeader.SectionAlignment);

    // Copy the data from file.
    std::memcpy(db->bytes.data(),
      &ctx.file_buffer[section.PointerToRawData], db->bytes.size());

    // Can we write to this section?
    db->read_only = !(section.Characteristics & IMAGE_SCN_MEM_WRITE);

    // This is a work-around since the section name wont be null-terminated
    // if it is exactly 8 bytes long.
    char section_name[9] = { 0 };
    std::memcpy(section_name, section.Name, 8);

    // Create a symbol for the start of this data section.
    auto const sym = create_symbol(symbol_type::data, section_name);
    ctx.rva_to_sym[section.VirtualAddress] = sym;
    sym->db                                = db;
    sym->offset                            = 0;
  }
}

// Generate the basic blocks for this binary.
bool binary::disassemble(disassembler_context& ctx) {
  // A queue of RVAs to disassemble from.
  std::queue<std::uint32_t> disassembly_queue = {};

  // Add the specified RVA to the disassembly queue.
  auto const enqueue_code_rva = [&](
      std::uint32_t const rva, char const* const name = nullptr) {
    disassembly_queue.push(rva);

    // Make sure we're not creating a duplicate symbol.
    assert(ctx.rva_to_sym[rva] == nullptr);

    // Create a new symbol that will point to the start of this basic block.
    auto const sym = ctx.rva_to_sym[rva] =
      create_symbol(symbol_type::code, name);

    // Create a new basic block.
    sym->bb = create_basic_block();
    sym->bb->sym_id = sym->id;

    return sym;
  };

  // Convert an RVA to a file offset by iterating over every PE section.
  auto const rva_to_file_offset = [&](std::uint32_t const rva) -> std::uint32_t {
    for (std::size_t i = 0; i < ctx.nt_header->FileHeader.NumberOfSections; ++i) {
      auto const& sec = ctx.sections[i];
      if (rva >= sec.VirtualAddress && rva < (sec.VirtualAddress + sec.Misc.VirtualSize))
        return sec.PointerToRawData + (rva - sec.VirtualAddress);
    }

    return 0;
  };

  // Add the entrypoint to the disassembly queue.
  if (ctx.nt_header->OptionalHeader.AddressOfEntryPoint) {
    enqueue_code_rva(
      ctx.nt_header->OptionalHeader.AddressOfEntryPoint, "<entry-point>");
  }

  // TODO: Add exports to the disassembly queue.

  while (!disassembly_queue.empty()) {
    // Pop an RVA from the front of the queue.
    auto const rva_start = disassembly_queue.front();
    disassembly_queue.pop();

    auto const file_start = rva_to_file_offset(rva_start);

    // This is the basic block that we're constructing.
    auto const curr_bb = ctx.rva_to_sym[rva_start]->bb;

    //std::printf("[+] Started basic block at RVA 0x%X.\n", rva_start);

    // Keep decoding until we hit a terminating instruction.
    for (std::uint32_t instr_offset = 0;
         file_start + instr_offset < ctx.file_buffer.size();) {
      // A pointer to the current instruction in the raw binary.
      auto const curr_instr_buffer = &ctx.file_buffer[file_start + instr_offset];

      // The amount of bytes until the file end.
      // TODO: We should be using the section end instead.
      auto const remaining_buffer_length =
        ctx.file_buffer.size() - (file_start + instr_offset);

      // Decode the current instruction.
      ZydisDecodedInstruction decoded_instr;
      if (ZYAN_FAILED(ZydisDecoderDecodeInstruction(&decoder_, nullptr,
          curr_instr_buffer, remaining_buffer_length, &decoded_instr))) {
        std::printf("[!] Failed to decode instruction.\n");
        std::printf("[!]   RVA: 0x%X.\n", rva_start + instr_offset);
        return false;
      }

      // This is the instruction that we'll be adding to the basic block. It
      // it usually the same as the original instruction, unless it has any
      // relative operands.
      instruction instr;

      if (decoded_instr.attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
        // A small optimization, since branch instructions can mostly be
        // handled without needing to decode operands.
        if (decoded_instr.raw.imm[0].is_relative) {
          auto const target_rva = static_cast<std::uint32_t>(rva_start +
            instr_offset + decoded_instr.length + decoded_instr.raw.imm[0].value.s);

          // Get the symbol for the branch destination.
          auto target_sym = ctx.rva_to_sym[target_rva];

          // This is undiscovered code, add it to the disassembly queue.
          if (!target_sym)
            target_sym = enqueue_code_rva(target_rva, "<branch-target>");

          assert(target_sym->type == symbol_type::code);
        }

        // Copy the original instruction.
        instr.length = decoded_instr.length;
        std::memcpy(instr.bytes, curr_instr_buffer, instr.length);
      } else {
        // Copy the original instruction.
        instr.length = decoded_instr.length;
        std::memcpy(instr.bytes, curr_instr_buffer, instr.length);
      }

      // Add the instruction to the basic block.
      curr_bb->instructions.push_back(instr);

      // If this is a terminating instruction, end the block.
      if (decoded_instr.meta.category == ZYDIS_CATEGORY_RET ||
          decoded_instr.meta.category == ZYDIS_CATEGORY_COND_BR ||
          decoded_instr.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
        // Conditional branches require a fallthrough target.
        if (decoded_instr.meta.category == ZYDIS_CATEGORY_COND_BR) {
          auto const fallthrough_rva = static_cast<std::uint32_t>(rva_start +
            instr_offset + decoded_instr.length);

          // If the fallthrough target doesn't have a symbol yet, add it to
          // the disassembly queue.
          if (auto const sym = ctx.rva_to_sym[fallthrough_rva])
            curr_bb->fallthrough_target = sym->bb;
          else
            curr_bb->fallthrough_target = enqueue_code_rva(fallthrough_rva, "<fallthrough-target>")->bb;
        }

        break;
      }

      instr_offset += instr.length;

      // If we've entered into another basic block, end the current block.
      if (auto const sym = ctx.rva_to_sym[rva_start + instr_offset]) {
        // TODO: It *might* be possible to accidently fall into a jump table
        //       (which would be marked as data, not code).
        assert(sym->type == symbol_type::code);
        curr_bb->fallthrough_target = sym->bb;

        break;
      }
    }

    // TODO: Handle empty basic blocks.
    assert(!curr_bb->instructions.empty());
  }

  return true;
}

} // namespace chum

