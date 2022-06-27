#include "chum.h"
#include "util.h"

#include <fstream>
#include <cassert>

namespace chum {

// Create an empty binary.
binary::binary() {
  // Initialize the Zydis decoder for x86-64.
  assert(ZYAN_SUCCESS(ZydisDecoderInit(&decoder_,
    ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)));
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
  auto const null_symbol = create_symbol(symbol_type::invalid, "null symbol");
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

    std::printf("[+]   #%-4zd Size: 0x%-8zX Alignment: 0x%-5X Read-only: %s\n",
      i, db->bytes.size(), db->alignment, db->read_only ? "true" : "false");
  }

  std::printf("[+]\n[+] Basic blocks:\n");
  for (std::size_t i = 0; i < basic_blocks_.size(); ++i) {
    auto const bb = data_blocks_[i];

    std::printf("[+]   #%zd\n", i);
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
    std::memcpy(db->bytes.data(), &ctx.file_buffer[section.PointerToRawData],
      db->bytes.size());

    // Can we write to this section?
    db->read_only = !(section.Characteristics & IMAGE_SCN_MEM_WRITE);

    // This is a work-around since the section name wont be null-terminated
    // if it is exactly 8 bytes long.
    char section_name[9] = { 0 };
    std::memcpy(section_name, section.Name, 8);

    // Create a symbol for the start of this data section.
    auto const sym = create_symbol(symbol_type::data, section_name);
    sym->db     = db;
    sym->offset = 0;
  }
}

// Generate the basic blocks for this binary.
bool binary::disassemble(disassembler_context& ctx) {
  return true;
}

} // namespace chum

