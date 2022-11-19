#include "binary.h"
#include "pe-builder.h"

#include <cassert>
#include <algorithm>
#include <fstream>

#include <Windows.h>
#include <zycore/Format.h>

namespace chum {

static ZydisFormatterFunc orig_zydis_format_operand_mem = nullptr;
static ZydisFormatterFunc orig_zydis_format_operand_imm = nullptr;

static ZyanStatus hook_zydis_format_operand_mem(
    ZydisFormatter const* const formatter,
    ZydisFormatterBuffer* const buffer, ZydisFormatterContext* const context) {
  // Call the original function.
  if (context->operand->mem.base != ZYDIS_REGISTER_RIP)
    return orig_zydis_format_operand_mem(formatter, buffer, context);

  auto const mask = (1ull << context->instruction->raw.disp.size) - 1;
  auto const& sym_table = *reinterpret_cast<std::vector<symbol*>*>(context->user_data);
  auto const sym_id = *reinterpret_cast<std::uint64_t const*>(&context->operand->mem.disp.value) & mask;
  auto const sym = sym_table[sym_id];

  ZyanString* string;
  ZydisFormatterBufferAppend(buffer, ZYDIS_TOKEN_SYMBOL);
  ZydisFormatterBufferGetString(buffer, &string);

  if (!sym->name.empty())
    ZyanStringAppendFormat(string, "%s", sym->name.c_str());
  else
    ZyanStringAppendFormat(string, "symbol_%u", sym->id);


  return ZYAN_STATUS_SUCCESS;
}

static ZyanStatus hook_zydis_format_operand_imm(
    ZydisFormatter const* const formatter,
    ZydisFormatterBuffer* const buffer, ZydisFormatterContext* const context) {
  // Call the original function.
  if (!context->operand->imm.is_relative)
    return orig_zydis_format_operand_imm(formatter, buffer, context);

  auto const mask = (1ull << context->operand->size) - 1;
  auto const& sym_table = *reinterpret_cast<std::vector<symbol*>*>(context->user_data);
  auto const sym = sym_table[context->operand->imm.value.u & mask];

  ZyanString* string;
  ZydisFormatterBufferAppend(buffer, ZYDIS_TOKEN_SYMBOL);
  ZydisFormatterBufferGetString(buffer, &string);

  if (!sym->name.empty())
    ZyanStringAppendFormat(string, "%s", sym->name.c_str());
  else
    ZyanStringAppendFormat(string, "symbol_%u", sym->id);

  return ZYAN_STATUS_SUCCESS;
}

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

  orig_zydis_format_operand_mem = hook_zydis_format_operand_mem;
  ZydisFormatterSetHook(&formatter_, ZYDIS_FORMATTER_FUNC_FORMAT_OPERAND_MEM,
    reinterpret_cast<void const**>(&orig_zydis_format_operand_mem));

  orig_zydis_format_operand_imm = hook_zydis_format_operand_imm;
  ZydisFormatterSetHook(&formatter_, ZYDIS_FORMATTER_FUNC_FORMAT_OPERAND_IMM,
    reinterpret_cast<void const**>(&orig_zydis_format_operand_imm));

  // Create the null symbol.
  auto const null_symbol = create_symbol(symbol_type::invalid, "<null>");
  assert(null_symbol->id == null_symbol_id);
}

// Free any resources.
binary::~binary() {
  for (auto const e : symbols_)
    delete e;
  for (auto const e : data_blocks_)
    delete e;
  for (auto const e : basic_blocks_)
    delete e;
  for (auto const e : import_modules_)
    delete e;
}

// Move constructor.
binary::binary(binary&& other) {
  // I *think* this is correct...
  std::swap(decoder_,        other.decoder_);
  std::swap(formatter_,      other.formatter_);
  std::swap(entrypoint_,     other.entrypoint_);
  std::swap(symbols_,        other.symbols_);
  std::swap(data_blocks_,    other.data_blocks_);
  std::swap(basic_blocks_,   other.basic_blocks_);
  std::swap(import_modules_, other.import_modules_);
}

// Move assignment operator.
binary& binary::operator=(binary&& other) {
  // I *think* this is correct...
  std::swap(decoder_,        other.decoder_);
  std::swap(formatter_,      other.formatter_);
  std::swap(entrypoint_,     other.entrypoint_);
  std::swap(symbols_,        other.symbols_);
  std::swap(data_blocks_,    other.data_blocks_);
  std::swap(basic_blocks_,   other.basic_blocks_);
  std::swap(import_modules_, other.import_modules_);

  return *this;
}

// Print the contents of this binary, for debugging purposes.
void binary::print(bool const verbose) {
  std::printf("[+] Symbols (%zu):\n", symbols_.size());

  if (verbose) {
    for (auto const sym : symbols_) {
      std::printf("[+]   ID: %-6u Type: %-8s",
        sym->id.value, serialize_symbol_type(sym->type));

      // Print the target, if it exists.
      if (sym->type == symbol_type::data && sym->target)
        std::printf(" Target: %-6u", sym->target.value);

      // Print the name, if it exists.
      if (!sym->name.empty())
        std::printf(" Name: %s\n", sym->name.c_str());
      else
        std::printf("\n");
    }
    std::printf("[+]\n");
  }

  std::printf("[+] Import modules (%zu):\n", import_modules_.size());

  if (verbose) {
    for (auto const& mod : import_modules_) {
      std::printf("[+]   %s:\n", mod->name());

      for (auto const& routine : mod->routines())
        std::printf("[+]     - %s\n", routine->name.c_str());
    }
    std::printf("[+]\n");
  }

  std::printf("[+] Data blocks (%zu):\n", data_blocks_.size());

  if (verbose) {
    for (std::size_t i = 0; i < data_blocks_.size(); ++i) {
      auto const db = data_blocks_[i];

      std::printf("[+]   #%-4zu Size: 0x%-8zX Alignment: 0x%-5X Read-only: %s\n",
        i, db->bytes.size(), db->alignment, db->read_only ? "true" : "false");
    }
    std::printf("[+]\n");
  }

  std::printf("[+] Basic blocks (%zu):\n", basic_blocks_.size());

  if (verbose) {
    for (std::size_t i = 0; i < basic_blocks_.size(); ++i) {
      auto const bb = basic_blocks_[i];

      std::printf("[+]   #%-4zd Symbol: %-6u Instruction count: %-4zu",
        i, bb->sym_id.value, bb->instructions.size());

      // Print the fallthrough target symbol ID, if it exists.
      if (bb->fallthrough_target)
        std::printf(" Fallthrough: %-6u\n", bb->fallthrough_target.value);
      else
        std::printf("\n");

      // Print the symbol name as a label.
      if (auto const sym = get_symbol(bb->sym_id); sym && !sym->name.empty()) {
        std::printf("[+]     +000\n");
        std::printf("[+]     +000 %20.20s:\n", sym->name.c_str());
      }

      // Print every instruction.
      std::uint32_t instr_offset = 0;
      for (auto const& instr : bb->instructions) {
        ZydisDecodedInstruction decoded_instr;
        ZydisDecodedOperand decoded_operands[ZYDIS_MAX_OPERAND_COUNT];

        ZydisDecoderDecodeFull(&decoder_, instr.bytes, instr.length,
          &decoded_instr, decoded_operands);

        char buffer[128] = { 0 };
        ZydisFormatterFormatInstruction(&formatter_, &decoded_instr,
          decoded_operands, decoded_instr.operand_count_visible, buffer,
          128, 0, &symbols_);

        std::printf("[+]     +%.3X                       %s\n", instr_offset, buffer);

        instr_offset += instr.length;
      }
      std::printf("[+]\n");
    }
  }
}

// Create a new PE file from this binary.
bool binary::create(char const* const path) const {
  return pe_builder(*this).create(path);
}

// Get the entrypoint of this binary, if it exists.
basic_block* binary::entrypoint() const {
  return entrypoint_;
}

// Set the entrypoint of this binary.
void binary::entrypoint(basic_block* const bb) {
  entrypoint_ = bb;
}

// Create a new symbol that is assigned a unique symbol ID.
symbol* binary::create_symbol(symbol_type const type, char const* const name) {
  auto const sym = symbols_.emplace_back(new symbol{});
  sym->id        = symbol_id{ static_cast<std::uint32_t>(symbols_.size() - 1) };
  sym->type      = type;
  sym->name      = name ? name : "";
  return sym;
}

// Get a symbol from its ID.
symbol* binary::get_symbol(symbol_id const sym_id) const {
  if (sym_id.value >= symbols_.size())
    return nullptr;
  return symbols_[sym_id.value];
}

// Get every symbol.
std::vector<symbol*>& binary::symbols() {
  return symbols_;
}

// Get every symbol.
std::vector<symbol*> const& binary::symbols() const {
  return symbols_;
}

// Create a zero-initialized data block of the specified size and alignment.
data_block* binary::create_data_block(
    std::uint32_t const size, std::uint32_t const alignment) {
  auto const db = data_blocks_.emplace_back(new data_block{});
  db->bytes     = std::vector<std::uint8_t>(size, 0);
  db->alignment = alignment;
  db->read_only = false;
  return db;
}

// Create and initialize a new data block from a raw blob of data.
data_block* binary::create_data_block(void const* const data,
    std::uint32_t const size, std::uint32_t const alignment) {
  // "Iterators" to pass to std::vector constructor.
  auto const data_begin = static_cast<std::uint8_t const*>(data);
  auto const data_end   = data_begin + size;

  auto const db = data_blocks_.emplace_back(new data_block{});
  db->bytes     = std::vector<std::uint8_t>(data_begin, data_end);
  db->alignment = alignment;
  db->read_only = false;
  return db;
}

// Get every data block.
std::vector<data_block*>& binary::data_blocks() {
  return data_blocks_;
}

// Get every data block.
std::vector<data_block*> const& binary::data_blocks() const {
  return data_blocks_;
}

// Create a new basic block for the specific code symbol. This block
// contains zero instructions upon creation. This function also updates
// the specified symbol so that it points to the newly created block.
basic_block* binary::create_basic_block(symbol_id const sym_id) {
  // Make sure we're dealing with a code symbol.
  auto const sym = symbols_[sym_id.value];
  assert(sym->type == symbol_type::code);

  sym->bb = basic_blocks_.emplace_back(new basic_block{});
  sym->bb->sym_id             = sym_id;
  sym->bb->fallthrough_target = null_symbol_id;
  sym->bb->instructions       = {};

  // Reserve enough space for atleast 6 instructions, to help performance.
  sym->bb->instructions.reserve(6);

  return sym->bb;
}

// Create a new basic block, as well as a new code symbol that points
// to this block. This block contains zero instructions upon creation.
basic_block* binary::create_basic_block(char const* const name) {
  return create_basic_block(create_symbol(symbol_type::code, name)->id);
}

// Get every basic block.
std::vector<basic_block*>& binary::basic_blocks() {
  return basic_blocks_;
}

// Get every basic block.
std::vector<basic_block*> const& binary::basic_blocks() const {
  return basic_blocks_;
}

// Create an empty import module.
import_module* binary::create_import_module(char const* const name) {
  // TODO: Make sure this isn't a duplicate.
  return import_modules_.emplace_back(new import_module(*this, name));
}

// Get an import routine.
import_routine* binary::get_import_routine(
    char const* const module_name, char const* const routine_name) const {
  // Search for the matching import module.
  for (auto const mod : import_modules_) {
    if (_stricmp(mod->name(), module_name) != 0)
      continue;

    // Search for the routine in this module.
    for (auto const routine : mod->routines()) {
      if (_stricmp(routine->name.c_str(), routine_name) == 0)
        return routine;
    }
  }

  return nullptr;
}

// Get an import routine. If the routine could not be found, create the
// routine.
import_routine* binary::get_or_create_import_routine(
    char const* const module_name, char const* const routine_name) {
  // Search for the matching import module.
  for (auto const mod : import_modules_) {
    if (_stricmp(mod->name(), module_name) != 0)
      continue;

    // Search for the routine in this module.
    for (auto const routine : mod->routines()) {
      if (_stricmp(routine->name.c_str(), routine_name) == 0)
        return routine;
    }

    return mod->create_routine(routine_name);
  }

  return create_import_module(module_name)->create_routine(routine_name);
}

} // namespace chum

