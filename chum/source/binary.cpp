#include "binary.h"

#include <cassert>
#include <algorithm>
#include <fstream>
#include <unordered_map>

#include <Windows.h>
#include <zycore/Format.h>
#include <pe-builder/pe-builder.h>

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
  pb::pe_builder pe;
  pe.file_characteristics(IMAGE_FILE_DLL);

  // We don't want to resize in the middle of adding sections.
  if (pe.sections_until_resize() < 1 + data_blocks_.size())
    return false;

  // Map a data block to its virtual address.
  std::unordered_map<data_block*, std::uint64_t> db_to_va;

  for (auto const db : data_blocks_) {
    // Create a new section.
    auto& sec = pe.section()
      .name(".rdata")
      .characteristics(IMAGE_SCN_MEM_READ);

    // Add the +W characteristic if needed.
    if (!db->read_only) {
      sec.name(".data")
         .characteristics(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
    }

    // Copy the data from the data block into the section.
    sec.data() = db->bytes;

    db_to_va[db] = pe.virtual_address(sec);
  }

  // Symbol table that maps symbols to virtual addresses.
  std::vector<std::uint64_t> sym_to_va(symbols_.size(), 0);

  // Assign virtual addresses to the symbols that we already know.
  for (auto const sym : symbols_) {
    if (sym->type == symbol_type::data)
      sym_to_va[sym->id.value] = db_to_va[sym->db] + sym->db_offset;
  }

  if (!import_modules_.empty()) {
    // Create the .idata section for holding the IAT.
    auto& idata_sec = pe.section()
      .name(".idata")
      .characteristics(IMAGE_SCN_MEM_READ);

    auto& idata_data = idata_sec.data();
    auto const idata_rva = pe.rvirtual_address(idata_sec);

    // Allocate space for every descriptor (plus the null descriptor).
    idata_data.insert(end(idata_data), (import_modules_.size() + 1)
      * sizeof(IMAGE_IMPORT_DESCRIPTOR) , 0);

    for (std::size_t i = 0; i < import_modules_.size(); ++i) {
      auto const& imp_mod = import_modules_[i];

      // Set the Name RVA to the ASCII string we're about to append.
      reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        &idata_data[i * sizeof(IMAGE_IMPORT_DESCRIPTOR)])->Name =
        idata_rva + static_cast<std::uint32_t>(idata_data.size());

      // Append the name of this import module to the .idata section
      // (plus the null-terminator).
      idata_data.insert(end(idata_data), imp_mod->name(),
        imp_mod->name() + std::strlen(imp_mod->name()) + 1);

      // Set the OrigFirstThunk RVA to the name thunk table that we're about to append.
      reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        &idata_data[i * sizeof(IMAGE_IMPORT_DESCRIPTOR)])->OriginalFirstThunk =
        idata_rva + static_cast<std::uint32_t>(idata_data.size());

      auto const name_table_off = idata_data.size();

      // Allocate the thunk table (plus the null thunk).
      idata_data.insert(end(idata_data), 8 * (imp_mod->routines().size() + 1), 0);

      for (std::size_t j = 0; j < imp_mod->routines().size(); ++j) {
        auto const& routine = imp_mod->routines()[j];

        // Set the RVA to the IMAGE_IMPORT_BY_NAME that we're about to append.
        *reinterpret_cast<std::uint64_t*>(&idata_data[name_table_off + j * 8]) =
          idata_rva + idata_data.size();

        // IMAGE_IMPORT_BY_NAME::Hint.
        idata_data.insert(end(idata_data), 2, 0);

        // IMAGE_IMPORT_BY_NAME::Name.
        idata_data.insert(end(idata_data), begin(routine->name), end(routine->name));
        idata_data.insert(end(idata_data), 1, 0);
      }

      // Set the FirstThunk RVA to the thunk table that we're about to append.
      reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        &idata_data[i * sizeof(IMAGE_IMPORT_DESCRIPTOR)])->FirstThunk =
        idata_rva + static_cast<std::uint32_t>(idata_data.size());

      auto const thunk_table_off = idata_data.size();

      // Allocate the thunk table which is identical to the name thunk table.
      idata_data.insert(end(idata_data), 8 * (imp_mod->routines().size() + 1), 0);
      std::memcpy(&idata_data[thunk_table_off],
        &idata_data[name_table_off], 8 * imp_mod->routines().size());

      // Set the symbol VAs in the symbol table for each routine.
      for (std::size_t j = 0; j < imp_mod->routines().size(); ++j) {
        sym_to_va[imp_mod->routines()[j]->sym_id.value] =
          pe.virtual_address(idata_sec) + thunk_table_off + j * 8;
      }
    }

    pe.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT,
      idata_rva, static_cast<std::uint32_t>(idata_data.size()));
  }

  // Create the .text section for holding code.
  auto& text_sec = pe.section()
    .name(".text")
    .characteristics(IMAGE_SCN_MEM_EXECUTE);

  auto& text_sec_data = text_sec.data();
  auto const text_sec_va = pe.virtual_address(text_sec);

  struct delayed_reloc_entry {
    std::uint32_t offset;
    std::uint8_t  size;
    symbol_id     sym_id;
  };

  std::vector<delayed_reloc_entry> delayed_relocs = {};

  // Write every instruction to the text section (first pass).
  for (auto const bb : basic_blocks_) {
    // This block is already written (perhaps because it was a fallthrough target).
    if (sym_to_va[bb->sym_id.value] != 0)
      continue;

    // Assign this basic block an address.
    sym_to_va[bb->sym_id.value] = text_sec_va + text_sec_data.size();

    for (auto const& instr : bb->instructions) {
      auto const curr_instr_va = text_sec_va + text_sec_data.size();

      // Decode the instruction so we can re-encode it with the
      // correct operand values.
      ZydisDecodedInstruction decoded_instr;
      ZydisDecodedOperand decoded_ops[ZYDIS_MAX_OPERAND_COUNT];
      ZYAN_ASSERT(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder_, instr.bytes,
        instr.length, &decoded_instr, decoded_ops)));

      // Create an encoder request from the decoded instruction.
      ZydisEncoderRequest enc_req;
      ZYAN_ASSERT(ZYAN_SUCCESS(ZydisEncoderDecodedInstructionToEncoderRequest(
        &decoded_instr, decoded_ops, decoded_instr.operand_count_visible, &enc_req)));

      // We want the encoder to choose the best branch size for us.
      enc_req.branch_type  = ZYDIS_BRANCH_TYPE_NONE;
      enc_req.branch_width = ZYDIS_BRANCH_WIDTH_NONE;

      symbol_id delay_sym_id = null_symbol_id;

      // Convert the relative addresses into absolute addresses.
      if (decoded_instr.attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
        for (std::size_t i = 0; i < decoded_instr.operand_count_visible; ++i) {
          auto& enc_op = enc_req.operands[i];

          // Relative immediate operand.
          if (decoded_ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
              decoded_ops[i].imm.is_relative) {
            // We need to copy the symbol ID this way in order to workaround
            // annoying sign bugs.
            symbol_id sym_id = null_symbol_id;
            std::memcpy(&sym_id.value, instr.bytes +
              decoded_instr.raw.imm[0].offset, decoded_instr.raw.imm[0].size / 8);

            if (sym_to_va[sym_id.value] != 0)
              enc_op.imm.u = sym_to_va[sym_id.value];
            else {
              delay_sym_id = sym_id;

              // Force the encoder to use the largest branch size.
              enc_op.imm.u = curr_instr_va + 0x12345678;
            }
          }
          // Relative memory reference.
          else if (decoded_ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                   decoded_instr.raw.modrm.mod == 0 &&
                   decoded_instr.raw.modrm.rm == 5) {
            // We need to copy the symbol ID this way in order to workaround
            // annoying sign bugs.
            symbol_id sym_id = null_symbol_id;
            std::memcpy(&sym_id.value, instr.bytes + decoded_instr.raw.disp.offset, 4);

            if (sym_to_va[sym_id.value] != 0)
              enc_op.mem.displacement = sym_to_va[sym_id.value];
            else {
              delay_sym_id = sym_id;

              // Force the encoder to use the largest branch size.
              enc_op.mem.displacement = curr_instr_va + 0x12345678;
            }
          }
        }
      }

      // Encode the new instruction.
      std::uint8_t instr_buffer[15];
      std::size_t instr_length = 15;
      ZYAN_ASSERT(ZYAN_SUCCESS(ZydisEncoderEncodeInstructionAbsolute(&enc_req,
        &instr_buffer, &instr_length, curr_instr_va)));

      // Append the new instruction to the text section.
      text_sec_data.insert(end(text_sec_data),
        instr_buffer, instr_buffer + instr_length);

      if (delay_sym_id) {
        delayed_relocs.push_back({
          static_cast<std::uint32_t>(text_sec_data.size() - 4),
          4,
          delay_sym_id
        });
      }
    }

    if (bb->fallthrough_target) {

    }
  }

  // Patch every delayed reloc.
  for (auto const& reloc : delayed_relocs) {
    if (!sym_to_va[reloc.sym_id.value]) {
      printf("Unresolved symbol.\n");
      return false;
    }

    auto const rip = text_sec_va + reloc.offset + reloc.size;
    auto const off = static_cast<std::uint32_t>(
      sym_to_va[reloc.sym_id.value] - rip);

    assert(reloc.size == 4);
    printf("%X.\n", off);
    std::memcpy(&text_sec_data[reloc.offset], &off, reloc.size);
  }

  // Set the entrypoint to the start of the text section.
  if (entrypoint_)
    pe.entrypoint(sym_to_va[entrypoint_->sym_id.value]);

  return pe.write(path);
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

