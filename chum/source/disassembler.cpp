#include "disassembler.h"
#include "util.h"

#include <queue>

#include <Windows.h>
#include <Zydis/Zydis.h>

namespace chum {

// Get the symbol that an RVA points to.
symbol* disassembled_binary::rva_to_symbol(std::uint32_t const rva) const {
  if (rva >= rva_map_.size())
    return nullptr;

  auto const& entry = rva_map_[rva];

  // This RVA points to an instruction inside of a basic block, not a symbol.
  if (entry.blink != 0)
    return nullptr;

  return get_symbol(entry.sym_id);
}

// Get the RVA of a symbol.
std::uint32_t disassembled_binary::symbol_to_rva(symbol_id const sym_id) const {
  if (sym_id.value >= sym_rva_map_.size())
    return 0;

  return sym_rva_map_[sym_id.value];
}

// Get the RVA of a symbol.
std::uint32_t disassembled_binary::symbol_to_rva(symbol const* const sym) const {
  return symbol_to_rva(sym->id);
}

// Get the data block at the specified RVA.
data_block* disassembled_binary::rva_to_db(std::uint32_t const rva) const {
  std::uint32_t offset = 0;
  auto const db = rva_to_containing_db(rva, &offset);

  if (!db || offset != 0)
    return nullptr;

  return db;
}

// Get the data block that contains the specified RVA.
data_block* disassembled_binary::rva_to_containing_db(
    std::uint32_t const rva, std::uint32_t* const offset) const {
  static auto const comp = 
    [](rva_data_block_entry const& left, rva_data_block_entry const& right) {
      return (left.rva + left.db->bytes.size()) < right.rva;
    };

  // Find the first entry that is <= the specified RVA.
  auto const it = std::lower_bound(begin(rva_data_block_map_),
    end(rva_data_block_map_), rva_data_block_entry{ rva, nullptr }, comp);

  if (it == end(rva_data_block_map_))
    return nullptr;

  if (rva < it->rva || rva >= it->rva + it->db->bytes.size())
    return nullptr;

  // Calculate the offset from the start of the data block.
  if (offset)
    *offset = rva - it->rva;

  return it->db;
}

// Get the basic block at the specified RVA.
basic_block* disassembled_binary::rva_to_bb(std::uint32_t const rva) const {
  std::uint32_t offset = 0;
  auto const bb = rva_to_containing_bb(rva, &offset);

  if (!bb || offset != 0)
    return nullptr;

  return bb;
}

// Get the basic block at the specified RVA, which includes any addresses
// that point to an instruction in the basic block.
basic_block* disassembled_binary::rva_to_containing_bb(
    std::uint32_t const rva, std::uint32_t* const offset) const {
  if (rva >= rva_map_.size())
    return nullptr;

  auto const& entry = rva_map_[rva];

  // This RVA entry points to a symbol.
  if (entry.blink == 0) {
    auto const sym = get_symbol(entry.sym_id);
    if (!sym || sym->type != symbol_type::code)
      return nullptr;

    return sym->bb;
  }

  std::uint32_t count = 0;

  // Keep walking backwards through the linked list until we reach the root
  // symbol.
  for (auto curr_rva = rva; true;) {
    auto const& node = rva_map_[curr_rva];

    // We reached the root symbol.
    if (node.blink == 0) {
      auto const sym = get_symbol(node.sym_id);
      if (sym->type != symbol_type::code)
        return nullptr;

      if (offset)
        *offset = count;

      return sym->bb;
    }

    ++count;
    curr_rva -= node.blink;
  }

  return nullptr;
}

// Insert the specified data block into the RVA to data block map.
void disassembled_binary::insert_data_block_in_rva_map(
    std::uint32_t const rva, data_block* const db) {
  // 
  // Code is mostly taken from https://stackoverflow.com/a/25524075.
  // 

  static auto const comp = 
    [](rva_data_block_entry const& left, rva_data_block_entry const& right) {
      return left.rva < right.rva;
    };

  rva_data_block_entry const entry = { rva, db };

  // We want to insert the entry while still keeping the map sorted.
  auto const it = std::upper_bound(
    begin(rva_data_block_map_), end(rva_data_block_map_), entry, comp);
  rva_data_block_map_.insert(it, entry);
}

// This is an internal structure that is used to produce a disassembled
// binary. I don't really like how this is structured, but I couldn't find
// a better solution.
class disassembler {
public:
  // This is the binary that is being produced.
  disassembled_binary bin = {};

public:
  // Initialize various structures in the disassembler. This function should
  // only be called ONCE for each instantiation.
  bool initialize(char const* const path) {
    // Initialize the Zydis decoder for x86-64.
    assert(ZYAN_SUCCESS(ZydisDecoderInit(&decoder_,
      ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)));

    file_buffer_ = read_file_to_buffer(path);
    if (file_buffer_.empty())
      return false;

    dos_header_ = reinterpret_cast<PIMAGE_DOS_HEADER>(&file_buffer_[0]);
    if (dos_header_->e_magic != IMAGE_DOS_SIGNATURE)
      return false;

    nt_header_ = reinterpret_cast<PIMAGE_NT_HEADERS>(
      &file_buffer_[dos_header_->e_lfanew]);
    if (nt_header_->Signature != IMAGE_NT_SIGNATURE)
      return false;

    // Make sure we're dealing with a 64-bit PE image.
    if (nt_header_->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
      return false;

    sections_ = reinterpret_cast<PIMAGE_SECTION_HEADER>(nt_header_ + 1);

    // Allocate the RVA to symbol table so that any RVA can be used as an index.
    bin.rva_map_ = std::vector<rva_map_entry>(
      nt_header_->OptionalHeader.SizeOfImage, rva_map_entry{});

    // Add the entrypoint to the disassembly queue.
    if (nt_header_->OptionalHeader.AddressOfEntryPoint) {
      auto const entry = enqueue_rva(
        nt_header_->OptionalHeader.AddressOfEntryPoint, "<entrypoint>");
      bin.entrypoint(bin.get_symbol(entry.sym_id)->bb);
    }

    return true;
  }

  // Create a data block for every PE data section.
  void create_section_data_blocks() {
    for (std::size_t i = 0; i < nt_header_->FileHeader.NumberOfSections; ++i) {
      auto const& section = sections_[i];

      // Ignore executable sections.
      if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
        continue;

      assert(section.Characteristics & IMAGE_SCN_MEM_READ);

      // Create the data block.
      auto const db = bin.create_data_block(section.Misc.VirtualSize,
        nt_header_->OptionalHeader.SectionAlignment);
      bin.insert_data_block_in_rva_map(section.VirtualAddress, db);

      // Zero-initialize the data block.
      std::memset(db->bytes.data(), 0, section.Misc.VirtualSize);

      // Copy the data from file.
      std::memcpy(db->bytes.data(),
        &file_buffer_[section.PointerToRawData],
        min(section.Misc.VirtualSize, section.SizeOfRawData));

      // Can we write to this section?
      db->read_only = !(section.Characteristics & IMAGE_SCN_MEM_WRITE);
    }
  }

  // Create an import routine for every PE import.
  void parse_imports() {
    auto const& idata =
      nt_header_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (!idata.VirtualAddress || idata.Size <= 0)
      return;

    // An import descriptor essentially represents a DLL that we are importing from.
    auto import_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
      &file_buffer_[rva_to_file_offset(idata.VirtualAddress)]);

    // Iterate over every import descriptor until we hit the null terminator.
    for (; import_descriptor->OriginalFirstThunk; ++import_descriptor) {
      // Import DLL name.
      auto const dll_name = reinterpret_cast<char const*>(&file_buffer_[
        rva_to_file_offset(import_descriptor->Name)]);

      // Create an import module for this DLL.
      auto const imp_mod = bin.create_import_module(dll_name);

      // The original first thunk contains the name, while the first thunk
      // contains the runtime address of the import.
      auto first_thunk_rva = import_descriptor->FirstThunk;
      auto orig_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
        &file_buffer_[rva_to_file_offset(import_descriptor->OriginalFirstThunk)]);

      for (; orig_first_thunk->u1.AddressOfData;
             first_thunk_rva += sizeof(IMAGE_THUNK_DATA), ++orig_first_thunk) {
        // This contains the null-terminated import name.
        auto const import_by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
          &file_buffer_[rva_to_file_offset(static_cast<std::uint32_t>(
          orig_first_thunk->u1.AddressOfData))]);

        // Create an import routine.
        auto const routine = imp_mod->create_routine(import_by_name->Name);

        // Point this RVA to its import symbol.
        assert(bin.rva_map_[first_thunk_rva].sym_id == null_symbol_id);
        bin.rva_map_[first_thunk_rva] = { routine->sym_id, 0 };
        bin.sym_rva_map_.push_back(first_thunk_rva);
      }
    }
  }

  // Add function exports to the disassembly queue.
  void parse_exports() {
    auto const& edata =
      nt_header_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (!edata.VirtualAddress || edata.Size <= 0)
      return;

    auto const exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
      &file_buffer_[rva_to_file_offset(edata.VirtualAddress)]);
    auto const names = reinterpret_cast<std::uint32_t*>(
      &file_buffer_[rva_to_file_offset(exports->AddressOfNames)]);
    auto const ordinals = reinterpret_cast<std::uint16_t*>(
      &file_buffer_[rva_to_file_offset(exports->AddressOfNameOrdinals)]);
    auto const functions = reinterpret_cast<std::uint32_t*>(
      &file_buffer_[rva_to_file_offset(exports->AddressOfFunctions)]);

    // Iterate over every export (including those without a name) and create
    // a symbol for them. If this is a function export, add it to the
    // disassembly queue as well.
    for (std::uint32_t ordinal = 0; ordinal < exports->NumberOfFunctions; ++ordinal) {
      auto const rva = functions[ordinal];

      // This can occur when a DLL exports the same function by multiple
      // names.
      if (bin.rva_map_[rva].sym_id != null_symbol_id)
        continue;

      // Forwarders point to a null-terminated name, rather than code/data.
      // TODO: We should make a new symbol for forwarders that are aliases
      //       of existing import symbols.
      // 
      // if (rva >= edata.VirtualAddress && rva < (edata.VirtualAddress + edata.Size))

      // Get the section that this export lies in.
      auto const section = rva_to_section(rva);
      assert(section != nullptr);

      // If the RVA lands in executable memory, assume that it is a
      // function export. Otherwise, create a data symbol.
      if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
        enqueue_rva(rva);
      else {
        assert(section->Characteristics & IMAGE_SCN_MEM_READ);

        std::uint32_t db_offset = 0;
        auto const db = bin.rva_to_containing_db(rva, &db_offset);

        assert(db != nullptr);

        // Create a new data symbol.
        auto const sym = bin.create_symbol(symbol_type::data);
        sym->db        = db;
        sym->db_offset = db_offset;
        sym->target    = null_symbol_id;

        bin.rva_map_[rva] = { sym->id, 0 };
        bin.sym_rva_map_.push_back(rva);

        fully_analyze_data_symbol(sym);
      }
    }

    // Iterate over every named export and give their symbols a name.
    for (std::uint32_t i = 0; i < exports->NumberOfNames; ++i) {
      auto const ordinal = ordinals[i];
      auto const rva = functions[ordinal];
      auto const name = reinterpret_cast<char const*>(
        &file_buffer_[rva_to_file_offset(names[i])]);

      // Get the symbol for this export.
      auto const sym = bin.get_symbol(bin.rva_map_[rva].sym_id);
      assert(sym->id != null_symbol_id);

      sym->name = name;
    }
  }

  // Parse the exceptions directory and add any exception handlers to the
  // disassembly queue.
  void parse_exceptions() {
    auto const& pdata =
      nt_header_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    if (!pdata.VirtualAddress || pdata.Size <= 0)
      return;

    auto const runtime_funcs = reinterpret_cast<PRUNTIME_FUNCTION>(
      &file_buffer_[rva_to_file_offset(pdata.VirtualAddress)]);
    auto const runtime_funcs_count = pdata.Size / sizeof(RUNTIME_FUNCTION);

    for (std::size_t i = 0; i < runtime_funcs_count; ++i) {
      auto const& func = runtime_funcs[i];

      // Ignore addresses that don't land in an executable section. An
      // example of this occurs in ntoskrnl.exe, at the start of the
      // INITDATA section.
      if (!rva_in_exec_section(func.BeginAddress))
        continue;

      // Add the start address of the RUNTIME_FUNCTION to the disassembly queue.
      if (bin.rva_map_[func.BeginAddress].sym_id == null_symbol_id)
        enqueue_rva(func.BeginAddress);
    }
  }

  // Parse the relocs directory in order to find any absolute addresses that
  // may be hard to find (such as function pointers, etc).
  void parse_relocs() {
    auto const& reloc =
      nt_header_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (!reloc.VirtualAddress || reloc.Size <= 0)
      return;

    auto const initial_block_addr =
      &file_buffer_[rva_to_file_offset(reloc.VirtualAddress)];

    // Iterate over every relocation block.
    for (auto block_addr = initial_block_addr;
         block_addr < initial_block_addr + reloc.Size;) {
      auto const block = reinterpret_cast<PIMAGE_BASE_RELOCATION>(block_addr);
      block_addr += block->SizeOfBlock;

      // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only
      struct base_reloc_entry {
        std::uint16_t offset : 12;
        std::uint16_t type   : 4;
      };

      // This is the number of relocations in this block.
      auto const entry_count = (block->SizeOfBlock - sizeof(*block)) / 2;

      // The entries are located right after the relocation block in memory.
      auto const entries = reinterpret_cast<base_reloc_entry*>(block + 1);

      for (std::size_t i = 0; i < entry_count; ++i) {
        auto const& entry = entries[i];

        // This is the RVA where the relocation is going to occur.
        // TODO: Sanity check the reloc RVA.
        auto const reloc_rva = block->VirtualAddress + entry.offset;

        // This is used as padding and can be safely ignored.
        if (entry.type == IMAGE_REL_BASED_ABSOLUTE)
          continue;

        assert(entry.type == IMAGE_REL_BASED_DIR64);

        auto& rva_entry = bin.rva_map_[reloc_rva];

        // Basic block creation should not have been executed yet...
        assert(rva_entry.blink == 0);

        // This symbol has already been discovered.
        if (rva_entry.sym_id)
          continue;

        // TODO: Handle this when it comes up...
        assert(!rva_in_exec_section(reloc_rva));

        std::uint32_t db_offset = 0;
        auto db = bin.rva_to_containing_db(reloc_rva, &db_offset);

        // This might happen if the RVA lands in the PE header... maybe.
        if (!db)
          continue;

        auto const sym        = bin.create_symbol(symbol_type::data);
        sym->db               = db;
        sym->db_offset        = db_offset;
        sym->target           = null_symbol_id;

        rva_entry = { sym->id, 0 };
        bin.sym_rva_map_.push_back(reloc_rva);

        fully_analyze_data_symbol(sym);
      }
    }
  }

  // The main engine of the recursive disassembler. This tries to distinguish
  // code from data and form the basic blocks that compose this binary.
  bool disassemble() {
    while (!disassembly_queue_.empty()) {
      // Pop an RVA from the front of the queue.
      auto const rva_start = disassembly_queue_.front();
      disassembly_queue_.pop();

      auto const file_start = rva_to_file_offset(rva_start);

      // TODO: Properly handle these cases.
      assert(file_start != 0);

      auto const section = rva_to_section(rva_start);
      auto const file_end = file_start + section->SizeOfRawData;

      // This is the basic block that we're constructing.
      assert(bin.get_symbol(bin.rva_map_[rva_start].sym_id)->type == symbol_type::code);
      auto curr_bb = bin.get_symbol(bin.rva_map_[rva_start].sym_id)->bb;

      // Keep decoding until we hit a terminating instruction.
      for (std::uint32_t instr_offset = 0;
           file_start + instr_offset < file_end;) {
        // A pointer to the current instruction in the raw binary.
        auto const curr_instr_buffer = &file_buffer_[file_start + instr_offset];

        // The amount of bytes until the file end.
        // TODO: We should be using the section end instead.
        auto const remaining_buffer_length =
          file_buffer_.size() - (file_start + instr_offset);

        // Decode the current instruction.
        ZydisDecoderContext decoded_ctx;
        ZydisDecodedInstruction decoded_instr;
        if (ZYAN_FAILED(ZydisDecoderDecodeInstruction(&decoder_, &decoded_ctx,
            curr_instr_buffer, remaining_buffer_length, &decoded_instr))) {
          std::printf("[!] Failed to decode instruction.\n");
          std::printf("[!]   RVA: 0x%X.\n", rva_start + instr_offset);
          break;
        }

        // This is the instruction that we'll be adding to the basic block. It
        // it usually the same as the original instruction, unless it has any
        // relative operands.
        instruction instr;

        // Copy the original instruction.
        instr.length = decoded_instr.length;
        std::memcpy(instr.bytes, curr_instr_buffer, instr.length);

        // Rewrite relative instructions to use symbols, as well as adding any
        // discovered code to be further disassembled.
        if (decoded_instr.attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
          // A small optimization, since most instructions can be
          // handled without needing to decode operands.
          if (decoded_instr.raw.imm[0].is_relative) {
            assert(decoded_instr.raw.imm[0].is_signed);

            auto const target_rva = static_cast<std::uint32_t>(rva_start +
              instr_offset + decoded_instr.length + decoded_instr.raw.imm[0].value.s);

            // Get the RVA entry for the branch destination.
            auto target_rva_entry = bin.rva_map_[target_rva];

            // We jumped into the middle of a basic block.
            if (target_rva_entry.blink != 0) {
              target_rva_entry = split_block(target_rva);

              // This happens if we need to split the block that
              // we're currently building.
              if (target_rva >= rva_start && target_rva < rva_start + instr_offset)
                curr_bb = bin.get_symbol(target_rva_entry.sym_id)->bb;
            }
            // This is undiscovered code, add it to the disassembly queue.
            else if (target_rva_entry.sym_id == null_symbol_id) {
              if (rva_in_exec_section(target_rva))
                target_rva_entry = enqueue_rva(target_rva);
            }

            assert(target_rva_entry.blink == 0);

            // If we can fit the symbol ID in the original instruction, do that
            // instead of re-encoding.
            if (target_rva_entry.sym_id.value < (1ull << decoded_instr.raw.imm[0].size)) {
              // Modify the displacement bytes to point to a symbol ID instead.
              assert(decoded_instr.raw.imm[0].size <= 32);
              std::memcpy(instr.bytes + decoded_instr.raw.imm[0].offset,
                &target_rva_entry.sym_id, decoded_instr.raw.imm[0].size / 8);
            }
            // Re-encode the new instruction.
            else {
              if (rva_start + instr_offset == 0x10CA)
                std::printf("REAL SYMID: %X.\n", target_rva_entry.sym_id.value);

              ZydisDecodedOperand decoded_ops[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
              ZYAN_ASSERT(ZYAN_SUCCESS(ZydisDecoderDecodeOperands(&decoder_, &decoded_ctx,
                &decoded_instr, decoded_ops, decoded_instr.operand_count_visible)));

              ZydisEncoderRequest enc_req;
              ZYAN_ASSERT(ZYAN_SUCCESS(ZydisEncoderDecodedInstructionToEncoderRequest(
                &decoded_instr, decoded_ops, decoded_instr.operand_count_visible, &enc_req)));

              // We want the encoder to choose the best branch size for us.
              enc_req.branch_type  = ZYDIS_BRANCH_TYPE_NONE;
              enc_req.branch_width = ZYDIS_BRANCH_WIDTH_NONE;

              // This might have sign issues? Not sure yet, don't care.
              enc_req.operands[0].imm.u = target_rva_entry.sym_id.value;

              std::size_t length = sizeof(instr.bytes);
              ZYAN_ASSERT(ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(
                &enc_req, instr.bytes, &length)));
              instr.length = length;
            }
          }
          // RIP relative memory references.
          else if (decoded_instr.raw.disp.offset != 0 &&
                   decoded_instr.raw.modrm.mod   == 0 &&
                   decoded_instr.raw.modrm.rm    == 5) {
            // x86-64 memory references *should* always be 4 bytes, unless im stupid.
            assert(decoded_instr.raw.disp.size == 32);

            auto const target_rva = static_cast<std::uint32_t>(rva_start +
              instr_offset + decoded_instr.length + decoded_instr.raw.disp.value);

            // Get the RVA entry for this memory reference.
            auto target_rva_entry = bin.rva_map_[target_rva];

            // We're accessing an instruction in the middle of a basic block.
            if (target_rva_entry.blink != 0) {
              target_rva_entry = split_block(target_rva);

              // This happens if we need to split the block that
              // we're currently building.
              if (target_rva >= rva_start && target_rva < rva_start + instr_offset)
                curr_bb = bin.get_symbol(target_rva_entry.sym_id)->bb;
            }

            // LEA instructions are often used for accessing code, not just data.
            if (decoded_instr.mnemonic == ZYDIS_MNEMONIC_LEA &&
                target_rva_entry.sym_id == null_symbol_id &&
                rva_in_exec_section(target_rva))
              target_rva_entry = enqueue_rva(target_rva);

            // This is the first reference to this address. Assume that it
            // is a data access, and create a new symbol for it.
            if (target_rva_entry.sym_id == null_symbol_id) {
              std::uint32_t offset = 0;
              auto const db = bin.rva_to_containing_db(target_rva, &offset);

              // If we cant find the containing data block, just use the null
              // symbol. This can occur if the binary is referencing memory
              // in the PE header, which we don't map.
              auto sym = bin.get_symbol(null_symbol_id);

              if (db) {
                // Create the new symbol.
                sym = bin.create_symbol(symbol_type::data);
                sym->db        = db;
                sym->db_offset = offset;
                sym->target    = null_symbol_id;

                // TODO: Should we analyze this data symbol?

                bin.sym_rva_map_.push_back(target_rva);
              }

              // Add the symbol to the RVA map.
              target_rva_entry = bin.rva_map_[target_rva] = { sym->id, 0 };
            }

            // Modify the displacement bytes to point to a symbol ID instead.
            static_assert(sizeof(target_rva_entry.sym_id) == 4);
            std::memcpy(instr.bytes +
              decoded_instr.raw.disp.offset, &target_rva_entry.sym_id, 4);
          }
          else {
            std::printf("[!] Unhandled relative instruction.\n");
            return false;
          }
        }

        // Add the instruction to the basic block.
        curr_bb->instructions.push_back(instr);

        // If this is a terminating instruction, end the block.
        if (decoded_instr.meta.category == ZYDIS_CATEGORY_RET       ||
            decoded_instr.meta.category == ZYDIS_CATEGORY_COND_BR   ||
            decoded_instr.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
           (decoded_instr.meta.category == ZYDIS_CATEGORY_INTERRUPT &&
            decoded_instr.raw.imm[0].value.s == 0x29)) {
          // Conditional branches require a fallthrough target.
          if (decoded_instr.meta.category == ZYDIS_CATEGORY_COND_BR) {
            auto const fallthrough_rva = static_cast<std::uint32_t>(rva_start +
              instr_offset + decoded_instr.length);

            if (auto rva_entry = bin.rva_map_[fallthrough_rva];
                rva_entry.sym_id != null_symbol_id) {
              // It *might* be possible to fallthrough into the middle of
              // an already existing basic block if the binary jumps into
              // the middle of instructions.
              if (rva_entry.blink != 0)
                rva_entry = split_block(fallthrough_rva);

              // Point the fallthrough target to the next basic block.
              curr_bb->fallthrough_target = rva_entry.sym_id;
            }
            // If the fallthrough target doesn't have a RVA entry yet, add it to
            // the disassembly queue.
            else {
              curr_bb->fallthrough_target = 
                enqueue_rva(fallthrough_rva).sym_id;
            }
          }

          break;
        }

        instr_offset += instr.length;

        // If we've entered into another basic block, end the current block.
        if (auto rva_entry = bin.rva_map_[rva_start + instr_offset];
            rva_entry.sym_id != null_symbol_id) {
          auto const sym = bin.get_symbol(rva_entry.sym_id);

          // We incorrectly identified this symbol as data instead of code.
          if (sym->type == symbol_type::data) {
            sym->type = symbol_type::code;
            sym->name = "data_to_code";
            rva_entry = enqueue_rva(rva_start + instr_offset, sym->id);
          }

          // TODO: It *might* be possible to accidently fall into a jump table
          //       (which would be marked as data, not code).
          assert(sym->type == symbol_type::code);
          curr_bb->fallthrough_target = rva_entry.sym_id;

          break;
        }

        // Create an RVA entry for the next instruction.
        bin.rva_map_[rva_start + instr_offset] = {
          0, decoded_instr.length };
      }
    }

    return true;
  }

  // Sort the basic blocks by RVA, the same way that they're laid out in the
  // original binary.
  void sort_basic_blocks() {
    auto& blocks = bin.basic_blocks();

    std::sort(begin(blocks), end(blocks),
      [&](auto const& left, auto const& right) {
        return bin.symbol_to_rva(left->sym_id) < bin.symbol_to_rva(right->sym_id);
      });
  }

  // This function is just used to double check that nothing weird is going
  // on.
  bool verify() {
    if (bin.sym_rva_map_.size() != bin.symbols().size())
      return false;

    for (auto const& bb : bin.basic_blocks()) {
      // We are not allowed to have empty basic blocks.
      if (bb->instructions.empty())
        return false;
    }

    // This is the number of symbols/bbs that are in the RVA map.
    std::size_t bb_count = 0;
    std::size_t sym_count = 0;

    for (std::uint32_t rva = 0; rva < bin.rva_map_.size(); ++rva) {
      auto const& entry = bin.rva_map_[rva];

      // There is nothing at this RVA.
      if (entry.blink == 0 && entry.sym_id == null_symbol_id)
        continue;

      // This is an instruction entry.
      if (entry.blink != 0) {
        if (entry.sym_id != null_symbol_id) {
          __debugbreak();
          return false;
        }

        std::size_t instr_count = 0;

        // Count the number of instructions from the current RVA to the root
        // node.
        for (auto curr_rva = rva; true;) {
          ++instr_count;

          // We reached the root basic block.
          if (bin.rva_map_[curr_rva].blink == 0) {
            if (bin.rva_map_[curr_rva].sym_id == null_symbol_id)
              return false;

            auto const root = bin.get_symbol(bin.rva_map_[curr_rva].sym_id);
            if (!root)
              return false;

            if (root->type != symbol_type::code)
              return false;

            if (instr_count > root->bb->instructions.size())
              return false;

            break;
          }

          curr_rva -= bin.rva_map_[curr_rva].blink;
        }

        continue;
      }

      auto const sym = bin.get_symbol(entry.sym_id);
      if (!sym)
        return false;

      if (bin.symbol_to_rva(sym) != rva)
        return false;

      ++sym_count;

      if (sym->type == symbol_type::code)
        ++bb_count;
    }

    // Make sure the RVA map and the binary report the same number of
    // basic blocks.
    if (bb_count != bin.basic_blocks().size())
      return false;

    // Make sure the RVA map and the binary report the same number of
    // symbols (the +1 is for the null symbol).
    if (sym_count + 1 != bin.symbols().size())
      return false;

    return true;
  }

private:
  // Convert an RVA to its corresponding file offset by iterating over every
  // PE section and translating accordingly.
  std::uint32_t rva_to_file_offset(std::uint32_t const rva) const {
    auto const sec = rva_to_section(rva);
    if (!sec)
      return 0;

    return sec->PointerToRawData + (rva - sec->VirtualAddress);
  }

  // Get the section that an RVA is located inside of.
  PIMAGE_SECTION_HEADER rva_to_section(std::uint32_t const rva) const {
    for (std::size_t i = 0; i < nt_header_->FileHeader.NumberOfSections; ++i) {
      auto& sec = sections_[i];
      if (rva >= sec.VirtualAddress && rva < (sec.VirtualAddress + sec.Misc.VirtualSize))
        return &sec;
    }

    return nullptr;
  }

  // Return true if the provided RVA is in an executable section.
  bool rva_in_exec_section(std::uint32_t const rva) const {
    auto const sec = rva_to_section(rva);
    if (!sec)
      return false;

    return sec->Characteristics & IMAGE_SCN_MEM_EXECUTE;
  }

  // Add an RVA to the disassembly queue. This function will create a basic
  // block and code symbol for the specified RVA.
  rva_map_entry& enqueue_rva(
      std::uint32_t const rva, char const* const name = nullptr) {
    bin.sym_rva_map_.push_back(rva);
    return enqueue_rva(rva, bin.create_symbol(symbol_type::code, name)->id);
  }

  // Add an RVA to the disassembly queue. This function will create a basic
  // block for the specified RVA. The provided code symbol will point to the
  // new basic block. This should be used when a symbol has already been
  // created, but it was never disassembled.
  rva_map_entry& enqueue_rva(std::uint32_t const rva, symbol_id const sym_id) {
    // This RVA better point to executable code...
    assert(rva_in_exec_section(rva));

    disassembly_queue_.push(rva);

    // Make sure this is a code symbol.
    assert(bin.get_symbol(sym_id)->type == symbol_type::code);

    // Create a new basic block.
    bin.create_basic_block(sym_id);

    return bin.rva_map_[rva] = { sym_id, 0 };
  }

  // Split the basic block at the specified RVA into two, and return the
  // new RVA entry.
  rva_map_entry& split_block(
      std::uint32_t const rva, char const* const name = nullptr) {
    std::size_t count        = 0;
    basic_block* original_bb = nullptr;

    // Calculate the number of instructions that should remain in
    // the original basic block by following the linked list backwards.
    for (auto curr_rva = rva; true; ++count) {
      auto const& entry = bin.rva_map_[curr_rva];

      // Keep walking until we reach the root.
      if (entry.blink != 0) {
        curr_rva -= entry.blink;
        continue;
      }

      original_bb = bin.get_symbol(bin.rva_map_[curr_rva].sym_id)->bb;
      break;
    }

    auto const new_bb = bin.create_basic_block(name);
    bin.sym_rva_map_.push_back(rva);

    // Steal the original block's fallthrough target.
    new_bb->fallthrough_target = original_bb->fallthrough_target;
    original_bb->fallthrough_target = new_bb->sym_id;

    // Steal the tail end instructions from the original block.
    new_bb->instructions.insert(begin(new_bb->instructions),
      begin(original_bb->instructions) + count,
      end(original_bb->instructions));
    original_bb->instructions.erase(
      begin(original_bb->instructions) + count,
      end(original_bb->instructions));

    return bin.rva_map_[rva] = { new_bb->sym_id, 0 };
  };

  // Probe the provided data symbol to see whether it contains a
  // pointer or not. Return an RVA to the memory, if found.
  std::uint32_t calc_potential_ptr(symbol const* const sym) const {
    assert(sym->type == symbol_type::data);
    assert(sym->db != nullptr);

    // Make sure we dont read past the end of the data block.
    if (sym->db_offset + 8 >= sym->db->bytes.size())
      return 0;

    // Read the data that the symbol points to.
    std::uint64_t value = 0;
    std::memcpy(&value, &sym->db->bytes[sym->db_offset], 8);

    auto const image_base = nt_header_->OptionalHeader.ImageBase;
    auto const image_size = nt_header_->OptionalHeader.SizeOfImage;

    // Make sure we're dealing with a valid RVA.
    if (value < image_base || value >= image_base + image_size)
      return 0;

    return static_cast<std::uint32_t>(value - image_base);
  }

  // Analyze the data symbol to see if it contains any further memory
  // references. The RVA to the new memory reference is returned, if found.
  // 0 is returned if an already-existing memory reference was found.
  std::uint32_t analyze_data_symbol(symbol* const sym) {
    assert(sym->type == symbol_type::data);
    assert(sym->db != nullptr);

    auto const ptr_rva = calc_potential_ptr(sym);

    // This data symbol does not contain a pointer.
    if (!ptr_rva)
      return 0;

    auto& rva_entry = bin.rva_map_[ptr_rva];

    // This memory reference already has a symbol for it.
    if (rva_entry.sym_id) {
      sym->target = rva_entry.sym_id;
      return 0;
    }

    // The pointer points into the middle of a basic block.
    if (rva_entry.blink != 0) {
      sym->target = split_block(ptr_rva).sym_id;
      return ptr_rva;
    }

    // We're dealing with a data pointer.
    if (!rva_in_exec_section(ptr_rva)) {
      std::uint32_t db_offset = 0;
      auto const db = bin.rva_to_containing_db(ptr_rva, &db_offset);

      if (!db)
        return 0;

      auto const new_sym = bin.create_symbol(symbol_type::data);
      new_sym->db        = db;
      new_sym->db_offset = db_offset;
      new_sym->target    = null_symbol_id;

      bin.sym_rva_map_.push_back(ptr_rva);
      rva_entry = { new_sym->id, 0 };
      sym->target = new_sym->id;

      return ptr_rva;
    }

    // This is undiscovered code.
    sym->target = enqueue_rva(ptr_rva).sym_id;

    return ptr_rva;
  }

  // Analyze the data symbol, following the pointer chain all the way
  // to the end.
  void fully_analyze_data_symbol(symbol* sym) {
    while (true) {
      auto const rva = analyze_data_symbol(sym);
      if (!rva)
        break;

      sym = bin.get_symbol(bin.rva_map_[rva].sym_id);
      if (sym->type != symbol_type::data)
        break;
    }
  }

private:
  ZydisDecoder decoder_ = {};

  // The raw file contents.
  std::vector<std::uint8_t> file_buffer_ = {};

  // A queue of code RVAs to disassemble from.
  std::queue<std::uint32_t> disassembly_queue_ = {};

  // Pointers into the file buffer for commonly used PE structures.
  PIMAGE_DOS_HEADER     dos_header_ = nullptr;
  PIMAGE_NT_HEADERS     nt_header_  = nullptr;
  PIMAGE_SECTION_HEADER sections_   = nullptr;
};

// Disassemble an x86-64 PE file.
std::optional<disassembled_binary> disassemble(char const* const path) {
  disassembler dasm = {};

  // Initialize the disassembler.
  if (!dasm.initialize(path))
    return {};

  // Create a data block for every data section.
  dasm.create_section_data_blocks();

  // Extract as much metadata as possible from the PE file.
  dasm.parse_imports();
  dasm.parse_exports();
  dasm.parse_exceptions();
  dasm.parse_relocs();

  if (!dasm.disassemble())
    return {};

  dasm.sort_basic_blocks();

  assert(dasm.verify());

  return std::move(dasm.bin);
}

} // namespace chum

