#include "disassembler.h"
#include "util.h"

#include <queue>
#include <Windows.h>

#include <Zydis/Zydis.h>

namespace chum {

// This contains information about an RVA.
struct rva_map_entry {
  // If the blink is 0, this is the symbol that this RVA lands in.
  symbol_id sym_id = null_symbol_id;

  // If nonzero, this is the number of bytes to the previous RVA entry.
  std::uint32_t blink = 0;
};

// Get the symbol that an RVA points to.
symbol* disassembled_binary::rva_to_symbol(std::uint32_t const rva) {
  assert(false);
  return nullptr;
}

// Get the closest symbol that contains the specified RVA. For example,
// if the specified RVA lands inside of a basic block, then the basic
// block's symbol would be returned.
symbol* disassembled_binary::rva_to_containing_symbol(std::uint32_t const rva) {
  assert(false);
  return nullptr;
}

// Get the data block at the specified RVA.
data_block* disassembled_binary::rva_to_db(
    std::uint32_t const rva) const {
  static auto const comp = 
    [](rva_data_block_entry const& left, rva_data_block_entry const& right) {
      return left.rva < right.rva;
    };

  // Find the first entry that is <= the specified RVA.
  auto const it = std::lower_bound(begin(rva_data_block_map_),
    end(rva_data_block_map_), rva_data_block_entry{ rva, nullptr }, comp);

  if (it == end(rva_data_block_map_))
    return nullptr;

  if (rva != it->rva)
    return nullptr;

  return it->db;
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
    rva_map_ = std::vector<rva_map_entry>(
      nt_header_->OptionalHeader.SizeOfImage, rva_map_entry{});

    // Add the entrypoint to the disassembly queue.
    if (nt_header_->OptionalHeader.AddressOfEntryPoint)
      enqueue_rva(nt_header_->OptionalHeader.AddressOfEntryPoint, "<entrypoint>");

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
        assert(rva_map_[first_thunk_rva].sym_id == null_symbol_id);
        rva_map_[first_thunk_rva] = { routine->sym_id, 0 };
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
      if (rva_map_[rva].sym_id != null_symbol_id)
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

        // Create a new data symbol.
        auto const sym = bin.create_symbol(symbol_type::data);
        rva_map_[rva] = { sym->id, 0 };
      }
    }

    // Iterate over every named export and give their symbols a name.
    for (std::uint32_t i = 0; i < exports->NumberOfNames; ++i) {
      auto const ordinal = ordinals[i];
      auto const rva = functions[ordinal];
      auto const name = reinterpret_cast<char const*>(
        &file_buffer_[rva_to_file_offset(names[i])]);

      // Get the symbol for this export.
      auto const sym = bin.get_symbol(rva_map_[rva].sym_id);
      assert(sym->id != null_symbol_id);

      sym->name = name;
    }

    // First pass: create symbols.
    // Second pass: add names.
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
      if (rva_map_[func.BeginAddress].sym_id == null_symbol_id)
        enqueue_rva(func.BeginAddress);
    }
  }

  // The main engine of the recursive disassembler. This tries to distinguish
  // code from data and form the basic blocks that compose this binary.
  bool disassemble() {
    // Split the basic block at the specified RVA into two, and return the
    // new RVA entry.
    auto const split_block = [&](std::uint32_t const rva) {
      std::size_t count        = 0;
      basic_block* original_bb = nullptr;

      // Calculate the number of instructions that should remain in
      // the original basic block by following the linked list backwards.
      for (auto curr_rva = rva; true; ++count) {
        auto const& entry = rva_map_[curr_rva];

        // Keep walking until we reach the root.
        if (entry.blink != 0) {
          curr_rva -= entry.blink;
          continue;
        }

        original_bb = bin.get_symbol(rva_map_[curr_rva].sym_id)->bb;
        break;
      }

      // Auto-generate a name for this symbol.
      //char generated_sym_name[32] = { 0 };
      //sprintf_s(generated_sym_name, "loc_%X", rva);

      //auto const new_bb = bin.create_basic_block(generated_sym_name);
      auto const new_bb = bin.create_basic_block();

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

      return rva_map_[rva] = { new_bb->sym_id, 0 };
    };

    while (!disassembly_queue_.empty()) {
      // Pop an RVA from the front of the queue.
      auto const rva_start = disassembly_queue_.front();
      disassembly_queue_.pop();

      auto const file_start = rva_to_file_offset(rva_start);

      // TODO: Properly handle these cases.
      if (file_start == 0)
        continue;

      auto const section = rva_to_section(rva_start);
      auto const file_end = file_start + section->SizeOfRawData;

      // This is the basic block that we're constructing.
      assert(bin.get_symbol(rva_map_[rva_start].sym_id)->type == symbol_type::code);
      auto curr_bb = bin.get_symbol(rva_map_[rva_start].sym_id)->bb;

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
        ZydisDecodedInstruction decoded_instr;
        if (ZYAN_FAILED(ZydisDecoderDecodeInstruction(&decoder_, nullptr,
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
            auto target_rva_entry = rva_map_[target_rva];

            // We jumped into the middle of a basic block.
            if (target_rva_entry.blink != 0) {
              target_rva_entry = split_block(target_rva);

              // TODO: Should this be <= ?
              // This happens if we need to split the current block that
              // we're building.
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
            if (target_rva_entry.sym_id < (1ull << decoded_instr.raw.imm[0].size)) {
              // Modify the displacement bytes to point to a symbol ID instead.
              assert(decoded_instr.raw.imm[0].size <= 32);
              std::memcpy(instr.bytes + decoded_instr.raw.imm[0].offset,
                &target_rva_entry.sym_id, decoded_instr.raw.imm[0].size / 8);
            }
            // Re-encode the new instruction.
            else {
              std::uint32_t zero = 0;
              std::memcpy(instr.bytes + decoded_instr.raw.imm[0].offset,
                &zero, decoded_instr.raw.imm[0].size / 8);
              //assert(false);
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
            auto target_rva_entry = rva_map_[target_rva];

            // This is the first reference to this address. Create a new symbol
            // for it.
            if (target_rva_entry.sym_id == null_symbol_id) {
              assert(target_rva_entry.blink == 0);

              std::uint32_t offset = 0;
              auto const db = bin.rva_to_containing_db(target_rva, &offset);

              // If we cant find the containing data block, just use the null
              // symbol. This can occur if the binary is referencing memory
              // in the PE header, which we don't map.
              auto sym = bin.get_symbol(null_symbol_id);

              if (db) {
                // Create the new symbol.
                sym = bin.create_symbol(symbol_type::data);
                sym->db = db;
                sym->db_offset = offset;
              }

              // Add the symbol to the RVA map.
              target_rva_entry = rva_map_[target_rva] = { sym->id, 0 };
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
        if (decoded_instr.meta.category == ZYDIS_CATEGORY_RET ||
            decoded_instr.meta.category == ZYDIS_CATEGORY_COND_BR ||
            decoded_instr.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
            (decoded_instr.meta.category == ZYDIS_CATEGORY_INTERRUPT &&
             decoded_instr.raw.imm[0].value.s == 0x29)) {
          // Conditional branches require a fallthrough target.
          if (decoded_instr.meta.category == ZYDIS_CATEGORY_COND_BR) {
            auto const fallthrough_rva = static_cast<std::uint32_t>(rva_start +
              instr_offset + decoded_instr.length);

            if (auto rva_entry = rva_map_[fallthrough_rva];
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
        if (auto rva_entry = rva_map_[rva_start + instr_offset];
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
        rva_map_[rva_start + instr_offset] = {
          curr_bb->sym_id, decoded_instr.length };
      }
    }

    return true;
  }

  // This function is just used to double check that nothing weird is going
  // on.
  bool verify() {
    for (auto const& entry : bin.rva_data_block_map_)
      std::printf("RVA: %X.\n", entry.rva);

    for (auto const& bb : bin.basic_blocks()) {
      // We are not allowed to have empty basic blocks.
      if (bb->instructions.empty())
        return false;
    }

    // This is the number of symbols/bbs that are in the RVA map.
    std::size_t bb_count = 0;
    std::size_t sym_count = 0;

    for (std::uint32_t rva = 0; rva < rva_map_.size(); ++rva) {
      auto const& entry = rva_map_[rva];

      // There is nothing at this RVA.
      if (entry.blink == 0 && entry.sym_id == null_symbol_id)
        continue;

      // This is an instruction entry.
      if (entry.blink != 0) {
        std::size_t instr_count = 0;

        // Count the number of instructions from the current RVA to the root
        // node.
        for (auto curr_rva = rva; true;) {
          ++instr_count;

          // We reached the root basic block.
          if (rva_map_[curr_rva].blink == 0) {
            if (rva_map_[curr_rva].sym_id == null_symbol_id)
              return false;

            auto const root = bin.get_symbol(rva_map_[curr_rva].sym_id);
            if (!root)
              return false;

            if (root->type != symbol_type::code)
              return false;

            if (instr_count > root->bb->instructions.size())
              return false;

            break;
          }

          curr_rva -= rva_map_[curr_rva].blink;
        }

        continue;
      }

      auto const sym = bin.get_symbol(entry.sym_id);
      if (!sym)
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
  std::uint32_t rva_to_file_offset(std::uint32_t const rva) {
    auto const sec = rva_to_section(rva);
    if (!sec)
      return 0;

    return sec->PointerToRawData + (rva - sec->VirtualAddress);
  }

  // Get the section that an RVA is located inside of.
  PIMAGE_SECTION_HEADER rva_to_section(std::uint32_t const rva) {
    for (std::size_t i = 0; i < nt_header_->FileHeader.NumberOfSections; ++i) {
      auto& sec = sections_[i];
      if (rva >= sec.VirtualAddress && rva < (sec.VirtualAddress + sec.Misc.VirtualSize))
        return &sec;
    }

    return nullptr;
  }

  // Return true if the provided RVA is in an executable section.
  bool rva_in_exec_section(std::uint32_t const rva) {
    auto const sec = rva_to_section(rva);
    if (!sec)
      return false;

    return sec->Characteristics & IMAGE_SCN_MEM_EXECUTE;
  }

  // Add an RVA to the disassembly queue. This function will create a basic
  // block and code symbol for the specified RVA.
  rva_map_entry& enqueue_rva(
      std::uint32_t const rva, char const* const name = nullptr) {
    // This RVA better point to executable code...
    assert(rva_in_exec_section(rva));

    disassembly_queue_.push(rva);

    // Make sure we're not creating a duplicate symbol.
    assert(rva_map_[rva].sym_id == null_symbol_id);

    return rva_map_[rva] = { bin.create_basic_block(name)->sym_id, 0 };
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

    return rva_map_[rva] = { sym_id, 0 };
  }

private:
  ZydisDecoder decoder_ = {};

  // The raw file contents.
  std::vector<std::uint8_t> file_buffer_ = {};

  // A map that contains RVAs and their metadata.
  std::vector<rva_map_entry> rva_map_ = {};

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

  if (!dasm.disassemble())
    return {};

  if (!dasm.verify())
    return {};

  return std::move(dasm.bin);
}

} // namespace chum

