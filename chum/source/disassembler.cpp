#include "disassembler.h"
#include "util.h"

#include <queue>
#include <Windows.h>

#include <Zydis/Zydis.h>

namespace chum {

struct rva_map_entry {
  // This is the symbol that this RVA lands in.
  symbol_id sym_id = null_symbol_id;

  // If the symbol points to code, then this is how many instructions from
  // the start of the block that this RVA is. Otherwise, this is 0.
  std::uint32_t offset = 0;
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

  // Create a symbol for every PE import.
  void create_import_symbols() {
    auto const import_data_dir = nt_header_->OptionalHeader.DataDirectory[
      IMAGE_DIRECTORY_ENTRY_IMPORT];

    // No imports. :(
    if (!import_data_dir.VirtualAddress || import_data_dir.Size <= 0)
      return;

    // An import descriptor essentially represents a DLL that we are importing from.
    auto import_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
      &file_buffer_[rva_to_file_offset(import_data_dir.VirtualAddress)]);

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

  // The main engine of the recursive disassembler. This tries to distinguish
  // code from data and form the basic blocks that compose this binary.
  bool disassemble() {
    // A queue of RVAs to disassemble from.
    std::queue<std::uint32_t> disassembly_queue = {};

    // Add the specified RVA to the disassembly queue and return the
    // code symbol ID that points to the created basic block.
    auto const enqueue_code_rva =
      [&](std::uint32_t const rva, char const* name = nullptr) {
        disassembly_queue.push(rva);

        // Make sure we're not creating a duplicate symbol.
        assert(rva_map_[rva].sym_id == null_symbol_id);

        // Auto-generate a name for this symbol if none was provided.
        char generated_sym_name[32] = { 0 };
        if (!name) {
          sprintf_s(generated_sym_name, "loc_%X", rva);
          name = generated_sym_name;
        }

        return rva_map_[rva] = { bin.create_basic_block(name)->sym_id, 0 };
      };

    // Add the entrypoint to the disassembly queue.
    if (nt_header_->OptionalHeader.AddressOfEntryPoint) {
      enqueue_code_rva(
        nt_header_->OptionalHeader.AddressOfEntryPoint, "entrypoint");
      enqueue_code_rva(0x1030);
    }

    while (!disassembly_queue.empty()) {
      // Pop an RVA from the front of the queue.
      auto const rva_start = disassembly_queue.front();
      disassembly_queue.pop();

      auto const file_start = rva_to_file_offset(rva_start);
      assert(file_start != 0);

      // This is the basic block that we're constructing.
      assert(bin.get_symbol(rva_map_[rva_start].sym_id)->type == symbol_type::code);
      auto const curr_bb = bin.get_symbol(rva_map_[rva_start].sym_id)->bb;

      std::printf("[+] Started basic block at RVA 0x%X.\n", rva_start);

      // Keep decoding until we hit a terminating instruction.
      for (std::uint32_t instr_offset = 0;
           file_start + instr_offset < file_buffer_.size();) {
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
          return false;
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

            // This is undiscovered code, add it to the disassembly queue.
            if (target_rva_entry.sym_id == null_symbol_id)
              target_rva_entry = enqueue_code_rva(target_rva);

            // We jumped into the middle of a basic block.
            if (target_rva_entry.offset != 0) {
              auto const target_sym = bin.get_symbol(target_rva_entry.sym_id);
              assert(target_sym->type == symbol_type::code);
              assert(target_sym->bb->instructions.size() > target_rva_entry.offset);

              auto const new_bb = bin.create_basic_block("middle_of_bb");

              // Steal the original basic block's fallthrough target.
              new_bb->fallthrough_target = target_sym->bb->fallthrough_target;
              target_sym->bb->fallthrough_target = new_bb->sym_id;

              // Steal the original basic block's instructions.
              new_bb->instructions.insert(begin(new_bb->instructions),
                begin(target_sym->bb->instructions) + target_rva_entry.offset,
                end(target_sym->bb->instructions));

              // Erase the instructions that we stole from the original block.
              target_sym->bb->instructions.erase(
                begin(target_sym->bb->instructions) + target_rva_entry.offset,
                end(target_sym->bb->instructions));

              target_rva_entry = rva_map_[target_rva] = { new_bb->sym_id, 0 };
            }

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
              assert(false);
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
              // Create a name for this symbol that contains the target RVA.
              char symbol_name[32] = { 0 };
              sprintf_s(symbol_name, "unk_%X", target_rva);

              // Create the new symbol and add it to the RVA map.
              target_rva_entry = rva_map_[target_rva] = {
                bin.create_symbol(symbol_type::data, symbol_name)->id, 0 };
            }

            // TODO: This isn't correct, but it's just for testing.
            assert(bin.get_symbol(target_rva_entry.sym_id)->type == symbol_type::data ||
                   bin.get_symbol(target_rva_entry.sym_id)->type == symbol_type::import);

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
            decoded_instr.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
          // Conditional branches require a fallthrough target.
          if (decoded_instr.meta.category == ZYDIS_CATEGORY_COND_BR) {
            auto const fallthrough_rva = static_cast<std::uint32_t>(rva_start +
              instr_offset + decoded_instr.length);

            if (auto const rva_entry = rva_map_[fallthrough_rva];
                rva_entry.sym_id != null_symbol_id) {
              if (rva_entry.offset != 0)
                __debugbreak();

              // Point the fallthrough target to the next basic block.
              curr_bb->fallthrough_target = rva_entry.sym_id;
            }
            // If the fallthrough target doesn't have a RVA entry yet, add it to
            // the disassembly queue.
            else {
              curr_bb->fallthrough_target = 
                enqueue_code_rva(fallthrough_rva).sym_id;
            }
          }

          break;
        }

        instr_offset += instr.length;

        // If we've entered into another basic block, end the current block.
        if (auto const rva_entry = rva_map_[rva_start + instr_offset];
            rva_entry.sym_id != null_symbol_id) {
          // TODO: It *might* be possible to accidently fall into a jump table
          //       (which would be marked as data, not code).
          assert(bin.get_symbol(rva_entry.sym_id)->type == symbol_type::code);
          curr_bb->fallthrough_target = rva_entry.sym_id;

          break;
        }

        // Create an RVA entry for the next instruction.
        rva_map_[rva_start + instr_offset] = { curr_bb->sym_id,
          static_cast<std::uint32_t>(curr_bb->instructions.size()) };

      }

      // TODO: Handle empty basic blocks.
      assert(!curr_bb->instructions.empty());
    }

    return true;
  }

private:
  // Convert an RVA to its corresponding file offset by iterating over every
  // PE section and translating accordingly.
  std::uint32_t rva_to_file_offset(std::uint32_t const rva) {
    for (std::size_t i = 0; i < nt_header_->FileHeader.NumberOfSections; ++i) {
      auto const& sec = sections_[i];
      if (rva >= sec.VirtualAddress && rva < (sec.VirtualAddress + sec.Misc.VirtualSize))
        return sec.PointerToRawData + (rva - sec.VirtualAddress);
    }

    return 0;
  }

private:
  ZydisDecoder decoder_ = {};

  // The raw file contents.
  std::vector<std::uint8_t> file_buffer_ = {};

  // Pointers into the file buffer for commonly used PE structures.
  PIMAGE_DOS_HEADER     dos_header_ = nullptr;
  PIMAGE_NT_HEADERS     nt_header_  = nullptr;
  PIMAGE_SECTION_HEADER sections_   = nullptr;

  // A map that contains RVAs and their metadata.
  std::vector<rva_map_entry> rva_map_ = {};
};

// Disassemble an x86-64 PE file.
std::optional<disassembled_binary> disassemble(char const* const path) {
  disassembler dasm = {};

  // Initialize the disassembler.
  if (!dasm.initialize(path))
    return {};

  // Create a data block for every data section.
  dasm.create_section_data_blocks();

  // Create symbols for every PE import.
  dasm.create_import_symbols();

  if (!dasm.disassemble())
    return {};

  return std::move(dasm.bin);
}

} // namespace chum

