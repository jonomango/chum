#include <Zydis/Zydis.h>
#include <cstdio>
#include <vector>
#include <fstream>
#include <Windows.h>

// instructions that need to be "fixed"
struct relative_instruction {
  // virtual offset of this instruction
  std::size_t virtual_offset;

  // relative offset to the target
  std::int64_t target_delta;
};

// an instruction that was modified/replaced by another instruction(s) that
// have a different size (therefore size_delta will never be 0).
struct modified_instruction {
  std::size_t virtual_offset;

  // difference between the old instruction size and the new instruction size (new - old)
  std::int8_t size_delta;
};

// TODO: make the code_block structure smaller. size fields can be a single
//       byte each (they're RARELY that big, if ever) and if they happen to
//       overflow, simply split the code block. the file offset can also be
//       derived from the virtual offset (or vise-versa).
struct code_block {
  // the absolute virtual address of this code block after being written to memory
  void* final_virtual_address;

  // virtual offset of this code block in the original binary
  std::uint32_t virtual_offset;

  // file offset in the raw binary
  std::uint32_t file_offset;

  // size of the instructions on file
  std::uint32_t file_size;

  // size of the instructions after being written to memory. if not written
  // yet, this is the pessimistic expected size of the code block.
  union {
    std::uint32_t expected_size;
    std::uint32_t final_size;
  };

  // relative code blocks contain a SINGLE instruction that is RIP-relative
  bool is_relative : 1;
};

class chum_parser {
public:
  chum_parser(char const* const file_path) {
    // initialize the decoder
    if (ZYAN_FAILED(ZydisDecoderInit(&decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
      printf("[!] Failed to initialize Zydis decoder.\n");
      return;
    }

    // initialize the formatter
    if (ZYAN_FAILED(ZydisFormatterInit(&formatter_, ZYDIS_FORMATTER_STYLE_INTEL))) {
      printf("[!] Failed to initialize Zydis formatter.\n");
      return;
    }

    ZydisFormatterSetProperty(&formatter_, ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_BRANCHES, true);
    ZydisFormatterSetProperty(&formatter_, ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_RIPREL,   true);
    ZydisFormatterSetProperty(&formatter_, ZYDIS_FORMATTER_PROP_PRINT_BRANCH_SIZE,       true);

    file_buffer_ = read_file_to_buffer(file_path);
    if (file_buffer_.empty()) {
      printf("[!] Failed to read file.\n");
      return;
    }

    dos_header_ = reinterpret_cast<PIMAGE_DOS_HEADER>(&file_buffer_[0]);
    nt_header_  = reinterpret_cast<PIMAGE_NT_HEADERS>(&file_buffer_[dos_header_->e_lfanew]);
    sections_   = reinterpret_cast<PIMAGE_SECTION_HEADER>(nt_header_ + 1);

    // the exception directory (aka the .pdata section) contains an array of functions
    auto const& exception_dir = nt_header_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    runtime_funcs_ = reinterpret_cast<PRUNTIME_FUNCTION>(
      &file_buffer_[rva_to_file_offset(exception_dir.VirtualAddress)]);
    runtime_funcs_count_ = exception_dir.Size / sizeof(RUNTIME_FUNCTION);

    if (!parse())
      printf("[!] Failed to parse binary.\n");
  }

  bool write_2() {
    // index of the code region that we are currently writing to
    std::size_t curr_region_idx = 0;

    // current write offset into the current region
    std::uint32_t curr_region_offset = 0;

    if (code_regions_.empty()) {
      printf("[!] No code regions provided.\n");
      return false;
    }

    for (auto& cb : code_blocks_) {
      print_code_block(cb);

      // the current region we're writing to
      auto const& curr_region = code_regions_[curr_region_idx];

      // amount of space left in the current region
      auto const remaining_region_size = (curr_region.size - curr_region_offset);

      // non-relative instructions can be directly memcpy'd
      if (!cb.is_relative) {
        // TODO: account for the jmp stub size
        if (cb.file_size > remaining_region_size) {
          // TODO: write a jmp to the next region
          printf("[!] Ran out of space in the current code region.\n");
          return false;
        }

        cb.final_virtual_address = curr_region.virtual_address + curr_region_offset;
        cb.final_size            = cb.file_size;

        memcpy(curr_region.virtual_address + curr_region_offset,
          &file_buffer_[cb.file_offset], cb.file_size);
        
        printf("[+] Copied 0x%X bytes from +0x%X to 0x%zX.\n",
          cb.file_size, cb.virtual_offset, cb.final_virtual_address);

        curr_region_offset += cb.file_size;
        continue;
      }

      ZydisDecodedInstruction decoded_instruction;
      ZydisDecodedOperand decoded_operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

      // decode the current instruction
      auto const status = ZydisDecoderDecodeFull(&decoder_,
        &file_buffer_[cb.file_offset], cb.file_size, &decoded_instruction,
        decoded_operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE,
        ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY);

      if (ZYAN_FAILED(status)) {
        printf("[!] Failed to decode instruction. Status = 0x%X.\n", status);
        return false;
      }

      // find the relative operand.
      // determine if its forwards or backwards.
    }


    printf("[+] # of code blocks: %zu (0x%zX bytes).\n",
      code_blocks_.size(), code_blocks_.size() * sizeof(code_block));

    return true;
  }

  // write the new binary to memory
  bool write() {
    // total number of bytes that have been written so far
    std::size_t curr_flat_offset = 0;
    
    // number of bytes that have been written to the current code region
    std::size_t curr_region_offset = 0;

    // index of the region that is currently being written to
    std::size_t curr_region_idx = 0;

    // index of the next reloc instruction
    std::size_t next_reloc_idx = 0;

    // we need to keep track of each modified instruction so that we can
    // accurately calculate the new relative distances.
    std::vector<modified_instruction> modified_instructions = {};

    // copy every instruction to the new binary
    for (std::size_t i = 0; i < runtime_funcs_count_; ++i) {
      auto const& runtime_func = runtime_funcs_[i];

      // virtual offset, file offset, and size of the current code block
      auto const block_virt_offset = runtime_func.BeginAddress;
      auto const block_file_offset = rva_to_file_offset(runtime_func.BeginAddress);
      auto const block_size        = (runtime_func.EndAddress - runtime_func.BeginAddress);

      // disassemble every instruction in this block
      for (std::size_t instruction_offset = 0; instruction_offset < block_size;) {
        ZydisDecodedInstruction decoded_instruction;
        ZydisDecodedOperand decoded_operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

        // pointer to the current instruction in the binary blob
        auto const buffer_curr_instruction = &file_buffer_[block_file_offset + instruction_offset];
        auto const remaining_size = (block_size - instruction_offset);

        // decode the current instruction
        auto status = ZydisDecoderDecodeFull(&decoder_, buffer_curr_instruction,
          remaining_size, &decoded_instruction, decoded_operands,
          ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY);
        
        // this *really* shouldn't happen but it isn't a fatal error... just
        // ignore any possible remaining instructions in the block.
        if (ZYAN_FAILED(status)) {
          printf("[!] Failed to decode instruction! VA=0x%zX. Status=0x%X.\n",
            block_virt_offset + instruction_offset, status);
          break;
        }

        ZydisEncoderRequest enc_request;

        // create a request that will encode the exact same instruction that was decoded
        status = ZydisEncoderDecodedInstructionToEncoderRequest(&decoded_instruction,
          decoded_operands, decoded_instruction.operand_count_visible, &enc_request);

        if (ZYAN_FAILED(status)) {
          printf("[!] Failed to create encoder request: status=0x%X.\n", status);
          return false;
        }

        // we want the encoder to automatically use the smallest instruction available
        enc_request.branch_type  = ZYDIS_BRANCH_TYPE_NONE;
        enc_request.branch_width = ZYDIS_BRANCH_WIDTH_NONE;

        // relative instructions can't be written as-is
        if (next_reloc_idx < relative_instructions.size() &&
            relative_instructions[next_reloc_idx].virtual_offset ==
            (block_virt_offset + instruction_offset)) {
          auto const& relinstr = relative_instructions[next_reloc_idx++];

          // absolute virtual offset of the target
          auto const target = relinstr.virtual_offset + decoded_instruction.length + relinstr.target_delta;

          printf("[+] Relative instruction:\n");
          printf("[+]   Target delta: %+zd.\n", relinstr.target_delta);
          printf("[+]   Target virtual offset: %zX.\n", target);

          // backwards targets can be fixed immediately
          if (relinstr.target_delta < 0) {
            printf("[+]   Backwards target.\n");

            bool found_new_target = false;

            // this is the new target delta (starting from the
            // address of the CURRENT instruction, not the NEXT)
            std::int64_t adjusted_delta = 0;

            // the first code block is a special case
            adjusted_delta -= instruction_offset;

            // if the target is in the same block as this instruction
            if (target >= block_virt_offset) {
              adjusted_delta += (target - block_virt_offset);
              found_new_target = true;

              printf("[+]   Found code block: %zu.\n", i);
            }
            // target destination is in another block
            else {
              // find the code block that the target resides in
              for (std::size_t j = i; j > 0; --j) {
                auto const& b = runtime_funcs_[j - 1];

                if (target >= b.BeginAddress && target < b.EndAddress) {
                  // add all of the region up until we reach the target
                  adjusted_delta -= (b.EndAddress - target);
                  found_new_target = true;

                  printf("[+]   Found code block: %zu.\n", j);
                  break;
                }

                // add the entire region
                adjusted_delta -= (b.EndAddress - b.BeginAddress);
              }
            }

            if (found_new_target) {
              printf("[+]   Adjusted delta (pre-reloc): %+zd.\n", adjusted_delta);

              for (auto j = modified_instructions.size(); j > 0; --j) {
                auto const& m = modified_instructions[j - 1];
                if (m.virtual_offset < target)
                  break;
                
                adjusted_delta -= m.size_delta;
              }

              printf("[+]   Adjusted delta (post-reloc): %+zd.\n", adjusted_delta);
              printf("[+]   Adjusted target virtual offset: %zX.\n", curr_flat_offset + adjusted_delta);

              char orig_target_instruction[256];
              char adju_target_instruction[256];
              disassemble_and_format(&file_buffer_[rva_to_file_offset(target)], 15, orig_target_instruction, 256);
              disassemble_and_format(&code_regions_[0].virtual_address[curr_flat_offset + adjusted_delta], 15, adju_target_instruction, 256);

              printf("[+]   Target instruction (original): %s.\n", orig_target_instruction);
              printf("[+]   Target instruction (adjusted): %s.\n", adju_target_instruction);
            }
            else {
              printf("[!]   Failed to calculate new target.\n");
            }
          }
          // forwards targets need to be fixed later
          else {
            printf("[+]   Forwards target.\n");
          }
        }

        std::uint8_t encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
        std::size_t instruction_length = ZYDIS_MAX_INSTRUCTION_LENGTH;

        // encode the new instruction
        status = ZydisEncoderEncodeInstruction(&enc_request, encoded_instruction, &instruction_length);

        if (ZYAN_FAILED(status)) {
          printf("[!] Failed to encode instruction: status=0x%X.\n", status);
          return false;
        }

        // add to the list of modified instructions if the new instruction
        // length doesn't equal the original instruction length.
        if (instruction_length != decoded_instruction.length) {
          modified_instructions.push_back({ block_virt_offset + instruction_offset,
            static_cast<std::int8_t>(instruction_length) - static_cast<std::int8_t>(decoded_instruction.length) });
        }

        auto const& curr_region = code_regions_[curr_region_idx];

        // check if we still have space in the current region to write this instruction
        if (curr_region_offset + instruction_length > curr_region.size) {
          // TODO: encode a jmp to the next region
          curr_region_offset = 0;

          printf("[!] Ran out of space in the current code region.\n");
          return false;
        }

        // copy the encoded instruction to memory
        memcpy(curr_region.virtual_address + curr_region_offset,
          encoded_instruction, instruction_length);

        printf("[+] Wrote instruction to code region %zX:%p:%zX. Virtual offset: %zX. Raw bytes:",
          curr_region_idx, curr_region.virtual_address, curr_region_offset, block_virt_offset + instruction_offset);

        for (std::size_t j = 0; j < instruction_length; ++j)
          printf(" %.2X", encoded_instruction[j]);

        printf("\n");

        instruction_offset += decoded_instruction.length;
        curr_region_offset += instruction_length;
        curr_flat_offset   += instruction_length;
      }
    }

    return true;
  }

  // memory where code will reside (X)
  void add_code_region(void* const virtual_address, std::size_t const size) {
    code_regions_.push_back({ static_cast<std::uint8_t*>(virtual_address), size });

    // TODO: make sure the code regions are sorted
  }

  // memory where data will reside (RW)
  void add_data_region(void* const virtual_address, std::size_t const size) {
    data_regions_.push_back({ static_cast<std::uint8_t*>(virtual_address), size });
  }

private:
  // the real "meat" of the parser
  bool parse() {
    // TODO: add external references to code blocks that are not covered by
    //       exception directory.

    // disassemble every function and create a list of instructions that
    // will need to be fixed later on.
    for (std::size_t i = 0; i < runtime_funcs_count_; ++i) {
      auto const& runtime_func = runtime_funcs_[i];

      // virtual offset, file offset, and size of the current code block
      auto const block_virt_offset = runtime_func.BeginAddress;
      auto const block_file_offset = rva_to_file_offset(runtime_func.BeginAddress);
      auto const block_size        = (runtime_func.EndAddress - runtime_func.BeginAddress);

      ZydisDecodedInstruction decoded_instruction;
      ZydisDecodedOperand decoded_operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

      // create a new code block
      auto cb = &code_blocks_.emplace_back();
      cb->is_relative = false;

      cb->final_virtual_address = 0;
      cb->final_size            = 0;

      cb->virtual_offset = block_virt_offset;
      cb->file_offset    = block_file_offset;
      cb->file_size      = 0;

      // disassemble every instruction in this block
      for (std::size_t instruction_offset = 0;
           instruction_offset < block_size;
           instruction_offset += decoded_instruction.length) {
        // pointer to the current instruction in the binary blob
        auto const buffer_curr_instruction = &file_buffer_[block_file_offset + instruction_offset];
        auto const remaining_size = (block_size - instruction_offset);

        // decode the current instruction
        auto const status = ZydisDecoderDecodeFull(&decoder_, buffer_curr_instruction,
          remaining_size, &decoded_instruction, decoded_operands,
          ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY);
        
        // this *really* shouldn't happen but it isn't a fatal error... just
        // ignore any possible remaining instructions in the block.
        if (ZYAN_FAILED(status)) {
          printf("[!] Failed to decode instruction! VA=0x%zX. Status=0x%X.\n",
            block_virt_offset + instruction_offset, status);
          break;
        }

        // if the current code block is relative, we need to create a new, empty, non-relative one
        if (cb->is_relative) {
          cb = &code_blocks_.emplace_back();
          cb->is_relative = false;

          cb->final_virtual_address = 0;
          cb->final_size            = 0;

          cb->virtual_offset = block_virt_offset + instruction_offset;
          cb->file_offset    = block_file_offset + instruction_offset;
          cb->file_size      = 0;
        }

        // non-relative instructions (these can simply be memcpy'd to memory)
        if (!(decoded_instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE)) {
          assert(!cb->is_relative);

          cb->file_size  += decoded_instruction.length;
          cb->final_size += decoded_instruction.length;
          continue;
        }

        // we need to end the current code block and create a new empty one
        if (cb->file_size > 0) {
          cb = &code_blocks_.emplace_back();
          cb->is_relative = false;

          cb->final_virtual_address = 0;
          cb->final_size            = 0;

          cb->virtual_offset = block_virt_offset + instruction_offset;
          cb->file_offset    = block_file_offset + instruction_offset;
          cb->file_size      = 0;
        }

        assert(cb->file_size <= 0);

        // change the current (empty) code block into a relative code block
        cb->is_relative    = true;
        cb->file_size     += decoded_instruction.length;
        cb->expected_size += decoded_instruction.length + 69;

        // only one of the operands can be relative (i think?)
        for (std::size_t j = 0; j < decoded_instruction.operand_count_visible; ++j) {
          auto const& op = decoded_operands[j];

          // memory references
          if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            // sanity check
            if (op.mem.base  != ZYDIS_REGISTER_RIP  ||
                op.mem.index != ZYDIS_REGISTER_NONE ||
                op.mem.scale != 0 ||
               !op.mem.disp.has_displacement) {
              printf("[!] Memory operand isn't RIP-relative!\n");
              return false;
            }

            printf("[+] Memory operand displacement: %+zd.\n", op.mem.disp.value);

            relative_instructions.push_back({ block_virt_offset + instruction_offset, op.mem.disp.value });
            break;
          }
          // relative CALLs, JMPs, etc
          else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
            printf("[+] Immediate operand value: %+zd.\n", op.imm.value.s);

            relative_instructions.push_back({ block_virt_offset + instruction_offset, op.imm.value.s });
            break;
          }
        }
      }
    }

    return true;
  }

  // read all the contents of a file and return the bytes in a vector
  static std::vector<std::uint8_t> read_file_to_buffer(char const* const path) {
    // open the file
    std::ifstream file(path, std::ios::binary);
    if (!file)
      return {};

    // get the size of the file
    file.seekg(0, file.end);
    std::vector<std::uint8_t> contents(file.tellg());
    file.seekg(0, file.beg);

    // read
    file.read((char*)contents.data(), contents.size());

    return contents;
  }

  // convert an RVA offset to a file offset
  std::uint32_t rva_to_file_offset(std::uint32_t const rva) const {
    for (std::size_t i = 0; i < nt_header_->FileHeader.NumberOfSections; ++i) {
      auto const& section = sections_[i];

      if (rva >= section.VirtualAddress && rva < (section.VirtualAddress + section.Misc.VirtualSize))
        return (rva - section.VirtualAddress) + section.PointerToRawData;
    }

    return 0;
  }

  std::uint8_t disassemble_and_format(void const* const buffer,
      std::size_t const length, char* const str, std::size_t const str_size) const {
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

    ZydisDecoderDecodeFull(&decoder_, buffer, length, &instruction, operands,
      ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY);
    
    ZydisFormatterFormatInstruction(&formatter_, &instruction, operands,
      instruction.operand_count_visible, str, str_size, ZYDIS_RUNTIME_ADDRESS_NONE);

    return instruction.length;
  }

  void print_code_block(code_block const& cb) const {
    printf("[+] Code block:\n");

    printf("[+]   is_relative    = %d.\n", cb.is_relative);
    printf("[+]   virtual_offset = 0x%X.\n", cb.virtual_offset);
    printf("[+]   file_offset    = 0x%X.\n", cb.file_offset);
    printf("[+]   file_size      = 0x%X.\n", cb.file_size);

    if (cb.is_relative)
      printf("[+]   expected_size  = 0x%X.\n", cb.final_size);

    printf("[+]   instructions:\n");

    std::size_t offset = 0;
    while (offset < cb.file_size) {
      char str[256];
      auto const length = disassemble_and_format(
        &file_buffer_[cb.file_offset + offset], cb.file_size - offset, str, 256);
      
      printf("[+]    ");
      for (std::size_t i = 0; i < length; ++i)
        printf(" %.2X", file_buffer_[cb.file_offset + offset + i]);
      for (std::size_t i = 0; i < (15 - length); ++i)
        printf("   ");
      printf(" %s.\n", str);

      offset += length;
    }
  }

private:
  struct memory_region {
    std::uint8_t* virtual_address;
    std::size_t size;
  };

private:
  // zydis
  ZydisDecoder decoder_     = {};
  ZydisFormatter formatter_ = {};

  // raw binary blob of the PE file
  std::vector<std::uint8_t> file_buffer_ = {};

  // pointers into the file buffer
  PIMAGE_DOS_HEADER dos_header_   = nullptr;
  PIMAGE_NT_HEADERS nt_header_    = nullptr;
  PIMAGE_SECTION_HEADER sections_ = nullptr;

  // exception directory
  PRUNTIME_FUNCTION runtime_funcs_ = nullptr;
  std::size_t runtime_funcs_count_ = 0;

  // this is where the binary will be written to
  std::vector<memory_region> code_regions_ = {};
  std::vector<memory_region> data_regions_ = {};

  // instructions that need to be fixed
  std::vector<relative_instruction> relative_instructions = {};

  std::vector<code_block> code_blocks_ = {};
};

int main() {
  chum_parser chum("./hello-world-x64.dll");

  // add 0x2000 bytes of executable memory and 0x2000 bytes of read-write memory
  chum.add_code_region(VirtualAlloc(nullptr, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE), 0x2000);
  chum.add_data_region(VirtualAlloc(nullptr, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE),         0x2000);

  if (!chum.write_2())
    printf("[!] Failed to write binary to memory.\n");
}
