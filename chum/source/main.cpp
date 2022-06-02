#include <Zydis/Zydis.h>
#include <cstdio>
#include <vector>
#include <fstream>
#include <queue>
#include <Windows.h>

  struct memory_region {
    std::uint8_t* virtual_address;
    std::size_t size;
  };

// TODO: make the code_block structure smaller. size fields can be a single
//       byte each (they're RARELY that big, if ever) and if they happen to
//       overflow, simply split the code block. the file offset can also be
//       derived from the virtual offset (or vise-versa).
struct code_block {
  // the absolute virtual address of this code block after being written to memory
  std::uint8_t* final_virtual_address;

  // virtual offset of this code block in the original binary
  std::uint32_t virtual_offset;

  // file offset in the raw binary
  std::uint32_t file_offset;

  // size of the code block on file
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

struct data_block {
  // the absolute virtual address of this data block after being written to memory
  std::uint8_t* final_virtual_address;

  // virtual offset of this data block in the original binary
  std::uint32_t virtual_offset;

  // file offset in the raw binary
  std::uint32_t file_offset;

  // size of the data block on file
  std::uint32_t file_size;

  // size of the data block in virtual memory
  std::uint32_t virtual_size;
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

  // write the new binary to memory
  bool write() {
    if (!write_data_blocks()) {
      printf("[!] Failed to write data blocks to memory.\n");
      return false;
    }

    if (!write_code_blocks()) {
      printf("[!] Failed to write code blocks to memory.\n");
      return false;
    }

    return true;
  }

  bool write_data_blocks() {
    if (data_blocks_.empty())
      return true;

    // index of the data region that we are currently writing to
    std::size_t curr_region_idx = 0;

    // current write offset into the current region
    // TODO: align the current region offset
    std::uint32_t curr_region_offset = 0;

    if (data_regions_.empty()) {
      printf("[!] No data regions provided.\n");
      return false;
    }

    for (auto& db : data_blocks_) {
      // the current region we're writing to
      auto const& curr_region = data_regions_[curr_region_idx];

      // amount of space left in the current region
      auto const remaining_region_size = (curr_region.size - curr_region_offset);

      if (db.virtual_size > remaining_region_size) {
        printf("[!] Ran out of space in the current data region.\n");
        return false;
      }

      db.final_virtual_address = curr_region.virtual_address + curr_region_offset;

      // fill the data block with 0s
      memset(db.final_virtual_address, 0, db.virtual_size);

      // copy the contents from file to memory
      if (db.file_size > 0) {
        auto const size = min(db.file_size, db.virtual_size);

        memcpy(db.final_virtual_address, &file_buffer_[db.file_offset], size);

        printf("[+] Copied 0x%X data bytes from +0x%X to 0x%p.\n",
          size, db.virtual_offset, db.final_virtual_address);
      }

      curr_region_offset += db.virtual_size;

      // TODO: align the current region offset
    }

    printf("[+] # of data blocks: %zu (0x%zX bytes).\n",
      data_blocks_.size(), data_blocks_.size() * sizeof(data_block));

    return true;
  }

  bool write_code_blocks() {
    if (code_blocks_.empty())
      return true;

    // index of the code region that we are currently writing to
    std::size_t curr_region_idx = 0;

    // current write offset into the current region
    std::uint32_t curr_region_offset = 0;

    if (code_regions_.empty()) {
      printf("[!] No code regions provided.\n");
      return false;
    }

    for (std::size_t curr_cb_idx = 0; curr_cb_idx < code_blocks_.size(); ++curr_cb_idx) {
      auto& cb = code_blocks_[curr_cb_idx];

      print_code_block(cb);

      // the current region we're writing to
      auto const& curr_region = code_regions_[curr_region_idx];

      // amount of space left in the current region
      auto const remaining_region_size = (curr_region.size - curr_region_offset);

      // non-relative instructions can be directly memcpy'd
      // TODO: make a function for copying instruction bytes to the current
      //       code region (and possibly proceeding to the next region if
      //       there isn't enough space).
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

        printf("[+] Copied 0x%X code bytes from +0x%X to 0x%p.\n",
          cb.file_size, cb.virtual_offset, cb.final_virtual_address);

        curr_region_offset += cb.final_size;
        continue;
      }

      ZydisDecodedInstruction decoded_instruction;
      ZydisDecodedOperand decoded_operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

      // decode the current instruction
      auto status = ZydisDecoderDecodeFull(&decoder_,
        &file_buffer_[cb.file_offset], cb.file_size, &decoded_instruction,
        decoded_operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE,
        ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY);

      if (ZYAN_FAILED(status)) {
        printf("[!] Failed to decode instruction. Status = 0x%X.\n", status);
        return false;
      }

      assert(decoded_instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE);

      ZydisEncoderRequest encoder_request;

      // create an encoder request from the decoded instruction
      status = ZydisEncoderDecodedInstructionToEncoderRequest(&decoded_instruction,
        decoded_operands, decoded_instruction.operand_count_visible, &encoder_request);

      if (ZYAN_FAILED(status)) {
        printf("[!] Failed to create encoder request. Status = 0x%X.\n", status);
        return false;
      }

      // we want the encoder to automatically use the smallest instruction available
      encoder_request.branch_type  = ZYDIS_BRANCH_TYPE_NONE;
      encoder_request.branch_width = ZYDIS_BRANCH_WIDTH_NONE;

      // find the relative operand.
      // determine if its forwards or backwards.
      for (std::size_t i = 0; i < decoded_instruction.operand_count_visible; ++i) {
        auto const& op = decoded_operands[i];

        // the value that is added to RIP to get the target address
        std::int64_t* target_delta = nullptr;

        // memory references
        if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
          // sanity check
          assert(op.mem.disp.has_displacement);
          assert(op.mem.base  == ZYDIS_REGISTER_RIP);
          assert(op.mem.index == ZYDIS_REGISTER_NONE);
          assert(op.mem.scale == 0);

          target_delta = &encoder_request.operands[i].mem.displacement;
        }
        // relative CALLs, JMPs, etc
        else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative)
          target_delta = &encoder_request.operands[i].imm.s;
        else
          continue;

        assert(target_delta != nullptr);

        auto const target_virtual_offset = cb.virtual_offset +
          decoded_instruction.length + *target_delta;

        // TODO: fix targets into data regions immediately (even if they're forwards)

        // backward targets can be fixed immediately
        if (*target_delta < 0) {
          printf("[+] Adjusting backwards target.\n");
          printf("[+]   Target delta:                   -0x%zX.\n", -(*target_delta));
          printf("[+]   Target virtual offset:           0x%zX.\n", target_virtual_offset);

          for (std::size_t j = 0; j < curr_cb_idx; ++j) {
            auto const& target_cb = code_blocks_[j];

            if (target_virtual_offset < target_cb.virtual_offset ||
                target_virtual_offset >= (target_cb.virtual_offset + target_cb.file_size))
              continue;

            auto const offset = (target_virtual_offset - target_cb.virtual_offset);

            // the new target delta
            auto const adjusted_target_delta = (curr_region.virtual_address +
              curr_region_offset + decoded_instruction.length) -
              (target_cb.final_virtual_address + offset);

            printf("[+]   Adjusted target delta:          -0x%zX.\n",
              adjusted_target_delta);
            printf("[+]   Adjusted target virtual address: 0x%p.\n",
              target_cb.final_virtual_address + offset);

            char str[256];
            disassemble_and_format(&file_buffer_[rva_to_file_offset(
              static_cast<std::uint32_t>(target_virtual_offset))], 15, str, 256);
            printf("[+]   Original target instruction:     %s.\n", str);

            disassemble_and_format(target_cb.final_virtual_address + offset, 15, str, 256);
            printf("[+]   Adjusted target instruction:     %s.\n", str);

            *target_delta = -adjusted_target_delta;
            break;
          }
        }
        // forward targets need to be resolved later. for now, just estimate
        // the instruction length for the worst case scenario.
        else {
          printf("[+] Estimating placeholder forwards target.\n");
          printf("[+]   Target delta:                    +0x%zX.\n", *target_delta);
          printf("[+]   Target virtual offset:            0x%zX.\n", target_virtual_offset);

          bool is_data_target = false;

          for (auto const& db : data_blocks_) {
            if (target_virtual_offset < db.virtual_offset ||
                target_virtual_offset >= (db.virtual_offset + db.virtual_size))
              continue;

            auto const offset = target_virtual_offset - db.virtual_offset;
            auto const adjusted_target_delta = (curr_region.virtual_address +
              curr_region_offset + decoded_instruction.length) - 
              (db.final_virtual_address + offset);

            printf("[+]   Adjusted target delta:           +0x%zX.\n", adjusted_target_delta);
            printf("[+]   Adjusted target virtual address:  0x%p.\n",
              db.final_virtual_address + offset);

            *target_delta = adjusted_target_delta;

            is_data_target = true;
            break;
          }

          if (!is_data_target) {
            std::size_t pessimistic_distance = 0;

            // this is a very ROUGH estimate, but it gets the job done
            for (std::size_t j = curr_cb_idx; j < code_blocks_.size(); ++j) {
              auto const& target_cb = code_blocks_[j];

              pessimistic_distance += target_cb.expected_size;

              if (target_virtual_offset >= target_cb.virtual_offset &&
                  target_virtual_offset < (target_cb.virtual_offset + target_cb.file_size))
                break;
            }

            printf("[+]   Pessimistic target delta:        +0x%zX.\n", pessimistic_distance);

            // TODO: need to encode an absolute target
            if (pessimistic_distance >= INT_MAX) {
              printf("[!] Pessimistic distance is too far.\n");
              return false;
            }

            // TODO: calculate the target into the next code region
            if (pessimistic_distance > remaining_region_size) {
              printf("[!] Pessimistic target is outside of the current code region.\n");
              return false;
            }

            *target_delta = pessimistic_distance;
          }

          printf("[+]   Target in data block:             %d.\n", is_data_target);
        }

        break;
      }

      std::uint8_t new_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
      std::size_t new_instruction_length = ZYDIS_MAX_INSTRUCTION_LENGTH;

      // encode the new "fixed" relative instruction
      status = ZydisEncoderEncodeInstruction(&encoder_request,
        new_instruction, &new_instruction_length);

      if (ZYAN_FAILED(status)) {
        printf("[!] Failed to encode relative instruction.\n");
        return false;
      }

      if (new_instruction_length > remaining_region_size) {
        printf("[!] Ran out of space in the current code region.\n");
        return false;
      }

      cb.final_virtual_address = curr_region.virtual_address + curr_region_offset;
      cb.final_size            = static_cast<std::uint32_t>(new_instruction_length);

      memcpy(curr_region.virtual_address + curr_region_offset,
        new_instruction, new_instruction_length);
      
      printf("[+] Encoded a new relative instruction at 0x%p:\n",
        cb.final_virtual_address);
      
      char str[256];
      disassemble_and_format(new_instruction, new_instruction_length, str, 256);
      printf("[+]   %s.\n", str);

      curr_region_offset += cb.final_size;
    }

    printf("[+] # of code blocks: %zu (0x%zX bytes).\n",
      code_blocks_.size(), code_blocks_.size() * sizeof(code_block));

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
  // populate the code/data blocks that make up the binary
  bool parse() {
    // TODO: add external references to code blocks that are not covered by
    //       exception directory.

    // disassemble every function and create a list of code blocks
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
      for (std::uint32_t instruction_offset = 0;
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
          printf("[!] Failed to decode instruction! Virtual offset: 0x%X. Status: 0x%X.\n",
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

        // TODO: calculate a more accurate expected size
        cb->expected_size += decoded_instruction.length + 32;
      }
    }

    // create a list of data blocks
    for (std::size_t i = 0; i < nt_header_->FileHeader.NumberOfSections; ++i) {
      auto const& section = sections_[i];

      // ignore sections that are executable
      if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
        continue;

      assert(section.Characteristics & IMAGE_SCN_MEM_READ);

      data_block block = {};
      block.final_virtual_address = nullptr;
      block.virtual_offset        = section.VirtualAddress;
      block.file_offset           = section.PointerToRawData;
      block.file_size             = section.SizeOfRawData;
      block.virtual_size          = section.Misc.VirtualSize;

      data_blocks_.push_back(block);
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

  // calculate the new target delta for a relative instruction. this new delta
  // is relative to the start of the current instruction, rather than the end.
  bool calculate_adjusted_target_delta(
      std::uint8_t const* const current_instruction_address,
      std::size_t         const current_cb_idx,
      std::uint32_t       const target_virtual_offset,
      std::int64_t&             target_delta,
      bool&                     fully_resolved) const {
    // get the current code block (which should be relative)
    auto const& cb = code_blocks_[current_cb_idx];
    assert(cb.is_relative);

    // if the target is in a data block, we can immediately calculate the
    // target delta (even if it is a forward target).
    for (auto const& db : data_blocks_) {
      if (target_virtual_offset < db.virtual_offset ||
          target_virtual_offset >= (db.virtual_offset + db.virtual_size))
        continue;

      auto const target_final_address = db.final_virtual_address +
        (target_virtual_offset - db.virtual_offset);

      target_delta   = current_instruction_address - target_final_address;
      fully_resolved = true;

      return true;
    }

    // backward targets can also be immediately resolved since their
    // final address has already been determined.
    if (target_virtual_offset <= cb.virtual_offset) {
      // search backwards for the code block that contains the target
      for (std::size_t i = current_cb_idx + 1; i > 0; --i) {
        auto const& cb = code_blocks_[i - 1];

        if (target_virtual_offset < cb.virtual_offset ||
            target_virtual_offset >= (cb.virtual_offset + cb.file_size))
          continue;

        // this is a bit of an edgecase so i'll just handle it when it comes up
        assert(!cb.is_relative);

        auto const target_final_address = cb.final_virtual_address +
          (target_virtual_offset - cb.virtual_offset);

        target_delta   = current_instruction_address - target_final_address;
        fully_resolved = true;

        return true;
      }

      // this is possible if the target isn't inside of any known code
      // blocks (i.e. we don't have complete code coverage).
      printf("[!] Failed to calculate backwards target delta.\n");
      return false;
    }

    target_delta   = 0;
    fully_resolved = false;

    // forward targets can't be immediately resolved, so we're just gonna
    // return the worst-case target delta. this will act as a placeholder
    // until we're able to resolve the real delta.
    for (std::size_t i = current_cb_idx; i < code_blocks_.size(); ++i) {
      auto const& cb = code_blocks_[i];

      target_delta  += cb.expected_size;

      if (target_virtual_offset < cb.virtual_offset ||
          target_virtual_offset >= (cb.virtual_offset + cb.file_size))
        continue;

      return true;
    }

    // this is possible if the target isn't inside of any known code
    // blocks (i.e. we don't have complete code coverage).
    return false;
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

  // blocks of code/data that make up the binary
  std::vector<code_block> code_blocks_ = {};
  std::vector<data_block> data_blocks_ = {};
};

int main() {
  chum_parser chum("./hello-world-x64.dll");

  // add 0x4000 bytes of executable memory and 0x4000 bytes of read-write memory
  chum.add_code_region(VirtualAlloc(nullptr, 0x4000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE), 0x4000);
  chum.add_data_region(VirtualAlloc(nullptr, 0x4000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE),         0x4000);

  if (!chum.write())
    printf("[!] Failed to write binary to memory.\n");
}
