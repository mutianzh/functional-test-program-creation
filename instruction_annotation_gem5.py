import re
import pandas as pd
from utils import *
from modules import *


class instructionAnnotationGem5:
    def __init__(self, target_module, annotation_table_path):
        self.annotation_table_path = annotation_table_path
        self.target_module_name = target_module
        self.modules = dict()
        self.create_regular_expressions()
        self.initialize_modules()


    def create_regular_expressions(self):
        """
        regular expressions to match each target log line
        """
        # self.instr_regex = re.compile(
        #     r'^\s*(?P<tick>\d+):\s+'  # Allow optional leading spaces and match the tick
        #     r'(?P<module>[^\s]+):\s+'  # Module
        #     r'T(?P<thread_id>\d+)\s+:\s+'  # Thread ID
        #     r'(?P<pc>0x[0-9a-fA-F]+)\s+'  # PC
        #     r'@(?P<instr_num>[^\s]+)\s+:\s+'  # Instruction Number or Label
        #     r'(?P<instruction>.+?)\s+:\s+'  # Instruction
        #     r'(?P<op_class>[^\s]+)\s*'  # Operation Class
        #     r'(?:\s*:\s*D=(?P<computed_data>[^\s]+))?\s*:?$'  # Optional Data Address or trailing colon
        # )

        self.instr_regex = re.compile(
            r'^\s*(?P<tick>\d+):\s+'  # Simulation tick
            r'(?P<module>[^\s]+):\s+'  # Module (e.g., system.cpu)
            r'T(?P<thread_id>\d+)\s+:\s+'  # Thread ID
            r'(?P<pc>0x[0-9a-fA-F]+)\s+'  # Program Counter (PC)
            r'@(?P<instr_num>[^\s]+)\s+:\s+'  # Instruction number or label
            r'(?P<instruction>.+?)\s+:\s+'  # The actual instruction
            r'(?P<op_class>[^\s]+)'  # Operation class (e.g., MemWrite)
            r'(?:\s*:\s*D=(?P<computed_data>[^\s]+))?'  # Optional computed data
            r'(?:\s*A=(?P<address>[^\s]+))?'  # Optional memory address
            r'\s*:?$'  # Optional trailing colon
        )


        self.instr_fetch_regex = re.compile(
            r"(?P<tick>\d+): .*? (?P<thread>T\d+) : (?P<pc>0x[0-9a-fA-F]+) @i(?P<icount>\d+) : (?P<instruction>.+)"
        )


        self.fu_assign_regex = re.compile(
            r'^(?P<tick>\d+):\s+'
            r'(?P<module>[^\s]+):\s+'
            r'Assigned FU idx (?P<fu_idx>\d+) to instruction PC '
            r'\((?P<pc_start>0x[0-9a-fA-F]+)=>(?P<pc_end>0x[0-9a-fA-F]+)\).'
            r'\(\d+=>\d+\)\s+\[sn:(?P<seq_num>\d+)\]'
        )

        """
        rename unit
        """

        #  112000: system.cpu.rename: [tid:0] Looking up integer arch reg 6, got phys reg 35 (integer)
        self.rename_src_regex = re.compile(
            r'^(?P<tick>\d+):\s+'  # Tick count (e.g., 112000)
            r'(?P<module>system\.cpu\.rename):\s+'  # Module name (system.cpu.rename)
            r'\[tid:(?P<tid>\d+)\]\s+'  # Thread ID (tid:0)
            r'Looking up (?P<reg_type>\w+) arch reg (?P<arch_reg>\d+),'  # Architectural register class & ID
            r'\s+got phys reg (?P<phys_reg>\d+)'  # Physical register name
        )

        #  112000: global: Renamed reg integer[6] to physical reg 36 (36) old mapping was 35 (35)
        self.rename_read_old_regex = re.compile(
            r'^(?P<tick>\d+):\s+'  # Tick count (e.g., 497000)
            r'global:\s+'  # Global module identifier
            r'Renamed reg (?P<reg_type>\w+)\[(?P<arch_reg>\d+)\]\s+'  # Register type (e.g., integer) and architectural register ID
            r'to physical reg (?P<new_phys_reg>\d+)\s+'  # New physical register ID
            r'\(\d+\)\s+'  # Ignore repeated physical reg ID in parentheses
            r'old mapping was (?P<old_phys_reg>\d+)\s+'  # Old physical register ID
            r'\(\d+\)'  # Ignore repeated old reg ID in parentheses
        )

        #  112000: system.cpu.rename: [tid:0] Processing instruction [sn:4] with PC (0x100ac=>0x100b0).(0=>1).
        self.rename_process_regex = re.compile(
            r'^(?P<tick>\d+):\s+'  # Tick count (e.g., 497000)
            r'(?P<module>system\.cpu\.rename):\s+'  # Module name (system.cpu.rename)
            r'\[tid:(?P<tid>\d+)\]\s+'  # Thread ID (tid:0)
            r'Processing instruction \[sn:(?P<sn>\d+)\] with PC\s+'  # Sequence number (sn:74)
            r'\((?P<pc>0x[0-9a-fA-F]+)=>0x[0-9a-fA-F]+\).'  # Extract PC before rename
            r'\(\d+=>\d+\)\.'  # Ensure it correctly matches the cycle format at the end
        )

        """
        Issue queue
        """
        # log line says that an entry gets new value
        # self.issue_queue_new_value = re.compile(
        #     r'Insertion of PC\s+\((?P<pc>0x[\da-fA-F]+)=>0x[\da-fA-F]+\)\.\(\d+=>\d+\):\s+entry (?P<entry_id>\d+)'
        # )

        self.issue_queue_new_value = re.compile(
            r'^(?P<tick>\d+): .*Insertion of PC\s+\((?P<pc>0x[\da-fA-F]+)=>0x[\da-fA-F]+\)\.\(\d+=>\d+\):\s+entry (?P<entry_id>\d+)'
        )

        # log line says that an entry keeps old value
        self.issue_queue_original_value = re.compile(
            r'^(?P<tick>\d+): .*Entry (?P<entry_id>\d+)\s+keep original value\s+\(PC: \((?P<pc>0x[\da-fA-F]+)=>'
        )

        # log line says that entry is issued to a function unit
        self.issue_queue_issued = re.compile(
            r'^(?P<tick>\d+): .*Issued \[sn:\d+\] PC \((?P<pc>0x[\da-fA-F]+)=>0x[\da-fA-F]+\)\.\(\d+=>\d+\) '
            r'from iq_position (?P<entry_id>\d+) to FU index (?P<fu_index>\d+)'
        )

        # log line says that an instruction is added to the IQ
        # 4988000: system.cpu.iq: Issue queue entry 0 took new value (PC: (0x10d5c=>0x10d60).(0=>1), SN: 1134)
        self.iq_add = re.compile(
            r'^(?P<tick>\d+): system\.cpu\.iq: Issue queue entry (?P<entry_id>\d+) took new value '
            r'\(PC: \((?P<pc>0x[0-9a-fA-F]+)=>(?P<pc_next>0x[0-9a-fA-F]+)\)\.\(\d+=>\d+\), SN: (?P<seqnum>\d+)\)'
        )

        # log line says that an instruction is added to the IQ
        # 4988000: system.cpu.iq: Issue queue entry 7 current value removed
        self.iq_remove = re.compile(
            r'^(?P<tick>\d+): system\.cpu\.iq: Issue queue entry (?P<entry_id>\d+) current value removed'
        )

        """
        ROB
        """
        # add new instructions to ROB
        self.rob_insert = re.compile(
            r'^(?P<tick>\d+): system\.cpu\.rob: \[tid:(?P<tid>\d+)\] '
            r'Instruction with PC \((?P<pc>0x[0-9a-fA-F]+)=>(?P<pc_next>0x[0-9a-fA-F]+)\)\.\(\d+=>\d+\) '
            r'inserted at ROB entry (?P<entry>\d+); head = ROB entry (?P<head>\d+); numInstsInROB = (?P<num>\d+)'
        )

        # graduate instruction
        self.rob_graduate = re.compile(
            r'^(?P<tick>\d+): system\.cpu\.rob: \[tid:(?P<tid>\d+)\] '
            r'Instruction with PC \((?P<pc>0x[0-9a-fA-F]+)=>(?P<pc_next>0x[0-9a-fA-F]+)\)\.\(\d+=>\d+\) '
            r'graduated at ROB entry (?P<entry>\d+); tail = (?P<tail>(\d+|<none>)); numInstsInROB = (?P<num>\d+)'
        )

        # squash instruction
        self.rob_squash = re.compile(
            r'^(?P<tick>\d+): system\.cpu\.rob: \[tid:(?P<tid>\d+)\] '
            r'Squashed instruction with PC \((?P<pc>0x[0-9a-fA-F]+)=>(?P<pc_next>0x[0-9a-fA-F]+)\)\.\(\d+=>\d+\) '
            r'removed from ROB entry (?P<entry>\d+); tail = (?P<tail>(\d+|<none>)); numInstsInROB = (?P<num>\d+)'
        )

        self.rob_dependency_match = re.compile(
            r'^(?P<tick>\d+): system\.cpu\.commit: \[tid:(?P<tid>\d+)\] \[RAW\] '
            r'PC \((?P<pc>0x[0-9a-fA-F]+)=>(?P<pc_next>0x[0-9a-fA-F]+)\)\.\(\d+=>\d+\) '
            r'src\[(?P<src_idx>\d+)\] \((?P<src_reg>\d+)\) reads from PC '
            r'\((?P<dep_pc>0x[0-9a-fA-F]+)=>(?P<dep_pc_next>0x[0-9a-fA-F]+)\)\.\(\d+=>\d+\) '
            r'dst\[(?P<dst_idx>\d+)\] \((?P<dst_reg>\d+)\); ROB entry (?P<entry>\d+)'
        )

        # 4988000: system.cpu.rob: ROB entry 134 took new value (PC: (0x10d60=>0x10d64).(0=>1), SN: 1135)
        self.rob_add = re.compile(
            r'^(?P<tick>\d+): system\.cpu\.rob: ROB entry (?P<entry_id>\d+) took new value '
            r'\(PC: \((?P<pc>0x[0-9a-fA-F]+)=>(?P<pc_next>0x[0-9a-fA-F]+)\)\.\(\d+=>\d+\), SN: (?P<seqnum>\d+)\)'
        )

        # 4991000: system.cpu.rob: ROB entry 114 current value removed
        self.rob_remove = re.compile(
            r'^(?P<tick>\d+): system\.cpu\.rob: ROB entry (?P<entry_id>\d+) current value removed'
        )

        """
        Branch predictor
        """
        # 2-bit local
        # 12561000: system.cpu.branchPred: Looking up index 0
        # 12561000: system.cpu.branchPred: prediction is 3.
        # 399000: system.cpu.branchPred: PC 0x10168 reads LocalBP row 90 and get 0
        # self.bpt_local_look_up = re.compile(f"^(?P<tick>\d+): system.cpu.branchPred: Looking up index 0")
        # self.bpt_local_read = re.compile(f"^(?P<tick>\d+): system.cpu.branchPred: prediction is 3.")
        self.bpt_local_read = re.compile(f"^(?P<tick>\d+): system.cpu.branchPred: PC (?P<pc>0x[0-9a-fA-F]+) reads LocalBP row (?P<row>\d+) and get (?P<val>\d+)")

        # index_pattern = re.compile(r"branchPred: Looking up index\s+(0x[0-9a-fA-F]+|\d+)")
        # pred_pattern = re.compile(r"branchPred: prediction\s+is\s+(\d+)")

        # 4604000: system.cpu.branchPred: PC 0x10c34 (seqNum %llu) updates LocalBP row 269 : 2 to 1
        self.bpt_local_update = re.compile(
            r'^(?P<tick>\d+)'                                # 4604000
                r':\s+system\.cpu\.branchPred:\s+'
                r'PC\s+(?P<pc>0x[0-9a-fA-F]+)\s+'                # 0x10c34
                r'updates\s+LocalBP\s+row\s+(?P<row>\d+)\s+:\s+'
                r'(?P<old>\d+)\s+to\s+(?P<new>\d+)'              # 2 to 1
        )

        # bi mode branch predictor
        # 327000: system.cpu.branchPred: bi-mode: PC 0x10108 updates NotTakenPHT row 66 : 0 to 0
        self.bpt_bi_not_taken_table = re.compile(
            r'^(?P<tick>\d+)'  # 4604000
            r':\s+system\.cpu\.branchPred: bi-mode:\s+'
            r'PC\s+(?P<pc>0x[0-9a-fA-F]+)\s+'  # 0x10c34
            r'updates\s+NotTakenPHT\s+row\s+(?P<row>\d+):\s+'
            r'(?P<old>\d+)\s+to\s+(?P<new>\d+)'  # 2 to 1
        )

        # Taken table: TakenPHT
        self.bpt_bi_taken_table = re.compile(
            r'^(?P<tick>\d+)'  # 4604000
            r':\s+system\.cpu\.branchPred: bi-mode:\s+'
            r'PC\s+(?P<pc>0x[0-9a-fA-F]+)\s+'  # 0x10c34
            r'updates\s+TakenPHT\s+row\s+(?P<row>\d+):\s+'
            r'(?P<old>\d+)\s+to\s+(?P<new>\d+)'  # 2 to 1
        )

        # choice table
        # 327000: system.cpu.branchPred: bi-mode: PC 0x10108 updates Choice row 66 : 0 to 0
        self.bpt_bi_choice_table = re.compile(
            r'^(?P<tick>\d+)'  # 4604000
            r':\s+system\.cpu\.branchPred: bi-mode:\s+'
            r'PC\s+(?P<pc>0x[0-9a-fA-F]+)\s+'  # 0x10c34
            r'updates\s+Choice\s+row\s+(?P<row>\d+):\s+'
            r'(?P<old>\d+)\s+to\s+(?P<new>\d+)'  # 2 to 1
        )

        self.bpt_bi_lookups = re.compile(
            r'^(?P<tick>\d+)'  # 1438000
            r':\s+system\.cpu\.branchPred:\s+bi-mode:\s+GH=0x[0-9a-fA-F]+\s+'  # Non-captured fields: GH=0xffbf
            r'PC=(?P<pc>0x[0-9a-fA-F]+)\s+'  # 0x10420
            r'lookups\s+Choice\s+row\s+(?P<choice_row>\d+)\s+'  # Choice row 264
            r'get\s+(?P<choice_val>\d+)\s+'  # get 3
            r'looks\s+up\s+(?P<chosen_table>[A-Za-z]+PHT)\s+'  # looks up TakenPHT
            r'row\s+(?P<chosen_row>\d+)\s+'  # row 695
            r'get\s+(?P<chosen_val>\d+)'  # get 0
        )


        """
        Store set
        """
        # 887000: global: Inst 0x102b4 with index 173 had no SSID
        self.store_set_no_ssid = re.compile(
            r'^(?P<tick>\d+): global: '
            r'Inst\s+(?P<pc>0x[0-9a-fA-F]+)\s+with index\s+(?P<row>\d+)\s+had no SSID'
        )

        # DPRINTF(StoreSet, "Inst %#x with index %i and SSID %i had no "
        #                   "dependency\n", PC, index, inst_SSID);
        self.store_set_read_ssid_no_lfst = re.compile(
            r'^(?P<tick>\d+): global: '
            r'Inst (?P<pc>0x[0-9a-fA-F]+) with index (?P<row>\d+) and SSID (?P<ssid>\d+) had no dependency'
        )


        # DPRINTF(StoreSet, "Inst %#x with index %i and SSID %i had LFST "
        #                   "inum of %i\n", PC, index, inst_SSID, LFST[inst_SSID]);
        self.store_set_read_ssid_w_lfst = re.compile(
            r'^(?P<tick>\d+): global: '
            r'Inst (?P<pc>0x[0-9a-fA-F]+) with index (?P<row>\d+) and SSID (?P<ssid>\d+) had LFST inum of (?P<inum>\d+)'
        )

        # 1889000: global: StoreSet: Neither load nor store had a valid storeset, creating a new one: 165 for load 0x104e4 with index 313, store 0x104d4 with index 309
        # 3340000: global: StoreSet: Neither load nor store had a valid storeset, creating a new one: 178 for load 0x108f0 with index 572, store 0x108d8 with index 566
        self.store_set_violation_case1 = re.compile(
            r'^(?P<tick>\d+): global: '
            r'StoreSet: Neither load nor store had a valid storeset, creating a new one: (?P<ssid>\d+) for load (?P<pc_load>0x[0-9a-fA-F]+) with index (?P<row_load>\d+), store (?P<pc_store>0x[0-9a-fA-F]+) with index (?P<row_store>\d+)'
        )


        # DPRINTF(StoreSet, "StoreSet: Load had a valid store set.  Adding "
        #                   "store to that set: %i for load %#x with index %i, store %#x with index %i\n",
        #         load_SSID, load_PC, load_index, store_PC, store_index);
        self.store_set_violation_case2 = re.compile(
            r'^(?P<tick>\d+): global: '
            r'StoreSet: Load had a valid store set.\s+Adding store to that set: (?P<ssid>\d+) for load (?P<pc_load>0x[0-9a-fA-F]+) with index (?P<row_load>\d+), store (?P<pc_store>0x[0-9a-fA-F]+) with index (?P<row_store>\d+)'
        )

        # DPRINTF(StoreSet, "StoreSet: Store had a valid store set: %i for "
        #                   "load %#x with index %i, store %#x with index %i\n",
        #         store_SSID, load_PC, load_index, store_PC, store_index);
        self.store_set_violation_case3 = re.compile(
            r'^(?P<tick>\d+): global: '
            r'StoreSet: Store had a valid store set: (?P<ssid>\d+) for load (?P<pc_load>0x[0-9a-fA-F]+) with index (?P<row_load>\d+), store (?P<pc_store>0x[0-9a-fA-F]+) with index (?P<row_store>\d+)'
        )

        # DPRINTF(StoreSet, "StoreSet: Load had smaller store set: %i; "
        #                   "for load %#x with index %i, store %#x with index %i\n",
        #         load_SSID, load_PC, load_index, store_PC, store_index);

        # DPRINTF(StoreSet, "StoreSet: Store had smaller store set: %i; "
        #                   "for load %#x with index %i, store %#x with index %i\n",
        #         store_SSID, load_PC, load_index, store_PC, store_index);
        self.store_set_violation_case4_0 = re.compile(
            r'^(?P<tick>\d+): global: '
            r'StoreSet: Load had smaller store set: (?P<ssid_load>\d+); for load (?P<pc_load>0x[0-9a-fA-F]+) with index (?P<row_load>\d+), store (?P<pc_store>0x[0-9a-fA-F]+) with index (?P<row_store>\d+), replace set (?P<ssid_store>\d+)'
        )

        self.store_set_violation_case4_1 = re.compile(
            r'^(?P<tick>\d+): global: '
            r'StoreSet: Store had smaller store set: (?P<ssid_store>\d+); for load (?P<pc_load>0x[0-9a-fA-F]+) with index (?P<row_load>\d+), store (?P<pc_store>0x[0-9a-fA-F]+) with index (?P<row_store>\d+), replace set (?P<ssid_load>\d+)'
        )

        # DPRINTF(StoreSet, "StoreSet: store %#x with SSID %i invalidated itself in LFST.\n", issued_PC, store_SSID);
        self.store_set_invalidate_lfst = re.compile(
            r'^(?P<tick>\d+): global: '
            r'StoreSet: store (?P<pc>0x[0-9a-fA-F]+) with SSID (?P<ssid>\d+) invalidated itself in LFST.'
        )

        # DPRINTF(StoreSet, "Store %#x validated the LFST, SSID: %i\n",
        # store_PC, store_SSID);
        self.store_set_validate_lfst = re.compile(
            r'^(?P<tick>\d+): global: '
            r'Store (?P<pc>0x[0-9a-fA-F]+) validated the LFST, SSID: (?P<ssid>\d+)'
        )

        # DPRINTF(StoreSet, "Store %#x replaced the LFST, SSID: %i\n",
        # store_PC, store_SSID);
        self.store_set_replace_lfst = re.compile(
            r'^(?P<tick>\d+): global: '
            r'Store (?P<pc>0x[0-9a-fA-F]+) replaced the LFST, SSID: (?P<ssid>\d+)'
        )

        """
        Cache
        """
        # read and write access
        # 496000: system.cpu.icache: ReadMiss pc=0x101c0 set=255 way=255 addr=0x1c0
        # self.cache_access = re.compile(
        #     r'^(?P<tick>\d+): '  # 4604000
        #     r'system\.cpu\.(?P<cache>[0-9a-fA-F]+): (?P<kind>[a-fA-F]+) '
        #     r'pc=(?P<pc>0x[0-9a-fA-F]+) '  # 0x101c0
        #     r'set=(?P<set>\d+) '
        #     r'way=(?P<way>\d+) '
        #     r'addr=(?P<addr>0x[0-9a-fA-F]+) '
        # )

        self.cache_access = re.compile(
            r'^\s*(?P<tick>\d+):\s+'  # 496000:
            r'system\.(?:cpu\.)?(?P<cache>[A-Za-z0-9_]+):\s+'  # icache / dcache / l2cache
            r'(?P<kind>\w+)\s+'  # ReadMiss / WriteHit
            # r'pc=(?P<pc>0x[0-9a-fA-F]+)\s+'
            r'pc=(?P<pc>(?:0x)?[0-9a-fA-F]+)\s+' # pc=0x101c0 or pc=0
            r'set=(?P<set>\d+)\s+'  # set=255
            r'way=(?P<way>\d+)\s+'  # way=255
            r'addr=(?P<addr>0x[0-9a-fA-F]+)\s+'  # addr=0x1c0
            r'block_addr=(?P<block_addr>0x[0-9a-fA-F]+)\s*$'
        )

        # 107000: system.cpu.icache: EvictClean trigger_pc=0x100a0 victim set=2 way=0 addr=0xffffffffffffe080
        self.cache_evict = re.compile(
            r'^\s*(?P<tick>\d+):\s+'  # 107000:
            r'system\.(?:cpu\.)?(?P<cache>[A-Za-z0-9_]+):\s+'  # icache / l2cache
            r'(?P<kind>\w+)\s+'  # EvictClean / EvictDirty
            r'trigger_pc=(?P<trigpc>0x[0-9a-fA-F]+)\s+'  # trigger_pc=0x100a0
            r'victim\s+set=(?P<set>\d+)\s+'  # victim set=2
            r'way=(?P<way>\d+)\s+'  # way=0
            r'addr=(?P<addr>0x[0-9a-fA-F]+)\s*$',  # addr=0xffff...
            re.IGNORECASE
        )


    def parse_rv32im_instruction_single(self, instruction: str):
        """
        Parse RV32IM assembly instructions into structured components.
        """
        # Updated regex to handle 1 to 3 operands
        pattern = r"(\w+)\s+([\w]+)(?:,\s*([\w()\-+]+))?(?:,\s*([\w()\-+]+))?"

        # RV32IM Instruction categories
        R_TYPE = {"add", "sub", "sll", "slt", "sltu", "xor", "srl", "sra", "or", "and", "mul", "mulh", "mulhsu",
                  "mulhu", "div", "divu", "rem", "remu"}
        I_TYPE = {"addi", "slti", "sltiu", "xori", "ori", "andi", "lb", "lh", "lw", "lbu", "lhu", "jalr", "slli",
                  "srli", "srai"}
        S_TYPE = {"sb", "sh", "sw"}
        B_TYPE = {"beq", "bne", "blt", "bge", "bltu", "bgeu"}
        U_TYPE = {"lui", "auipc"}
        J_TYPE = {"jal"}

        attributes = {
            "type": '-',
            "mnemonic": '-',
            "rd": '-',
            "rs1": '-',
            "rs2": '-',
            "imm": '-',
        }

        match = re.match(pattern, instruction.strip())
        if not match:
            raise Exception(f"Cannot parse instruction {instruction}")

        operation = match.group(1)
        op1 = match.group(2)
        op2 = match.group(3)
        op3 = match.group(4)

        attributes['mnemonic'] = operation
        parse_success = True
        # R-type
        if operation in R_TYPE:
            attributes['type'] = 'R'
            attributes['rd'] = transform_abi_to_register(op1)
            attributes['rs1'] = transform_abi_to_register(op2)
            attributes['rs2'] = transform_abi_to_register(op3)

        # I-type (includes loads and jalr)
        elif operation in I_TYPE:
            attributes['type'] = 'I'
            attributes['rd'] = transform_abi_to_register(op1)

            # Handle load syntax like lw a0, 0(sp)
            if '(' in op2:
                # e.g., op2 = '0(sp)' ???? imm = 0, rs1 = sp
                imm, rs1 = re.match(r"(-?\d+)\((\w+)\)", op2).groups()
                attributes['rs1'] = transform_abi_to_register(rs1)
                attributes['imm'] = int(imm)
            else:
                attributes['rs1'] = transform_abi_to_register(op2)
                attributes['imm'] = int(op3) if op3 and op3.lstrip('-').isdigit() else op3

        # S-type (stores)
        elif operation in S_TYPE:
            attributes['type'] = 'S'
            attributes['rs2'] = transform_abi_to_register(op1)
            imm, rs1 = re.match(r"(-?\d+)\((\w+)\)", op2).groups()
            attributes['rs1'] = transform_abi_to_register(rs1)
            attributes['imm'] = int(imm)

        # B-type (branches)
        elif operation in B_TYPE:
            attributes['type'] = 'B'
            attributes['rs1'] = transform_abi_to_register(op1)
            attributes['rs2'] = transform_abi_to_register(op2)
            attributes['imm'] = int(op3) if op3 and op3.lstrip('-').isdigit() else op3

        # U-type (lui, auipc)
        elif operation in U_TYPE:
            attributes['type'] = 'U'
            attributes['rd'] = transform_abi_to_register(op1)
            attributes['imm'] = int(op2)

        # J-type (jal)
        elif operation in J_TYPE:
            attributes['type'] = 'J'
            attributes['rd'] = transform_abi_to_register(op1)
            attributes['imm'] = int(op2) if op2 and op2.lstrip('-').isdigit() else op2

        else:
            # raise Exception(f"Unseen instruction {instruction}")
            # print(f"Unseen instruction {instruction}")
            parse_success = False


        return parse_success, attributes


    def initialize_modules(self):
        self.modules['issue_queue'] = issue_queue(64, num_IntAlu + num_MulAlu)
        self.modules['rob'] = ROB(320)
        self.modules['rmt'] = register_mapping_table()
        self.modules['bpt_local'] = BPT_local(2, 1024)
        self.modules['bpt_bi'] = BPT_bi_mode(2, 1024)
        self.modules['store_set'] = store_set(1024, 1024)
        self.modules['dcache'] = cache(2, 512)
        self.modules['icache'] = cache(2, 512)
        self.modules['l2cache'] = cache(8, 512)


    def parse_trace_file(self, log_file_path):
        """
        :param log_file_path: the path to the log file generated by gem5
        :return:
        """
        instructions_dict = defaultdict(dict)

        """
        Initialize modules
        """

        cols = []

        instruction_attributes = ['pc', 'tick', 'type', 'mnemonic', 'rd', 'rs1', 'rs2', 'imm', 'rd_v', 'rs1_v', 'rs2_v', 'mem_addr']
        cols += instruction_attributes

        # rename unit
        rename_event_attributes = ['rename_arch_reg_read',
                                   'rename_phys_reg_read',
                                   'rename_arch_reg_write',
                                   'rename_phys_reg_write']
        cols += rename_event_attributes

        # issue queue
        issue_queue_event_attributes = [
            'issue_entry_new_value',
            'issue_entry_original_value',
            'issue_entry_issued',
            'issue_entry_fu_id'
        ]
        cols += issue_queue_event_attributes

        # ROB
        rob_event_attributes = ['rob_entry_insert', 'rob_entry_graduate', 'rob_entry_squash', 'rob_head', 'rob_tail', 'rob_entry_match', 'rob_numInsts']
        cols += rob_event_attributes

        # branch predictor
        # 2-bit local branch predictor
        bpt_event_attributes = ['bpt_table_name', 'bpt_row_id', 'bpt_old_val', 'bpt_new_val', 'bpt_bit_0_op', 'bpt_bit_1_op', 'read_val']
        # bpt_bi_mode_event_attributes = ['bpt_table_name', 'bpt_row_id', 'bpt_old_val', 'bpt_new_val']
        cols += bpt_event_attributes

        # store set
        store_set_attributes = ['ss_table_name', 'ss_row', 'ss_op', 'ss_value']
        cols += store_set_attributes

        # cache
        # set associative
        cache_attributes = ['cahce_name', 'cahce_set', 'cahce_way', 'cahce_operation', 'addr', 'block_addr']
        cols += cache_attributes

        # Read and parse the log file
        cnt = 0
        cur_pc_value = ''
        with open(log_file_path, 'r') as file:
            lines = file.readlines()

            # log instructions
            # for line in file:
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                match = self.instr_regex.match(line)
                if match:
                    # print(line)
                    info = match.groupdict()
                    pc = info['pc']
                    inst_str = info['instruction']
                    produced_result = info['computed_data']

                    if inst_str not in ['ecall']:
                        parse_suc, parse_res = self.parse_rv32im_instruction_single(inst_str)
                        if parse_suc:
                            instructions_dict[pc]['inst_attributes'] = {key: '-' for key in instruction_attributes}
                            instructions_dict[pc]['inst_attributes']['pc'] = pc
                            instructions_dict[pc]['inst_str'] = inst_str
                            if produced_result:
                                instructions_dict[pc]['inst_attributes']['rd_v'] = hex_to_decimal_2s_complement(produced_result)
                            for key, value in parse_res.items():
                                instructions_dict[pc]['inst_attributes'][key] = value
                            instructions_dict[pc]['events'] = []
                else:
                    match = self.instr_fetch_regex.match(line)
                    if match:
                        # print(line)
                        info = match.groupdict()
                        pc = info['pc']
                        inst_str = info['instruction']
                        if inst_str not in ['ecall']:
                            parse_suc, parse_res = self.parse_rv32im_instruction_single(inst_str)
                            if parse_suc:
                                instructions_dict[pc]['inst_attributes'] = {key: '-' for key in instruction_attributes}
                                instructions_dict[pc]['inst_attributes']['pc'] = pc
                                instructions_dict[pc]['inst_str'] = inst_str
                                for key, value in parse_res.items():
                                    instructions_dict[pc]['inst_attributes'][key] = value
                                instructions_dict[pc]['events'] = []

            for line in lines:
                line = line.strip()

                # renaming table
                # Match rename instruction process log
                rename_processing_match = self.rename_process_regex.match(line)
                if rename_processing_match:
                    cur_pc_value = rename_processing_match.groupdict()['pc']


                # Match rename read old register rename log
                match = self.rename_read_old_regex.match(line)
                if match:
                    pc = cur_pc_value
                    if pc in instructions_dict:
                        arch_reg = int(match.group('arch_reg'))
                        new_phys_reg = int(match.group('new_phys_reg'))
                        old_phys_reg = int(match.group('old_phys_reg'))
                        tick = int(match.group('tick'))
                        event = {
                            'tick': tick,
                            'rename_arch_reg_read': arch_reg,
                            'rename_phys_reg_read': old_phys_reg,
                        }
                        instructions_dict[pc]['events'].append(event)
                        self.modules['rmt'].log_event('r', arch_reg, old_phys_reg)

                        event = {
                            'tick': tick,
                            'rename_arch_reg_write': arch_reg,
                            'rename_phys_reg_write': new_phys_reg,
                        }
                        instructions_dict[pc]['events'].append(event)
                        self.modules['rmt'].log_event('w', arch_reg, new_phys_reg)


                # Try to match rename source register log
                match = self.rename_src_regex.match(line)
                if match:
                    pc = cur_pc_value
                    if pc in instructions_dict:
                        arch_reg = int(match.group('arch_reg'))
                        phys_reg = int(match.group('phys_reg'))
                        tick = int(match.group('tick'))
                        event = {
                            'tick': tick,
                            'rename_arch_reg_read': arch_reg,
                            'rename_phys_reg_read': phys_reg,
                        }
                        instructions_dict[pc]['events'].append(event)
                        self.modules['rmt'].log_event('r', arch_reg, phys_reg)


                # log coverage events of issue queue
                match = self.issue_queue_new_value.search(line)
                if match:
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        entry_id = match.group('entry_id')
                        tick = match.group('tick')
                        event = {'issue_entry_new_value': entry_id, 'tick': tick}
                        # print(line)
                        instructions_dict[pc]['events'].append(event)

                match = self.issue_queue_original_value.search(line)
                if match:
                    if pc in instructions_dict:
                        pc = match.group('pc')
                        entry_id = match.group('entry_id')
                        tick = match.group('tick')
                        event = {'issue_entry_original_value': entry_id, 'tick': tick}
                        instructions_dict[pc]['events'].append(event)

                match = self.issue_queue_issued.search(line)
                if match:
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        entry_id = match.group('entry_id')
                        fu_id = match.group('fu_index')
                        tick = match.group('tick')
                        event = {'issue_entry_issued': entry_id,
                                 'issue_entry_fu_id': fu_id,
                                 'tick': tick}
                        instructions_dict[pc]['events'].append(event)

                        # update coverage measure
                        self.modules['issue_queue'].log_issue_event(entry_id, fu_id)


                match = self.iq_add.search(line)
                if match:
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        entry_id = match.group('entry_id')
                        tick = match.group('tick')
                        seqnum = match.group('seqnum')
                        inst_str = instructions_dict[pc]['inst_str']
                        content = f'{pc},{seqnum},{inst_str}'
                        self.modules['issue_queue'].add_value(tick, entry_id, content)


                match = self.iq_remove.search(line)
                if match:
                    entry_id = match.group('entry_id')
                    tick = match.group('tick')
                    self.modules['issue_queue'].remove_value(tick, entry_id)


                # ROB
                # rob_event_attributes = ['rob_entry_insert', 'rob_entry_graduate', 'rob_entry_squash']
                match = self.rob_insert.search(line)
                if match:
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        event_name = 'rob_entry_insert'
                        tick = match.group('tick')
                        entry = match.group('entry')
                        head = match.group('head')
                        numInsts = match.group('num')
                        event = {
                            event_name: entry,
                            'rob_numInsts': numInsts,
                            'rob_head': head,
                            'rob_tail': entry,
                            'tick': tick
                        }
                        instructions_dict[pc]['events'].append(event)

                        self.modules['rob'].log_event(event_name, entry, head, entry, numInsts)

                match = self.rob_graduate.search(line)
                if match:
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        event_name = 'rob_entry_graduate'
                        tick = match.group('tick')
                        entry = match.group('entry')
                        tail = match.group('tail')
                        numInsts = match.group('num')
                        event = {
                            'rob_entry_graduate': entry,
                            'rob_numInsts': numInsts,
                            'rob_head': entry,
                            'rob_tail': tail,
                            'tick': tick
                        }
                        instructions_dict[pc]['events'].append(event)
                        self.modules['rob'].log_event(event_name, entry, entry, tail, numInsts)


                match = self.rob_squash.search(line)
                if match:
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        event_name = 'rob_entry_squash'
                        tick = match.group('tick')
                        entry = match.group('entry')
                        tail = match.group('tail')
                        numInsts = match.group('num')
                        event = {
                            'rob_entry_squash': entry,
                            'rob_numInsts': numInsts,
                            'rob_head': entry,
                            'rob_tail': tail,
                            'tick': tick
                        }
                        instructions_dict[pc]['events'].append(event)
                        self.modules['rob'].log_event(event_name, entry, entry, tail, numInsts)


                match = self.rob_dependency_match.search(line)
                if match:
                    # print(line)
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        event_name = 'rob_entry_squash'
                        tick = match.group('tick')
                        entry = match.group('entry')
                        event = {
                            'rob_entry_match': entry,
                            'tick': tick
                        }
                        instructions_dict[pc]['events'].append(event)
                        self.modules['rob'].log_event_match(entry)


                match = self.rob_add.search(line)
                if match:
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        entry_id = match.group('entry_id')
                        tick = match.group('tick')
                        seqnum = match.group('seqnum')
                        inst_str = instructions_dict[pc]['inst_str']
                        content = f'{pc},{seqnum},{inst_str}'
                        self.modules['rob'].add_value(tick, entry_id, content)


                match = self.rob_remove.search(line)
                if match:
                    entry_id = match.group('entry_id')
                    tick = match.group('tick')
                    self.modules['rob'].remove_value(tick, entry_id)


                # Branch prediction
                # 2-bit local
                # bpt_event_attributes = ['bpt_table_name', 'bpt_row_id', 'bpt_old_val', 'bpt_new_val', 'bpt_bit_0_op', 'bpt_bit_1_op']
                match = self.bpt_local_update.match(line)
                if match:
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        tick = match.group('tick')
                        row = match.group('row')
                        old = match.group('old')
                        new = match.group('new')
                        bit0, bit1 = int_to_bits(new, 2)
                        event = {
                            'bpt_row_id': row,
                            'bpt_old_val': old,
                            'bpt_new_val': new,
                            'tick': tick,
                            'bpt_bit_0_op': f'w{bit0}',
                            'bpt_bit_1_op': f'w{bit1}',
                        }
                        instructions_dict[pc]['events'].append(event)
                        self.modules['bpt_local'].log_event(row, old, new)

                # self.bpt_local_read = re.compile(f"^(?P<tick>\d+): system.cpu.branchPred: PC (?P<pc>0x[0-9a-fA-F]+) reads LocalBP row (?P<row>\d+) and get (?P<val>\d+)")
                match = self.bpt_local_read.match(line)
                if match:
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        tick = match.group('tick')
                        row = match.group('row')
                        val = match.group('val')

                        bit0, bit1 = int_to_bits(val, 2)
                        event = {
                            'bpt_row_id': row,
                            'bpt_bit_0_op': f'r{bit0}',
                            'bpt_bit_1_op': f'r{bit1}',
                            'tick': tick
                        }
                        instructions_dict[pc]['events'].append(event)


                # bi-mode
                # bpt_bi_mode_event_attributes = ['bpt_table_name', 'bpt_row_id', 'bpt_old_val', 'bpt_new_val']
                match = self.bpt_bi_taken_table.match(line)
                if match:
                    table_name = 'taken'
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        tick = match.group('tick')
                        row = match.group('row')
                        old = match.group('old')
                        new = match.group('new')
                        event = {
                            'bpt_table_name': table_name,
                            'bpt_row_id': row,
                            'bpt_old_val': old,
                            'bpt_new_val': new,
                            'tick': tick
                        }
                        instructions_dict[pc]['events'].append(event)
                        self.modules['bpt_bi'].log_event(table_name, row, old, new)


                match = self.bpt_bi_not_taken_table.match(line)
                if match:
                    table_name = 'not_taken'
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        tick = match.group('tick')
                        row = match.group('row')
                        old = match.group('old')
                        new = match.group('new')
                        event = {
                            'bpt_table_name': table_name,
                            'bpt_row_id': row,
                            'bpt_old_val': old,
                            'bpt_new_val': new,
                            'tick': tick
                        }
                        instructions_dict[pc]['events'].append(event)
                        self.modules['bpt_bi'].log_event(table_name, row, old, new)


                match = self.bpt_bi_choice_table.match(line)
                if match:
                    table_name = 'choice'
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        tick = match.group('tick')
                        row = match.group('row')
                        old = match.group('old')
                        new = match.group('new')
                        event = {
                            'bpt_table_name': table_name,
                            'bpt_row_id': row,
                            'bpt_old_val': old,
                            'bpt_new_val': new,
                            'tick': tick
                        }
                        instructions_dict[pc]['events'].append(event)
                        self.modules['bpt_bi'].log_event(table_name, row, old, new)

                self.bpt_bi_lookups = re.compile(
                    r'^(?P<tick>\d+)'  # 1438000
                    r':\s+system\.cpu\.branchPred:\s+bi-mode:\s+GH=0x[0-9a-fA-F]+\s+'  # Non-captured fields: GH=0xffbf
                    r'PC=(?P<pc>0x[0-9a-fA-F]+)\s+'  # 0x10420
                    r'lookups\s+Choice\s+row\s+(?P<choice_row>\d+)\s+'  # Choice row 264
                    r'get\s+(?P<choice_val>\d+)\s+'  # get 3
                    r'looks\s+up\s+(?P<chosen_table>[A-Za-z]+PHT)\s+'  # looks up TakenPHT
                    r'row\s+(?P<chosen_row>\d+)\s+'  # row 695
                    r'get\s+(?P<chosen_val>\d+)'  # get 0
                )

                match = self.bpt_bi_lookups.match(line)
                if match:
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        tick = match.group('tick')
                        choice_row = match.group('choice_row')
                        choice_val = match.group('choice_val')
                        chosen_table = match.group('chosen_table')
                        chosen_row = match.group('chosen_row')
                        chosen_val = match.group('chosen_val')

                        event = {
                            'bpt_table_name': 'choice',
                            'bpt_row_id': choice_row,
                            # 'bpt_old_val': old,
                            # 'bpt_new_val': new,
                            'tick': tick,
                            'read_val': choice_val

                        }
                        instructions_dict[pc]['events'].append(event)

                        event = {
                            'bpt_table_name': chosen_table,
                            'bpt_row_id': chosen_row,
                            # 'bpt_old_val': old,
                            # 'bpt_new_val': new,
                            'tick': tick,
                            'read_val': chosen_val

                        }
                        instructions_dict[pc]['events'].append(event)
                        # self.modules['bpt_bi'].log_event(table_name, row, old, new)


                # ============ store set ============
                # store_set_attributes = ['ss_table_name', 'ss_row', 'ss_op', 'ss_value']
                # ===================================
                match = self.store_set_no_ssid.match(line)
                if match:
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        tick = match.group('tick')
                        row = match.group('row')
                        self.modules['store_set'].log_event('ssit', 'read_invalid', row)
                        event = {
                            'tick': tick,
                            'ss_table_name': 'ssit',
                            'ss_row': row,
                            'ss_op': 'read_invalid',
                            'ss_value': '-'
                        }
                        instructions_dict[pc]['events'].append(event)


                match = self.store_set_read_ssid_no_lfst.match(line)
                if match:
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        tick = match.group('tick')
                        row = match.group('row')
                        ssid = match.group('ssid')
                        self.modules['store_set'].log_event('ssit', 'read_valid', row)
                        self.modules['store_set'].log_event('lfst', 'read_invalid', ssid)
                        event_1 = {
                            'tick': tick,
                            'ss_table_name': 'ssit',
                            'ss_row': row,
                            'ss_op': 'read_valid',
                            'ss_value': ssid
                        }
                        event_2 = {
                            'tick': tick,
                            'ss_table_name': 'lfst',
                            'ss_row': ssid,
                            'ss_op': 'read_invalid',
                            'ss_value': '-'
                        }
                        instructions_dict[pc]['events'].append(event_1)
                        instructions_dict[pc]['events'].append(event_2)


                match = self.store_set_read_ssid_w_lfst.match(line)
                if match:
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        tick = match.group('tick')
                        row = match.group('row')
                        ssid = match.group('ssid')
                        self.modules['store_set'].log_event('ssit', 'read_valid', row)
                        self.modules['store_set'].log_event('lfst', 'read_valid', ssid)
                        event_1 = {
                            'tick': tick,
                            'ss_table_name': 'ssit',
                            'ss_row': row,
                            'ss_op': 'read_valid',
                            'ss_value': ssid
                        }
                        event_2 = {
                            'tick': tick,
                            'ss_table_name': 'lfst',
                            'ss_row': ssid,
                            'ss_op': 'read_valid',
                            'ss_value': '-'
                        }
                        instructions_dict[pc]['events'].append(event_1)
                        instructions_dict[pc]['events'].append(event_2)


                match = self.store_set_violation_case1.match(line)
                if match:
                    pc_load = match.group('pc_load')
                    pc_store = match.group('pc_store')
                    if pc_load in instructions_dict and pc_store in instructions_dict:
                        tick = match.group('tick')
                        row_load = match.group('row_load')
                        row_store = match.group('row_store')
                        ssid = match.group('ssid')
                        self.modules['store_set'].log_event('ssit', 'read_invalid', row_load)
                        self.modules['store_set'].log_event('ssit', 'read_invalid', row_store)
                        self.modules['store_set'].log_event('ssit', 'write_invalid', row_load)
                        self.modules['store_set'].log_event('ssit', 'write_invalid', row_store)

                        event_1 = {
                            'tick': tick,
                            'ss_table_name': 'ssit',
                            'ss_row': row_load,
                            'ss_op': 'read_invalid',
                            'ss_value': '-'
                        }
                        event_2 = {
                            'tick': tick,
                            'ss_table_name': 'ssit',
                            'ss_row': row_store,
                            'ss_op': 'read_invalid',
                            'ss_value': '-'
                        }
                        event_3 = {
                            'tick': tick,
                            'ss_table_name': 'ssit',
                            'ss_row': row_load,
                            'ss_op': 'write_invalid',
                            'ss_value': ssid
                        }
                        event_4 = {
                            'tick': tick,
                            'ss_table_name': 'ssit',
                            'ss_row': row_store,
                            'ss_op': 'write_invalid',
                            'ss_value': ssid
                        }
                        instructions_dict[pc_load]['events'].append(event_1)
                        instructions_dict[pc_store]['events'].append(event_2)
                        instructions_dict[pc_load]['events'].append(event_3)
                        instructions_dict[pc_store]['events'].append(event_4)



                match = self.store_set_violation_case2.match(line)
                if match:
                    pc_load = match.group('pc_load')
                    pc_store = match.group('pc_store')
                    if pc_load in instructions_dict and pc_store in instructions_dict:
                        tick = match.group('tick')
                        row_load = match.group('row_load')
                        row_store = match.group('row_store')
                        ssid = match.group('ssid')
                        self.modules['store_set'].log_event('ssit', 'read_valid', row_load)
                        self.modules['store_set'].log_event('ssit', 'read_invalid', row_store)
                        self.modules['store_set'].log_event('ssit', 'write_invalid', row_store)

                        event_1 = {
                            'tick': tick,
                            'ss_table_name': 'ssit',
                            'ss_row': row_load,
                            'ss_op': 'read_valid',
                            'ss_value': ssid
                        }
                        event_2 = {
                            'tick': tick,
                            'ss_table_name': 'ssit',
                            'ss_row': row_store,
                            'ss_op': 'read_invalid',
                            'ss_value': '-'
                        }
                        event_3 = {
                            'tick': tick,
                            'ss_table_name': 'ssit',
                            'ss_row': row_store,
                            'ss_op': 'write_invalid',
                            'ss_value': ssid
                        }
                        instructions_dict[pc_load]['events'].append(event_1)
                        instructions_dict[pc_store]['events'].append(event_2)
                        instructions_dict[pc_store]['events'].append(event_3)


                match = self.store_set_violation_case3.match(line)
                if match:
                    pc_load = match.group('pc_load')
                    pc_store = match.group('pc_store')
                    if pc_load in instructions_dict and pc_store in instructions_dict:
                        tick = match.group('tick')
                        row_load = match.group('row_load')
                        row_store = match.group('row_store')
                        ssid = match.group('ssid')
                        self.modules['store_set'].log_event('ssit', 'read_invalid', row_load)
                        self.modules['store_set'].log_event('ssit', 'read_valid', row_store)
                        self.modules['store_set'].log_event('ssit', 'write_invalid', row_load)

                        event_1 = {
                            'tick': tick,
                            'ss_table_name': 'ssit',
                            'ss_row': row_load,
                            'ss_op': 'read_invalid',
                            'ss_value': '-'
                        }
                        event_2 = {
                            'tick': tick,
                            'ss_table_name': 'ssit',
                            'ss_row': row_store,
                            'ss_op': 'read_valid',
                            'ss_value': ssid
                        }
                        event_3 = {
                            'tick': tick,
                            'ss_table_name': 'ssit',
                            'ss_row': row_load,
                            'ss_op': 'write_invalid',
                            'ss_value': ssid
                        }
                        instructions_dict[pc_load]['events'].append(event_1)
                        instructions_dict[pc_store]['events'].append(event_2)
                        instructions_dict[pc_store]['events'].append(event_3)

                # load has smaller set number
                match = self.store_set_violation_case4_0.match(line)
                if match:
                    pc_load = match.group('pc_load')
                    pc_store = match.group('pc_store')
                    if pc_load in instructions_dict and pc_store in instructions_dict:
                        tick = match.group('tick')
                        row_load = match.group('row_load')
                        row_store = match.group('row_store')
                        ssid_load = match.group('ssid_load')
                        ssid_store = match.group('ssid_store')
                        self.modules['store_set'].log_event('ssit', 'read_valid', row_load)
                        self.modules['store_set'].log_event('ssit', 'read_valid', row_store)
                        self.modules['store_set'].log_event('ssit', 'write_valid', row_store)

                        event_1 = {
                            'tick': tick,
                            'ss_table_name': 'ssit',
                            'ss_row': row_load,
                            'ss_op': 'read_valid',
                            'ss_value': ssid_load

                        }
                        event_2 = {
                            'tick': tick,
                            'ss_table_name': 'ssit',
                            'ss_row': row_store,
                            'ss_op': 'read_valid',
                            'ss_value': ssid_store
                        }
                        event_3 = {
                            'tick': tick,
                            'ss_table_name': 'ssit',
                            'ss_row': row_store,
                            'ss_op': 'write_valid',
                            'ss_value': ssid_load
                        }
                        instructions_dict[pc_load]['events'].append(event_1)
                        instructions_dict[pc_store]['events'].append(event_2)
                        instructions_dict[pc_store]['events'].append(event_3)

                match = self.store_set_violation_case4_1.match(line)
                if match:
                    pc_load = match.group('pc_load')
                    pc_store = match.group('pc_store')
                    if pc_load in instructions_dict and pc_store in instructions_dict:
                        tick = match.group('tick')
                        row_load = match.group('row_load')
                        row_store = match.group('row_store')
                        ssid_load = match.group('ssid_load')
                        ssid_store = match.group('ssid_store')
                        self.modules['store_set'].log_event('ssit', 'read_valid', row_load)
                        self.modules['store_set'].log_event('ssit', 'read_valid', row_store)
                        self.modules['store_set'].log_event('ssit', 'write_valid', row_load)

                        event_1 = {
                            'tick': tick,
                            'ss_table_name': 'ssit',
                            'ss_row': row_load,
                            'ss_op': 'read_valid',
                            'ss_value': ssid_load
                        }
                        event_2 = {
                            'tick': tick,
                            'ss_table_name': 'ssit',
                            'ss_row': row_store,
                            'ss_op': 'read_valid',
                            'ss_value': ssid_store
                        }
                        event_3 = {
                            'tick': tick,
                            'ss_table_name': 'ssit',
                            'ss_row': row_load,
                            'ss_op': 'write_valid',
                            'ss_value': ssid_store
                        }
                        instructions_dict[pc_load]['events'].append(event_1)
                        instructions_dict[pc_store]['events'].append(event_2)
                        instructions_dict[pc_store]['events'].append(event_3)


                match = self.store_set_invalidate_lfst.match(line)
                if match:
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        tick = match.group('tick')
                        ssid = match.group('ssid')
                        self.modules['store_set'].log_event('lfst', 'invalidate', ssid)
                        event_1 = {
                            'tick': tick,
                            'ss_table_name': 'lfst',
                            'ss_row': ssid,
                            'ss_op': 'invalidate',
                            'ss_value': '-'
                        }
                        instructions_dict[pc]['events'].append(event_1)

                match = self.store_set_validate_lfst.match(line)
                if match:
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        tick = match.group('tick')
                        ssid = match.group('ssid')
                        self.modules['store_set'].log_event('lfst', 'write_invalid', ssid)
                        event_1 = {
                            'tick': tick,
                            'ss_table_name': 'lfst',
                            'ss_row': ssid,
                            'ss_op': 'write_invalid',
                            'ss_value': '-'
                        }
                        instructions_dict[pc]['events'].append(event_1)


                match = self.store_set_replace_lfst.match(line)
                if match:
                    pc = match.group('pc')
                    if pc in instructions_dict:
                        tick = match.group('tick')
                        ssid = match.group('ssid')
                        self.modules['store_set'].log_event('lfst', 'write_valid', ssid)

                        event_1 = {
                            'tick': tick,
                            'ss_table_name': 'lfst',
                            'ss_row': ssid,
                            'ss_op': 'write_valid',
                            'ss_value': '-'
                        }
                        instructions_dict[pc]['events'].append(event_1)


                # ============ cache ============
                # cache_attributes = ['cahce_name', 'cahce_set', 'cahce_way', 'cahce_operation', 'addr', 'block_addr']
                match = self.cache_access.match(line)
                if match:
                    # print(line)
                    pc = match.group('pc')
                    tick = match.group('tick')
                    cache = match.group('cache')
                    kind = match.group('kind')
                    set = match.group('set')
                    way = match.group('way')
                    addr = match.group('addr')
                    block_addr = match.group('block_addr')


                    # if kind == "WriteMiss" and cache == "l2cache":
                    #     print("===")
                    #     print(line)
                    #     print("===")

                    if pc in instructions_dict:

                        if kind in ["ReadHit", "WriteHit"]:
                            self.modules[cache].log_event(set, way, kind)
                        elif kind in ["ReadMiss", "WriteMiss"]:
                            for i in range(self.modules[cache].num_way):
                                self.modules[cache].log_event(set, i, kind)



                        event = {
                            'tick': tick,
                            'cahce_name': cache,
                            'cahce_set': set,
                            'cahce_way': way,
                            'cahce_operation': kind,
                            'addr': addr,
                            'block_addr': block_addr
                        }
                        instructions_dict[pc]['events'].append(event)
                        instructions_dict[pc]['inst_attributes']['mem_addr'] = addr


                match = self.cache_evict.match(line)
                if match:
                    pc = match.group('trigpc')

                    tick = match.group('tick')
                    cache = match.group('cache')
                    kind = match.group('kind')
                    set = match.group('set')
                    way = match.group('way')
                    addr = '-'
                    block_addr = match.group('addr')
                    if kind in ["EvictClean", "EvictDirty"]:
                        self.modules[cache].log_event(set, way, kind)

                    if pc in instructions_dict:
                        event = {
                            'tick': tick,
                            'cahce_name': cache,
                            'cahce_set': set,
                            'cahce_way': way,
                            'cahce_operation': kind,
                            'addr': addr,
                            'block_addr': block_addr
                        }
                        instructions_dict[pc]['events'].append(event)
                        # instructions_dict[pc]['inst_attributes']['mem_addr'] = addr


            # # update values in the register
            # if instr['computed_data']:
            #     computed_data_decimal = hex_to_decimal_2s_complement(instr['computed_data'])
            #     register_file_module.update_value(res['destination'], computed_data_decimal)
            """
            Generate the annotation table
            """
            if self.annotation_table_path:
                rows_list = []
                for pc in sorted(instructions_dict):
                    events = instructions_dict[pc]['events']
                    if events:
                        for event in events:
                            row = {key: '-' for key in cols}
                            for k, v in instructions_dict[pc]['inst_attributes'].items():
                                row[k] = v
                            for k, v in event.items():
                                row[k] = v
                            rows_list.append(row)
                    else:
                        row = {key: '-' for key in cols}
                        for k, v in instructions_dict[pc]['inst_attributes'].items():
                            row[k] = v

                df = pd.DataFrame(rows_list)
                df.to_csv(self.annotation_table_path, mode='w', index=False)


    def coverage_report(self, module_name, path):
        print(f'=== Coverage measure of {module_name}: ===')
        coverage_measure = self.modules[module_name].coverage_report(path)
        print(coverage_measure)
        # print(target_module.uncovered_events)
        return coverage_measure
