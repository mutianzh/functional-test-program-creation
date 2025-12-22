import re
import math
import os
import random
import subprocess
import pandas as pd
import numpy as np
import csv

from modules import *


gem5_path = "/home/mutianzh-debug/gem5-extension"

"""
regular expressions for parsing spike log
"""
instruction_line_regex = re.compile(
        r'core\s+(\d+):\s+(0x[0-9a-fA-F]+)\s+\((0x[0-9a-fA-F]+)\)\s+(\w+)\s+(.+)'
    )

register_update_regex = re.compile(
    r'core\s+'  # Match 'core' followed by one or more spaces
    r'(\d+):\s+'  # Capture core number followed by ':' and spaces
    r'(\d+)\s+'  # Capture privilege level
    r'(0x[0-9a-fA-F]+)\s+'  # Capture PC address in hexadecimal
    r'\((0x[0-9a-fA-F]+)\)\s+'  # Capture instruction encoding in parentheses
    r'(x\d+)\s+'  # Capture register name (e.g., x30)
    r'(0x[0-9a-fA-F]+)'  # Capture register value in hexadecimal
)

memory_update_regex = re.compile(
    r'core\s+'                      # Match 'core' followed by spaces
    r'(\d+):\s+'                    # Capture core number
    r'(\d+)\s+'                     # Capture privilege level
    r'(0x[0-9a-fA-F]+)\s+'          # Capture PC address
    r'\((0x[0-9a-fA-F]+)\)\s+'      # Capture instruction encoding inside parentheses
    r'mem\s+'                       # Match 'mem' followed by spaces
    r'(0x[0-9a-fA-F]+)\s+'          # Capture memory address
    r'(0x[0-9a-fA-F]+)'             # Capture memory updated value
)

memory_load_regex = re.compile(
    r'core\s+'  # Match 'core' followed by spaces
    r'(\d+):\s+'  # Capture core number
    r'(\d+)\s+'  # Capture privilege level
    r'(0x[0-9a-fA-F]+)\s+'  # Capture PC address
    r'\((0x[0-9a-fA-F]+)\)\s+'  # Capture instruction encoding inside parentheses
    r'(x\d+)\s+'  # Capture register name
    r'(0x[0-9a-fA-F]+)\s+'  # Capture register value
    r'mem\s+(0x[0-9a-fA-F]+)'  # Capture memory address after 'mem'
)

"""
Regular for parsing gem5 log
"""





"""
IO functions
"""
def write_list_to_file(filename, string_list):
    with open(filename, 'w') as file:
        for string in string_list:
            file.write(string + '\n')


"""
data form converstion
"""
def hex_to_signed_32bit(hex_string):
    # Convert the hex string to an integer
    unsigned_value = int(hex_string, 16)

    # If the unsigned value is larger than or equal to 2^31, it's negative in a 32-bit signed context
    if unsigned_value >= 0x80000000:
        return unsigned_value - 0x100000000  # Convert to signed by subtracting 2^32
    else:
        return unsigned_value

def hex_to_unsigned_32bit(hex_string):
    # Convert the hex string to an integer
    unsigned_value = int(hex_string, 16)
    return unsigned_value


def hex_to_decimal_2s_complement(hex_str, bits=64):
    # Convert hex string to integer
    num = int(hex_str, 16)
    # Check if the number is negative (MSB is 1)
    if num >= 2 ** (bits - 1):
        # Convert to negative two's complement
        num -= 2 ** bits
    return num


def signed_binary_to_decimal(binary_array):
    # Check if the most significant bit is 1 (negative number)
    if binary_array[0] == 1:
        # Calculate the two's complement to find the negative decimal value
        inverted_bits = [1 - bit for bit in binary_array]
        binary_string = ''.join(str(bit) for bit in inverted_bits)
        decimal_number = int(binary_string, 2) + 1
        return -decimal_number
    else:
        # Positive number, directly convert to decimal
        binary_string = ''.join(str(bit) for bit in binary_array)
        decimal_number = int(binary_string, 2)
        return decimal_number


def hex_to_bin(hex_string):
    return bin(int(hex_string, 16))[2:]


def unsigned_dec_to_signed_dec(value, bits=64) -> int:
    """
    Converts an unsigned integer to a signed integer.

    :param value: The unsigned integer to convert.
    :param bits: The number of bits of the integer. Default is 64.
    :return: The signed integer equivalent.
    """
    max_unsigned = 1 << bits  # 2^bits
    max_signed = 1 << (bits - 1)  # 2^(bits-1)

    # If the value exceeds or equals the max_signed range, convert it.
    if value >= max_signed:
        return value - max_unsigned
    return value


def decimal_to_32bit_binary(n) -> str:
    """
    Converts a signed decimal integer to its 32-bit binary representation using two's complement.

    Parameters:
    n (int): The signed decimal integer to convert. Must be within the 32-bit signed integer range.

    Returns:
    str: A 32-character string representing the binary form of the input integer.

    Raises:
    TypeError: If the input is not an integer.
    ValueError: If the input is outside the 32-bit signed integer range.
    """
    # Check if input is an integer
    if not isinstance(n, int):
        raise TypeError("Input must be an integer.")

    # Define 32-bit signed integer range
    MIN_INT = -2**31
    MAX_INT = 2**31 - 1

    # Check if input is within the 32-bit signed integer range
    if n < MIN_INT or n > MAX_INT:
        raise ValueError(f"Input must be within 32-bit signed integer range ({MIN_INT} to {MAX_INT}).")

    # For positive numbers and zero
    if n >= 0:
        binary_str = format(n, '032b')
    else:
        # Compute two's complement for negative numbers
        # Add 2^32 to make it positive in the unsigned 32-bit space
        binary_str = format((1 << 32) + n, '032b')

    return binary_str


"""
Instruction Parsing
"""

def get_instruction_type(mnemonic):
    # Dictionary mapping mnemonics to instruction types
    instruction_types = {
        # R-type instructions
        'add': 'R-type', 'sub': 'R-type', 'and': 'R-type', 'or': 'R-type', 'xor': 'R-type',
        'sll': 'R-type', 'srl': 'R-type', 'sra': 'R-type', 'slt': 'R-type', 'sltu': 'R-type',
        'mul': 'R-type', 'mulh': 'R-type', 'mulhsu': 'R-type', 'mulhu': 'R-type', 'div': 'R-type',
        'divu': 'R-type', 'rem': 'R-type', 'remu': 'R-type',

        # I-type instructions (including immediate operations and load instructions)
        'addi': 'I-type', 'andi': 'I-type', 'ori': 'I-type', 'xori': 'I-type',
        'slti': 'I-type', 'sltiu': 'I-type', 'slli': 'I-type', 'srli': 'I-type', 'srai': 'I-type',

        # Load instructions (memory access, I-type)
        'lb': 'Load', 'lh': 'Load', 'lw': 'Load', 'lbu': 'Load', 'lhu': 'Load',

        # S-type instructions (store instructions for memory access)
        'sb': 'Store', 'sh': 'Store', 'sw': 'Store',

        # B-type instructions (branch instructions)
        'beq': 'B-type', 'bne': 'B-type', 'blt': 'B-type', 'bge': 'B-type', 'bltu': 'B-type', 'bgeu': 'B-type',

        # U-type instructions
        'lui': 'U-type', 'auipc': 'U-type',

        # J-type instructions
        'jal': 'J-type', 'jalr': 'J-type',

        # Fence-type and system instructions
        'fence': 'Fence-type', 'fence.i': 'Fence-type', 'ecall': 'System', 'ebreak': 'System'
    }

    # Return the instruction type if the mnemonic is in the dictionary, else return 'Unknown'
    return instruction_types.get(mnemonic, 'Unknown')


def get_instruction_code(mnemonic):
    # Dictionary mapping mnemonics to integer codes
    instruction_codes = {
        # R-type instructions
        'add': 1, 'sub': 2, 'and': 3, 'or': 4, 'xor': 5,
        'sll': 6, 'srl': 7, 'sra': 8, 'slt': 9, 'sltu': 10,
        'mul': 11, 'mulh': 12, 'mulhsu': 13, 'mulhu': 14, 'div': 15,
        'divu': 16, 'rem': 17, 'remu': 18,

        # I-type instructions
        'addi': 19, 'andi': 20, 'ori': 21, 'xori': 22,
        'slti': 23, 'sltiu': 24, 'slli': 25, 'srli': 26, 'srai': 27,

        # Load instructions (I-type)
        'lb': 28, 'lh': 29, 'lw': 30, 'lbu': 31, 'lhu': 32,

        # S-type instructions (Store)
        'sb': 33, 'sh': 34, 'sw': 35,

        # B-type instructions (Branch)
        'beq': 36, 'bne': 37, 'blt': 38, 'bge': 39, 'bltu': 40, 'bgeu': 41,

        # U-type instructions
        'lui': 42, 'auipc': 43,

        # J-type instructions
        'jal': 44, 'jalr': 45,

        # Fence and system instructions
        'fence': 46, 'fence.i': 47, 'ecall': 48, 'ebreak': 49
    }

    # Return the integer code if mnemonic is in the dictionary, else return -1
    return instruction_codes.get(mnemonic, -1)


def get_mnemonic(code):
    # Dictionary mapping mnemonics to integer codes
    instruction_codes = {
        'add': 1, 'sub': 2, 'and': 3, 'or': 4, 'xor': 5,
        'sll': 6, 'srl': 7, 'sra': 8, 'slt': 9, 'sltu': 10,
        'mul': 11, 'mulh': 12, 'mulhsu': 13, 'mulhu': 14, 'div': 15,
        'divu': 16, 'rem': 17, 'remu': 18, 'addi': 19, 'andi': 20,
        'ori': 21, 'xori': 22, 'slti': 23, 'sltiu': 24, 'slli': 25,
        'srli': 26, 'srai': 27, 'lb': 28, 'lh': 29, 'lw': 30,
        'lbu': 31, 'lhu': 32, 'sb': 33, 'sh': 34, 'sw': 35,
        'beq': 36, 'bne': 37, 'blt': 38, 'bge': 39, 'bltu': 40,
        'bgeu': 41, 'lui': 42, 'auipc': 43, 'jal': 44, 'jalr': 45,
        'fence': 46, 'fence.i': 47, 'ecall': 48, 'ebreak': 49
    }

    # Create a reverse mapping of codes to mnemonics
    code_to_mnemonic = {v: k for k, v in instruction_codes.items()}

    # Return the mnemonic if the code is in the dictionary, else return 'Unknown'
    return code_to_mnemonic.get(code, 'Unknown')


def get_type_code(type):
    type_codes = {
        'R-type': 1,
        'I-type': 2,
        'Load': 3,
        'Store': 4,
        'B-type': 5,
        'U-type': 6,
        'J-type': 7,
        'Fence-type': 8,
        'System': 9,
        'Unknown': -1
    }
    return type_codes[type]


def parse_r_type(instruction):
    parts = instruction.split()
    mnemonic = parts[0]
    rd = parts[1].split(',')[0].strip()
    rs1 = parts[2].split(',')[0].strip()
    rs2 = parts[3].strip()
    return mnemonic, rd, rs1, rs2


def parse_i_type(instruction):
    parts = instruction.split()
    mnemonic = parts[0]
    rd = parts[1].split(',')[0].strip()
    rs1 = parts[2].split(',')[0].strip()
    imm = int(parts[3].strip())
    return mnemonic, rd, rs1, imm


def parse_u_type(instruction):
    parts = instruction.split()
    mnemonic = parts[0]
    rd = parts[1].split(',')[0].strip()
    imm = int(parts[2].strip())
    return mnemonic, rd, imm


def parse_b_type(instruction):
    parts = instruction.split()
    mnemonic = parts[0]
    rs1 = parts[1].strip().split(',')[0]
    rs2 = parts[2].strip().split(',')[0]
    offset_sign = parts[4].strip()
    offset = parts[5].strip()
    return mnemonic, rs1, rs2, offset_sign, offset


def parse_load_type(instruction):
    """
    Parses load-type instructions with the format: mnemonic rd, offset(rs1)
    """
    try:
        parts = instruction.split()
        mnemonic = parts[0]
        rd = parts[1].split(',')[0].strip()
        offset, rs1 = parts[2].split('(')
        rs1 = rs1.strip(')')
        return mnemonic, rd, int(offset), rs1
    except (IndexError, ValueError):
        raise ValueError("Instruction format is incorrect for Load-type.")


def parse_store_type(instruction):
    """
    Parses store-type instructions with the format: mnemonic rs2, offset(rs1)
    """
    try:
        parts = instruction.split()
        mnemonic = parts[0]
        rs2 = parts[1].split(',')[0].strip()
        offset, rs1 = parts[2].split('(')
        rs1 = rs1.strip(')')
        return mnemonic, rs2, int(offset), rs1
    except (IndexError, ValueError):
        raise ValueError("Instruction format is incorrect for Store-type.")


parse_functions = {
    'R-type': parse_r_type,
    'I-type': parse_i_type,
    'B-type': parse_b_type,
    'Load': parse_load_type,
    'Store': parse_store_type
}

# def get_branch_result(mnemonic, rs1, rs2, registers):
def get_branch_result(mnemonic, v1, v2):
    # v1 = registers[abi_to_register[rs1]]
    # v2 = registers[abi_to_register[rs2]]
    branch_instruction = mnemonic.upper()

    if branch_instruction == 'BEQ':
        # Branch if equal: branch is taken if v1 == v2
        return v1 == v2

    elif branch_instruction == 'BNE':
        # Branch if not equal: branch is taken if v1 != v2
        return v1 != v2

    elif branch_instruction == 'BLT':
        # Branch if less than (signed): branch is taken if v1 < v2 (signed comparison)
        return v1 < v2

    elif branch_instruction == 'BGE':
        # Branch if greater than or equal (signed): branch is taken if v1 >= v2 (signed comparison)
        return v1 >= v2

    elif branch_instruction == 'BLTU':
        # Branch if less than (unsigned): branch is taken if v1 < v2 (unsigned comparison)
        return (v1 & 0xFFFFFFFF) < (v2 & 0xFFFFFFFF)

    elif branch_instruction == 'BGEU':
        # Branch if greater than or equal (unsigned): branch is taken if v1 >= v2 (unsigned comparison)
        return (v1 & 0xFFFFFFFF) >= (v2 & 0xFFFFFFFF)

    else:
        raise ValueError(f"Unknown branch instruction: {branch_instruction}")




def transform_abi_to_register(reg_name):
    abi_to_register = {
        'zero': 'x0',  # Hard-wired zero
        'ra': 'x1',  # Return address
        'sp': 'x2',  # Stack pointer
        'gp': 'x3',  # Global pointer
        'tp': 'x4',  # Thread pointer
        't0': 'x5',  # Temporary/alternate link register
        't1': 'x6',  # Temporaries
        't2': 'x7',  # Temporaries
        's0': 'x8',  # Saved register/frame pointer
        'fp': 'x8',  # Frame pointer (alias for s0)
        's1': 'x9',  # Saved register
        'a0': 'x10',  # Function argument / return value
        'a1': 'x11',  # Function argument / return value
        'a2': 'x12',  # Function argument
        'a3': 'x13',  # Function argument
        'a4': 'x14',  # Function argument
        'a5': 'x15',  # Function argument
        'a6': 'x16',  # Function argument
        'a7': 'x17',  # Function argument
        's2': 'x18',  # Saved register
        's3': 'x19',  # Saved register
        's4': 'x20',  # Saved register
        's5': 'x21',  # Saved register
        's6': 'x22',  # Saved register
        's7': 'x23',  # Saved register
        's8': 'x24',  # Saved register
        's9': 'x25',  # Saved register
        's10': 'x26',  # Saved register
        's11': 'x27',  # Saved register
        't3': 'x28',  # Temporaries
        't4': 'x29',  # Temporaries
        't5': 'x30',  # Temporaries
        't6': 'x31'  # Temporaries
    }
    if reg_name in abi_to_register:
        return abi_to_register[reg_name]
    else:
        return reg_name

print(transform_abi_to_register('zero'))



abi_to_register = {
    'zero': 'x0',  # Hard-wired zero
    'ra':   'x1',  # Return address
    'sp':   'x2',  # Stack pointer
    'gp':   'x3',  # Global pointer
    'tp':   'x4',  # Thread pointer
    't0':   'x5',  # Temporary/alternate link register
    't1':   'x6',  # Temporaries
    't2':   'x7',  # Temporaries
    's0':   'x8',  # Saved register/frame pointer
    'fp':   'x8',  # Frame pointer (alias for s0)
    's1':   'x9',  # Saved register
    'a0':   'x10', # Function argument / return value
    'a1':   'x11', # Function argument / return value
    'a2':   'x12', # Function argument
    'a3':   'x13', # Function argument
    'a4':   'x14', # Function argument
    'a5':   'x15', # Function argument
    'a6':   'x16', # Function argument
    'a7':   'x17', # Function argument
    's2':   'x18', # Saved register
    's3':   'x19', # Saved register
    's4':   'x20', # Saved register
    's5':   'x21', # Saved register
    's6':   'x22', # Saved register
    's7':   'x23', # Saved register
    's8':   'x24', # Saved register
    's9':   'x25', # Saved register
    's10':  'x26', # Saved register
    's11':  'x27', # Saved register
    't3':   'x28', # Temporaries
    't4':   'x29', # Temporaries
    't5':   'x30', # Temporaries
    't6':   'x31'  # Temporaries
}

int_to_register = {
    0: 'zero', 1: 'ra', 2: 'sp', 3: 'gp', 4: 'tp',
    5: 't0', 6: 't1', 7: 't2', 8: 'fp', 9: 's1',
    10: 'a0', 11: 'a1', 12: 'a2', 13: 'a3',
    14: 'a4', 15: 'a5', 16: 'a6', 17: 'a7',
    18: 's2', 19: 's3', 20: 's4', 21: 's5',
    22: 's6', 23: 's7', 24: 's8', 25: 's9',
    26: 's10', 27: 's11', 28: 't3', 29: 't4',
    30: 't5', 31: 't6'
}



def encode_transition_BP(s, d):
    if s==0 and d==0:
        return 0

    if s==0 and d==1:
        return 1

    if s == 1 and d == 2:
        return 2

    if s == 2 and d == 3:
        return 3

    if s == 3 and d == 3:
        return 4

    if s == 3 and d == 2:
        return 5

    if s == 2 and d == 1:
        return 6

    if s == 1 and d == 0:
        return 7


def remove_nan_from_set(values):
    """
    Removes all NaN values from a given set.

    Args:
        values (set): A set containing elements, possibly including NaN values.

    Returns:
        set: A new set with NaN values removed.
    """
    return {x for x in values if not (isinstance(x, float) and math.isnan(x))}

"""
Create test template
"""

# Spike
def add_starters(code):
    starter = []
    starter.append('.section ".tohost","aw",@progbits')
    starter.append('.align 4')
    starter.append('.globl tohost')
    starter.append('tohost: .dword 0')
    starter.append('.align 4')
    starter.append('.globl fromhost')
    starter.append('')
    starter.append('fromhost: .dword 0')
    starter.append('        .section .text')
    starter.append('        .globl _start')
    starter.append('_start:')
    code = starter + code
    return code


def exit_program(code):
    code.append('write_tohost:')
    code.append('        la      t1, tohost')
    code.append('        li      t2, 1')
    code.append('        sw      t2, 0(t1)')
    return code

# Gem5

def add_starters_gem5(code):
    starter = []
    starter.append('user_stack_end:')
    starter.append('init:')
    code = starter + code
    return code


def load_immediate_32(imm, reg='t0'):
    """
    Generate RISC-V assembly instructions to load a signed 32-bit integer `imm`
    into register `reg` without using the pseudo-instruction 'li'.
    This version ensures that the immediate for `lui` fits in the 20-bit unsigned range.
    """

    # If it fits in a signed 12-bit immediate (-2048 to 2047),
    # we can use a single addi from x0.
    if -2048 <= imm <= 2047:
        return [f"addi {reg}, x0, {imm}"]

    # For larger values, we use LUI+ADDI.
    # Compute the upper 20 bits.
    # The (imm + 0x800) >> 12 trick helps with rounding toward the nearest representable upper part.
    upper_20 = (imm + 0x800) >> 12

    # Mask to 20 bits to ensure it fits in the 0..1048575 range.
    upper_20 &= 0xFFFFF

    # Extract and adjust the lower 12 bits.
    lower_12 = imm & 0xFFF
    if lower_12 & 0x800:  # if the sign bit of the 12-bit part is set, it represents a negative number
        lower_12 -= 0x1000

    instructions = []
    instructions.append(f"lui {reg}, {upper_20}")
    instructions.append(f"addi {reg}, {reg}, {lower_12}")
    return instructions


def register_files_initialization(code, init_value):
    register_names = [f'x{i}' for i in range(32)]
    value_range = [-2**(32-1), 2**(32-1)-1]

    init_code = []
    for name in register_names:
        if init_value == 'random':
            v = random.randint(value_range[0], value_range[1])
        elif init_value == 'zero':
            v = 0
        else:
            raise Exception("Undefined initial value")
        load_instr = load_immediate_32(v, name)
        for instr in load_instr:
            init_code.append(f'        {instr}')
        # init_code.append(f'        li      {name}, {v}')
    return init_code + code


def exit_program_gem5(code):
    code.append('exit:        li      a7, 93')
    code.append('        li a1, 0')
    code.append('        ecall')
    return code


def save_code(code, path):
    code_string = '\n'.join(code)
    f = open(path, "w")
    f.write(code_string)
    f.close()


def generate_data_section(region_name, size_kb):
    # Convert size from KB to bytes
    size_bytes = size_kb * 1024

    # Each `.word` in assembly occupies 4 bytes, so we calculate how many `.word` we need
    num_words = size_bytes // 4

    # Start generating the assembly code
    asm_code = f"""
.section .data
.align 1;
.globl {region_name}_start
{region_name}_start:
"""

    # Generate the `.word` entries, grouping 16 words per line
    words_per_line = 16
    for i in range(0, num_words, words_per_line):
        line_words = ", ".join("0x00000000" for _ in range(min(words_per_line, num_words - i)))
        asm_code += f"    .dword {line_words}\n"

    # Close the section with the region end label
    asm_code += f"{region_name}_end:\n"

    return asm_code


def add_data_section(code, region_name, size_kb):
    data_section = generate_data_section(region_name, size_kb)
    code.append(data_section)
    return code


def finalize(code):
    code = add_starters_gem5(code)
    code = exit_program_gem5(code)
    print(f'Length of code is {len(code)}')
    return code


"""
Simulate .S file with gem5
"""

# run gem5 simulation
def run_simulation(base_path, filename):
    """
    :param base_path: the path to the .S file and where the output log to be saved
    :param filename: name of the .S file: <filename>.S
    :return:
    """
    # save the program to a temp directory
    # Save the program to a .S file
    source_file = os.path.join(base_path, f"{filename}.S")
    object_file = os.path.join(base_path, f"{filename}.o")
    output_file = os.path.join(base_path, filename)

    # Compile the .S file
    # Assemble command
    assemble_command = [
        "riscv32-unknown-elf-as",
        # "-march=rv32im",
        # "-mabi=ilp32",
        "-o", object_file,
        source_file
    ]

    # Link command
    link_command = [
        "riscv32-unknown-elf-ld",
        "-o", output_file,
        object_file
    ]

    try:
        # Run the assemble command
        result_assemble = subprocess.run(
            assemble_command,
            capture_output=True,
            text=True
        )
        if result_assemble.returncode != 0:
            print(f"Assembly failed: {result_assemble.stderr}")
            return False

        # Run the link command
        result_link = subprocess.run(
            link_command,
            capture_output=True,
            text=True
        )
        if result_link.returncode != 0:
            print(f"Linking failed: {result_link.stderr}")
            return False

    except Exception as e:
        print(f"An error occurred: {e}")
        return False

    # Update gem5 python file
    input_python_file_path = f"{gem5_path}/configs/mutian/ooo_customize_fu_two_level_cache_riscv.py"
    output_python_file_path = f"{gem5_path}/configs/mutian/temp/{filename}.py"
    content = {}
    content["K_IntAlu"] = num_IntAlu
    content["K_MulAlu"] = num_MulAlu
    content["default_binary"] = f"{base_path}/{filename}"
    update_gem5_python(input_python_file_path, output_python_file_path, content)

    # run the .S file using gem5
    # run_command = f"build/RISCV/gem5.opt --debug-flags=StoreSet,Fetch,Instr,IQ,ROB,Commit,Rename,CacheAll,Registers --debug-file={base_path}/{filename}.out configs/mutian/temp/{filename}.py"
    run_command = f"build/RISCV/gem5.opt --debug-flags=Instr,O3CPUAll,CacheAll --debug-file={base_path}/{filename}.out configs/mutian/temp/{filename}.py"

    # result_run = subprocess.run(
    #     run_command,
    #     shell=True,
    #     cwd=gem5_path,
    #     capture_output=True,
    #     text=True,
    # )
    process = subprocess.Popen(
        run_command,
        shell=True,
        cwd=gem5_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    # Print gem5 output in real-time
    for line in process.stdout:
        print(line, end="")  # Avoid double newlines

    for line in process.stderr:
        print(line, end="")  # Print error messages

    process.wait()  # Wait for gem5 to finish execution


def gem5_simulation(file_path, dot_S_filename, python_filename):
    # compile .S file
    source_file = os.path.join(file_path, f"{dot_S_filename}.S")
    object_file = os.path.join(file_path, f"{dot_S_filename}.o")
    output_file = os.path.join(file_path, dot_S_filename)

    assemble_command = [
        "riscv32-unknown-elf-as",
        "-o", object_file,
        source_file
    ]

    # Link command
    link_command = [
        "riscv32-unknown-elf-ld",
        "-o", output_file,
        object_file
    ]

    try:
        # Run the assemble command
        result_assemble = subprocess.run(
            assemble_command,
            capture_output=True,
            text=True
        )
        if result_assemble.returncode != 0:
            print(f"Assembly failed: {result_assemble.stderr}")
            return False

        # Run the link command
        result_link = subprocess.run(
            link_command,
            capture_output=True,
            text=True
        )
        if result_link.returncode != 0:
            print(f"Linking failed: {result_link.stderr}")
            return False

    except Exception as e:
        print(f"An error occurred: {e}")
        return False

    # run the .S file using gem5
    run_command = f"build/RISCV/gem5.opt --debug-flags=Exec,FU --debug-file={file_path}/{dot_S_filename}.out configs/mutian/temp/{python_filename}.py"
    gem5_path = '/home/mutianzh/gem5'
    result_run = subprocess.run(
        run_command,
        shell=True,
        cwd=gem5_path,
        capture_output=True,
        text=True
        )
    return


def update_gem5_python(input_file_path, output_file_path, content):
    # Read the contents of the input file
    with open(input_file_path, "r") as file:
        file_content = file.readlines()

    # Modify the lines containing K_IntALU and default_binary
    modified_content = []
    for line in file_content:
        matched = False
        for key in content.keys():
            if line.strip().startswith(key):
                new_content = content[key]
                if isinstance(new_content, str):
                    modified_content.append(f'{key} = "{new_content}"\n')
                else:
                    modified_content.append(f'{key} = {new_content}\n')
                matched = True
                break

        if not matched:
            modified_content.append(line)

    # Write the modified content to the output file
    with open(output_file_path, "w") as file:
        file.writelines(modified_content)

    # print(f"Modified file saved to: {output_file_path}")


def gem5_simulate_program(base_path, program_name):
    """
    :param base_path:
    :param program_name:
    :return:
    simulate ./<base_address>/program_name.S
    create ./<base_address>/program_name.out
    """
    python_filename = f'temp_default'
    input_python_file_path = "/home/mutianzh/gem5/configs/mutian/ooo_customize_fu_two_level_cache_riscv.py"
    output_python_file_path = f"/home/mutianzh/gem5/configs/mutian/temp/{python_filename}.py"
    content = {}
    content["K_IntAlu"] = num_IntAlu
    content["K_MulAlu"] = num_MulAlu
    content["default_binary"] = f"{base_path}/{program_name}"
    update_gem5_python(input_python_file_path, output_python_file_path, content)
    gem5_simulation(file_path=f'{base_path}', dot_S_filename=program_name, python_filename=python_filename)
    return


"""
Simulate .S file with spike
"""

import os
def spike_simulate_assembly_file(path, file_name):
    # Extract file name without extension and directory for output naming
    riscv_file = f"{file_name}.riscv"
    instructions_file = f"{file_name}.S"
    log_file = f"{file_name}_log.txt"

    # Step 1: Compile the .S file into a .riscv binary
    compile_command = f"riscv32-unknown-elf-gcc -march=rv32im -mabi=ilp32 -static -o {path}{riscv_file} {path}{instructions_file} -T {path}link.ld -nostartfiles"
    os.system(compile_command)

    # # Step 2: Run spike to extract instructions only
    # spike_instructions_command = f"spike -l --isa rv32im {riscv_file} > {instructions_file} 2>&1"
    # os.system(spike_instructions_command)

    # Step 3: Run spike with log commits enabled to generate the test log
    spike_log_command = f"spike -l --log-commits --isa rv32im {path}{riscv_file} > {path}{log_file} 2>&1"
    os.system(spike_log_command)
    print(f"Completed processing for {file_name}")


"""
Datamining
"""
def generate_query_string(conditions):
    """
    :param conditions: col name: condition
    :return:
    """
    query_str = ' & '.join([f'{col}{cond}' for col, cond in conditions.items()])
    return query_str


def run_query(conditions, df):
    """
    :param conditions:
    :param df:
    :return:
    Example condition:
    conditions = {
        # 'L1_acc_type': '.notna()',
        # 'address': '==2147627064',
        # 'L2_hit': '== True',
        'L1_set': f'== {s}',
        # 'L1_way': '== 3',
        # 'L1_wb': '== True',
        # 'tag': '== 0',
        # 's': '==2',
        # 'd': '==1',
        #
        # 'pc':"=='0x8000b220'"
    }

    """
    query_str = generate_query_string(conditions)
    query_result = df.query(query_str)
    return query_result


def find_unique_rows(cols_to_analyze, df):
    unique_rows_count = df.groupby(cols_to_analyze).size().reset_index(name='Count')
    return unique_rows_count


"""
Parameterize holes in the coverage space
"""



"""
Circuit level shit
"""

def int_to_bits(n, width=None):
    """
    :param n: integer value in decimal
    :param width: number of bits
    :return: a list of value at each bit

    int_to_bits(3,2)
    [1,1]
    """
    # Convert to binary string (without '0b')
    n = int(n)
    b = bin(n)[2:]
    # Pad with leading zeros if width is specified
    if width:
        b = b.zfill(width)
    # Convert string to list of integers
    return [int(bit) for bit in b]



"""
Global Variables
"""

indent_str = '        '
