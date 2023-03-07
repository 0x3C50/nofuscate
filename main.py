import argparse
import ast
import binascii
import bz2
import dis
import gzip
import lzma
import marshal
import zlib
from io import StringIO
from types import CodeType
from typing import IO
from ast import *
import struct
import sys


def _pack_uint32(val):
    """Convert integer to 32-bit little-endian bytes"""
    return struct.pack("<I", val)


def _code_to_bytecode(code, compile_time=0, source_size=0):
    """
    Serialise the passed code object (PyCodeObject*) to bytecode as a .pyc file
    The args compile_time and source_size are inconsequential metadata in the .pyc file.
    """

    # Get the magic number for the running Python version
    from importlib.util import MAGIC_NUMBER

    magic_number = MAGIC_NUMBER

    # Add the magic number that indicates the version of Python the bytecode is for
    #
    # The .pyc may not decompile if this four-byte value is wrong. Either hardcode the
    # value for the target version (eg. b'\x33\x0D\x0D\x0A' instead of MAGIC_NUMBER)
    data = bytearray(magic_number)

    # Handle extra 32-bit field in header from Python 3.7 onwards
    # See: https://www.python.org/dev/peps/pep-0552
    if sys.version_info >= (3, 7):
        # Blank bit field value to indicate traditional pyc header
        data.extend(_pack_uint32(0))

    data.extend(_pack_uint32(int(compile_time)))

    # Handle extra 32-bit field for source size from Python 3.2 onwards
    # See: https://www.python.org/dev/peps/pep-3147/
    if sys.version_info >= (3, 2):
        data.extend(_pack_uint32(source_size))

    data.extend(code)

    return data


def parse_args():
    parser = argparse.ArgumentParser(
        prog="NoFuscate", description="Defeating Py-Fuscate, one decompress a time"
    )
    parser.add_argument(
        "-i",
        "--input",
        type=argparse.FileType("r", encoding="utf8"),
        required=True,
        help="The py-fuscate obfuscated input (NOT compiled; source code)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=argparse.FileType("wb"),
        required=True,
        help="The output file",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["disassembly", "marshal", "pyc"],
        default="disassembly",
        help="Which format to write to the output file",
    )
    return parser.parse_args()


known_compressors = {
    "lzma": lambda x: lzma.decompress(x),
    "gzip": lambda x: gzip.decompress(x),
    "bz2": lambda x: bz2.decompress(x),
    "binascii": lambda x: binascii.a2b_base64(x),
    "zlib": lambda x: zlib.decompress(x),
}


def check_ast_isinst(a, expected, text):
    if not isinstance(a, expected):
        print(
            f"[-] {text} - please report this to the author, "
            "INCLUDING THE FOLLOWING TEXT:"
        )
        if isinstance(a, AST):
            print(ast.dump(a, indent=2))
        else:
            print("(not an ast object, is of type " + str(type(a).mro()) + ")")
        exit(1)


def is_obfuscated(b: bytes):
    all_insns = list(dis.Bytecode(marshal.loads(b)))
    for i in range(len(all_insns) - 2):
        current_insn: dis.Instruction = all_insns[i]
        next_insn: dis.Instruction = all_insns[i + 1]
        next_next_insn: dis.Instruction = all_insns[i + 2]
        if (
            current_insn.opname == "LOAD_NAME"
            and current_insn.argval in known_compressors
            and next_insn.opname == "LOAD_ATTR"
            and next_insn.argval in ("decompress", "a2b_base64")
            and next_next_insn.opname == "LOAD_CONST"
            and type(next_next_insn.argval) == bytes
        ):
            # this has a decompressor, assume obfuscated
            return True
    return False


def deobfuscate_recursive(b: bytes):
    all_insns = list(dis.Bytecode(marshal.loads(b)))
    for i in range(len(all_insns) - 2):
        current_insn: dis.Instruction = all_insns[i]
        next_insn: dis.Instruction = all_insns[i + 1]
        next_next_insn: dis.Instruction = all_insns[i + 2]
        if (
            current_insn.opname == "LOAD_NAME"
            and current_insn.argval in known_compressors
            and next_insn.opname == "LOAD_ATTR"
            and next_insn.argval in ("decompress", "a2b_base64")
            and next_next_insn.opname == "LOAD_CONST"
            and type(next_next_insn.argval) == bytes
        ):
            decompr = known_compressors[current_insn.argval]
            decompressed = decompr(next_next_insn.argval)
            print(
                "[*] Stripped one layer with "
                + current_insn.argval
                + "."
                + next_insn.argval
            )
            if is_obfuscated(decompressed):
                return deobfuscate_recursive(decompressed)
            else:
                return decompressed
    return None


def deobfuscate_initial(a: AST):
    found = None
    found_decompr = None
    for x in ast.walk(a):
        if (
            isinstance(x, Call)
            and isinstance(x.func, Name)
            and x.func.id == "exec"
            and len(x.args) == 1
        ):
            z = x.args[0]
            if not isinstance(z, Call):
                continue
            if len(z.args) != 1:
                continue
            decompressor = z.args[0]
            if not isinstance(decompressor, Call):
                continue
            if len(decompressor.args) != 1:
                continue
            if not isinstance(decompressor.func, Attribute):
                continue
            val = decompressor.func.value
            if not isinstance(val, Name):
                continue
            print("[+] Found exec()")
            found = val
            found_decompr = decompressor
            break
    if found is None or found_decompr is None:
        print(
            "[-] Didn't find any appropiate exec() calls - please report this to the author, and include the "
            "file you tried to deobfuscate"
        )
        exit(1)
    if found.id not in known_compressors:
        print(
            "[-] Unknown decompressor "
            + ast.unparse(found_decompr.func)
            + ", please report this to the author, including the py file you tried to deobfuscate"
        )
        exit(1)
    dc = known_compressors[found.id]
    content = found_decompr.args[0]
    check_ast_isinst(content, Constant, "decompressor content wasn't a constant")
    assert isinstance(content, Constant)
    vl = bytes(content.value)
    decompressed_bytes = bytes(dc(vl))
    if is_obfuscated(decompressed_bytes):
        print("[*] Initial loader has more stages, continuing as expected")
        return deobfuscate_recursive(decompressed_bytes)
    else:
        print("[*] Just one stage was enough..? Alright then")
        return decompressed_bytes


def _handle_disassembly(m: CodeType, f: IO):
    t = StringIO()
    dis.dis(m, file=t)
    f.write(t.getvalue().encode("utf8"))


format_handlers = {
    "disassembly": _handle_disassembly,
    "marshal": lambda m, f: f.write(marshal.dumps(m)),
    "pyc": lambda m, f: f.write(_code_to_bytecode(marshal.dumps(m))),
}


def main():
    args = parse_args()
    inp_file: IO = args.input
    out_file: IO = args.output
    fmt: str = args.format
    src = inp_file.read()

    parsed_ast = ast.parse(src)

    deobfuscated = deobfuscate_initial(parsed_ast)
    if deobfuscated is None:
        print(
            "[-] Failed to deobfuscate: Pattern failed. Please submit this error AND the file you tried to"
            " deobfuscate to the author"
        )
        exit(1)

    ld: CodeType = marshal.loads(deobfuscated)
    # remove branding :^)
    ld = ld.replace(co_filename="nofuscate")
    handler = format_handlers[fmt]
    handler(ld, out_file)
    print("[+] OK, output written to " + out_file.name)


if __name__ == "__main__":
    main()
