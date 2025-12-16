import random

def generate_dns_typo_payload():
    """
    Generates a raw bytes payload simulating various DNS 'typos'
    Based on 'Protocol Fuzzing' and 'DNS Attack Vectors' docs.
    """
    attack_type = random.choice(['length_mismatch', 'null_injection', 'gray_area'])
    
    if attack_type == 'length_mismatch':
        # Says length is 20, provides only 4 bytes [cite: 186]
        return b"\x14test" 
        
    elif attack_type == 'null_injection':
        # Injects NULL byte to confuse C string functions [cite: 192]
        return b"\x04te\x00t"
        
    elif attack_type == 'gray_area':
        # Uses label length bits 01xxxxxx (0x40-0xBF) [cite: 199]
        return b"\x45" + b"A"*5
    
    return b"\x03www" # Fallback
