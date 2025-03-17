# This removes the following type of obfuscation
"""
180012d12  50                 push    rax
180012d13  0f8403fcffff       je      0x18001291c   <---- Jumping here
180012d19  90                 nop                   <---- Junk Code
180012d1a  0f85fcfbffff       jne     0x18001291c   <---- JJumping here again 
180012d20  0f82d4e1ffff       jb      0x180010efa   <---- Unreachable code
180012d26  48832600           and     qword [rsi], 0x0
180012d2a  f6c100             test    cl, 0x0
180012d2d  e8e73affff         call    sub_180006819
180012d32  c3                 retn    
"""

jcc_instructions = [
    "jae", "je", "jge", "jnb", "jnc", "jnl", "jno", "jns", "jp", "jpe", "jz",
    "ja", "jb", "jbe", "jc", "jg", "jl", "jle", "jna", "jnae", "jnbe", "jne",
    "jnge", "jnle", "jnp", "jnz", "jo", "jpo", "js"
]
# maps from one jump to the opposite including those with multiple instrucitons that does
# the same thing
opposite_jumps = {
    "je": ["jne", "jnz"], "jne": ["je", "jz"], "jz": ["jne", "jnz"], "jnz": ["je", "jz"],
    "ja": ["jbe", "jna"], "jbe": ["ja", "jnbe"], "jnbe": ["jbe", "jna"], "jna": ["ja", "jnbe"],
    "jae": ["jb", "jnae", "jc"], "jb": ["jae", "jnb", "jnc"], "jnb": ["jb", "jc"], "jnae": ["jae", "jnb"],
    "jc": ["jnc", "jnb"], "jnc": ["jc", "jb"],
    "jg": ["jle", "jng"], "jle": ["jg", "jnle"], "jnle": ["jle", "jng"], "jng": ["jg", "jnle"],
    "jge": ["jl", "jnge"], "jl": ["jge", "jnl"], "jnl": ["jl"], "jnge": ["jge", "jnl"],
    "jp": ["jnp", "jpo"], "jnp": ["jp", "jpe"], "jpe": ["jpo", "jnp"], "jpo": ["jpe", "jp"],
    "jo": ["jno"], "jno": ["jo"], "js": ["jns"], "jns": ["js"]
}
print("[+] Starting opaque predicate detection...")
patched_count = 0
for function in bv.functions:
    # function = bv.get_function_at(0x180005d55)
    print(f"[*] Analyzing function: {function.name} at {hex(function.start)} ")
    cond_jumps = {} # this stores all the jump mnemonic including the address of this and the target address
    # map all conditional jumps in the function
    blocks = function.basic_blocks
    for block in blocks:
        addr = block.start
        while addr < block.end:
            instr_text = bv.get_disassembly(addr)
            if not instr_text:
                # Move to next address if we couldn't get disassembly
                addr += 1
                continue
            # Check if jump instruction
            parts = instr_text.lower().split()
            if parts and parts[0] in jcc_instructions:
                mnemonic = parts[0]
                # Try to parse the target
                try:
                    target_text = parts[-1]  # target to jump to (rel32)
                    if '0x' in target_text:
                        target = int(target_text, 16)
                    else:
                        target = int(target_text)
                    cond_jumps[addr] = (mnemonic, target)
                    print(f"Found conditional jump: {hex(addr)}: {mnemonic} to {hex(target)}")
                except Exception as e:
                    print(f"Error parsing target at {hex(addr)}: {e}")
                    # Don't continue here - let the code advance normally
            # Always advance to the next instruction
            instr_len = bv.get_instruction_length(addr)
            addr += instr_len if instr_len > 0 else 1
    # IDentify the OP by grouping all the target addresses and checking the jumps if they are opposing. 
    # i am aware that there are possible negative side effects which we will need to chantge if it comes
    target_dict = {}
    # group all the tartget addresses
    for addr, (mnemonic, target) in cond_jumps.items():
        if target not in target_dict:
            target_dict[target] = []
        target_dict[target].append((addr, mnemonic))
    # check if the jumps are opposing
    for target, jumps in target_dict.items():
        # sort the jumps so that we can find the opposing jumps eaily by target
        jumps.sort(key=lambda x: x[0])  # sort by target
        # Example Entry :    0x18000b981  :  [(6442474844, 'jo'), (6442474852, 'jno')]
        # print(hex(target), " : " , jumps)
        if len(jumps)< 2:
            continue   #nothing to compare with if there is 1 or less
        for i in range(len(jumps)):
            addr1, mnemonic1 = jumps[i] # get the address (previous to the next) and the mnemonic
            for j in range(i+1, len(jumps)):
                addr2, mnemonic2 = jumps [j] # get the other address and mnemonic for comparison
                if mnemonic2 in opposite_jumps.get(mnemonic1, []):
                    print(f"[*] Found opaque predicate: {hex(addr1)}: {mnemonic1} and {hex(addr2)}: {mnemonic2}")
                    # patch the first jump to a nop
                    bv.begin_undo_actions() 
                    rel32_offset = target - (addr1 + 5 )  #offset is relative to the end fo the instruction
                    jmp_bytes = bytearray([0xe9])  #jmp instruction
                    jmp_bytes.extend(rel32_offset.to_bytes(4, byteorder='little', signed=True))
                    orig_length = bv.get_instruction_length(addr1)  # get the original length of the instruction
                    bv.write(addr1, jmp_bytes) # write the nop instruction
                    # also nop the remaining
                    if orig_length > len(jmp_bytes):
                        nop_count = orig_length - len(jmp_bytes)
                        nop_bytes = b"\x90" * nop_count
                        bv.write(addr1 + len(jmp_bytes), nop_bytes)
                    bv.commit_undo_actions()   
                    patched_count += 1
                    print(f"[*] Patched {hex(addr1)} to be unconditional jump to {hex(target)}")
                    break
            if j< len(jumps):
                break
    function.reanalyze()

print(f"[+] Patched {patched_count} opaque predicates")
