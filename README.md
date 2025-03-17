# Call Ret Modifier Deobfuscator

Using Binary Ninja, it is possible to deobfuscate this type of obfuscation. It seems to work really well though I can think of edge cases which should be addressed when it arises. Note there is a jump to address which is the target for two opposing jump statements. This is a part of Conrol Flow Obfuscation found ina real world malware. The article from [Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/scatterbrain-unmasking-poisonplug-obfuscator) also covered this as well under `Opaque Predicates`.

```asm
180012d12  50                 push    rax
180012d13  0f8403fcffff       je      0x18001291c   <---- Jumping here
180012d19  90                 nop                   <---- Junk Code
180012d1a  0f85fcfbffff       jne     0x18001291c   <---- Jumping here again 
180012d20  0f82d4e1ffff       jb      0x180010efa   <---- Unreachable code
180012d26  48832600           and     qword [rsi], 0x0
180012d2a  f6c100             test    cl, 0x0
180012d2d  e8e73affff         call    sub_180006819
180012d32  c3                 retn
```

which then changes to something like the following:

```asm
180012d12  push    rax {__saved_rax}
180012d13  jmp     0x18001291c

18001291c  mov     rax, qword [rsp+0x8 {__return_addr}]
180012921  jmp     0x180009354

180009354  movsxd  rax, dword [rax]
180009357  jmp     0x180008710

180008710  pushfq   {var_10}
180008711  jmp     0x180012b68

...
...
```

## The Idea

The idea here is to go through each block adn search for conditional jumps and just focusing on those with rel32 as jump (offsets) rather than things like ja [rbx]. These kind we ignore. Then we create another map that groups all the targets. then for each target, check if there are opposing jump (per function and not globally). If have, then we want to patch. Continue on for the rest

## Before

This is the CFG before the script
![image](https://github.com/user-attachments/assets/3b75283a-07da-4dbd-9826-bc782161ee6b)

## After
After scripting, it would show a simple control flow graph which calculates the return address
![image](https://github.com/user-attachments/assets/b23cb0c0-0287-486e-9864-f170899df017)


Binja version:  (4.2.6455)
