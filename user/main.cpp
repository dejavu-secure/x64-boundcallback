#include <Windows.h>
#include <iostream>

int main()
{
    PUCHAR Execute = (PUCHAR)VirtualAlloc((PVOID)0x91230000, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    printf("at: %p\n", Execute);
    
    if ((UINT64)Execute != 0x91230000) {
        // When returning to a 32-bit environment, addresses must be within the 32-bit range.
        // This address can be any 32-bit value if 0x91230000 is occupied.
        printf("When returning to a 32-bit environment, addresses must be within the 32-bit range.\n");
        printf("This address can be any 32-bit value if 0x91230000 is occupied.\n");
        system("pause");
    }
    
    // at 0x91230000
    UCHAR Shellcode[] = {
        // x64
        0x53, // push rbx
        0x57, // push rdi
        0x56, // push rsi
        0x55, // push rbp
        0x49, 0x89, 0xE0, // mov r8, rsp
        0x48, 0x89, 0xCA, // mov rdx, rcx
        0x48, 0xC1, 0xEA, 0x20, // shr rdx, 32
        0xE8, 0x00, 0x00, 0x00, 0x00, // call next-opcode
        0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00, // mov dword ptr [rsp+4], 23h
        0xC7, 0x04, 0x24, 0x23, 0x00, 0x23, 0x91, // mov dword ptr [rsp], x86
        0xCB, // retf
        // x86
        0xBC, 0x00, 0x05, 0x23, 0x91, // mov esp, Data(at 0x91230500)
        0xB8, 0xEE, 0xDD, 0xCC, 0xBB, // mov eax, BBCCDDEEh(magic code)
        0x62, 0x43, 0x08, 0x90, // bound eax, [esp + 8]
        0xCB, // retf
        // x64
        0x4C, 0x89, 0xC4, // mov rsp, r8 (address#1)
        0x5D, // pop rbp
        0x5E, // pop rsi
        0x5F, // pop rdi
        0x5B, // pop rbx
        0xC3, // ret
    };

    UINT32 Data[] = {
        (UINT32)Execute + sizeof(Shellcode) - 8, // address#1
        0x33u,
        0x64B0DCA1u, // dead code
        0x64B0DCA1u
    };
    
    memcpy(Execute, Shellcode, sizeof(Shellcode));
    memcpy(Execute + 0x500, Data, sizeof(Data));

    ((UINT64(*)(UINT64))Execute)((UINT64)0xDEADBEEF64B0DCA1);

    system("pause");
}