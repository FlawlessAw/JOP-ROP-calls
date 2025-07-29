#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

#define C_PTR( x ) ( PVOID )    x
#define U_PTR( x ) ( UINT_PTR ) x

typedef struct _GADGET_CHAIN {
    PVOID JmpRcx;
    PVOID PopRcxRet;
    PVOID Ret;
    PVOID JmpRcx2;
} GADGET_CHAIN, * PGADGET_CHAIN;

typedef struct _SYSCALL_INFO {
    DWORD SSN;
    PVOID SyscallAddress;
    BOOL  IsHooked;
} SYSCALL_INFO, * PSYSCALL_INFO;


typedef struct _WIN32_API {
    SYSCALL_INFO NtWriteFile;
    SYSCALL_INFO NtAllocateVirtualMemory;
    SYSCALL_INFO NtProtectVirtualMemory;
} WIN32_API, * PWIN32_API;


extern NTSTATUS JopCall(PVOID* GadgetChain, PSYSCALL_INFO SyscallInfo, ...);



BOOL GetSyscallInfo(PVOID FunctionAddress, OUT PSYSCALL_INFO SyscallInfo) {

    PBYTE pFunc        = (PBYTE)FunctionAddress;
    BOOL  Success      = FALSE;
    

    
    /* mov r10, rcx (4C 8B D1) */
    if (pFunc[0] != 0x4C || pFunc[1] != 0x8B || pFunc[2] != 0xD1) {
        printf("[!] Missing mov r10, rcx\n");
        goto _END_OF_CODE;
    }
    
    /* Check for jmp (E9) instead of mov eax */
    if (pFunc[3] == 0xE9) {
        printf("[!] jmp detected at offset 3 (hooked!)\n");
        SyscallInfo->IsHooked = TRUE;
    }
    
    /* SSN (B8) */
    if (pFunc[3] != 0xB8) {
        printf("[!] no mov eax\n");
        goto _END_OF_CODE;
    }
    

    SyscallInfo->SSN = *(PDWORD)(pFunc + 4);
    

    for (int i = 8; i < 32; i++) {
        if (pFunc[i] == 0x0F && pFunc[i + 1] == 0x05) {
            SyscallInfo->SyscallAddress = pFunc + i;
            Success = TRUE;
            break;
        }
    }
    
    if (!Success) {
        printf("[!] didnt find syscall instruction!\n");
    }

_END_OF_CODE:
    return Success;
}

BOOL InitWinApi32(OUT PWIN32_API pWin32Apis) {
    
    HMODULE hNtdll                      = { 0 };
    PVOID   pNtWriteFile                = { 0 };
    PVOID   pNtAllocateVirtualMemory    = { 0 };
    PVOID   pNtProtectVirtualMemory     = { 0 };




    if (!(hNtdll = GetModuleHandleA("ntdll"))) {
        printf("[!] GetModuleHandleA Failed, Error: %ld\n", GetLastError());
        return FALSE;
    }



    pNtWriteFile                = GetProcAddress(hNtdll, "NtWriteFile");
    pNtAllocateVirtualMemory    = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtProtectVirtualMemory     = GetProcAddress(hNtdll, "NtProtectVirtualMemory");



    if (!pNtWriteFile || !pNtAllocateVirtualMemory || !pNtProtectVirtualMemory) {
        printf("[!] Failed to get function addreses\n");
        return FALSE;
    }

    if (!GetSyscallInfo(pNtWriteFile, &pWin32Apis->NtWriteFile)) {
        printf("[!] Failed to get NtWriteFile syscall info\n");
        return FALSE;
    }

    if (!GetSyscallInfo(pNtAllocateVirtualMemory, &pWin32Apis->NtAllocateVirtualMemory)) {
        printf("[!] Failed to get NtAllocateVirtualMemory syscall info\n");
        return FALSE;
    }

    if (!GetSyscallInfo(pNtProtectVirtualMemory, &pWin32Apis->NtProtectVirtualMemory)) {
        printf("[!] Failed to get NtProtectVirtualMemory syscall info\n");
        return FALSE;
    }


    printf("    NtWriteFile:             SSN=0x%X, Syscall @ %p\n", pWin32Apis->NtWriteFile.SSN, pWin32Apis->NtWriteFile.SyscallAddress);
    printf("    NtAllocateVirtualMemory: SSN=0x%X, Syscall @ %p\n", pWin32Apis->NtAllocateVirtualMemory.SSN, pWin32Apis->NtAllocateVirtualMemory.SyscallAddress);
    printf("    NtProtectVirtualMemory:  SSN=0x%X, Syscall @ %p\n", pWin32Apis->NtProtectVirtualMemory.SSN, pWin32Apis->NtProtectVirtualMemory.SyscallAddress);

    return TRUE;
}

PVOID FindGadget(LPCSTR ModuleName, PBYTE Pattern, SIZE_T PatternSize) {

    HMODULE               hModule = { 0 };
    PBYTE                 pBase   = { 0 };
    PIMAGE_DOS_HEADER     pDos    = { 0 };
    PIMAGE_NT_HEADERS     pNt     = { 0 };
    PIMAGE_SECTION_HEADER pSec    = { 0 };
    PVOID                 pGadget = { 0 };


    if (!(hModule = GetModuleHandleA(ModuleName))) {
        printf("[!] GetModuleHandleA Failed, Error: %ld\n", GetLastError());
        goto _END_OF_CODE;
    }


    pBase   = (PBYTE)hModule;
    pDos    = (PIMAGE_DOS_HEADER)pBase;
    pNt     = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    pSec    = IMAGE_FIRST_SECTION(pNt);


    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            PBYTE pScanBase = pBase + pSec[i].VirtualAddress;
            SIZE_T ScanSize = pSec[i].Misc.VirtualSize;

            for (SIZE_T j = 0; j < ScanSize - PatternSize; j++) {
                if (memcmp(pScanBase + j, Pattern, PatternSize) == 0) {
                    pGadget = pScanBase + j;
                    goto _END_OF_CODE;
                }
            }
        }
    }

_END_OF_CODE:
    return pGadget;
}





BOOL InitGadgetChain(OUT PGADGET_CHAIN pGadgetChain) {
    BYTE JmpRcxPattern[]    = { 0xFF, 0xE1 };        // jmp rcx
    BYTE PopRcxRetPattern[] = { 0x59, 0xC3 };        // pop rcx; ret
    BYTE RetPattern[]       = { 0xC3 };              // ret

    pGadgetChain->JmpRcx    = FindGadget("ntdll.dll", JmpRcxPattern, sizeof(JmpRcxPattern));
    pGadgetChain->PopRcxRet = FindGadget("ntdll.dll", PopRcxRetPattern, sizeof(PopRcxRetPattern));
    pGadgetChain->Ret       = FindGadget("ntdll.dll", RetPattern, sizeof(RetPattern));
    pGadgetChain->JmpRcx2   = pGadgetChain->JmpRcx;

    if (!pGadgetChain->JmpRcx || !pGadgetChain->PopRcxRet || !pGadgetChain->Ret) {
        printf("[!] Failed to find required gadgets\n");
        return FALSE;
    }

    printf("[*] Gadgets found:\n");
    printf("    JmpRcx:    %p\n", pGadgetChain->JmpRcx);
    printf("    PopRcxRet: %p\n", pGadgetChain->PopRcxRet);
    printf("    Ret:       %p\n", pGadgetChain->Ret);
    printf("    JmpRcx2:   %p\n", pGadgetChain->JmpRcx2);

    return TRUE;
}




VOID TestGadgetChain() {
    NTSTATUS        Status    = { 0 };
    HANDLE          hFile     = { 0 };
    IO_STATUS_BLOCK IoStatus  = { 0 };
    CHAR            Buffer[]  = "[*] from JOP/ROP gadget chain\n";
    
    PWIN32_API pWin32Apis       = (PWIN32_API)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WIN32_API));
    PGADGET_CHAIN pGadgetChain  = (PGADGET_CHAIN)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(GADGET_CHAIN));

    if (!pWin32Apis || !pGadgetChain) {
        printf("[!] HeapAlloc Failed\n");
        goto _END_OF_CODE;
    }

    if (!InitWinApi32(pWin32Apis)) {
        printf("[!] Failed to init win32 api\n");
        goto _END_OF_CODE;
    }

    if (!InitGadgetChain(pGadgetChain)) {
        printf("[!] Failed to init gadget chain\n");
        goto _END_OF_CODE;
    }



    hFile = GetStdHandle(STD_OUTPUT_HANDLE);

    printf("\n[*] Executing NtWriteFile via JOP/ROP\n");
    // [orig_ret][g2][g3][g4]
    // g1(jmp rcx) -> syscall -> g2(pop rcx;ret) -> g4(jmp rcx) -> g3(ret) -> caller

    
    Status = JopCall(
        (PVOID*)pGadgetChain,
        &pWin32Apis->NtWriteFile,
        C_PTR(hFile),
        NULL,
        NULL,
        NULL,
        C_PTR(&IoStatus),
        C_PTR(Buffer),
        C_PTR(sizeof(Buffer) - 1),
        NULL,
        NULL
    );

    if (NT_SUCCESS(Status)) {
        printf("\n[+] NtWriteFile executed successfully! Status: 0x%lX\n", Status);
    } else {
        printf("\n[!] NtWriteFile failed! Status: 0x%lX\n", Status);
    }

_END_OF_CODE:
    if (pWin32Apis) {
        HeapFree(GetProcessHeap(), 0, pWin32Apis);
        pWin32Apis = NULL;
    }

    if (pGadgetChain) {
        HeapFree(GetProcessHeap(), 0, pGadgetChain);
        pGadgetChain = NULL;
    }
}
