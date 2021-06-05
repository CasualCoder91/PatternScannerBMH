#include <Windows.h> // HANDLE
#include <TlHelp32.h> // CreateToolhelp32Snapshot
#include <iostream>

//Timer
#include <chrono>


#include "ScanData.h"

HANDLE getHande(const char* proc) {
    HANDLE hProcessId = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    HANDLE handle = nullptr;
    DWORD processID = 0;
    PROCESSENTRY32 pEntry;
    pEntry.dwSize = sizeof(pEntry);
    Process32Next(hProcessId, &pEntry);
    do {
        if (!strcmp(reinterpret_cast<char*>(pEntry.szExeFile), proc)) {
            processID = pEntry.th32ProcessID;
            CloseHandle(hProcessId);
            return OpenProcess(PROCESS_ALL_ACCESS, false, processID);
        }

    } while (Process32Next(hProcessId, &pEntry));
    return 0;
}

uintptr_t bruteForce(const ScanData& signature, const ScanData& data) {
    for (size_t currentIndex = 0; currentIndex < data.size - signature.size; currentIndex++) {
        for (size_t sigIndex = 0; sigIndex < signature.size; sigIndex++) {
            if (data.data[currentIndex + sigIndex] != signature.data[sigIndex] && signature.data[sigIndex] != '?') {
                break;
            }
            else if (sigIndex == signature.size-1) {
                return currentIndex;
            }
        }
    }
    return 0;
}

uintptr_t boyerMooreHorspool(const ScanData& signature, const ScanData& data) {
    //get last '?' position in pattern and use it to calculate the max shift value.
    //the last position in the pattern should never be a '?' -> we do not bother checking it
    size_t maxShift = signature.size;
    size_t maxIndex = signature.size - 1;
    size_t wildCardIndex = 0;
    for (size_t i = 0; i < maxIndex; i++) {
        if (signature.data[i] == '?') {
            maxShift = maxIndex - i;
            wildCardIndex = i;
        }
    }


    //initialize the shift table
    size_t shiftTable[256];
    for (size_t i = 0; i <= 255; i++) {
        shiftTable[i] = maxShift;
    }

    //fill shiftTable
    //forgot this in the video: Because max shift should always be '?' we only update the shift table for bytes to the right of the last '?'
    for (size_t i = wildCardIndex+1; i < maxIndex - 1; i++) {
        shiftTable[signature.data[i]] = maxIndex - i;
    }

    //print shiftTable (for debugging)
    //for (size_t i = 0; i <= 255; i++) {
    //    printf_s("Value: 0x%02x \n", i);
    //    printf_s("Shift: %d \n", shiftTable[i]);
    //}


    for (size_t currentIndex = 0; currentIndex < data.size - signature.size;) {
        for (size_t sigIndex = maxIndex; sigIndex >= 0; sigIndex--) {
            //more output for debugging
            //if (shiftTable[data.data[currentIndex + sigIndex]] != signature.size) {
                //printf_s("Data: 0x%02x \n", data.data[currentIndex + sigIndex]);
                //printf_s("Sig: 0x%02x \n", signature.data[sigIndex]);
                //printf_s("Index: %d \n", currentIndex + sigIndex);
                //printf_s("Shift: %d \n", shiftTable[data.data[currentIndex + signature.size - 1]]);
                //printf_s("---------------------------------------------\n");
            //}
            if (data.data[currentIndex + sigIndex] != signature.data[sigIndex] && signature.data[sigIndex] != '?') {
                currentIndex += shiftTable[data.data[currentIndex + maxIndex]];
                break;
            }
            else if (sigIndex == 0) {
                return currentIndex;
            }
        }
    }

    return 0;
}


int main() {

    HANDLE pHandle = getHande("halo.exe");
    if (pHandle == 0) {
        printf_s("Faild to open Handle");
        return 0;
    }

    ScanData signature = ScanData("69 f6 ? ? ? ? 8a 44 24 10 03 F1 "); //add more bytes here if possible
    //signature.print();

    ScanData data = ScanData(2135809); // amout of bytes to read
    uintptr_t start = 0x5151C1;
    if (!ReadProcessMemory(pHandle, (void*)start, data.data, data.size, nullptr)) {
        printf_s("RPM failed. Error: %d \n", GetLastError());
    }
    //data.print();
    auto startTime = std::chrono::system_clock::now();
    uintptr_t offset = bruteForce(signature, data);
    auto endTime = std::chrono::system_clock::now();
    std::cout << "BruteForce: "  << std::hex << start + offset << std::endl;
    std::cout << "Time needed: " << std::chrono::duration<double>(endTime - startTime).count() << std::endl;

    startTime = std::chrono::system_clock::now();
    offset = boyerMooreHorspool(signature, data);
    endTime = std::chrono::system_clock::now();
    std::cout << "BMH: " << std::hex << start + offset << std::endl;
    std::cout << "Time needed: " << std::chrono::duration<double>(endTime - startTime).count() << std::endl;

    return 0;
}