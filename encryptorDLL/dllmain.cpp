#include <windows.h>

/* help from: https://www.youtube.com/watch?v=ru5VzUigKqw
compile and embed in the main project. This file is loaded 
by Wannacry for the encryption portion. */

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID) {
    switch (dwReason) {
      case DLL_PROCESS_ATTACH: MessageBoxA(NULL, "DLL_PROCESS_ATTACH", "DLL_PROCESS_ATTACH", MB_OK); break;
      case DLL_PROCESS_DETACH:
      //detach here
      break;
      case DLL_THREAD_ATTACH:
      case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
