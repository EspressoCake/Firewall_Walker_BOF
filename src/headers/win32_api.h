#include <windows.h>
#include <stdio.h>
#include <comutil.h>
#include <netfw.h>


extern "C" DECLSPEC_IMPORT HRESULT WINAPI  OLE32$CoCreateInstance (REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);
extern "C" DECLSPEC_IMPORT HRESULT WINAPI  OLE32$CoInitializeEx (LPVOID pvReserved, DWORD dwCoInit);
extern "C" DECLSPEC_IMPORT void    WINAPI  OLE32$CoUninitialize (void);


extern "C" {
    static GUID g_NetFwPolicy2  = { 0xe2b3c97f, 0x6ae1, 0x41ac, { 0x81, 0x7a, 0xf6, 0xf9, 0x21, 0x66, 0xd7, 0xdd } };
    static GUID g_INetFwPolicy2 = { 0x98325047, 0xc671, 0x4174, { 0x8d, 0x81, 0xde, 0xfc, 0xd3, 0xf0, 0x31, 0x86 } };
}