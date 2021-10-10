#include <windows.h>
#include <stdio.h>
#include <comutil.h>
#include <netfw.h>


extern "C" DECLSPEC_IMPORT HRESULT WINAPI  OLE32$CoCreateInstance (REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);
extern "C" DECLSPEC_IMPORT HRESULT WINAPI  OLE32$CoInitializeEx (LPVOID pvReserved, DWORD dwCoInit);
extern "C" DECLSPEC_IMPORT void    WINAPI  OLE32$CoUninitialize (void);
extern "C" DECLSPEC_IMPORT HRESULT WINAPI  OLEAUT32$VariantChangeType(VARIANTARG *pvargDest,VARIANTARG *pvarSrc,USHORT wFlags,VARTYPE vt);
extern "C" DECLSPEC_IMPORT HRESULT WINAPI  OLEAUT32$VariantClear(VARIANTARG *pvarg);
extern "C" DECLSPEC_IMPORT void    WINAPI  OLEAUT32$VariantInit(VARIANTARG *pvarg);
extern "C" DECLSPEC_IMPORT int     WINAPI  SHLWAPI$StrCmpW (PCWSTR psz1, PCWSTR psz2);
extern "C" DECLSPEC_IMPORT PCWSTR  WINAPI  SHLWAPI$StrStrW (PCWSTR pszFirst, PCWSTR pszSrch);

extern "C" {
    static GUID g_NetFwPolicy2      = { 0xe2b3c97f, 0x6ae1, 0x41ac, { 0x81, 0x7a, 0xf6, 0xf9, 0x21, 0x66, 0xd7, 0xdd } };
    static GUID g_INetFwPolicy2     = { 0x98325047, 0xc671, 0x4174, { 0x8d, 0x81, 0xde, 0xfc, 0xd3, 0xf0, 0x31, 0x86 } };
    static GUID g_INetFwRule        = { 0xaf230d27, 0xbaba, 0x4e42, { 0xac, 0xed, 0xf5, 0x24, 0xf2, 0x2c, 0xfc, 0xe2 } };
    static GUID g_IID_IEnumVARIANT  = { 0x00020404, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
}