#include <windows.h>
#include <stdio.h>
#include <combaseapi.h>
#include <comutil.h>
#include <oaidl.h>
#include <netfw.h>
#include "headers/cpp.h"
#include "headers/fw_defs.h"
#include "headers/win32_api.h"

extern "C" { void        DisplayVanityBanner (); }
extern "C" { int         GetFWStatus (); }
extern "C" { void        EnumerateFirewallSettingsProfiles(NET_FW_PROFILE_TYPE2 ProfileTypePassed, INetFwPolicy2* pNetFwPolicy2, const char* preamble); }
extern "C" { HRESULT     InitializeWindowsFirewallCOM(INetFwPolicy2** ppNetFwPolicy2); }
extern "C" { int         GetNumberOfRules (); }
extern "C" { int         DisableAllWindowsSoftwareFirewalls (); }
extern "C" { int         EnableAllWindowsSoftwareFirewalls (); }
extern "C" { int         AllRulesVerbose (); }
extern "C" { void        DumpFWRulesInCollection(INetFwRule* FwRule); }


extern const GUID        CLSID_NetFwPolicy2;
extern const GUID        IID_INetFwPolicy2;

void DisplayVanityBanner()
{
    LPCWSTR lpDBanner = L"-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-\n"
                        L"|           Firewall_Walker         |\n"
                        L"-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-\n"
                        L"| By:                               |\n"
                        L"|          @the_bit_diddler         |\n"
                        L"-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-\n";

    BeaconPrintf(CALLBACK_OUTPUT, "%ls", (wchar_t*)lpDBanner);
}

int GetFWStatus() 
{
    datap parser;
    
    HRESULT hrComInit = S_OK;
    HRESULT hr = S_OK;

    INetFwPolicy2 *pNetFwPolicy2 = NULL;

    // Display vanity banner
    DisplayVanityBanner();

    // Initialize COM.
    hrComInit = OLE32$CoInitializeEx(
                    0,
                    COINIT_APARTMENTTHREADED
                    );

    if (hrComInit != RPC_E_CHANGED_MODE)
    {
        if ( FAILED(hrComInit) )
        {
            BeaconPrintf(CALLBACK_ERROR, "CoInitializeEx failed: 0x%08lx\n", hrComInit);
            goto CleanupRoutine;
        }
    }

    
    // Retrieve INetFwPolicy2
    hr = InitializeWindowsFirewallCOM(&pNetFwPolicy2);
    if ( FAILED(hr) )
    {
        BeaconPrintf(CALLBACK_ERROR, "FAILED WFCOMInitialize call.\n");
        goto CleanupRoutine;
    }

    EnumerateFirewallSettingsProfiles(NET_FW_PROFILE2_DOMAIN, pNetFwPolicy2, "Firewall settings for domain profile");
    EnumerateFirewallSettingsProfiles(NET_FW_PROFILE2_PRIVATE, pNetFwPolicy2, "Firewall settings for private profile");
    EnumerateFirewallSettingsProfiles(NET_FW_PROFILE2_PUBLIC, pNetFwPolicy2, "Firewall settings for public profile");
    
    goto CleanupRoutine;

    CleanupRoutine:
        // Release INetFwPolicy2, this will crash otherwise.
        if (pNetFwPolicy2 != NULL)
        {
            pNetFwPolicy2->Release();
        }

        // Uninitialize COM.
        if (SUCCEEDED(hrComInit))
        {
            OLE32$CoUninitialize();
        }

        return 0;
}


HRESULT InitializeWindowsFirewallCOM(INetFwPolicy2** ppNetFwPolicy2)
{
    HRESULT hResult = S_OK;

    hResult = OLE32$CoCreateInstance(g_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER, g_INetFwPolicy2, (void**)ppNetFwPolicy2);

    if ( FAILED(hResult) )
    {
        BeaconPrintf(CALLBACK_ERROR, "CoCreateInstance for INetFwPolicy2 failed: 0x%08lx\n", hResult);
        goto CleanupRoutine;        
    }

    CleanupRoutine:
        return hResult;
}


void EnumerateFirewallSettingsProfiles(NET_FW_PROFILE_TYPE2 ProfileTypePassed, INetFwPolicy2* pNetFwPolicy2, const char* preamble)
{
    VARIANT_BOOL bIsEnabled = FALSE;

    if( SUCCEEDED(pNetFwPolicy2->get_FirewallEnabled(ProfileTypePassed, &bIsEnabled)) )
    {
        BeaconPrintf(CALLBACK_OUTPUT, "%s: %s\n", preamble, bIsEnabled ? "Enabled" : "Disabled");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Didn't receive info from Get_FirewallSettings_PerProfile\n");
        return;
    }

}


int GetNumberOfRules() 
{
    datap parser;

    HRESULT hrComInit = S_OK;
    HRESULT hrResult = S_OK;

    INetFwPolicy2   *pNetFwPolicy2 = NULL;
    INetFwRules     *pFwRules = NULL;

    LONG            fwRuleCount = 0;


    // Display vanity banner
    DisplayVanityBanner();
    
    // Initialize COM.
    hrComInit = OLE32$CoInitializeEx(0, COINIT_APARTMENTTHREADED);

    if (hrComInit != RPC_E_CHANGED_MODE)
    {
        if ( FAILED(hrComInit) )
        {
            BeaconPrintf(CALLBACK_ERROR, "CoInitializeEx failed: 0x%08lx\n", hrComInit);
            goto CleanupRoutine;
        }
    } 
        
    // Retrieve INetFwPolicy2
    hrResult = InitializeWindowsFirewallCOM(&pNetFwPolicy2);
    if ( FAILED(hrResult) )
    {
        BeaconPrintf(CALLBACK_ERROR, "FAILED WFCOMInitialize call.\n");
        goto CleanupRoutine;
    }

    hrResult = pNetFwPolicy2->get_Rules(&pFwRules);
    if ( FAILED(hrResult) )
    {
        goto CleanupRoutine;
    }


    hrResult = pNetFwPolicy2->get_Rules(&pFwRules);
    if ( FAILED(hrResult) ) {
        BeaconPrintf(CALLBACK_ERROR, "Failed trying to get rules.\n");
        goto CleanupRoutine;
    }

    hrResult = pFwRules->get_Count(&fwRuleCount);
    if ( FAILED(hrResult) ) {
        BeaconPrintf(CALLBACK_ERROR, "Failed getting number of rules.\n");
        goto CleanupRoutine;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Number of rules: %d\n", fwRuleCount);

    CleanupRoutine:
        // Release pFwRules
        if (pFwRules != NULL)
        {
            pFwRules->Release();
        }
    
        // Release INetFwPolicy2, this will crash otherwise.
        if (pNetFwPolicy2 != NULL)
        {
            pNetFwPolicy2->Release();
        }

        // Uninitialize COM.
        if ( SUCCEEDED(hrComInit) )
        {
            OLE32$CoUninitialize();
        }

        return 0;
}


int DisableAllWindowsSoftwareFirewalls() 
{
    datap parser;

    HRESULT hrComInit = S_OK;
    HRESULT hrResult = S_OK;

    INetFwPolicy2   *pNetFwPolicy2 = NULL;

    // Display vanity banner
    DisplayVanityBanner();
    
    // Initialize COM.
    hrComInit = OLE32$CoInitializeEx(0, COINIT_APARTMENTTHREADED);

    if (hrComInit != RPC_E_CHANGED_MODE)
    {
        if ( FAILED(hrComInit) )
        {
            BeaconPrintf(CALLBACK_ERROR, "CoInitializeEx failed: 0x%08lx\n", hrComInit);
            goto CleanupRoutine;
        }
    } 
        
    // Retrieve INetFwPolicy2
    hrResult = InitializeWindowsFirewallCOM(&pNetFwPolicy2);
    if ( FAILED(hrResult) )
    {
        BeaconPrintf(CALLBACK_ERROR, "FAILED WFCOMInitialize call.\n");
        goto CleanupRoutine;
    }

    hrResult = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_DOMAIN, FALSE);
    if ( FAILED(hrResult) )
    {
        BeaconPrintf(CALLBACK_ERROR, "Local firewall unable to be disabled.\n");
        goto CleanupRoutine;
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Local firewall successfully disabled.\n");
    }

    hrResult = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_PRIVATE, FALSE);
    if ( FAILED(hrResult) )
    {
        BeaconPrintf(CALLBACK_ERROR, "Private firewall unable to be disabled.\n");
        goto CleanupRoutine;
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Private firewall successfully disabled.\n");
    }

    hrResult = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_PUBLIC, FALSE);
    if ( FAILED(hrResult) )
    {
        BeaconPrintf(CALLBACK_ERROR, "Public firewall unable to be disabled.\n");
        goto CleanupRoutine;
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Public firewall successfully disabled.\n");
    }

    goto CleanupRoutine;

    CleanupRoutine:
        // Release INetFwPolicy2, this will crash otherwise.
        if (pNetFwPolicy2 != NULL)
        {
            pNetFwPolicy2->Release();
        }

        // Uninitialize COM.
        if ( SUCCEEDED(hrComInit) )
        {
            OLE32$CoUninitialize();
        }

        return 0;
}


int EnableAllWindowsSoftwareFirewalls()
{
    datap parser;

    HRESULT hrComInit = S_OK;
    HRESULT hrResult = S_OK;

    INetFwPolicy2   *pNetFwPolicy2 = NULL;

    // Display vanity banner
    DisplayVanityBanner();
    
    // Initialize COM.
    hrComInit = OLE32$CoInitializeEx(0, COINIT_APARTMENTTHREADED);

    if (hrComInit != RPC_E_CHANGED_MODE)
    {
        if ( FAILED(hrComInit) )
        {
            BeaconPrintf(CALLBACK_ERROR, "CoInitializeEx failed: 0x%08lx\n", hrComInit);
            goto CleanupRoutine;
        }
    } 
        
    // Retrieve INetFwPolicy2
    hrResult = InitializeWindowsFirewallCOM(&pNetFwPolicy2);
    if ( FAILED(hrResult) )
    {
        BeaconPrintf(CALLBACK_ERROR, "FAILED WFCOMInitialize call.\n");
        goto CleanupRoutine;
    }

    hrResult = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_DOMAIN, TRUE);
    if ( FAILED(hrResult) )
    {
        BeaconPrintf(CALLBACK_ERROR, "Local firewall unable to be enabled.\n");
        goto CleanupRoutine;
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Local firewall successfully enabled.\n");
    }

    hrResult = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_PRIVATE, TRUE);
    if ( FAILED(hrResult) )
    {
        BeaconPrintf(CALLBACK_ERROR, "Private firewall unable to be enabled.\n");
        goto CleanupRoutine;
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Private firewall successfully enabled.\n");
    }

    hrResult = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_PUBLIC, TRUE);
    if ( FAILED(hrResult) )
    {
        BeaconPrintf(CALLBACK_ERROR, "Public firewall unable to be enabled.\n");
        goto CleanupRoutine;
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Public firewall successfully enabled.\n");
    }

    goto CleanupRoutine;

    CleanupRoutine:
        // Release INetFwPolicy2, this will crash otherwise.
        if (pNetFwPolicy2 != NULL)
        {
            pNetFwPolicy2->Release();
        }

        // Uninitialize COM.
        if ( SUCCEEDED(hrComInit) )
        {
            OLE32$CoUninitialize();
        }

        return 0;
}

int AllRulesVerbose() 
{
    HRESULT hrComInit = S_OK;
    HRESULT hr = S_OK;

    ULONG cFetched = 0; 
    VARIANT var;

    IUnknown *pEnumerator;
    IEnumVARIANT* pVariant = NULL;

    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    INetFwRules *pFwRules = NULL;
    INetFwRule *pFwRule = NULL;

    long fwRuleCount;

    DisplayVanityBanner();

    // Best-practice, initialize our VARIANT
    OLEAUT32$VariantInit(&var);

    hrComInit = OLE32$CoInitializeEx(0, COINIT_APARTMENTTHREADED);

    if (hrComInit != RPC_E_CHANGED_MODE)
    {
        if (FAILED(hrComInit))
        {
            BeaconPrintf(CALLBACK_ERROR, "CoInitializeEx failed: 0x%08lx\n", hrComInit);
            goto CleanupRoutine;
        }
    }

    hr = InitializeWindowsFirewallCOM(&pNetFwPolicy2);
    if ( FAILED(hr) ) {
        goto CleanupRoutine;
    }

    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if ( FAILED(hr) ) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to retrieve rules.\n");
        goto CleanupRoutine;
    }

    hr = pFwRules->get_Count(&fwRuleCount);
    if ( FAILED(hr) ) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get total rule count.\n");
        goto CleanupRoutine;
    }

    pFwRules->get__NewEnum(&pEnumerator);
    
    if (pEnumerator) {
        hr = pEnumerator->QueryInterface(g_IID_IEnumVARIANT, (void **)&pVariant);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get enumerator.\n");
        goto CleanupRoutine;
    }


    while ( SUCCEEDED(hr) && hr != S_FALSE ) {
        OLEAUT32$VariantClear(&var);
        hr = pVariant->Next(1, &var, &cFetched);

        if ( S_FALSE != hr ) {
            if ( SUCCEEDED(hr) ) {
                hr = OLEAUT32$VariantChangeType(&var, &var, 0, VT_DISPATCH);
            } else {
                BeaconPrintf(CALLBACK_ERROR, "Failed to chage variant type to VT_DISPATCH.\n");
                goto CleanupRoutine;
            }

            if ( SUCCEEDED(hr) ) {
                hr = (V_DISPATCH(&var))->QueryInterface(g_INetFwRule, (void **)&pFwRule);
            } else {
                BeaconPrintf(CALLBACK_ERROR, "Failed to query INetFwRule interface.\n");
                goto CleanupRoutine;
            }

            if ( SUCCEEDED(hr) ) {
                DumpFWRulesInCollection(pFwRule);
            }
        }
    }

    goto CleanupRoutine;

    CleanupRoutine:
        // Release pFwRule
        if (pFwRule != NULL)
        {
            pFwRule->Release();
        }

        // Release INetFwPolicy2
        if (pNetFwPolicy2 != NULL)
        {
            pNetFwPolicy2->Release();
        }

        // Uninitialize COM.
        if (SUCCEEDED(hrComInit))
        {
            OLE32$CoUninitialize();
        }
    
        return 0;
}


void DumpFWRulesInCollection(INetFwRule* FwRule)
{
    VARIANT_BOOL bEnabled;
    BSTR bstrVal;

    long lVal = 0;
    long lProfileBitmask = 0;

    NET_FW_RULE_DIRECTION fwDirection;
    NET_FW_ACTION fwAction;

    if ( SUCCEEDED(FwRule->get_Enabled(&bEnabled)) )
    {
        if (bEnabled)
        {
            if ( SUCCEEDED(FwRule->get_Name(&bstrVal)) ) 
            {
                if ( SHLWAPI$StrCmpW(bstrVal, L"(null)") >= 0 )
                {
                    BeaconPrintf(CALLBACK_OUTPUT, "\n======== ENABLED RULE DETECTED ========\n");
                    BeaconPrintf(CALLBACK_OUTPUT, "Name:        %ls\n", (wchar_t*)bstrVal);
                }
            }

            if ( SUCCEEDED(FwRule->get_Description(&bstrVal)) ) 
            {
                if ( SHLWAPI$StrCmpW(bstrVal, L"(null)") >= 0 )
                {
                    BeaconPrintf(CALLBACK_OUTPUT, "Description: %ls\n", (wchar_t*)bstrVal);
                }
            }

            if ( SUCCEEDED(FwRule->get_ApplicationName(&bstrVal)) ) 
            {
                if ( SHLWAPI$StrCmpW(bstrVal, L"(null)") >= 0 )
                {
                    BeaconPrintf(CALLBACK_OUTPUT, "App Name:    %ls\n", (wchar_t*)bstrVal);
                }
            }

            if ( SUCCEEDED(FwRule->get_ServiceName(&bstrVal)) ) 
            {
                if ( SHLWAPI$StrCmpW(bstrVal, L"(null)") >= 0 )
                {
                    BeaconPrintf(CALLBACK_OUTPUT, "Service:     %ls\n", (wchar_t*)bstrVal);
                }
            }

            if ( SUCCEEDED(FwRule->get_Protocol(&lVal)) ) 
            {
                switch (lVal) 
                {
                    case NET_FW_IP_PROTOCOL_TCP:
                        BeaconPrintf(CALLBACK_OUTPUT, "Protocol:    %ls\n", (wchar_t*)NET_FW_IP_PROTOCOL_TCP_NAME);
                        break;
                    case NET_FW_IP_PROTOCOL_UDP:
                        BeaconPrintf(CALLBACK_OUTPUT, "Protocol:    %ls\n", (wchar_t*)NET_FW_IP_PROTOCOL_UDP_NAME);
                        break;
                    default:
                        break;
                }

                if ( lVal != NET_FW_IP_VERSION_V4 && lVal != NET_FW_IP_VERSION_V6)
                {
                    if ( SUCCEEDED(FwRule->get_LocalPorts(&bstrVal)) )
                    {
                        if ( SHLWAPI$StrCmpW(bstrVal, L"(null)") >= 0 )
                        {
                            BeaconPrintf(CALLBACK_OUTPUT, "LPorts:      %ls\n", (wchar_t*)bstrVal); 
                        }
                    }

                    if ( SUCCEEDED(FwRule->get_RemotePorts(&bstrVal)) )
                    {
                        if ( SHLWAPI$StrCmpW(bstrVal, L"(null)") >= 0 )
                        {
                            BeaconPrintf(CALLBACK_OUTPUT, "RPorts:      %ls\n", (wchar_t*)bstrVal);
                        }
                    }
                }
            }

            if ( SUCCEEDED(FwRule->get_Direction(&fwDirection)) )
            {
                switch(fwDirection)
                {
                    case NET_FW_RULE_DIR_IN:
                        BeaconPrintf(CALLBACK_OUTPUT, "Direction:   %ls\n", (wchar_t*)NET_FW_RULE_DIR_IN_NAME);
                        break;

                    case NET_FW_RULE_DIR_OUT:
                        BeaconPrintf(CALLBACK_OUTPUT, "Direction:   %ls\n", (wchar_t*)NET_FW_RULE_DIR_OUT_NAME);
                        break;
                    
                    default:
                        break;
                }
            }
        }
    }
}