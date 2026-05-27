#include "wmi_query.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <Wbemidl.h>
#include <comdef.h>
#include <sstream>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")

namespace Core {

static std::string BstrToString(BSTR bstr) {
    if (!bstr) return {};
    int len = SysStringLen(bstr);
    if (len == 0) return {};
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, bstr, len, nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0) return {};
    std::string result(sizeNeeded, '\0');
    WideCharToMultiByte(CP_UTF8, 0, bstr, len, result.data(), sizeNeeded, nullptr, nullptr);
    return result;
}

static std::wstring Utf8ToWide(const std::string& str) {
    if (str.empty()) return {};
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), nullptr, 0);
    if (sizeNeeded <= 0) return {};
    std::wstring result(sizeNeeded, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), result.data(), sizeNeeded);
    return result;
}

static std::string VariantToString(VARIANT& var) {
    switch (var.vt) {
    case VT_BSTR:
        return BstrToString(var.bstrVal);
    case VT_I4:
        return std::to_string(var.lVal);
    case VT_UI4:
        return std::to_string(var.ulVal);
    case VT_I2:
        return std::to_string(var.iVal);
    case VT_UI2:
        return std::to_string(var.uiVal);
    case VT_I1:
        return std::to_string(static_cast<int>(var.cVal));
    case VT_UI1:
        return std::to_string(static_cast<unsigned>(var.bVal));
    case VT_BOOL:
        return (var.boolVal == VARIANT_TRUE) ? "True" : "False";
    case VT_R4:
        return std::to_string(var.fltVal);
    case VT_R8:
        return std::to_string(var.dblVal);
    case VT_I8:
        return std::to_string(var.llVal);
    case VT_UI8:
        return std::to_string(var.ullVal);
    case VT_NULL:
    case VT_EMPTY:
        return {};
    default:
        // For array or unknown types, try to convert via VariantChangeType
        {
            VARIANT converted;
            VariantInit(&converted);
            if (SUCCEEDED(VariantChangeType(&converted, &var, 0, VT_BSTR))) {
                std::string result = BstrToString(converted.bstrVal);
                VariantClear(&converted);
                return result;
            }
            VariantClear(&converted);
        }
        return "(unsupported type)";
    }
}

bool WmiQuery::InitializeCom() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        return false;
    }

    hr = CoInitializeSecurity(
        nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE, nullptr);

    // S_OK or RPC_E_TOO_LATE are both acceptable
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        return false;
    }

    return true;
}

void WmiQuery::UninitializeCom() {
    CoUninitialize();
}

std::vector<WmiResult> WmiQuery::Query(
    const std::string& wmiNamespace,
    const std::string& query)
{
    std::vector<WmiResult> results;

    IWbemLocator* pLocator = nullptr;
    IWbemServices* pServices = nullptr;
    IEnumWbemClassObject* pEnumerator = nullptr;

    HRESULT hr = CoCreateInstance(
        CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, reinterpret_cast<void**>(&pLocator));

    if (FAILED(hr)) {
        return results;
    }

    std::wstring wideNamespace = Utf8ToWide(wmiNamespace);
    BSTR bstrNamespace = SysAllocString(wideNamespace.c_str());

    hr = pLocator->ConnectServer(
        bstrNamespace, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &pServices);

    SysFreeString(bstrNamespace);

    if (FAILED(hr)) {
        pLocator->Release();
        return results;
    }

    hr = CoSetProxyBlanket(
        pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE);

    if (FAILED(hr)) {
        pServices->Release();
        pLocator->Release();
        return results;
    }

    std::wstring wideQuery = Utf8ToWide(query);
    BSTR bstrLanguage = SysAllocString(L"WQL");
    BSTR bstrQuery = SysAllocString(wideQuery.c_str());

    hr = pServices->ExecQuery(
        bstrLanguage, bstrQuery,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr, &pEnumerator);

    SysFreeString(bstrLanguage);
    SysFreeString(bstrQuery);

    if (FAILED(hr)) {
        pServices->Release();
        pLocator->Release();
        return results;
    }

    // Enumerate results
    while (true) {
        IWbemClassObject* pObj = nullptr;
        ULONG returned = 0;

        hr = pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &returned);
        if (hr == WBEM_S_FALSE || returned == 0) {
            break;
        }
        if (FAILED(hr)) {
            break;
        }

        WmiResult row;

        // Enumerate all properties of this object
        hr = pObj->BeginEnumeration(WBEM_FLAG_NONSYSTEM_ONLY);
        if (SUCCEEDED(hr)) {
            BSTR propName = nullptr;
            VARIANT propVal;

            while (pObj->Next(0, &propName, &propVal, nullptr, nullptr) == WBEM_S_NO_ERROR) {
                std::string name = BstrToString(propName);
                std::string value = VariantToString(propVal);

                if (!name.empty()) {
                    row.properties[name] = value;
                }

                SysFreeString(propName);
                propName = nullptr;
                VariantClear(&propVal);
            }

            pObj->EndEnumeration();
        }

        results.push_back(std::move(row));
        pObj->Release();
    }

    pEnumerator->Release();
    pServices->Release();
    pLocator->Release();

    return results;
}

std::vector<WmiResult> WmiQuery::QueryCimv2(const std::string& query) {
    return Query("ROOT\\CIMV2", query);
}

std::optional<std::string> WmiQuery::QuerySingleValue(
    const std::string& wmiNamespace,
    const std::string& query,
    const std::string& propertyName)
{
    auto results = Query(wmiNamespace, query);
    if (results.empty()) {
        return std::nullopt;
    }

    auto it = results[0].properties.find(propertyName);
    if (it == results[0].properties.end()) {
        return std::nullopt;
    }

    return it->second;
}

} // namespace Core
