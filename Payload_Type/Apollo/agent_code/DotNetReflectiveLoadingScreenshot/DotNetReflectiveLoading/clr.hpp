#pragma once

#include <Windows.h>
#include <wrl.h>
#include <metahost.h>
#include <cstdint>
#include <vector>
#include <memory>
#include <array>
#include "utils.hpp"

#import <mscorlib.tlb> raw_interfaces_only				\
    high_property_prefixes("_get","_put","_putref")		\
    rename("ReportEvent", "InteropServices_ReportEvent")



namespace clr {
    constexpr wchar_t clr_default_version[] = /*L"v2.0.50727"; */L"v4.0.30319";
    constexpr unsigned long clr_ver_reservation = 30;
    constexpr mscorlib::BindingFlags mem_fn_call = static_cast<mscorlib::BindingFlags>(mscorlib::BindingFlags_InvokeMethod | mscorlib::BindingFlags_Instance | mscorlib::BindingFlags_Public);
    constexpr mscorlib::BindingFlags static_fn_call = static_cast<mscorlib::BindingFlags>(mscorlib::BindingFlags_InvokeMethod | mscorlib::BindingFlags_Static | mscorlib::BindingFlags_Public);

    class ClrClass {
    private:
        mscorlib::_TypePtr pType_;
        variant_t instance_;

    public:
        ClrClass(mscorlib::_TypePtr pt, variant_t inst) : pType_(pt), instance_(inst) {}

        template<typename... Args>
        variant_t invoke_method(const std::wstring& name, Args&&... args) {
            variant_t ret;
            HRESULT hr = S_OK;
            bstr_t fn_name(name.c_str());
            std::array<variant_t, sizeof...(args)> var_args{ variant_t(args)... };
            auto arglist = SafeArrayCreateVector(VT_VARIANT, 0, var_args.size());
            std::shared_ptr<SAFEARRAY> arglist_ptr(arglist, [](auto p) { if (p) SafeArrayDestroy(p); });
            for (auto i = 0; i < sizeof...(args); ++i) {
                LONG tmp = i;
                if (FAILED((hr = SafeArrayPutElement(arglist, &tmp, &var_args[i])))) {
                    throw std::runtime_error("Failed to add element to safe array!");
                }
            }
            if (FAILED((hr = pType_->InvokeMember_3(fn_name, mem_fn_call, nullptr, instance_, arglist, &ret)))) {
                throw std::runtime_error("Failed to invoke method!");
            }
            return ret;
        }
    };

    class ClrAssembly {
    private:
        mscorlib::_AssemblyPtr p_;
        SAFEARRAY* mod_;
    public:
        ClrAssembly(mscorlib::_AssemblyPtr p) : p_(p) {}
        mscorlib::_TypePtr find_type(const std::wstring& clsname)
        {
            mscorlib::_TypePtr   pClsType = nullptr;
            mscorlib::_TypePtr* pTypes = nullptr;
            BSTR                 pName = L"";
            HRESULT              hr = S_OK;
            bool                 found = false;
            SAFEARRAY* pArray = nullptr;
            long                 lower_bound = 0;
            long                 upper_bound = 0;

            if (FAILED((hr = p_->GetTypes(&pArray)))) {
                LOG_ERROR("Failed to get types!", hr);
                return false;
            }
            SafeArrayGetLBound(pArray, 1, &lower_bound);
            SafeArrayGetUBound(pArray, 1, &upper_bound);
            SafeArrayAccessData(pArray, (void**)&pTypes);
            auto elem_count = upper_bound - lower_bound + 1;
            for (auto i = 0; i < elem_count; ++i) {
                pClsType = pTypes[i];
                if (FAILED((hr = pClsType->get_FullName(&pName)))) {
                    LOG_ERROR("Failed to query for name!", hr);
                    break;
                }

                if (pName == clsname) {
                    found = true;
                    break;
                }
            }
            SafeArrayUnaccessData(pArray);
            if (!found)
                return nullptr;

            return pClsType;

        }

        std::unique_ptr<ClrClass> construct(const std::wstring& classname)
        {
            std::unique_ptr<ClrClass> cls;
            HRESULT             hr = S_OK;
            bool                found = false;
            mscorlib::_TypePtr  pClsType = nullptr;
            bstr_t              pName(classname.c_str());
            variant_t           var;

            if (FAILED((hr = p_->CreateInstance(pName, &var)))) {
                LOG_ERROR("Failed to create class instance!", hr);
                return nullptr;
            }

            pClsType = find_type(classname);
            if (pClsType == nullptr) {
                LOG("Failed to find class!");
                return nullptr;
            }

            cls = std::make_unique<ClrClass>(pClsType, var);
            return cls;
        }

        template<typename... Args>
        variant_t invoke_static(const std::wstring& clsName, const std::wstring& methodName, Args&&... args) {
            variant_t ret;
            variant_t v_empty;
            HRESULT hr = S_OK;
            bstr_t fn_name(methodName.c_str());
            std::array<variant_t, sizeof...(args)> var_args{ variant_t(args)... };
            auto pType = find_type(clsName);
            if (nullptr == pType)
                throw std::runtime_error("Failed to find type!");
            auto arglist = SafeArrayCreateVector(VT_VARIANT, 0, var_args.size());
            std::shared_ptr<SAFEARRAY> arglist_ptr(arglist, [](auto p) { if (p) SafeArrayDestroy(p); });
            for (auto i = 0; i < sizeof...(args); ++i) {
                LONG tmp = i;
                if (FAILED((hr = SafeArrayPutElement(arglist, &tmp, &var_args[i])))) {
                    throw std::runtime_error("Failed to add element to safe array!");
                }
            }
            if (FAILED((hr = pType->InvokeMember_3(fn_name, static_fn_call, nullptr, v_empty, arglist, &ret)))) {
                throw std::runtime_error("Failed to invoke method!");
            }

            return ret;
        }
    };

    class ClrDomain {
    private:
        Microsoft::WRL::ComPtr<ICLRMetaHost>	pMeta_;
        Microsoft::WRL::ComPtr<ICLRRuntimeInfo> pRuntime_;
        Microsoft::WRL::ComPtr<ICorRuntimeHost> pHost_;
        std::vector<std::shared_ptr<SAFEARRAY>>	arr_;
        std::wstring find_runtime()
        {
            HRESULT hr = S_OK;
            int g_maj = 0;
            int g_min = 0;
            int g_build = 0;
            std::wstring ver = clr_default_version;

            if (!pMeta_)
                return ver;

            IEnumUnknown* pRuntimes = nullptr;
            ICLRRuntimeInfo* pInfo = nullptr;
            ULONG fetched = 0;

            if (FAILED((hr = pMeta_->EnumerateInstalledRuntimes(&pRuntimes)))) {
                LOG_ERROR("Failed to enumerate installed runtimes!", hr);
                return ver;
            }

            while (SUCCEEDED((hr = pRuntimes->Next(1, (IUnknown**)&pInfo, &fetched))) && 0 != fetched) {
                wchar_t ver_string[clr_ver_reservation] = { 0 };
                DWORD ver_size = clr_ver_reservation;
                int c_min = 0, c_maj = 0, c_build = 0;
                if (FAILED((hr = pInfo->GetVersionString(ver_string, &ver_size)))) {
                    LOG_ERROR("Failed to get version string!", hr);
                    continue;
                }
                swscanf_s(ver_string, L"v%d.%d.%d", &c_maj, &c_min, &c_build);
                if (c_maj > g_maj) {
                    g_maj = c_maj;
                    g_min = c_min;
                    g_build = c_build;
                    ver = ver_string;
                }
                else if (c_maj == g_maj) {
                    if (c_min > g_min || (c_min == g_min && c_build > g_build)) {
                        g_min = c_min;
                        g_build = c_build;
                        ver = ver_string;
                    }
                }
            }

            return ver;
        }
    public:
        ClrDomain()
        {
            HRESULT hr = S_OK;
            BOOL loadable = FALSE;
            LOG("Runtime initialization started...");

            if (FAILED((hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(pMeta_.GetAddressOf()))))) {
                LOG_ERROR("Failed to initialize metahost!", hr);
                throw EXCEPT("Host initialization failed!");
            }

            auto clr_version = find_runtime();

            if (FAILED((hr = pMeta_->GetRuntime(clr_version.c_str(), IID_PPV_ARGS(pRuntime_.GetAddressOf()))))) {
                LOG_ERROR("Runtime initialization failed!", hr);
                throw EXCEPT("Runtime init failed!");
            }

            if (FAILED((hr = pRuntime_->IsLoadable(&loadable)) || !loadable)) {
                LOG_ERROR("Runtime not loadable!", hr);
                throw EXCEPT("Runtime not loadable!");
            }

            if (FAILED((hr = pRuntime_->GetInterface(CLSID_CorRuntimeHost, IID_PPV_ARGS(pHost_.GetAddressOf()))))) {
                LOG_ERROR("Failed to get runtime host!", hr);
                throw EXCEPT("Unable to host application!");
            }

            if (FAILED((hr = pHost_->Start()))) {
                LOG_ERROR("Host failed to start!", hr);
                throw EXCEPT("Host start failed!");
            }

            LOG("Initialization Complete!");
        }
        ~ClrDomain()
        {
            pHost_->Stop();
        }
        std::unique_ptr<ClrAssembly> load(std::vector<uint8_t>& mod)
        {
            std::unique_ptr<ClrAssembly> clr;
            IUnknownPtr		        pDomainThunk = nullptr;
            mscorlib::_AppDomainPtr	pAppDomain = nullptr;
            mscorlib::_AssemblyPtr	pAsm = nullptr;
            HRESULT			        hr = S_OK;
            SAFEARRAY* pModContainer = nullptr;

            auto modSize = mod.size();
            if (modSize > ULONG_MAX) {
                LOG("Failed to load module, file size is too large!");
                return nullptr;
            }

            if (FAILED((hr = pHost_->GetDefaultDomain(&pDomainThunk)))) {
                LOG_ERROR("Failed to get default appdomain!", hr);
                return nullptr;
            }

            if (FAILED((hr = pDomainThunk->QueryInterface(IID_PPV_ARGS(&pAppDomain))))) {
                LOG_ERROR("Failed to get app domain interface from thunk!", hr);
                return nullptr;
            }

            if (nullptr == (pModContainer = SafeArrayCreateVector(VT_UI1, 0, static_cast<ULONG>(modSize)))) {
                LOG("Failed to allocate safe array vector!");
                return nullptr;
            }

            unsigned char* buf = nullptr;
            if (FAILED((hr = SafeArrayAccessData(pModContainer, reinterpret_cast<void**>(&buf))))) {
                LOG_ERROR("Failed to access safe array!", hr);
                return nullptr;
            }

            memcpy(buf, mod.data(), mod.size());
            SafeArrayUnaccessData(pModContainer);

            if (FAILED((hr = pAppDomain->Load_3(pModContainer, &pAsm)))) {
                LOG_ERROR("Failed to load assembly!", hr);
                return nullptr;
            }


            arr_.push_back(std::shared_ptr<SAFEARRAY>(pModContainer, [](auto p) { if (p) SafeArrayDestroy(p); }));
            clr = std::make_unique<ClrAssembly>(pAsm);

            return clr;
        }
    };
}

