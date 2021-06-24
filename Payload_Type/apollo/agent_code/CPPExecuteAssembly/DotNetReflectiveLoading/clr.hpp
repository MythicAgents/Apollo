#pragma once

#include <Windows.h>
#include <wrl.h>
#include <metahost.h>
#include <cstdint>
#include <vector>
#include <memory>
#include <array>

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
        ClrClass(mscorlib::_TypePtr pt, variant_t inst);

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
        ClrAssembly(mscorlib::_AssemblyPtr p);
        mscorlib::_TypePtr find_type(const std::wstring& clsname);
        std::unique_ptr<ClrClass> construct(const std::wstring& classname);
        
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
        std::wstring find_runtime();
    public:
        ClrDomain();
        ~ClrDomain();
        std::unique_ptr<ClrAssembly> load(std::vector<uint8_t>& mod);
    };
}

