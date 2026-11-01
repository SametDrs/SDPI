#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>

#include "sdpi/signature_verifier.hpp"

#include <algorithm>
#include <cwctype>
#include <mutex>
#include <vector>

namespace discorddpi {

namespace {

std::wstring normalize_cache_key(const std::wstring& path) {
    std::wstring key = path;
    std::transform(key.begin(), key.end(), key.begin(), [](wchar_t ch) {
        if (ch == L'/') {
            return L'\\';
        }
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return key;
}

bool query_file_stamp(const std::wstring& path, uint64_t& out_size, uint64_t& out_mtime) noexcept {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) {
        return false;
    }
    if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        return false;
    }
    out_size = (static_cast<uint64_t>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
    out_mtime = (static_cast<uint64_t>(data.ftLastWriteTime.dwHighDateTime) << 32) |
                data.ftLastWriteTime.dwLowDateTime;
    return true;
}

bool equals_case_insensitive(const std::wstring& a, const std::wstring& b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::towlower(a[i]) != std::towlower(b[i])) {
            return false;
        }
    }
    return true;
}

std::wstring extract_signer_display_name(const std::wstring& file_path) {
    HCERTSTORE store = nullptr;
    HCRYPTMSG msg = nullptr;
    DWORD encoding = 0;
    DWORD content_type = 0;
    DWORD format_type = 0;

    const BOOL ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        file_path.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &encoding,
        &content_type,
        &format_type,
        &store,
        &msg,
        nullptr);

    if (!ok || store == nullptr || msg == nullptr) {
        if (msg != nullptr) {
            CryptMsgClose(msg);
        }
        if (store != nullptr) {
            CertCloseStore(store, 0);
        }
        return {};
    }

    std::wstring display_name;
    DWORD signer_info_size = 0;
    if (CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signer_info_size) &&
        signer_info_size > 0) {
        std::vector<uint8_t> buffer(signer_info_size);
        auto* signer_info = reinterpret_cast<PCMSG_SIGNER_INFO>(buffer.data());
        if (CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, signer_info, &signer_info_size)) {
            CERT_INFO cert_info{};
            cert_info.Issuer = signer_info->Issuer;
            cert_info.SerialNumber = signer_info->SerialNumber;

            PCCERT_CONTEXT cert = CertFindCertificateInStore(
                store,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_SUBJECT_CERT,
                &cert_info,
                nullptr);

            if (cert != nullptr) {
                const DWORD chars_needed = CertGetNameStringW(
                    cert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    nullptr,
                    nullptr,
                    0);
                if (chars_needed > 1) {
                    std::wstring buf(chars_needed, L'\0');
                    const DWORD written = CertGetNameStringW(
                        cert,
                        CERT_NAME_SIMPLE_DISPLAY_TYPE,
                        0,
                        nullptr,
                        buf.data(),
                        chars_needed);
                    if (written > 1) {
                        buf.resize(written - 1);
                        display_name = std::move(buf);
                    }
                }
                CertFreeCertificateContext(cert);
            }
        }
    }

    CryptMsgClose(msg);
    CertCloseStore(store, 0);
    return display_name;
}

} // namespace

SignatureVerifier::SignatureVerifier(std::wstring required_signer)
    : required_signer_(std::move(required_signer)) {}

SignatureResult SignatureVerifier::verify_file(const std::wstring& file_path) const {
    if (file_path.empty()) {
        return SignatureResult{false, false, {}, ERROR_INVALID_PARAMETER};
    }

    uint64_t file_size = 0;
    uint64_t last_write = 0;
    if (!query_file_stamp(file_path, file_size, last_write)) {
        return SignatureResult{false, false, {}, GetLastError()};
    }

    const std::wstring key = normalize_cache_key(file_path);

    {
        std::shared_lock lock(mutex_);
        const auto it = cache_.find(key);
        if (it != cache_.end() &&
            it->second.file_size == file_size &&
            it->second.last_write_time == last_write) {
            return it->second.result;
        }
    }

    SignatureResult computed = verify_file_uncached(file_path, required_signer_);

    {
        std::unique_lock lock(mutex_);
        cache_[key] = CacheEntry{file_size, last_write, computed};
    }
    return computed;
}

SignatureResult SignatureVerifier::verify_file_uncached(
    const std::wstring& file_path,
    const std::wstring& required_signer) {
    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
    file_info.pcwszFilePath = file_path.c_str();
    file_info.hFile = nullptr;
    file_info.pgKnownSubject = nullptr;

    WINTRUST_DATA trust_data{};
    trust_data.cbStruct = sizeof(WINTRUST_DATA);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;

    GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(
        static_cast<HWND>(INVALID_HANDLE_VALUE),
        &policy_guid,
        &trust_data);

    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policy_guid, &trust_data);

    SignatureResult res{};
    res.win32_status = static_cast<uint32_t>(status);
    res.signature_valid = (status == ERROR_SUCCESS);
    res.signer_subject = extract_signer_display_name(file_path);

    if (res.signature_valid && !required_signer.empty()) {
        res.signer_matched = equals_case_insensitive(res.signer_subject, required_signer);
    } else if (res.signature_valid && required_signer.empty()) {
        res.signer_matched = true;
    }

    return res;
}

std::size_t SignatureVerifier::cache_size() const {
    std::shared_lock lock(mutex_);
    return cache_.size();
}

void SignatureVerifier::clear_cache() {
    std::unique_lock lock(mutex_);
    cache_.clear();
}

} // namespace discorddpi
