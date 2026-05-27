#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "privacy_session.h"

#include <windows.h>
#include <bcrypt.h>
#include <shellapi.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <ctime>
#include <exception>
#include <fstream>
#include <iomanip>
#include <map>
#include <sstream>
#include <system_error>
#include <vector>

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Shell32.lib")

namespace fs = std::filesystem;

namespace {

constexpr int kSessionSchemaVersion = 1;

struct RegistrySettingPlan {
    std::wstring subKey;
    std::wstring valueName;
    DWORD applyValue;
    std::string note;
};

struct RegistrySnapshot {
    RegistrySettingPlan plan;
    bool existedBefore = false;
    DWORD previousType = REG_NONE;
    DWORD previousDword = 0;
    DWORD appliedType = REG_DWORD;
    DWORD appliedDword = 0;
    bool changed = false;
    std::string restoreStatus = "pending";
};

struct CommandResult {
    bool started = false;
    DWORD exitCode = 1;
    DWORD errorCode = 0;
    std::string output;
};

std::string TimestampForFile() {
    std::time_t now = std::time(nullptr);
    std::tm local{};
    localtime_s(&local, &now);

    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", &local);
    return buf;
}

std::string TimestampIso() {
    std::time_t now = std::time(nullptr);
    std::tm local{};
    localtime_s(&local, &now);

    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &local);
    return buf;
}

std::string Narrow(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1) {
        return {};
    }

    std::string out(static_cast<size_t>(size - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, out.data(), size, nullptr, nullptr);
    return out;
}

std::wstring Widen(const std::string& value) {
    if (value.empty()) {
        return {};
    }

    int size = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    if (size <= 1) {
        return {};
    }

    std::wstring out(static_cast<size_t>(size - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, out.data(), size);
    return out;
}

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string NormalizeSeparators(std::string value) {
    std::replace(value.begin(), value.end(), '/', '\\');
    return value;
}

bool PathExists(const fs::path& path) {
    std::error_code ec;
    return fs::exists(path, ec);
}

bool IsRegularFile(const fs::path& path) {
    std::error_code ec;
    return fs::is_regular_file(path, ec);
}

bool IsDirectoryPath(const fs::path& path) {
    std::error_code ec;
    return fs::is_directory(path, ec);
}

fs::path AbsolutePath(const fs::path& path) {
    std::error_code ec;
    fs::path absolute = fs::absolute(path, ec);
    return ec ? path : absolute;
}

std::wstring QuoteForCmd(const fs::path& path) {
    return L"\"" + path.wstring() + L"\"";
}

std::wstring QuoteForCommandLine(const std::wstring& value) {
    return L"\"" + value + L"\"";
}

std::string BoolJson(bool value) {
    return value ? "true" : "false";
}

std::string TruncateForJson(std::string value, size_t maxLength = 1200) {
    if (value.size() <= maxLength) {
        return value;
    }
    value.resize(maxLength);
    value += "...";
    return value;
}

std::string JsonEscape(const std::string& value) {
    std::ostringstream escaped;
    for (unsigned char ch : value) {
        switch (ch) {
            case '\\': escaped << "\\\\"; break;
            case '"': escaped << "\\\""; break;
            case '\b': escaped << "\\b"; break;
            case '\f': escaped << "\\f"; break;
            case '\n': escaped << "\\n"; break;
            case '\r': escaped << "\\r"; break;
            case '\t': escaped << "\\t"; break;
            default:
                if (ch < 0x20) {
                    escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(ch)
                            << std::dec << std::setfill(' ');
                } else {
                    escaped << static_cast<char>(ch);
                }
                break;
        }
    }
    return escaped.str();
}

std::string BytesToHex(const unsigned char* bytes, size_t length) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        out << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return out.str();
}

std::string GenerateSessionId() {
    unsigned char bytes[8]{};
    if (BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return "session-" + TimestampForFile();
    }
    return "session-" + BytesToHex(bytes, sizeof(bytes));
}

bool WriteStringFile(const fs::path& path, const std::string& content) {
    std::ofstream f(path, std::ios::binary);
    if (!f.is_open()) {
        return false;
    }
    f << content;
    return f.good();
}

bool IsRunningAsAdminLocal() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;

    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

bool ReadDwordValue(const std::wstring& subKey, const std::wstring& valueName, bool& existed, DWORD& type, DWORD& value) {
    existed = false;
    type = REG_NONE;
    value = 0;

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return true;
    }

    DWORD size = sizeof(value);
    LONG status = RegQueryValueExW(hKey, valueName.c_str(), nullptr, &type, reinterpret_cast<BYTE*>(&value), &size);
    RegCloseKey(hKey);

    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) {
        return true;
    }
    if (status != ERROR_SUCCESS) {
        return false;
    }

    existed = true;
    return true;
}

bool WriteDwordValue(const std::wstring& subKey, const std::wstring& valueName, DWORD value) {
    HKEY hKey = nullptr;
    DWORD disposition = 0;
    LONG status = RegCreateKeyExW(HKEY_CURRENT_USER, subKey.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, &disposition);
    if (status != ERROR_SUCCESS) {
        return false;
    }
    status = RegSetValueExW(hKey, valueName.c_str(), 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value));
    RegCloseKey(hKey);
    return status == ERROR_SUCCESS;
}

bool DeleteValue(const std::wstring& subKey, const std::wstring& valueName) {
    HKEY hKey = nullptr;
    LONG status = RegOpenKeyExW(HKEY_CURRENT_USER, subKey.c_str(), 0, KEY_SET_VALUE, &hKey);
    if (status != ERROR_SUCCESS) {
        return status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND;
    }
    status = RegDeleteValueW(hKey, valueName.c_str());
    RegCloseKey(hKey);
    return status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND;
}

std::vector<RegistrySettingPlan> UserModeSettingPlans() {
    return {
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", L"Enabled", 0,
            "Disable current-user advertising ID use." },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Privacy", L"TailoredExperiencesWithDiagnosticDataEnabled", 0,
            "Disable tailored experiences with diagnostic data." },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"ContentDeliveryAllowed", 0,
            "Disable Windows content delivery suggestions." },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"SilentInstalledAppsEnabled", 0,
            "Disable silent suggested app installation." },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"SubscribedContent-338388Enabled", 0,
            "Disable Windows suggestions content." },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"SubscribedContent-353694Enabled", 0,
            "Disable personalized tips content." },
    };
}

std::string EscapeXml(const std::string& value) {
    std::string out;
    for (char ch : value) {
        switch (ch) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default: out.push_back(ch); break;
        }
    }
    return out;
}

std::string RegTypeName(DWORD type) {
    switch (type) {
        case REG_DWORD: return "REG_DWORD";
        case REG_NONE: return "REG_NONE";
        default: return "REG_" + std::to_string(type);
    }
}

std::string BuildSnapshotJson(const std::string& sessionId, const std::string& mode, const std::string& createdAt,
    const std::string& restoreState, const std::vector<RegistrySnapshot>& settings,
    const std::vector<std::string>& browserLaunchers, const std::vector<std::string>& diagnostics) {
    std::ostringstream f;
    f << "{\n";
    f << "  \"schemaVersion\": " << kSessionSchemaVersion << ",\n";
    f << "  \"sessionId\": \"" << JsonEscape(sessionId) << "\",\n";
    f << "  \"createdAt\": \"" << JsonEscape(createdAt) << "\",\n";
    f << "  \"mode\": \"" << JsonEscape(mode) << "\",\n";
    f << "  \"restoreState\": \"" << JsonEscape(restoreState) << "\",\n";
    f << "  \"settings\": [\n";
    for (size_t i = 0; i < settings.size(); ++i) {
        const auto& s = settings[i];
        f << "    {\n";
        f << "      \"root\": \"HKCU\",\n";
        f << "      \"keyPath\": \"" << JsonEscape(Narrow(s.plan.subKey)) << "\",\n";
        f << "      \"valueName\": \"" << JsonEscape(Narrow(s.plan.valueName)) << "\",\n";
        f << "      \"valueType\": \"" << RegTypeName(s.previousType) << "\",\n";
        f << "      \"existedBefore\": " << (s.existedBefore ? "true" : "false") << ",\n";
        f << "      \"previousValue\": " << s.previousDword << ",\n";
        f << "      \"appliedValue\": " << s.appliedDword << ",\n";
        f << "      \"changed\": " << (s.changed ? "true" : "false") << ",\n";
        f << "      \"restoreStatus\": \"" << JsonEscape(s.restoreStatus) << "\",\n";
        f << "      \"note\": \"" << JsonEscape(s.plan.note) << "\"\n";
        f << "    }" << (i + 1 == settings.size() ? "\n" : ",\n");
    }
    f << "  ],\n";
    f << "  \"browserLaunchers\": [\n";
    for (size_t i = 0; i < browserLaunchers.size(); ++i) {
        f << "    \"" << JsonEscape(browserLaunchers[i]) << "\"" << (i + 1 == browserLaunchers.size() ? "\n" : ",\n");
    }
    f << "  ],\n";
    f << "  \"diagnostics\": [\n";
    for (size_t i = 0; i < diagnostics.size(); ++i) {
        f << "    \"" << JsonEscape(diagnostics[i]) << "\"" << (i + 1 == diagnostics.size() ? "\n" : ",\n");
    }
    f << "  ],\n";
    f << "  \"launchHistory\": [],\n";
    f << "  \"policyRules\": []\n";
    f << "}\n";
    return f.str();
}

std::string BuildReportJson(const std::string& sessionId, const std::string& mode, const std::string& createdAt,
    int changedCount, bool launched, const fs::path& sessionPath) {
    std::ostringstream f;
    f << "{\n";
    f << "  \"schemaVersion\": " << kSessionSchemaVersion << ",\n";
    f << "  \"sessionId\": \"" << JsonEscape(sessionId) << "\",\n";
    f << "  \"createdAt\": \"" << JsonEscape(createdAt) << "\",\n";
    f << "  \"mode\": \"" << JsonEscape(mode) << "\",\n";
    f << "  \"changedSettingCount\": " << changedCount << ",\n";
    f << "  \"sandboxLaunchAttempted\": " << (launched ? "true" : "false") << ",\n";
    f << "  \"sessionPath\": \"" << JsonEscape(sessionPath.string()) << "\",\n";
    f << "  \"kernelBoundary\": \"control-plane only; no hooks, attachments, dispatch patching, PDB offsets, or identifier spoofing\"\n";
    f << "}\n";
    return f.str();
}

bool ComputeSha256(const fs::path& path, std::string& hash, std::string& error) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) {
        error = "cannot open file";
        return false;
    }

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hashHandle = nullptr;
    DWORD objectLength = 0;
    DWORD hashLength = 0;
    DWORD resultLength = 0;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0) {
        error = "BCryptOpenAlgorithmProvider failed";
        return false;
    }

    status = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &resultLength, 0);
    if (status >= 0) {
        status = BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength), &resultLength, 0);
    }
    if (status < 0 || objectLength == 0 || hashLength == 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        error = "BCryptGetProperty failed";
        return false;
    }

    std::vector<unsigned char> hashObject(objectLength);
    std::vector<unsigned char> digest(hashLength);
    status = BCryptCreateHash(alg, &hashHandle, hashObject.data(), objectLength, nullptr, 0, 0);
    if (status < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        error = "BCryptCreateHash failed";
        return false;
    }

    char buffer[8192];
    while (f.good()) {
        f.read(buffer, sizeof(buffer));
        std::streamsize bytesRead = f.gcount();
        if (bytesRead > 0) {
            status = BCryptHashData(hashHandle, reinterpret_cast<PUCHAR>(buffer), static_cast<ULONG>(bytesRead), 0);
            if (status < 0) {
                BCryptDestroyHash(hashHandle);
                BCryptCloseAlgorithmProvider(alg, 0);
                error = "BCryptHashData failed";
                return false;
            }
        }
    }

    status = BCryptFinishHash(hashHandle, digest.data(), hashLength, 0);
    BCryptDestroyHash(hashHandle);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (status < 0) {
        error = "BCryptFinishHash failed";
        return false;
    }

    hash = BytesToHex(digest.data(), digest.size());
    return true;
}

bool WriteManifest(const fs::path& path, const std::string& sessionId, const std::vector<std::pair<std::string, fs::path>>& files,
    std::string& error) {
    std::ostringstream f;
    f << "{\n";
    f << "  \"schemaVersion\": " << kSessionSchemaVersion << ",\n";
    f << "  \"sessionId\": \"" << JsonEscape(sessionId) << "\",\n";
    f << "  \"createdAt\": \"" << JsonEscape(TimestampIso()) << "\",\n";
    f << "  \"files\": [\n";

    for (size_t i = 0; i < files.size(); ++i) {
        const auto& [role, filePath] = files[i];
        std::string hash;
        if (!ComputeSha256(filePath, hash, error)) {
            return false;
        }
        unsigned long long size = 0;
        try {
            size = static_cast<unsigned long long>(fs::file_size(filePath));
        } catch (...) {
            error = "cannot read file size";
            return false;
        }

        f << "    {\n";
        f << "      \"role\": \"" << JsonEscape(role) << "\",\n";
        f << "      \"path\": \"" << JsonEscape(filePath.string()) << "\",\n";
        f << "      \"fileName\": \"" << JsonEscape(filePath.filename().string()) << "\",\n";
        f << "      \"size\": " << size << ",\n";
        f << "      \"sha256\": \"" << JsonEscape(hash) << "\"\n";
        f << "    }" << (i + 1 == files.size() ? "\n" : ",\n");
    }
    f << "  ]\n";
    f << "}\n";

    return WriteStringFile(path, f.str());
}

std::string ReadFileString(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) {
        return {};
    }
    std::ostringstream out;
    out << f.rdbuf();
    return out.str();
}

std::string ExtractJsonString(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return {};
    pos = json.find(':', pos);
    if (pos == std::string::npos) return {};
    pos = json.find('"', pos);
    if (pos == std::string::npos) return {};
    ++pos;

    std::string value;
    bool escape = false;
    for (; pos < json.size(); ++pos) {
        char ch = json[pos];
        if (escape) {
            switch (ch) {
                case 'n': value.push_back('\n'); break;
                case 'r': value.push_back('\r'); break;
                case 't': value.push_back('\t'); break;
                default: value.push_back(ch); break;
            }
            escape = false;
        } else if (ch == '\\') {
            escape = true;
        } else if (ch == '"') {
            break;
        } else {
            value.push_back(ch);
        }
    }
    return value;
}

bool ExtractJsonBool(const std::string& json, const std::string& key, bool& value) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos);
    if (pos == std::string::npos) return false;
    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\r' || json[pos] == '\n')) ++pos;
    if (json.compare(pos, 4, "true") == 0) {
        value = true;
        return true;
    }
    if (json.compare(pos, 5, "false") == 0) {
        value = false;
        return true;
    }
    return false;
}

DWORD ExtractJsonDword(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return 0;
    pos = json.find(':', pos);
    if (pos == std::string::npos) return 0;
    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\r' || json[pos] == '\n')) ++pos;
    return static_cast<DWORD>(std::strtoul(json.c_str() + pos, nullptr, 10));
}

std::vector<std::string> ExtractJsonObjects(const std::string& json, const std::string& arrayKey) {
    std::vector<std::string> objects;
    std::string needle = "\"" + arrayKey + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return objects;
    pos = json.find('[', pos);
    if (pos == std::string::npos) return objects;

    int depth = 0;
    size_t start = std::string::npos;
    bool inString = false;
    bool escape = false;
    for (; pos < json.size(); ++pos) {
        char ch = json[pos];
        if (inString) {
            if (escape) {
                escape = false;
            } else if (ch == '\\') {
                escape = true;
            } else if (ch == '"') {
                inString = false;
            }
            continue;
        }
        if (ch == '"') {
            inString = true;
        } else if (ch == '{') {
            if (depth == 0) start = pos;
            ++depth;
        } else if (ch == '}') {
            --depth;
            if (depth == 0 && start != std::string::npos) {
                objects.push_back(json.substr(start, pos - start + 1));
                start = std::string::npos;
            }
        } else if (ch == ']' && depth == 0) {
            break;
        }
    }
    return objects;
}

fs::path ResolveSessionBase(const PrivacySessionStartOptions& options, const std::string& sessionDirName) {
    fs::path base = options.outputPath.empty() ? options.workDir : options.outputPath;
    if (base.is_relative()) {
        base = options.workDir / base;
    }
    if (base.extension().empty()) {
        return base / sessionDirName;
    }
    return base.parent_path() / sessionDirName;
}

fs::path ResolveSessionPath(const fs::path& workDir, const std::string& sessionRef) {
    fs::path p(sessionRef);
    if (fs::exists(p)) return fs::absolute(p);
    if (p.is_relative()) {
        fs::path underWorkDir = workDir / p;
        if (fs::exists(underWorkDir)) return fs::absolute(underWorkDir);
    }

    if (fs::exists(workDir) && fs::is_directory(workDir)) {
        for (const auto& entry : fs::directory_iterator(workDir)) {
            if (!entry.is_directory()) continue;
            std::string name = entry.path().filename().string();
            if (name == sessionRef || name.find(sessionRef) != std::string::npos) {
                return fs::absolute(entry.path());
            }
        }
        for (const auto& entry : fs::recursive_directory_iterator(workDir, fs::directory_options::skip_permission_denied)) {
            if (!entry.is_directory()) continue;
            std::string name = entry.path().filename().string();
            if (name == sessionRef || name.find(sessionRef) != std::string::npos) {
                return fs::absolute(entry.path());
            }
        }
    }
    return {};
}

void AddEnvRelativeCandidate(std::vector<fs::path>& candidates, const wchar_t* envName, const wchar_t* relativePath) {
    wchar_t base[MAX_PATH]{};
    DWORD got = GetEnvironmentVariableW(envName, base, MAX_PATH);
    if (got > 0 && got < MAX_PATH) {
        candidates.push_back(fs::path(base) / relativePath);
    }
}

std::vector<fs::path> BrowserInstallCandidates(const std::string& label) {
    std::vector<fs::path> candidates;
    if (label == "chrome") {
        AddEnvRelativeCandidate(candidates, L"ProgramFiles", L"Google\\Chrome\\Application\\chrome.exe");
        AddEnvRelativeCandidate(candidates, L"ProgramFiles(x86)", L"Google\\Chrome\\Application\\chrome.exe");
        AddEnvRelativeCandidate(candidates, L"LocalAppData", L"Google\\Chrome\\Application\\chrome.exe");
    } else if (label == "edge") {
        AddEnvRelativeCandidate(candidates, L"ProgramFiles", L"Microsoft\\Edge\\Application\\msedge.exe");
        AddEnvRelativeCandidate(candidates, L"ProgramFiles(x86)", L"Microsoft\\Edge\\Application\\msedge.exe");
        AddEnvRelativeCandidate(candidates, L"LocalAppData", L"Microsoft\\Edge\\Application\\msedge.exe");
    } else if (label == "firefox") {
        AddEnvRelativeCandidate(candidates, L"ProgramFiles", L"Mozilla Firefox\\firefox.exe");
        AddEnvRelativeCandidate(candidates, L"ProgramFiles(x86)", L"Mozilla Firefox\\firefox.exe");
        AddEnvRelativeCandidate(candidates, L"LocalAppData", L"Mozilla Firefox\\firefox.exe");
    } else if (label == "brave") {
        AddEnvRelativeCandidate(candidates, L"ProgramFiles", L"BraveSoftware\\Brave-Browser\\Application\\brave.exe");
        AddEnvRelativeCandidate(candidates, L"ProgramFiles(x86)", L"BraveSoftware\\Brave-Browser\\Application\\brave.exe");
        AddEnvRelativeCandidate(candidates, L"LocalAppData", L"BraveSoftware\\Brave-Browser\\Application\\brave.exe");
    }
    return candidates;
}

std::string BrowserLabelForFileName(const std::string& fileName) {
    std::string name = LowerAscii(fileName);
    if (name == "chrome" || name == "chrome.exe") return "chrome";
    if (name == "msedge" || name == "msedge.exe" || name == "edge" || name == "edge.exe") return "edge";
    if (name == "firefox" || name == "firefox.exe") return "firefox";
    if (name == "brave" || name == "brave.exe") return "brave";
    return {};
}

std::wstring BuildBrowserProfileCommand(const std::string& label, const fs::path& exePath, const fs::path& sessionPath) {
    fs::path profilePath = sessionPath / "browser_profiles" / label;
    if (label == "firefox") {
        return QuoteForCmd(exePath) + L" -profile " + QuoteForCmd(profilePath) + L" -no-remote";
    }
    return QuoteForCmd(exePath) + L" --user-data-dir=" + QuoteForCmd(profilePath) + L" --no-first-run --disable-sync";
}

bool TryResolveKnownBrowserTarget(const std::string& targetText, const fs::path& resolvedTarget,
    std::string& label, fs::path& exePath) {
    fs::path requested(targetText);
    std::string fileName = requested.filename().string();
    if (fileName.empty()) {
        fileName = targetText;
    }

    label = BrowserLabelForFileName(fileName);
    if (label.empty()) {
        return false;
    }

    if (PathExists(resolvedTarget) && IsRegularFile(resolvedTarget)) {
        exePath = resolvedTarget;
        return true;
    }
    if (PathExists(requested) && IsRegularFile(requested)) {
        exePath = AbsolutePath(requested);
        return true;
    }
    for (const auto& candidate : BrowserInstallCandidates(label)) {
        if (PathExists(candidate) && IsRegularFile(candidate)) {
            exePath = AbsolutePath(candidate);
            return true;
        }
    }

    exePath = requested;
    return true;
}

std::vector<std::pair<std::string, std::wstring>> BrowserCommands(const fs::path& sessionPath) {
    std::vector<std::pair<std::string, std::wstring>> commands;
    const std::array<const char*, 4> labels = {{ "chrome", "edge", "firefox", "brave" }};

    for (const char* label : labels) {
        for (const auto& candidate : BrowserInstallCandidates(label)) {
            if (!PathExists(candidate) || !IsRegularFile(candidate)) {
                continue;
            }
            commands.push_back({ label, BuildBrowserProfileCommand(label, AbsolutePath(candidate), sessionPath) });
            break;
        }
    }
    return commands;
}

std::vector<std::string> WriteBrowserLaunchers(const fs::path& sessionPath) {
    std::vector<std::string> launcherPaths;
    fs::path launcherDir = sessionPath / "browser_launchers";
    fs::create_directories(launcherDir);
    fs::create_directories(sessionPath / "browser_profiles");

    for (const auto& [label, command] : BrowserCommands(sessionPath)) {
        fs::path launcher = launcherDir / ("launch_" + label + ".cmd");
        std::string content = "@echo off\r\n";
        content += "REM Aegis isolated browser launcher. Uses a session-local browser profile.\r\n";
        content += Narrow(command) + "\r\n";
        if (WriteStringFile(launcher, content)) {
            launcherPaths.push_back(launcher.string());
        }
    }
    return launcherPaths;
}

std::string BuildSandboxConfig(const fs::path& sessionPath) {
    std::ostringstream f;
    f << "<Configuration>\n";
    f << "  <VGpu>Disable</VGpu>\n";
    f << "  <Networking>Disable</Networking>\n";
    f << "  <MappedFolders>\n";
    f << "    <MappedFolder>\n";
    f << "      <HostFolder>" << EscapeXml(sessionPath.string()) << "</HostFolder>\n";
    f << "      <SandboxFolder>C:\\AegisSession</SandboxFolder>\n";
    f << "      <ReadOnly>true</ReadOnly>\n";
    f << "    </MappedFolder>\n";
    f << "  </MappedFolders>\n";
    f << "  <LogonCommand>\n";
    f << "    <Command>explorer.exe C:\\AegisSession</Command>\n";
    f << "  </LogonCommand>\n";
    f << "</Configuration>\n";
    return f.str();
}

struct LaunchPlanData {
    std::string createdAt;
    std::string sessionId;
    std::string sessionMode;
    std::string launchMode;
    std::string targetKind;
    fs::path originalTargetPath;
    fs::path resolvedTargetPath;
    fs::path launchPath;
    fs::path launchPlanPath;
    fs::path launchCommandPath;
    fs::path launchSandboxPath;
    fs::path policyRulesPath;
    std::string policyRuleName;
    std::string policyDirection;
    std::string policyAction;
    fs::path policyProgramPath;
    std::string policyApplyStatus;
    std::string policyRestoreStatus;
    DWORD policyApplyExitCode = 0;
    std::string policyApplyOutput;
    std::string warning;
    std::string recommendation;
    std::string errorMessage;
    bool sandboxUsed = false;
    bool hostLaunchWarning = false;
    bool launched = false;
    bool blocked = false;
};

fs::path ResolveLaunchTargetPath(const fs::path& workDir, const std::string& launchTarget) {
    fs::path requested(launchTarget);
    if (requested.empty()) {
        return {};
    }
    if (requested.is_relative()) {
        fs::path underWorkDir = workDir / requested;
        if (PathExists(underWorkDir)) {
            return AbsolutePath(underWorkDir);
        }
    }
    if (PathExists(requested)) {
        return AbsolutePath(requested);
    }
    return requested.is_relative() ? AbsolutePath(workDir / requested) : AbsolutePath(requested);
}

bool LooksInstalledAppPath(const fs::path& path) {
    std::string normalized = NormalizeSeparators(LowerAscii(path.string()));
    return normalized.find("\\program files\\") != std::string::npos ||
           normalized.find("\\program files (x86)\\") != std::string::npos ||
           normalized.find("\\windows\\") != std::string::npos ||
           normalized.find("\\programdata\\microsoft\\windows\\start menu\\") != std::string::npos;
}

bool IsExecutableLike(const fs::path& path) {
    std::string ext = LowerAscii(path.extension().string());
    return ext == ".exe" || ext == ".com" || ext == ".cmd" || ext == ".bat" || ext == ".ps1" || ext == ".msi";
}

bool IsPolicyExecutableTarget(const fs::path& path) {
    std::string ext = LowerAscii(path.extension().string());
    return ext == ".exe" || ext == ".com" || ext == ".cmd" || ext == ".bat";
}

std::string ClassifyLaunchTarget(const fs::path& resolvedTarget, bool isKnownBrowser) {
    if (isKnownBrowser) {
        return "browser";
    }
    if (!PathExists(resolvedTarget)) {
        return "missing";
    }
    if (IsDirectoryPath(resolvedTarget)) {
        return "folder";
    }
    if (LooksInstalledAppPath(resolvedTarget)) {
        return "installed-app";
    }
    if (IsExecutableLike(resolvedTarget)) {
        return "portable-executable";
    }
    return "file";
}

fs::path HostFolderForSandboxTarget(const fs::path& resolvedTarget, const std::string& targetKind) {
    if (targetKind == "folder") {
        return resolvedTarget;
    }
    return resolvedTarget.parent_path();
}

std::string SandboxMappedTargetPath(const fs::path& resolvedTarget, const std::string& targetKind) {
    if (targetKind == "folder") {
        return "C:\\AegisTarget";
    }
    return "C:\\AegisTarget\\" + resolvedTarget.filename().string();
}

std::string SandboxLogonCommandForTarget(const fs::path& resolvedTarget, const std::string& targetKind) {
    if (targetKind == "folder") {
        return "explorer.exe C:\\AegisTarget";
    }
    return "cmd.exe /c start \"\" \"" + SandboxMappedTargetPath(resolvedTarget, targetKind) + "\"";
}

std::string BuildProtectedSandboxConfig(const fs::path& sessionPath, const fs::path& resolvedTarget,
    const std::string& targetKind) {
    fs::path hostTargetFolder = HostFolderForSandboxTarget(resolvedTarget, targetKind);

    std::ostringstream f;
    f << "<Configuration>\n";
    f << "  <VGpu>Disable</VGpu>\n";
    f << "  <Networking>Disable</Networking>\n";
    f << "  <MappedFolders>\n";
    f << "    <MappedFolder>\n";
    f << "      <HostFolder>" << EscapeXml(hostTargetFolder.string()) << "</HostFolder>\n";
    f << "      <SandboxFolder>C:\\AegisTarget</SandboxFolder>\n";
    f << "      <ReadOnly>true</ReadOnly>\n";
    f << "    </MappedFolder>\n";
    f << "    <MappedFolder>\n";
    f << "      <HostFolder>" << EscapeXml(sessionPath.string()) << "</HostFolder>\n";
    f << "      <SandboxFolder>C:\\AegisSession</SandboxFolder>\n";
    f << "      <ReadOnly>true</ReadOnly>\n";
    f << "    </MappedFolder>\n";
    f << "  </MappedFolders>\n";
    f << "  <LogonCommand>\n";
    f << "    <Command>" << EscapeXml(SandboxLogonCommandForTarget(resolvedTarget, targetKind)) << "</Command>\n";
    f << "  </LogonCommand>\n";
    f << "</Configuration>\n";
    return f.str();
}

bool WriteLaunchCommand(const fs::path& path, const std::wstring& command) {
    std::string content = "@echo off\r\n";
    content += "REM Aegis protected launch command. See launch_plan.json for boundaries and warnings.\r\n";
    content += Narrow(command) + "\r\n";
    return WriteStringFile(path, content);
}

std::string BuildLaunchPlanJson(const LaunchPlanData& plan) {
    std::ostringstream f;
    f << "{\n";
    f << "  \"schemaVersion\": " << kSessionSchemaVersion << ",\n";
    f << "  \"createdAt\": \"" << JsonEscape(plan.createdAt) << "\",\n";
    f << "  \"sessionId\": \"" << JsonEscape(plan.sessionId) << "\",\n";
    f << "  \"sessionMode\": \"" << JsonEscape(plan.sessionMode) << "\",\n";
    f << "  \"launchMode\": \"" << JsonEscape(plan.launchMode) << "\",\n";
    f << "  \"targetKind\": \"" << JsonEscape(plan.targetKind) << "\",\n";
    f << "  \"originalTarget\": \"" << JsonEscape(plan.originalTargetPath.string()) << "\",\n";
    f << "  \"resolvedTarget\": \"" << JsonEscape(plan.resolvedTargetPath.string()) << "\",\n";
    f << "  \"sandboxUsed\": " << BoolJson(plan.sandboxUsed) << ",\n";
    f << "  \"hostLaunchWarning\": " << BoolJson(plan.hostLaunchWarning) << ",\n";
    f << "  \"launched\": " << BoolJson(plan.launched) << ",\n";
    f << "  \"blocked\": " << BoolJson(plan.blocked) << ",\n";
    f << "  \"artifacts\": {\n";
    f << "    \"directory\": \"" << JsonEscape(plan.launchPath.string()) << "\",\n";
    f << "    \"launchPlan\": \"" << JsonEscape(plan.launchPlanPath.string()) << "\",\n";
    f << "    \"launchCommand\": \"" << JsonEscape(plan.launchCommandPath.string()) << "\",\n";
    f << "    \"sandboxConfig\": \"" << JsonEscape(plan.launchSandboxPath.string()) << "\",\n";
    f << "    \"policyRules\": \"" << JsonEscape(plan.policyRulesPath.string()) << "\"\n";
    f << "  },\n";
    f << "  \"policyRule\": {\n";
    f << "    \"ruleName\": \"" << JsonEscape(plan.policyRuleName) << "\",\n";
    f << "    \"direction\": \"" << JsonEscape(plan.policyDirection) << "\",\n";
    f << "    \"action\": \"" << JsonEscape(plan.policyAction) << "\",\n";
    f << "    \"programPath\": \"" << JsonEscape(plan.policyProgramPath.string()) << "\",\n";
    f << "    \"applyStatus\": \"" << JsonEscape(plan.policyApplyStatus) << "\",\n";
    f << "    \"restoreStatus\": \"" << JsonEscape(plan.policyRestoreStatus) << "\"\n";
    f << "  },\n";
    f << "  \"warning\": \"" << JsonEscape(plan.warning) << "\",\n";
    f << "  \"recommendation\": \"" << JsonEscape(plan.recommendation) << "\",\n";
    f << "  \"error\": \"" << JsonEscape(plan.errorMessage) << "\",\n";
    f << "  \"boundary\": \"Protected launch never spoofs host hardware identifiers or hooks storage, network, filesystem, SMBIOS, TPM, GPU, or monitor paths.\"\n";
    f << "}\n";
    return f.str();
}

size_t FindJsonArrayEnd(const std::string& json, size_t openBracket) {
    bool inString = false;
    bool escape = false;
    int depth = 0;
    for (size_t i = openBracket; i < json.size(); ++i) {
        char ch = json[i];
        if (inString) {
            if (escape) {
                escape = false;
            } else if (ch == '\\') {
                escape = true;
            } else if (ch == '"') {
                inString = false;
            }
            continue;
        }
        if (ch == '"') {
            inString = true;
        } else if (ch == '[') {
            ++depth;
        } else if (ch == ']') {
            --depth;
            if (depth == 0) {
                return i;
            }
        }
    }
    return std::string::npos;
}

bool AppendJsonObjectToArray(const fs::path& jsonPath, const std::string& arrayKey, const std::string& item) {
    std::string json = ReadFileString(jsonPath);
    if (json.empty()) {
        return false;
    }

    size_t arrayPos = json.find("\"" + arrayKey + "\"");
    if (arrayPos == std::string::npos) {
        size_t insert = json.find_last_of('}');
        if (insert == std::string::npos) {
            return false;
        }
        std::string addition = ",\n  \"" + arrayKey + "\": [\n" + item + "\n  ]\n";
        json.insert(insert, addition);
        return WriteStringFile(jsonPath, json);
    }

    size_t open = json.find('[', arrayPos);
    if (open == std::string::npos) {
        return false;
    }
    size_t close = FindJsonArrayEnd(json, open);
    if (close == std::string::npos) {
        return false;
    }

    std::string current = json.substr(open + 1, close - open - 1);
    bool empty = current.find_first_not_of(" \t\r\n") == std::string::npos;
    std::string insertion = empty ? ("\n" + item + "\n  ") : (",\n" + item + "\n  ");
    json.insert(close, insertion);
    return WriteStringFile(jsonPath, json);
}

bool AppendLaunchHistory(const fs::path& snapshotPath, const LaunchPlanData& plan) {
    std::string json = ReadFileString(snapshotPath);
    if (json.empty()) {
        return false;
    }

    std::ostringstream item;
    item << "    {\n";
    item << "      \"createdAt\": \"" << JsonEscape(plan.createdAt) << "\",\n";
    item << "      \"launchMode\": \"" << JsonEscape(plan.launchMode) << "\",\n";
    item << "      \"targetKind\": \"" << JsonEscape(plan.targetKind) << "\",\n";
    item << "      \"target\": \"" << JsonEscape(plan.resolvedTargetPath.string()) << "\",\n";
    item << "      \"launchPlan\": \"" << JsonEscape(plan.launchPlanPath.string()) << "\",\n";
    item << "      \"sandboxUsed\": " << BoolJson(plan.sandboxUsed) << ",\n";
    item << "      \"hostLaunchWarning\": " << BoolJson(plan.hostLaunchWarning) << ",\n";
    item << "      \"launched\": " << BoolJson(plan.launched) << "\n";
    item << "    }";

    size_t historyPos = json.find("\"launchHistory\"");
    if (historyPos == std::string::npos) {
        size_t insert = json.find_last_of('}');
        if (insert == std::string::npos) {
            return false;
        }
        std::string addition = ",\n  \"launchHistory\": [\n" + item.str() + "\n  ]\n";
        json.insert(insert, addition);
        return WriteStringFile(snapshotPath, json);
    }

    size_t open = json.find('[', historyPos);
    if (open == std::string::npos) {
        return false;
    }
    size_t close = FindJsonArrayEnd(json, open);
    if (close == std::string::npos) {
        return false;
    }

    std::string current = json.substr(open + 1, close - open - 1);
    bool empty = current.find_first_not_of(" \t\r\n") == std::string::npos;
    std::string insertion = empty ? ("\n" + item.str() + "\n  ") : (",\n" + item.str() + "\n  ");
    json.insert(close, insertion);
    return WriteStringFile(snapshotPath, json);
}

std::string BuildPolicyRulesJson(const LaunchPlanData& plan) {
    std::ostringstream f;
    f << "{\n";
    f << "  \"schemaVersion\": " << kSessionSchemaVersion << ",\n";
    f << "  \"createdAt\": \"" << JsonEscape(plan.createdAt) << "\",\n";
    f << "  \"sessionId\": \"" << JsonEscape(plan.sessionId) << "\",\n";
    f << "  \"launchPlan\": \"" << JsonEscape(plan.launchPlanPath.string()) << "\",\n";
    f << "  \"rules\": [\n";
    f << "    {\n";
    f << "      \"ruleName\": \"" << JsonEscape(plan.policyRuleName) << "\",\n";
    f << "      \"direction\": \"" << JsonEscape(plan.policyDirection) << "\",\n";
    f << "      \"action\": \"" << JsonEscape(plan.policyAction) << "\",\n";
    f << "      \"programPath\": \"" << JsonEscape(plan.policyProgramPath.string()) << "\",\n";
    f << "      \"applyStatus\": \"" << JsonEscape(plan.policyApplyStatus) << "\",\n";
    f << "      \"restoreStatus\": \"" << JsonEscape(plan.policyRestoreStatus) << "\",\n";
    f << "      \"netshExitCode\": " << plan.policyApplyExitCode << ",\n";
    f << "      \"netshOutput\": \"" << JsonEscape(TruncateForJson(plan.policyApplyOutput)) << "\"\n";
    f << "    }\n";
    f << "  ]\n";
    f << "}\n";
    return f.str();
}

std::string BuildPolicyRuleSnapshotObject(const LaunchPlanData& plan) {
    std::ostringstream f;
    f << "    {\n";
    f << "      \"createdAt\": \"" << JsonEscape(plan.createdAt) << "\",\n";
    f << "      \"launchPlan\": \"" << JsonEscape(plan.launchPlanPath.string()) << "\",\n";
    f << "      \"policyRules\": \"" << JsonEscape(plan.policyRulesPath.string()) << "\",\n";
    f << "      \"ruleName\": \"" << JsonEscape(plan.policyRuleName) << "\",\n";
    f << "      \"direction\": \"" << JsonEscape(plan.policyDirection) << "\",\n";
    f << "      \"action\": \"" << JsonEscape(plan.policyAction) << "\",\n";
    f << "      \"programPath\": \"" << JsonEscape(plan.policyProgramPath.string()) << "\",\n";
    f << "      \"applyStatus\": \"" << JsonEscape(plan.policyApplyStatus) << "\",\n";
    f << "      \"restoreStatus\": \"" << JsonEscape(plan.policyRestoreStatus) << "\",\n";
    f << "      \"active\": " << BoolJson(plan.policyRestoreStatus == "active") << "\n";
    f << "    }";
    return f.str();
}

bool AppendPolicyRule(const fs::path& snapshotPath, const LaunchPlanData& plan) {
    return AppendJsonObjectToArray(snapshotPath, "policyRules", BuildPolicyRuleSnapshotObject(plan));
}

std::string ReplaceJsonStringField(std::string object, const std::string& key, const std::string& value) {
    std::string needle = "\"" + key + "\"";
    size_t pos = object.find(needle);
    if (pos == std::string::npos) {
        size_t insert = object.find_last_of('}');
        if (insert == std::string::npos) {
            return object;
        }
        std::string prefix = object.rfind('\n', insert) == std::string::npos ? ", " : ",\n";
        object.insert(insert, prefix + "      \"" + key + "\": \"" + JsonEscape(value) + "\"\n");
        return object;
    }

    size_t colon = object.find(':', pos);
    if (colon == std::string::npos) {
        return object;
    }
    size_t firstQuote = object.find('"', colon);
    if (firstQuote == std::string::npos) {
        return object;
    }
    size_t valueEnd = firstQuote + 1;
    bool escape = false;
    for (; valueEnd < object.size(); ++valueEnd) {
        char ch = object[valueEnd];
        if (escape) {
            escape = false;
        } else if (ch == '\\') {
            escape = true;
        } else if (ch == '"') {
            break;
        }
    }
    if (valueEnd >= object.size()) {
        return object;
    }
    object.replace(firstQuote, valueEnd - firstQuote + 1, "\"" + JsonEscape(value) + "\"");
    return object;
}

std::string ReplaceJsonBoolField(std::string object, const std::string& key, bool value) {
    std::string needle = "\"" + key + "\"";
    size_t pos = object.find(needle);
    if (pos == std::string::npos) {
        size_t insert = object.find_last_of('}');
        if (insert == std::string::npos) {
            return object;
        }
        std::string prefix = object.rfind('\n', insert) == std::string::npos ? ", " : ",\n";
        object.insert(insert, prefix + "      \"" + key + "\": " + BoolJson(value) + "\n");
        return object;
    }
    size_t colon = object.find(':', pos);
    if (colon == std::string::npos) {
        return object;
    }
    size_t start = colon + 1;
    while (start < object.size() && (object[start] == ' ' || object[start] == '\t')) {
        ++start;
    }
    size_t end = start;
    while (end < object.size() && std::isalpha(static_cast<unsigned char>(object[end]))) {
        ++end;
    }
    object.replace(start, end - start, BoolJson(value));
    return object;
}

std::string MarkPolicyRuleDeletedObject(std::string object, const std::string& restoredAt) {
    object = ReplaceJsonStringField(object, "restoreStatus", "deleted");
    object = ReplaceJsonStringField(object, "restoredAt", restoredAt);
    object = ReplaceJsonBoolField(object, "active", false);
    return object;
}

CommandResult RunHiddenCommand(const std::wstring& commandLine, DWORD timeoutMs = 30000) {
    CommandResult result;
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) {
        result.errorCode = GetLastError();
        return result;
    }
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;

    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(L'\0');

    BOOL ok = CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(writePipe);

    if (!ok) {
        result.errorCode = GetLastError();
        CloseHandle(readPipe);
        return result;
    }

    result.started = true;
    DWORD wait = WaitForSingleObject(pi.hProcess, timeoutMs);
    if (wait == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        result.exitCode = 1;
        result.output = "command timed out";
    } else {
        DWORD exitCode = 1;
        if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
            result.exitCode = exitCode;
        }
    }

    char buffer[4096];
    DWORD read = 0;
    while (ReadFile(readPipe, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
        result.output.append(buffer, buffer + read);
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(readPipe);
    return result;
}

std::wstring NetshQuoted(const std::wstring& value) {
    std::wstring escaped;
    for (wchar_t ch : value) {
        if (ch != L'"') {
            escaped.push_back(ch);
        }
    }
    return QuoteForCommandLine(escaped);
}

std::string BuildPolicyRuleName(const std::string& sessionId, const fs::path& launchPath) {
    std::string token = sessionId;
    for (char& ch : token) {
        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '-') {
            ch = '_';
        }
    }
    return "AegisPrivacy_" + token + "_" + launchPath.filename().string() + "_out";
}

CommandResult AddOutboundFirewallRule(const std::string& ruleName, const fs::path& programPath) {
    std::wstring command = L"netsh advfirewall firewall add rule name=" + NetshQuoted(Widen(ruleName)) +
        L" dir=out action=block program=" + NetshQuoted(programPath.wstring()) +
        L" enable=yes profile=any";
    return RunHiddenCommand(command);
}

CommandResult DeleteFirewallRule(const std::string& ruleName) {
    std::wstring command = L"netsh advfirewall firewall delete rule name=" + NetshQuoted(Widen(ruleName));
    return RunHiddenCommand(command);
}

bool FirewallDeleteSucceeded(const CommandResult& result) {
    if (result.started && result.exitCode == 0) {
        return true;
    }
    std::string output = LowerAscii(result.output);
    return output.find("no rules match") != std::string::npos ||
           output.find("no rules were matched") != std::string::npos;
}

bool ShellOpenPath(const fs::path& path) {
    HINSTANCE instance = ShellExecuteW(nullptr, L"open", path.wstring().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(instance) > 32;
}

bool ShellRunCommand(const std::wstring& command) {
    HINSTANCE instance = ShellExecuteW(nullptr, L"open", L"cmd.exe", (L"/c " + command).c_str(), nullptr, SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(instance) > 32;
}

bool RewriteSnapshotRestoreState(const fs::path& snapshotPath, const std::string& newState, const std::string& restoredAt) {
    std::string json = ReadFileString(snapshotPath);
    if (json.empty()) return false;
    std::string from = "\"restoreState\": \"active\"";
    std::string to = "\"restoreState\": \"" + JsonEscape(newState) + "\"";
    size_t pos = json.find(from);
    if (pos != std::string::npos) {
        json.replace(pos, from.size(), to);
    }
    if (!restoredAt.empty() && json.find("\"restoredAt\"") == std::string::npos) {
        size_t insert = json.find("\"settings\"");
        if (insert != std::string::npos) {
            json.insert(insert, "  \"restoredAt\": \"" + JsonEscape(restoredAt) + "\",\n");
        }
    }
    return WriteStringFile(snapshotPath, json);
}

bool WriteSessionManifest(const fs::path& sessionPath, const std::string& sessionId, std::string& error) {
    std::vector<std::pair<std::string, fs::path>> files;
    auto addIfExists = [&](const std::string& role, const fs::path& path) {
        if (fs::exists(path) && fs::is_regular_file(path)) {
            files.push_back({ role, path });
        }
    };
    addIfExists("snapshot", sessionPath / "snapshot.json");
    addIfExists("protection-report", sessionPath / "protection_report.json");
    addIfExists("restore-command", sessionPath / "restore.cmd");
    addIfExists("sandbox-config", sessionPath / "sandbox_privacy.wsb");

    fs::path launcherDir = sessionPath / "browser_launchers";
    if (fs::exists(launcherDir) && fs::is_directory(launcherDir)) {
        for (const auto& entry : fs::directory_iterator(launcherDir)) {
            if (entry.is_regular_file()) {
                files.push_back({ "browser-launcher", entry.path() });
            }
        }
    }

    fs::path launchesDir = sessionPath / "launches";
    if (fs::exists(launchesDir) && fs::is_directory(launchesDir)) {
        for (const auto& entry : fs::recursive_directory_iterator(launchesDir, fs::directory_options::skip_permission_denied)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            std::string fileName = LowerAscii(entry.path().filename().string());
            std::string role = "launch-artifact";
            if (fileName == "launch_plan.json") {
                role = "launch-plan";
            } else if (fileName == "launch.cmd") {
                role = "launch-command";
            } else if (fileName == "protected_launch.wsb") {
                role = "protected-sandbox-config";
            } else if (fileName == "policy_rules.json") {
                role = "policy-rules";
            }
            files.push_back({ role, entry.path() });
        }
    }

    return WriteManifest(sessionPath / "session_manifest.json", sessionId, files, error);
}

} // namespace

PrivacySessionResult StartPrivacySession(const PrivacySessionStartOptions& options) {
    PrivacySessionResult result;
    result.mode = options.mode.empty() ? "user" : options.mode;

    if (result.mode != "user" && result.mode != "sandbox" && result.mode != "policy") {
        result.errorMessage = "unsupported privacy session mode: " + result.mode;
        return result;
    }
    if (result.mode == "policy" && !IsRunningAsAdminLocal()) {
        result.errorMessage = "policy mode requires Administrator because it uses documented system policy controls";
        return result;
    }

    result.sessionId = GenerateSessionId();
    std::string createdAt = TimestampIso();
    std::string sessionDirName = "privacy_session_" + TimestampForFile() + "_" + result.sessionId;
    result.sessionPath = ResolveSessionBase(options, sessionDirName);
    result.snapshotPath = result.sessionPath / "snapshot.json";
    result.manifestPath = result.sessionPath / "session_manifest.json";
    result.reportPath = result.sessionPath / "protection_report.json";

    try {
        fs::create_directories(result.sessionPath);
    } catch (const std::exception& e) {
        result.errorMessage = e.what();
        return result;
    }

    std::vector<RegistrySnapshot> snapshots;
    std::vector<std::string> diagnostics = {
        "No kernel hooks, storage/network/filesystem attachment, dispatch patching, PDB offsets, mappers, or identifier forgery are used.",
        "Network adapter MAC randomization and override state remain diagnostics-only in this session."
    };

    if (result.mode == "user") {
        for (const auto& plan : UserModeSettingPlans()) {
            RegistrySnapshot snapshot;
            snapshot.plan = plan;
            snapshot.appliedDword = plan.applyValue;
            if (!ReadDwordValue(plan.subKey, plan.valueName, snapshot.existedBefore, snapshot.previousType, snapshot.previousDword)) {
                result.errorMessage = "failed to read HKCU setting: " + Narrow(plan.subKey) + "\\" + Narrow(plan.valueName);
                return result;
            }
            DWORD beforeValue = snapshot.existedBefore ? snapshot.previousDword : 0xFFFFFFFFUL;
            snapshot.changed = !snapshot.existedBefore || snapshot.previousType != REG_DWORD || beforeValue != plan.applyValue;
            if (!WriteDwordValue(plan.subKey, plan.valueName, plan.applyValue)) {
                result.errorMessage = "failed to apply HKCU setting: " + Narrow(plan.subKey) + "\\" + Narrow(plan.valueName);
                return result;
            }
            if (snapshot.changed) {
                ++result.changedCount;
            }
            snapshots.push_back(snapshot);
        }
    } else if (result.mode == "policy") {
        diagnostics.push_back("Policy mode is admin-gated and uses documented controls only. No default broad firewall or AppLocker block is applied without a target policy.");
    }

    std::vector<std::string> browserLaunchers;
    if (result.mode == "user") {
        browserLaunchers = WriteBrowserLaunchers(result.sessionPath);
    }

    if (result.mode == "sandbox") {
        result.sandboxPath = result.sessionPath / "sandbox_privacy.wsb";
        if (!WriteStringFile(result.sandboxPath, BuildSandboxConfig(result.sessionPath))) {
            result.errorMessage = "failed to write Windows Sandbox configuration";
            return result;
        }
        result.launched = ShellOpenPath(result.sandboxPath);
        if (!result.launched) {
            diagnostics.push_back("Windows Sandbox launch was attempted but did not start; the .wsb file remains available.");
        }
    }

    std::string snapshotJson = BuildSnapshotJson(result.sessionId, result.mode, createdAt, "active", snapshots, browserLaunchers, diagnostics);
    if (!WriteStringFile(result.snapshotPath, snapshotJson)) {
        result.errorMessage = "failed to write session snapshot";
        return result;
    }

    std::string reportJson = BuildReportJson(result.sessionId, result.mode, createdAt, result.changedCount, result.launched, result.sessionPath);
    if (!WriteStringFile(result.reportPath, reportJson)) {
        result.errorMessage = "failed to write protection report";
        return result;
    }

    std::string restoreCmd = "@echo off\r\n";
    restoreCmd += "REM Restore this privacy session with DmiUpdater.\r\n";
    restoreCmd += "DmiUpdater.exe --privacy-session-restore \"" + result.sessionPath.string() + "\"\r\n";
    WriteStringFile(result.sessionPath / "restore.cmd", restoreCmd);

    std::string manifestError;
    if (!WriteSessionManifest(result.sessionPath, result.sessionId, manifestError)) {
        result.errorMessage = manifestError;
        return result;
    }

    result.ok = true;
    return result;
}

PrivacySessionResult ShowPrivacySessionStatus(const PrivacySessionPathOptions& options) {
    PrivacySessionResult result;
    result.sessionPath = ResolveSessionPath(options.workDir, options.sessionRef);
    if (result.sessionPath.empty()) {
        result.errorMessage = "session not found";
        return result;
    }

    result.snapshotPath = result.sessionPath / "snapshot.json";
    result.manifestPath = result.sessionPath / "session_manifest.json";
    result.reportPath = result.sessionPath / "protection_report.json";
    std::string json = ReadFileString(result.snapshotPath);
    if (json.empty()) {
        result.errorMessage = "snapshot.json not found or unreadable";
        return result;
    }

    result.sessionId = ExtractJsonString(json, "sessionId");
    result.mode = ExtractJsonString(json, "mode");
    std::string restoreState = ExtractJsonString(json, "restoreState");
    result.restored = restoreState == "restored";
    result.changedCount = static_cast<int>(ExtractJsonObjects(json, "settings").size());
    result.ok = true;
    return result;
}

PrivacySessionResult RestorePrivacySession(const PrivacySessionPathOptions& options) {
    PrivacySessionResult result = ShowPrivacySessionStatus(options);
    if (!result.ok) {
        return result;
    }

    std::string json = ReadFileString(result.snapshotPath);
    if (ExtractJsonString(json, "restoreState") == "restored") {
        result.restored = true;
        result.changedCount = 0;
        return result;
    }

    auto policyObjects = ExtractJsonObjects(json, "policyRules");
    int restoredPolicyRules = 0;
    bool hasActivePolicyRules = false;
    for (const auto& object : policyObjects) {
        if (ExtractJsonString(object, "applyStatus") == "applied" &&
            ExtractJsonString(object, "restoreStatus") == "active") {
            hasActivePolicyRules = true;
            break;
        }
    }
    if (hasActivePolicyRules && !IsRunningAsAdminLocal()) {
        result.errorMessage = "privacy session restore requires Administrator to delete firewall policy rules";
        result.ok = false;
        return result;
    }
    if (hasActivePolicyRules) {
        std::string restoredAt = TimestampIso();
        for (const auto& object : policyObjects) {
            if (ExtractJsonString(object, "applyStatus") != "applied" ||
                ExtractJsonString(object, "restoreStatus") != "active") {
                continue;
            }

            std::string ruleName = ExtractJsonString(object, "ruleName");
            if (ruleName.empty()) {
                result.errorMessage = "active policy rule is missing a rule name";
                result.ok = false;
                return result;
            }

            CommandResult deleteRule = DeleteFirewallRule(ruleName);
            if (!FirewallDeleteSucceeded(deleteRule)) {
                result.errorMessage = "failed to delete firewall rule: " + ruleName;
                result.ok = false;
                return result;
            }

            std::string updatedObject = MarkPolicyRuleDeletedObject(object, restoredAt);
            size_t pos = json.find(object);
            if (pos != std::string::npos) {
                json.replace(pos, object.size(), updatedObject);
            }
            ++restoredPolicyRules;
        }

        if (restoredPolicyRules > 0 && !WriteStringFile(result.snapshotPath, json)) {
            result.errorMessage = "failed to update policy rule restore state";
            result.ok = false;
            return result;
        }
    }

    auto settingObjects = ExtractJsonObjects(json, "settings");
    int restoredCount = 0;
    for (const auto& object : settingObjects) {
        bool existed = false;
        ExtractJsonBool(object, "existedBefore", existed);
        std::wstring keyPath = Widen(ExtractJsonString(object, "keyPath"));
        std::wstring valueName = Widen(ExtractJsonString(object, "valueName"));
        DWORD previousValue = ExtractJsonDword(object, "previousValue");

        bool ok = existed ? WriteDwordValue(keyPath, valueName, previousValue) : DeleteValue(keyPath, valueName);
        if (!ok) {
            result.errorMessage = "failed to restore HKCU setting: " + Narrow(keyPath) + "\\" + Narrow(valueName);
            result.ok = false;
            return result;
        }
        ++restoredCount;
    }

    if (!RewriteSnapshotRestoreState(result.snapshotPath, "restored", TimestampIso())) {
        result.errorMessage = "failed to update snapshot restore state";
        result.ok = false;
        return result;
    }

    std::string manifestError;
    if (!WriteSessionManifest(result.sessionPath, result.sessionId, manifestError)) {
        result.errorMessage = manifestError;
        result.ok = false;
        return result;
    }

    result.changedCount = restoredCount;
    result.policyRuleCount = restoredPolicyRules;
    result.restored = true;
    result.ok = true;
    return result;
}

PrivacySessionResult LaunchPrivacySessionTarget(const PrivacySessionPathOptions& options) {
    PrivacySessionResult result = ShowPrivacySessionStatus(options);
    if (!result.ok) {
        return result;
    }
    if (options.launchTarget.empty()) {
        result.errorMessage = "missing launch target";
        result.ok = false;
        return result;
    }

    PrivacySessionPathOptions normalized = options;
    normalized.originalTargetPath = fs::path(options.launchTarget);
    normalized.resolvedTargetPath = ResolveLaunchTargetPath(options.workDir, options.launchTarget);

    std::string browserLabel;
    fs::path browserExe;
    bool browserRequested = TryResolveKnownBrowserTarget(options.launchTarget, normalized.resolvedTargetPath, browserLabel, browserExe);
    bool browserResolved = browserRequested && PathExists(browserExe) && IsRegularFile(browserExe);
    if (browserResolved) {
        normalized.resolvedTargetPath = browserExe;
    }
    normalized.targetKind = browserRequested && !browserResolved
        ? "browser"
        : ClassifyLaunchTarget(normalized.resolvedTargetPath, browserResolved);
    if (result.mode == "sandbox" && browserResolved && LooksInstalledAppPath(normalized.resolvedTargetPath)) {
        normalized.targetKind = "installed-app";
    }

    fs::path launchDir = result.sessionPath / "launches" / TimestampForFile();
    int suffix = 1;
    while (PathExists(launchDir)) {
        launchDir = result.sessionPath / "launches" / (TimestampForFile() + "_" + std::to_string(suffix++));
    }

    try {
        fs::create_directories(launchDir);
    } catch (const std::exception& e) {
        result.errorMessage = e.what();
        result.ok = false;
        return result;
    }

    normalized.launchPath = launchDir;
    normalized.launchPlanPath = launchDir / "launch_plan.json";
    normalized.launchCommandPath = launchDir / "launch.cmd";
    normalized.launchSandboxPath = launchDir / "protected_launch.wsb";
    normalized.policyRulesPath = launchDir / "policy_rules.json";

    LaunchPlanData plan;
    plan.createdAt = TimestampIso();
    plan.sessionId = result.sessionId;
    plan.sessionMode = result.mode;
    plan.targetKind = normalized.targetKind;
    plan.originalTargetPath = normalized.originalTargetPath;
    plan.resolvedTargetPath = normalized.resolvedTargetPath;
    plan.launchPath = normalized.launchPath;
    plan.launchPlanPath = normalized.launchPlanPath;
    plan.launchCommandPath = normalized.launchCommandPath;

    auto finish = [&](bool ok) {
        result.launchPath = plan.launchPath;
        result.launchPlanPath = plan.launchPlanPath;
        result.launchCommandPath = plan.launchCommandPath;
        result.launchSandboxPath = plan.launchSandboxPath;
        result.policyRulesPath = plan.policyRulesPath;
        result.originalTargetPath = plan.originalTargetPath;
        result.resolvedTargetPath = plan.resolvedTargetPath;
        result.targetKind = plan.targetKind;
        result.launchMode = plan.launchMode;
        result.sandboxUsed = plan.sandboxUsed;
        result.hostLaunchWarning = plan.hostLaunchWarning;
        result.launched = plan.launched;

        if (!plan.policyRulesPath.empty() && !plan.policyRuleName.empty()) {
            if (!WriteStringFile(plan.policyRulesPath, BuildPolicyRulesJson(plan))) {
                result.errorMessage = "failed to write policy rules artifact";
                result.ok = false;
                return;
            }
        }
        if (!WriteStringFile(plan.launchPlanPath, BuildLaunchPlanJson(plan))) {
            result.errorMessage = "failed to write launch plan";
            result.ok = false;
            return;
        }
        if (!AppendLaunchHistory(result.snapshotPath, plan)) {
            result.errorMessage = "failed to update snapshot launch history";
            result.ok = false;
            return;
        }

        std::string manifestError;
        if (!WriteSessionManifest(result.sessionPath, result.sessionId, manifestError)) {
            result.errorMessage = manifestError;
            result.ok = false;
            return;
        }

        if (!ok) {
            result.errorMessage = plan.errorMessage.empty() ? "failed to launch target" : plan.errorMessage;
            result.ok = false;
            return;
        }
        result.ok = true;
    };

    if (result.mode == "sandbox") {
        plan.launchMode = "sandbox";
        plan.sandboxUsed = true;
        plan.launchSandboxPath = normalized.launchSandboxPath;
        plan.recommendation = "Use portable apps or installers inside Windows Sandbox when an app needs virtualized hardware surfaces.";

        if (browserRequested && !browserResolved) {
            plan.blocked = true;
            plan.errorMessage = "known browser target was requested but no installed executable was found";
            plan.warning = "Use a full portable browser path, install the browser inside Windows Sandbox, or use a dedicated VM profile.";
            WriteLaunchCommand(plan.launchCommandPath, L"REM Launch blocked: browser executable was not found.");
            finish(false);
            return result;
        }
        bool explicitMissingPath = normalized.targetKind == "missing" &&
            (normalized.originalTargetPath.has_parent_path() || normalized.originalTargetPath.is_absolute());
        if (explicitMissingPath || normalized.targetKind == "missing") {
            plan.blocked = true;
            plan.errorMessage = "sandbox launch target was not found; provide an existing portable file or folder";
            WriteLaunchCommand(plan.launchCommandPath, L"REM Launch blocked: target was not found.");
            finish(false);
            return result;
        }
        if (normalized.targetKind == "installed-app") {
            plan.blocked = true;
            plan.errorMessage = "installed apps cannot be safely launched from a read-only Sandbox mapping";
            plan.warning = "Use a portable build, run the installer inside Windows Sandbox, or use a dedicated VM profile.";
            WriteLaunchCommand(plan.launchCommandPath, L"REM Launch blocked: installed apps are not portable into this Sandbox mapping.");
            finish(false);
            return result;
        }

        fs::path hostFolder = HostFolderForSandboxTarget(normalized.resolvedTargetPath, normalized.targetKind);
        if (hostFolder.empty() || !PathExists(hostFolder)) {
            plan.blocked = true;
            plan.errorMessage = "sandbox launch target parent folder was not found";
            WriteLaunchCommand(plan.launchCommandPath, L"REM Launch blocked: target parent folder was not found.");
            finish(false);
            return result;
        }

        if (!WriteStringFile(plan.launchSandboxPath, BuildProtectedSandboxConfig(result.sessionPath,
            normalized.resolvedTargetPath, normalized.targetKind))) {
            plan.blocked = true;
            plan.errorMessage = "failed to write protected Windows Sandbox configuration";
            WriteLaunchCommand(plan.launchCommandPath, L"REM Launch blocked: failed to write Sandbox configuration.");
            finish(false);
            return result;
        }

        if (!WriteLaunchCommand(plan.launchCommandPath, L"start \"\" " + QuoteForCmd(plan.launchSandboxPath))) {
            plan.blocked = true;
            plan.errorMessage = "failed to write launch command";
            finish(false);
            return result;
        }

        plan.launched = ShellOpenPath(plan.launchSandboxPath);
        if (!plan.launched) {
            plan.errorMessage = "failed to open Windows Sandbox configuration";
            finish(false);
            return result;
        }
        finish(true);
        return result;
    }

    if (result.mode == "user") {
        if (browserRequested && !browserResolved) {
            plan.launchMode = "isolated-browser";
            plan.blocked = true;
            plan.errorMessage = "known browser target was requested but no installed executable was found";
            plan.recommendation = "Pass a full browser executable path or install Chrome, Edge, Firefox, or Brave.";
            WriteLaunchCommand(plan.launchCommandPath, L"REM Launch blocked: browser executable was not found.");
            finish(false);
            return result;
        }

        if (browserResolved) {
            plan.launchMode = "isolated-browser";
            plan.recommendation = "Use this session-local browser profile for web activity that should not share normal browser state.";
            try {
                fs::create_directories(result.sessionPath / "browser_profiles" / browserLabel);
            } catch (const std::exception& e) {
                plan.blocked = true;
                plan.errorMessage = e.what();
                finish(false);
                return result;
            }

            if (!WriteLaunchCommand(plan.launchCommandPath,
                BuildBrowserProfileCommand(browserLabel, normalized.resolvedTargetPath, result.sessionPath))) {
                plan.blocked = true;
                plan.errorMessage = "failed to write isolated browser launch command";
                finish(false);
                return result;
            }

            plan.launched = ShellOpenPath(plan.launchCommandPath);
            if (!plan.launched) {
                plan.errorMessage = "failed to launch isolated browser profile";
                finish(false);
                return result;
            }
            finish(true);
            return result;
        }

        bool explicitMissingPath = normalized.targetKind == "missing" &&
            (normalized.originalTargetPath.has_parent_path() || normalized.originalTargetPath.is_absolute());
        if (explicitMissingPath) {
            plan.launchMode = "host";
            plan.blocked = true;
            plan.hostLaunchWarning = true;
            plan.warning = "The target would have launched on the host, where hardware identifiers remain visible.";
            plan.errorMessage = "host launch target was not found";
            WriteLaunchCommand(plan.launchCommandPath, L"REM Launch blocked: target was not found.");
            finish(false);
            return result;
        }

        plan.launchMode = "host";
        plan.hostLaunchWarning = true;
        plan.warning = "This target is launching on the host; host hardware identifiers remain visible to that process.";
        plan.recommendation = "Use sandbox mode, a portable build, or a VM when the app must see virtualized hardware.";

        fs::path commandTarget = PathExists(normalized.resolvedTargetPath) ? normalized.resolvedTargetPath : normalized.originalTargetPath;
        if (!WriteLaunchCommand(plan.launchCommandPath, L"start \"\" " + QuoteForCmd(commandTarget))) {
            plan.blocked = true;
            plan.errorMessage = "failed to write host launch command";
            finish(false);
            return result;
        }

        plan.launched = ShellOpenPath(plan.launchCommandPath);
        if (!plan.launched) {
            plan.errorMessage = "failed to launch target on host";
            finish(false);
            return result;
        }
        finish(true);
        return result;
    }

    if (result.mode == "policy") {
        plan.launchMode = "policy-firewall";
        plan.hostLaunchWarning = true;
        plan.warning = "This target is launching on the host with outbound network blocked; local host hardware identifiers remain visible to that process.";
        plan.recommendation = "Use sandbox mode or a VM when the app must see virtualized hardware surfaces.";
        plan.policyRuleName = BuildPolicyRuleName(result.sessionId, plan.launchPath);
        plan.policyDirection = "out";
        plan.policyAction = "block";
        plan.policyProgramPath = normalized.resolvedTargetPath;
        plan.policyRulesPath = normalized.policyRulesPath;
        plan.policyApplyStatus = "not-attempted";
        plan.policyRestoreStatus = "not-active";

        if (!IsRunningAsAdminLocal()) {
            plan.blocked = true;
            plan.errorMessage = "policy mode protected launch requires Administrator and made no firewall changes";
            plan.policyApplyStatus = "blocked";
            WriteLaunchCommand(plan.launchCommandPath, L"REM Launch blocked: policy mode requires Administrator.");
            finish(false);
            return result;
        }

        if (!PathExists(normalized.resolvedTargetPath) || !IsRegularFile(normalized.resolvedTargetPath)) {
            plan.blocked = true;
            plan.errorMessage = "policy launch target was not found; provide an existing executable target";
            plan.policyApplyStatus = "blocked";
            WriteLaunchCommand(plan.launchCommandPath, L"REM Launch blocked: target was not found.");
            finish(false);
            return result;
        }
        if (!IsPolicyExecutableTarget(normalized.resolvedTargetPath)) {
            plan.blocked = true;
            plan.errorMessage = "policy launch accepts only .exe, .com, .bat, or .cmd targets";
            plan.policyApplyStatus = "blocked";
            WriteLaunchCommand(plan.launchCommandPath, L"REM Launch blocked: target is not a supported executable type.");
            finish(false);
            return result;
        }

        CommandResult addRule = AddOutboundFirewallRule(plan.policyRuleName, normalized.resolvedTargetPath);
        plan.policyApplyExitCode = addRule.exitCode;
        plan.policyApplyOutput = addRule.started ? addRule.output : ("CreateProcess failed: " + std::to_string(addRule.errorCode));
        if (!addRule.started || addRule.exitCode != 0) {
            plan.blocked = true;
            plan.policyApplyStatus = "error";
            plan.errorMessage = "failed to add outbound Windows Firewall rule";
            WriteLaunchCommand(plan.launchCommandPath, L"REM Launch blocked: failed to add outbound Windows Firewall rule.");
            finish(false);
            return result;
        }

        plan.policyApplyStatus = "applied";
        plan.policyRestoreStatus = "active";
        if (!AppendPolicyRule(result.snapshotPath, plan)) {
            CommandResult deleteRule = DeleteFirewallRule(plan.policyRuleName);
            plan.policyApplyOutput += "\nSnapshot append failed; rollback delete exit code: " +
                std::to_string(deleteRule.exitCode) + "\n" + deleteRule.output;
            plan.blocked = true;
            plan.policyApplyStatus = FirewallDeleteSucceeded(deleteRule) ? "rolled-back" : "rollback-error";
            plan.policyRestoreStatus = FirewallDeleteSucceeded(deleteRule) ? "deleted" : "active";
            plan.errorMessage = "failed to record firewall rule in session snapshot";
            WriteLaunchCommand(plan.launchCommandPath, L"REM Launch blocked: failed to record firewall rule in session snapshot.");
            finish(false);
            return result;
        }

        if (!WriteLaunchCommand(plan.launchCommandPath, L"start \"\" " + QuoteForCmd(normalized.resolvedTargetPath))) {
            plan.blocked = true;
            plan.errorMessage = "failed to write policy launch command; firewall rule remains active until restore";
            finish(false);
            return result;
        }

        plan.launched = ShellOpenPath(plan.launchCommandPath);
        if (!plan.launched) {
            plan.errorMessage = "failed to launch target after firewall rule creation; firewall rule remains active until restore";
            finish(false);
            return result;
        }

        ++result.policyRuleCount;
        finish(true);
        return result;
    }

    plan.launchMode = "unsupported";
    plan.blocked = true;
    plan.errorMessage = "unsupported privacy session mode: " + result.mode;
    WriteLaunchCommand(plan.launchCommandPath, L"REM Launch blocked: unsupported privacy session mode.");
    finish(false);
    return result;
}
