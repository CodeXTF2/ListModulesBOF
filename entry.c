#include <windows.h>
#include <intrin.h>
#include <winver.h>
#include "beacon.h"

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN Spare;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

static PPEB get_peb(void)
{
#if defined(_M_X64)
    return (PPEB)__readgsqword(0x60);
#elif defined(_M_IX86)
    return (PPEB)__readfsdword(0x30);
#else
    return NULL;
#endif
}

static void get_module_description(const WCHAR *path, char *out, int out_len)
{
    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(path, &handle);
    void *data = NULL;
    void *value = NULL;
    UINT value_len = 0;

    if (!out || out_len <= 0) {
        return;
    }

    out[0] = '\0';
    if (size == 0) {
        return;
    }

    data = HeapAlloc(GetProcessHeap(), 0, size);
    if (!data) {
        return;
    }

    if (!GetFileVersionInfoW(path, 0, size, data)) {
        HeapFree(GetProcessHeap(), 0, data);
        return;
    }

    if (VerQueryValueW(data, L"\\VarFileInfo\\Translation", &value, &value_len) &&
        value_len >= sizeof(WORD) * 2) {
        WORD *lang = (WORD *)value;
        WCHAR subblock[64];
        int sub_len = wsprintfW(
            subblock,
            L"\\StringFileInfo\\%04x%04x\\FileDescription",
            lang[0], lang[1]);

        if (sub_len > 0 &&
            VerQueryValueW(data, subblock, &value, &value_len) &&
            value_len > 0) {
            int converted = WideCharToMultiByte(
                CP_ACP, 0, (WCHAR *)value, -1, out, out_len - 1, NULL, NULL);
            if (converted > 0) {
                out[converted] = '\0';
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, data);
}

static void format_repeat(formatp *format, char ch, int count)
{
    int i = 0;
    for (i = 0; i < count; i++) {
        BeaconFormatPrintf(format, "%c", ch);
    }
}

static void format_size(char *out, int out_len, unsigned int bytes)
{
    if (!out || out_len <= 0) {
        return;
    }

    if (bytes >= (1024U * 1024U)) {
        unsigned int mb_int = bytes / 1048576U;
        unsigned int rem = bytes % 1048576U;
        unsigned int mb_frac = (rem * 100U + 524288U) / 1048576U;
        wsprintfA(out, "%u.%02u MB", mb_int, mb_frac);
        out[out_len - 1] = '\0';
    } else {
        unsigned int kb = (bytes + 1023U) / 1024U;
        wsprintfA(out, "%u KB", kb);
        out[out_len - 1] = '\0';
    }
}

void go(char* args, int length)
{
    formatp format;
    int size = 0;
    char *output = NULL;
    PPEB peb = get_peb();

    BeaconFormatAlloc(&format, 16384);

    if (!peb || !peb->Ldr) {
        BeaconFormatPrintf(&format, "Failed to locate PEB loader data.");
    } else {
        int max_name = 4;
        int max_desc = 11;
        int base_width = (int)(2 + (int)(sizeof(void*) * 2));
        int size_width = 7;
        LIST_ENTRY *head = &peb->Ldr->InLoadOrderModuleList;
        LIST_ENTRY *entry = head->Flink;
        BeaconFormatPrintf(&format, "Loaded modules:\n");

        while (entry && entry != head) {
            PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)entry;
            int name_len = module->BaseDllName.Length / sizeof(WCHAR);
            char description[256];
            char size_text[32];
            int desc_len = 0;
            int size_len = 0;

            if (name_len > max_name) {
                max_name = name_len;
            }

            get_module_description(module->FullDllName.Buffer, description, (int)sizeof(description));
            if (description[0] == '\0') {
                lstrcpynA(description, "-", (int)sizeof(description));
            }
            desc_len = lstrlenA(description);
            if (desc_len > max_desc) {
                max_desc = desc_len;
            }

            format_size(size_text, (int)sizeof(size_text), (unsigned int)module->SizeOfImage);
            size_len = lstrlenA(size_text);
            if (size_len > size_width) {
                size_width = size_len;
            }

            entry = entry->Flink;
        }

        if (max_name > 80) {
            max_name = 80;
        }
        if (max_desc > 80) {
            max_desc = 80;
        }

        BeaconFormatPrintf(&format, "+");
        format_repeat(&format, '-', max_name + 2);
        BeaconFormatPrintf(&format, "+");
        format_repeat(&format, '-', base_width + 2);
        BeaconFormatPrintf(&format, "+");
        format_repeat(&format, '-', size_width + 2);
        BeaconFormatPrintf(&format, "+");
        format_repeat(&format, '-', max_desc + 2);
        BeaconFormatPrintf(&format, "+\n");

        BeaconFormatPrintf(
            &format,
            "| %-*s | %-*s | %-*s | %-*s |\n",
            max_name, "Name",
            base_width, "Base",
            size_width, "Size",
            max_desc, "Description");

        BeaconFormatPrintf(&format, "+");
        format_repeat(&format, '-', max_name + 2);
        BeaconFormatPrintf(&format, "+");
        format_repeat(&format, '-', base_width + 2);
        BeaconFormatPrintf(&format, "+");
        format_repeat(&format, '-', size_width + 2);
        BeaconFormatPrintf(&format, "+");
        format_repeat(&format, '-', max_desc + 2);
        BeaconFormatPrintf(&format, "+\n");

        entry = head->Flink;
        while (entry && entry != head) {
            PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)entry;
            int wide_len = module->BaseDllName.Length / sizeof(WCHAR);
            char name[MAX_PATH];
            char description[256];
            char size_text[32];
            int converted = WideCharToMultiByte(
                CP_ACP, 0, module->BaseDllName.Buffer, wide_len,
                name, (int)sizeof(name) - 1, NULL, NULL);

            if (converted <= 0) {
                lstrcpynA(name, "<unknown>", (int)sizeof(name));
            } else {
                name[converted] = '\0';
            }

            get_module_description(module->FullDllName.Buffer, description, (int)sizeof(description));
            if (description[0] == '\0') {
                lstrcpynA(description, "-", (int)sizeof(description));
            }

            format_size(size_text, (int)sizeof(size_text), (unsigned int)module->SizeOfImage);

            BeaconFormatPrintf(
                &format,
                "| %-*.*s | 0x%0*I64X | %-*.*s | %-*.*s |\n",
                max_name, max_name, name,
                base_width - 2,
#if defined(_M_X64)
                (unsigned long long)module->DllBase,
#else
                (unsigned long long)(ULONG_PTR)module->DllBase,
#endif
                size_width, size_width, size_text,
                max_desc, max_desc, description);
            entry = entry->Flink;
        }

        BeaconFormatPrintf(&format, "+");
        format_repeat(&format, '-', max_name + 2);
        BeaconFormatPrintf(&format, "+");
        format_repeat(&format, '-', base_width + 2);
        BeaconFormatPrintf(&format, "+");
        format_repeat(&format, '-', size_width + 2);
        BeaconFormatPrintf(&format, "+");
        format_repeat(&format, '-', max_desc + 2);
        BeaconFormatPrintf(&format, "+\n");
    }

    output = BeaconFormatToString(&format, &size);
    if (output) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s", output);
    }
    BeaconFormatFree(&format);
}
