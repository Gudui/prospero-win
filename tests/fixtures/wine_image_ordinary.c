/* SPDX-License-Identifier: MIT
 * Bounded ordinary Win32 section lifetime checks using this executable only.
 * No descriptor exhaustion, invalid memory accesses or host runtime execution.
 */
#define _WIN32_WINNT 0x0601
#include <windows.h>

static HANDLE report_file = INVALID_HANDLE_VALUE;
static unsigned checks, failures, cases;

struct line { char data[512]; unsigned used; };
static void text(struct line *line, const char *value)
{
    while (*value && line->used < sizeof(line->data) - 1)
        line->data[line->used++] = *value++;
}
static void hex(struct line *line, DWORD value)
{
    static const char digits[] = "0123456789abcdef";
    text(line, "0x");
    for (unsigned i = 0; i < 8; ++i)
        if (line->used < sizeof(line->data) - 1)
            line->data[line->used++] = digits[(value >> (28 - 4 * i)) & 15];
}
static void write_line(struct line *line)
{
    DWORD written;
    text(line, "\n");
    if (report_file != INVALID_HANDLE_VALUE)
        (void)WriteFile(report_file, line->data, line->used, &written, NULL);
    (void)WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), line->data, line->used, &written, NULL);
}
static void begin_case(const char *name)
{
    struct line line = {{0}, 0};
    ++cases;
    text(&line, "PW_IMAGE_ORDINARY case="); text(&line, name); write_line(&line);
}
static void check(const char *name, DWORD actual, DWORD expected)
{
    struct line line = {{0}, 0};
    ++checks;
    if (actual != expected) ++failures;
    text(&line, "PW_IMAGE_ORDINARY check="); text(&line, name);
    text(&line, " actual="); hex(&line, actual);
    text(&line, " expected="); hex(&line, expected);
    text(&line, actual == expected ? " result=PASS" : " result=FAIL");
    write_line(&line);
}
static BOOL valid(const char *name, HANDLE handle)
{
    BOOL ok = handle && handle != INVALID_HANDLE_VALUE;
    check(name, ok, TRUE);
    return ok;
}
static void close_handle(HANDLE handle)
{
    if (handle && handle != INVALID_HANDLE_VALUE) check("close_handle", CloseHandle(handle), TRUE);
}
static WCHAR asset[128];
static void name_text(unsigned *used, const WCHAR *text_value)
{
    while (*text_value && *used < 127) asset[(*used)++] = *text_value++;
    asset[*used] = 0;
}
static void name_hex(unsigned *used, DWORD value)
{
    static const WCHAR digits[] = L"0123456789abcdef";
    for (unsigned i = 0; i < 8 && *used < 127; ++i)
        asset[(*used)++] = digits[(value >> (28 - 4 * i)) & 15];
    asset[*used] = 0;
}
static BOOL own_asset(void)
{
    WCHAR source[MAX_PATH]; unsigned used = 0;
    DWORD length = GetModuleFileNameW(NULL, source, MAX_PATH);
    check("own_executable_path", length && length < MAX_PATH, TRUE);
    if (!length || length >= MAX_PATH) return FALSE;
    name_text(&used, L"pw-image-ordinary-"); name_hex(&used, GetCurrentProcessId());
    name_text(&used, L"-"); name_hex(&used, GetTickCount()); name_text(&used, L".exe");
    /* Copy only our own executable; fail rather than overwrite an existing file. */
    BOOL copied = CopyFileW(source, asset, TRUE);
    check("copy_own_executable", copied, TRUE); return copied;
}
static HANDLE file(void)
{
    HANDLE result = CreateFileW(asset, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    valid("open_fixture_asset", result); return result;
}
static HANDLE section(HANDLE handle, BOOL image)
{
    if (!handle || handle == INVALID_HANDLE_VALUE) return NULL;
    HANDLE result = CreateFileMappingW(handle, NULL, PAGE_READONLY | (image ? SEC_IMAGE : 0), 0, 0, NULL);
    valid(image ? "create_image_section" : "create_data_section", result); return result;
}
static void *view(HANDLE mapping)
{
    if (!mapping) return NULL;
    void *result = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    check("map_section_view", result != NULL, TRUE); return result;
}
static BOOL readable(const char *name, void *pointer, DWORD type)
{
    MEMORY_BASIC_INFORMATION info;
    if (!pointer) return FALSE;
    SIZE_T size = VirtualQuery(pointer, &info, sizeof(info));
    check(name, size == sizeof(info), TRUE);
    if (size != sizeof(info)) return FALSE;
    check("view_committed", info.State, MEM_COMMIT); check("view_type", info.Type, type);
    DWORD access = info.Protect & 0xff;
    BOOL can_read = access == PAGE_READONLY || access == PAGE_READWRITE || access == PAGE_WRITECOPY ||
                    access == PAGE_EXECUTE_READ || access == PAGE_EXECUTE_READWRITE || access == PAGE_EXECUTE_WRITECOPY;
    BOOL ok = info.State == MEM_COMMIT && can_read && !(info.Protect & PAGE_GUARD) &&
              info.RegionSize >= sizeof(WORD);
    check("view_readable", ok, TRUE); return ok;
}
static void header(const char *name, void *pointer, BOOL image)
{
    if (readable(name, pointer, image ? MEM_IMAGE : MEM_MAPPED))
        check("own_image_mz_header", *(const volatile WORD *)pointer, 0x5a4d);
}
static void unmap(void *pointer)
{
    if (pointer) check("unmap_view", UnmapViewOfFile(pointer), TRUE);
}
static void live_section(void)
{
    begin_case("live_section_later_view");
    HANDLE source = file(), mapping = section(source, TRUE);
    void *first = view(mapping); header("live_first_view", first, TRUE);
    close_handle(source); unmap(first);
    /* The still-open section remains usable after the source handle closes. */
    void *later = view(mapping); header("live_later_view", later, TRUE);
    close_handle(mapping); header("later_after_section_close", later, TRUE); unmap(later);
}
static void new_section(void)
{
    begin_case("closed_section_views_and_fresh_section");
    HANDLE source = file(), mapping = section(source, TRUE);
    void *first = view(mapping);
    close_handle(source); close_handle(mapping); header("retained_first_view", first, TRUE);
    /* A new file/section must use valid backing while the earlier view survives. */
    HANDLE next_source = file(), next_mapping = section(next_source, TRUE);
    void *second = view(next_mapping);
    close_handle(next_source); close_handle(next_mapping);
    header("fresh_section_view", second, TRUE); header("old_view_still_readable", first, TRUE);
    unmap(first); header("fresh_view_after_old_unmap", second, TRUE); unmap(second);
}
static void multiple_sections(void)
{
    begin_case("multiple_sections_and_last_mapping_owner");
    HANDLE source = file(), first_mapping = section(source, TRUE), second_mapping = section(source, TRUE);
    void *first = view(first_mapping), *second = view(second_mapping);
    close_handle(source); close_handle(first_mapping);
    /* The remaining section must support another view before its final close. */
    void *third = view(second_mapping); header("third_from_live_second_section", third, TRUE);
    close_handle(second_mapping);
    header("first_after_last_section_close", first, TRUE);
    header("second_after_last_section_close", second, TRUE);
    header("third_after_last_section_close", third, TRUE);
    unmap(first); unmap(second); header("third_after_other_views_unmap", third, TRUE); unmap(third);
}
static void retained_sharing(void)
{
    begin_case("image_sharing_metadata_after_section_close");
    HANDLE source = file(), mapping = section(source, TRUE); void *mapped = view(mapping);
    close_handle(source); close_handle(mapping); header("sharing_retained_view", mapped, TRUE);
    if (mapped)
    {
        SetLastError(0);
        HANDLE write_handle = CreateFileW(asset, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                          NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        DWORD error = GetLastError();
        check("mapped_image_write_rejected", write_handle == INVALID_HANDLE_VALUE, TRUE);
        if (write_handle == INVALID_HANDLE_VALUE) check("mapped_image_sharing_error", error, ERROR_SHARING_VIOLATION);
        close_handle(write_handle);
    }
    unmap(mapped);
    HANDLE after = CreateFileW(asset, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    valid("write_open_after_final_unmap", after); close_handle(after); /* No bytes are written. */
}
static void data_mapping(void)
{
    begin_case("data_mapping_lifetime_exclusion");
    HANDLE source = file(), mapping = section(source, FALSE); void *mapped = view(mapping);
    close_handle(source); close_handle(mapping); header("data_view_after_handles_close", mapped, FALSE);
    HANDLE next_source = file(), next_mapping = section(next_source, FALSE); void *next = view(next_mapping);
    close_handle(next_source); close_handle(next_mapping); header("fresh_data_view", next, FALSE);
    unmap(mapped); header("remaining_data_view", next, FALSE); unmap(next);
}
static void anonymous_mapping(void)
{
    begin_case("anonymous_mapping_lifetime_exclusion");
    HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, NULL);
    if (!valid("anonymous_section", mapping)) return;
    DWORD *mapped = MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 4096);
    check("anonymous_view", mapped != NULL, TRUE);
    if (mapped) *mapped = 0x12345678u;
    close_handle(mapping);
    if (readable("anonymous_after_section_close", mapped, MEM_MAPPED))
        check("anonymous_private_value", *(const volatile DWORD *)mapped, 0x12345678u);
    unmap(mapped);
}
void WINAPI mainCRTStartup(void)
{
    report_file = CreateFileW(L"pw-image-ordinary.log", GENERIC_WRITE, FILE_SHARE_READ, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    BOOL copied = own_asset();
    if (copied)
    {
        live_section(); new_section(); multiple_sections(); retained_sharing(); data_mapping(); anonymous_mapping();
        check("delete_owned_fixture_copy", DeleteFileW(asset), TRUE);
    }
    check("case_count", cases, 6);
    struct line line = {{0}, 0};
    text(&line, "PW_IMAGE_ORDINARY done cases="); hex(&line, cases);
    text(&line, " checks="); hex(&line, checks); text(&line, " failures="); hex(&line, failures);
    text(&line, failures ? " result=FAIL" : " result=PASS"); write_line(&line);
    if (report_file != INVALID_HANDLE_VALUE) (void)CloseHandle(report_file);
    ExitProcess(failures ? 1 : 0);
}
