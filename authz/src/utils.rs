use windows::Win32::Foundation::GetLastError;

pub(crate) fn get_last_error() -> u32 {
    unsafe { GetLastError().0 }
}

pub(crate) fn pwstr_to_str(ptr: *const u16) -> String {
    let mut len = 0;
    unsafe {
        while *(ptr.add(len)) != 0 {
            len += 1;
        }
    }
    let slice = unsafe { &*(std::ptr::slice_from_raw_parts(ptr, len)) };
    String::from_utf16_lossy(slice)
}