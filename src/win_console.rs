#[cfg(windows)]
pub fn init() {
    use std::ffi::c_void;

    extern "system" {
        fn SetConsoleOutputCP(wCodePageID: u32) -> i32;
        fn GetStdHandle(nStdHandle: u32) -> *mut c_void;
        fn GetConsoleMode(hConsoleHandle: *mut c_void, lpMode: *mut u32) -> i32;
        fn SetConsoleMode(hConsoleHandle: *mut c_void, dwMode: u32) -> i32;
    }

    const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // (DWORD)-11
    const STD_ERROR_HANDLE: u32  = 0xFFFF_FFF4; // (DWORD)-12
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    const CP_UTF8: u32 = 65001;
    const INVALID_HANDLE_VALUE: isize = -1;

    unsafe {
        // UTF-8 output so box-drawing / λ / ▸ render correctly on PS 5.1 (cp 437/1252)
        SetConsoleOutputCP(CP_UTF8);

        // Enable ANSI escape interpretation on both stdout and stderr
        for handle_id in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            let h = GetStdHandle(handle_id);
            if h.is_null() || h as isize == INVALID_HANDLE_VALUE {
                continue;
            }
            let mut mode: u32 = 0;
            if GetConsoleMode(h, &mut mode) != 0 {
                SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }
}

#[cfg(not(windows))]
pub fn init() {}
