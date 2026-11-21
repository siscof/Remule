// SPDX-License-Identifier: GPL-2.0-or-later
//! The free space of a folder's file system (`CStatistics::GetTempFreeSpace`,
//! `GetIncomingFreeSpace`; `GetAvailableSpaceOn`, OtherFunctions.cpp): what an
//! unprivileged user may still write there.

use std::path::Path;

/// Bytes free for us on the file system holding `path`; `None` when it
/// cannot be told.
#[cfg(unix)]
pub fn free_space(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c` is a valid C string and `st` a place statvfs fills.
    let r = unsafe { libc::statvfs(c.as_ptr(), st.as_mut_ptr()) };
    if r != 0 {
        return None;
    }
    // SAFETY: statvfs succeeded, so it filled `st`.
    let st = unsafe { st.assume_init() };
    #[allow(clippy::unnecessary_cast)]
    Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

#[cfg(windows)]
pub fn free_space(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut free: u64 = 0;
    // SAFETY: `wide` is NUL-terminated; the other outputs may be null.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    (ok != 0).then_some(free)
}

#[cfg(not(any(unix, windows)))]
pub fn free_space(_: &Path) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_real_folder_has_free_space_and_a_missing_one_none() {
        let tmp = std::env::temp_dir();
        assert!(super::free_space(&tmp).is_some());
        assert_eq!(
            super::free_space(&tmp.join("remuled-no-such-folder-at-all")),
            None
        );
    }
}
