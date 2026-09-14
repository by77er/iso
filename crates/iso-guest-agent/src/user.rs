//! Who a command runs as: a name or a uid, looked up in the guest's own
//! passwd database.

use std::ffi::{CStr, CString};

/// A resolved account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
}

/// Resolve `who`: a name, or a decimal uid. A uid with no passwd entry is
/// accepted as is (gid = uid, home `/`), the way `docker exec --user` does.
pub fn resolve(who: &str) -> Result<Account, String> {
    if let Ok(uid) = who.parse::<u32>() {
        return Ok(by_uid(uid).unwrap_or(Account { name: uid.to_string(), uid, gid: uid, home: "/".into() }));
    }
    by_name(who).ok_or_else(|| "no such user".to_string())
}

fn from_passwd(pw: &libc::passwd) -> Account {
    let s = |p: *const libc::c_char| -> String {
        if p.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
        }
    };
    Account { name: s(pw.pw_name), uid: pw.pw_uid, gid: pw.pw_gid, home: s(pw.pw_dir) }
}

fn by_name(name: &str) -> Option<Account> {
    let cname = CString::new(name).ok()?;
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; 16 * 1024];
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwnam_r(cname.as_ptr(), &mut pw, buf.as_mut_ptr() as *mut libc::c_char, buf.len(), &mut out) };
    if rc != 0 || out.is_null() {
        return None;
    }
    Some(from_passwd(&pw))
}

fn by_uid(uid: u32) -> Option<Account> {
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; 16 * 1024];
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr() as *mut libc::c_char, buf.len(), &mut out) };
    if rc != 0 || out.is_null() {
        return None;
    }
    Some(from_passwd(&pw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_by_name_and_by_uid_and_a_bare_uid() {
        let root = resolve("root").unwrap();
        assert_eq!((root.uid, root.gid), (0, 0));
        assert_eq!(resolve("0").unwrap().name, "root");
        let stray = resolve("65534123").unwrap();
        assert_eq!((stray.uid, stray.gid, stray.home.as_str()), (65534123, 65534123, "/"));
        assert!(resolve("no-such-user-iso").is_err());
    }
}
