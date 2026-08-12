use std::fs::{File, OpenOptions};
use std::path::{Component, Path, PathBuf};

use crate::{Error, Result};

/// Ownership and access requirements for a file whose contents influence a
/// security decision.
///
/// `UntrustedInput` still rejects links/reparse points and binds validation to
/// the opened handle, but intentionally permits a system- or group-owned input
/// (for example, a benchmark supplied by an administrator). The other modes
/// require current-user ownership. On Unix, `Private` additionally rejects all
/// group/other access. On Windows, protected objects must be owned by either
/// the current token's user SID or its exact default-owner SID, and both
/// protected modes reject broad-principal write, delete, ownership, and
/// DACL-control rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveFilePolicy {
    UntrustedInput,
    IntegrityProtected,
    Private,
}

/// Windows sharing permitted while a sensitive-file guard is alive.
///
/// Both modes deny delete/rename sharing. `ReadWrite` is intended for managed
/// databases whose real I/O handle is opened by a library such as SQLite after
/// the custody check; it does not grant filesystem permissions by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveFileSharing {
    ReadOnly,
    ReadWrite,
}

/// Stable identity captured from the actual open file handle.
///
/// Callers can compare two separately opened paths without trusting path text,
/// canonicalization, timestamps, or file size. This closes validation/open
/// races for sensitive reads and writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume_serial: u64,
    #[cfg(windows)]
    file_id: [u8; 16],
}

/// A validated directory handle. Windows keeps the handle alive so a caller
/// may retain the custody boundary for the duration of an operation.
#[derive(Debug)]
pub struct SensitiveDirectoryGuard {
    #[cfg(windows)]
    _directory: File,
}

/// Add the platform's do-not-follow behavior to a file open operation.
///
/// Unix callers may continue adding their existing `O_CLOEXEC`/mode flags.
/// Windows opens the reparse point itself and then rejects it using handle
/// metadata, rather than silently following it.
pub fn configure_no_follow(options: &mut OpenOptions) {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(not(windows))]
    let _ = options;
}

/// Open an existing sensitive file without following links/reparse points,
/// validate the actual handle, and keep replacement/writes excluded for the
/// lifetime of the returned handle on Windows.
pub fn open_sensitive_file(path: &Path, label: &str, policy: SensitiveFilePolicy) -> Result<File> {
    open_sensitive_file_with_sharing(path, label, policy, SensitiveFileSharing::ReadOnly)
}

/// Open and validate an existing sensitive file while allowing a subsequent
/// trusted handle to request read/write sharing on Windows.
pub fn open_sensitive_file_with_sharing(
    path: &Path,
    label: &str,
    policy: SensitiveFilePolicy,
    sharing: SensitiveFileSharing,
) -> Result<File> {
    reject_reparse_ancestors(path, label)?;
    let path_metadata = std::fs::symlink_metadata(path).map_err(|error| {
        Error::Other(format!(
            "failed to inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(Error::Other(format!(
            "{label} {} is not a regular non-link file",
            path.display()
        )));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    configure_no_follow(&mut options);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
        let share_mode = match sharing {
            SensitiveFileSharing::ReadOnly => FILE_SHARE_READ,
            SensitiveFileSharing::ReadWrite => FILE_SHARE_READ | FILE_SHARE_WRITE,
        };
        options.share_mode(share_mode);
    }
    #[cfg(not(windows))]
    let _ = sharing;
    let file = options.open(path).map_err(|error| {
        Error::Other(format!(
            "failed to open {label} {} securely: {error}",
            path.display()
        ))
    })?;
    validate_open_sensitive_file(&file, path, label, policy)?;
    Ok(file)
}

/// Reject a reparse point/symlink in the target or any existing ancestor.
///
/// Windows junctions are reparse points but are not always reported as Rust
/// symbolic links. Each component is therefore opened with
/// `FILE_FLAG_OPEN_REPARSE_POINT` and inspected through that handle.
///
/// Unix permits one narrow exception for platform aliases such as macOS
/// `/var -> /private/var`: an intermediate link must be root-owned and its
/// directory entry must remain below an entirely root-owned, non-group/world-
/// writable prefix. Unix link mode bits do not control replacement, so the
/// containing directory's custody is what matters. After traversal reaches a
/// user-owned or broadly writable directory, every subsequent link is rejected.
/// The requested target itself is always rejected when it is a link.
pub fn reject_reparse_ancestors(path: &Path, label: &str) -> Result<()> {
    #[cfg(windows)]
    {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut components = absolute
            .ancestors()
            .filter(|component| !component.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .collect::<Vec<_>>();
        components.reverse();
        for component in components {
            match std::fs::symlink_metadata(&component) {
                Ok(_) => windows::reject_reparse_path(&component, label)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => {
                    return Err(Error::Other(format!(
                        "failed to inspect {label} component {}: {error}",
                        component.display()
                    )))
                }
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut components = absolute
            .ancestors()
            .filter(|component| !component.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .collect::<Vec<_>>();
        components.reverse();

        let mut trusted_system_prefix = true;
        for component in components {
            let metadata = match std::fs::symlink_metadata(&component) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => {
                    return Err(Error::Other(format!(
                        "failed to inspect {label} component {}: {error}",
                        component.display()
                    )))
                }
            };
            if metadata.file_type().is_symlink() {
                let protected_system_alias =
                    component != absolute && trusted_system_prefix && metadata.uid() == 0;
                if !protected_system_alias {
                    return Err(Error::Other(format!(
                        "{label} contains a symbolic link: {}",
                        component.display()
                    )));
                }

                let target_metadata = std::fs::metadata(&component).map_err(|error| {
                    Error::Other(format!(
                        "failed to resolve trusted system alias for {label} component {}: {error}",
                        component.display()
                    ))
                })?;
                if !target_metadata.is_dir() {
                    return Err(Error::Other(format!(
                        "{label} contains a non-directory system alias: {}",
                        component.display()
                    )));
                }
                trusted_system_prefix =
                    target_metadata.uid() == 0 && target_metadata.permissions().mode() & 0o022 == 0;
            } else if metadata.is_dir() {
                trusted_system_prefix = trusted_system_prefix
                    && metadata.uid() == 0
                    && metadata.permissions().mode() & 0o022 == 0;
            } else {
                trusted_system_prefix = false;
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = (path, label);
    Ok(())
}

/// Validate an already-opened sensitive file and return its stable identity.
/// Security checks are performed on the handle that the caller will actually
/// read from or write to.
pub fn validate_open_sensitive_file(
    file: &File,
    path: &Path,
    label: &str,
    policy: SensitiveFilePolicy,
) -> Result<StableFileIdentity> {
    let metadata = file.metadata().map_err(|error| {
        Error::Other(format!(
            "failed to inspect open {label} {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(Error::Other(format!(
            "{label} {} is not a regular file",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if policy != SensitiveFilePolicy::UntrustedInput {
            let current_uid = unsafe { libc::geteuid() };
            if metadata.uid() != current_uid {
                return Err(Error::Other(format!(
                    "{label} {} is not owned by the current user",
                    path.display()
                )));
            }
            let forbidden = if policy == SensitiveFilePolicy::Private {
                0o077
            } else {
                0o022
            };
            let mode = metadata.permissions().mode();
            if mode & forbidden != 0 {
                return Err(Error::Other(format!(
                    "{label} {} has insecure permissions {:04o}",
                    path.display(),
                    mode & 0o7777
                )));
            }
        }
        Ok(StableFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    #[cfg(windows)]
    {
        windows::validate_handle(file, path, label, policy)?;
        windows::file_identity(file, path, label)
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, label, policy);
        Ok(StableFileIdentity {})
    }
}

/// Compare two open handles using platform-stable file identity.
pub fn ensure_same_open_file(
    expected: &File,
    actual: &File,
    path: &Path,
    label: &str,
) -> Result<()> {
    let expected =
        validate_open_sensitive_file(expected, path, label, SensitiveFilePolicy::UntrustedInput)?;
    let actual =
        validate_open_sensitive_file(actual, path, label, SensitiveFilePolicy::UntrustedInput)?;
    if expected != actual {
        return Err(Error::Other(format!(
            "{label} {} changed while it was being opened",
            path.display()
        )));
    }
    Ok(())
}

/// Validate a sensitive directory controlled by the current security context.
pub fn validate_sensitive_directory(path: &Path, label: &str) -> Result<SensitiveDirectoryGuard> {
    reject_reparse_ancestors(path, label)?;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        Error::Other(format!(
            "failed to inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::Other(format!(
            "{label} {} is not a real directory",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(Error::Other(format!(
                "{label} {} is not owned by the current user",
                path.display()
            )));
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(Error::Other(format!(
                "{label} {} is writable by group or other users",
                path.display()
            )));
        }
        Ok(SensitiveDirectoryGuard {})
    }

    #[cfg(windows)]
    {
        let directory = windows::open_directory_no_follow(path, label)?;
        windows::validate_handle(
            &directory,
            path,
            label,
            SensitiveFilePolicy::IntegrityProtected,
        )?;
        Ok(SensitiveDirectoryGuard {
            _directory: directory,
        })
    }

    #[cfg(not(any(unix, windows)))]
    Ok(SensitiveDirectoryGuard {})
}

#[cfg(windows)]
mod windows {
    use super::{Error, File, OpenOptions, Path, Result, SensitiveFilePolicy, StableFileIdentity};
    use std::mem::{size_of, MaybeUninit};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{
        CloseHandle, LocalFree, ERROR_SUCCESS, GENERIC_ALL, GENERIC_WRITE, HANDLE,
    };
    use windows_sys::Win32::Security::Authorization::{
        GetEffectiveRightsFromAclW, GetSecurityInfo, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT,
        TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, EqualSid, GetTokenInformation, TokenOwner, TokenUser,
        WinAuthenticatedUserSid, WinBuiltinUsersSid, WinWorldSid, ACL, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_INFORMATION_CLASS,
        TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FileAttributeTagInfo, FileIdInfo, GetFileInformationByHandleEx, DELETE, FILE_APPEND_DATA,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_DELETE_CHILD,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC,
        WRITE_OWNER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    struct CurrentUserSid {
        storage: Vec<usize>,
    }

    impl CurrentUserSid {
        fn as_ptr(&self) -> PSID {
            let user = unsafe { &*(self.storage.as_ptr().cast::<TOKEN_USER>()) };
            user.User.Sid
        }
    }

    struct CurrentDefaultOwnerSid {
        storage: Vec<usize>,
    }

    impl CurrentDefaultOwnerSid {
        fn as_ptr(&self) -> PSID {
            let owner = unsafe { &*(self.storage.as_ptr().cast::<TOKEN_OWNER>()) };
            owner.Owner
        }
    }

    struct WellKnownSid {
        storage: Vec<usize>,
    }

    impl WellKnownSid {
        fn as_ptr(&self) -> PSID {
            self.storage.as_ptr().cast_mut().cast()
        }
    }

    pub(super) fn open_directory_no_follow(path: &Path, label: &str) -> Result<File> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            // Retaining this guard blocks replacement of the validated
            // directory itself while still allowing normal child I/O.
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        options.open(path).map_err(|error| {
            Error::Other(format!(
                "failed to open {label} {} without following reparse points: {error}",
                path.display()
            ))
        })
    }

    pub(super) fn reject_reparse_path(path: &Path, label: &str) -> Result<()> {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            Error::Other(format!(
                "failed to inspect {label} component {}: {error}",
                path.display()
            ))
        })?;
        let file = if metadata.is_dir() {
            open_directory_no_follow(path, label)?
        } else {
            let mut options = OpenOptions::new();
            options
                .read(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            options.open(path).map_err(|error| {
                Error::Other(format!(
                    "failed to open {label} component {} without following reparse points: {error}",
                    path.display()
                ))
            })?
        };
        ensure_not_reparse(&file, path, label)
    }

    fn ensure_not_reparse(file: &File, path: &Path, label: &str) -> Result<()> {
        let mut info = MaybeUninit::<FILE_ATTRIBUTE_TAG_INFO>::zeroed();
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as HANDLE,
                FileAttributeTagInfo,
                info.as_mut_ptr().cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        };
        if ok == 0 {
            return Err(Error::Other(format!(
                "failed to inspect open {label} {} for reparse points: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }
        let info = unsafe { info.assume_init() };
        if info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::Other(format!(
                "{label} contains a Windows reparse point: {}",
                path.display()
            )));
        }
        Ok(())
    }

    pub(super) fn file_identity(
        file: &File,
        path: &Path,
        label: &str,
    ) -> Result<StableFileIdentity> {
        let mut info = MaybeUninit::<FILE_ID_INFO>::zeroed();
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as HANDLE,
                FileIdInfo,
                info.as_mut_ptr().cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        };
        if ok == 0 {
            return Err(Error::Other(format!(
                "failed to determine stable identity for {label} {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }
        let info = unsafe { info.assume_init() };
        Ok(StableFileIdentity {
            volume_serial: info.VolumeSerialNumber,
            file_id: info.FileId.Identifier,
        })
    }

    pub(super) fn validate_handle(
        file: &File,
        path: &Path,
        label: &str,
        policy: SensitiveFilePolicy,
    ) -> Result<()> {
        ensure_not_reparse(file, path, label)?;
        if policy == SensitiveFilePolicy::UntrustedInput {
            return Ok(());
        }

        let mut owner: PSID = null_mut();
        let mut dacl: *mut ACL = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(Error::Other(format!(
                "failed to inspect Windows ownership/DACL for {label} {}: {}",
                path.display(),
                std::io::Error::from_raw_os_error(status as i32)
            )));
        }
        let _descriptor = LocalSecurityDescriptor(descriptor);
        if owner.is_null() {
            return Err(Error::Other(format!(
                "{label} {} has no Windows owner SID",
                path.display()
            )));
        }
        if !owner_matches_current_token(owner)? {
            return Err(Error::Other(format!(
                "{label} {} is not owned by the current Windows user or token default owner",
                path.display()
            )));
        }
        if dacl.is_null() {
            return Err(Error::Other(format!(
                "{label} {} has a null DACL that grants unrestricted access",
                path.display()
            )));
        }

        for (sid_type, name) in [
            (WinWorldSid, "Everyone"),
            (WinAuthenticatedUserSid, "Authenticated Users"),
            (WinBuiltinUsersSid, "BUILTIN\\Users"),
        ] {
            let sid = well_known_sid(sid_type)?;
            let trustee = TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: sid.as_ptr().cast(),
            };
            let mut rights = 0u32;
            let status = unsafe { GetEffectiveRightsFromAclW(dacl, &trustee, &mut rights) };
            if status != ERROR_SUCCESS {
                return Err(Error::Other(format!(
                    "failed to evaluate {name} DACL rights for {label} {}: {}",
                    path.display(),
                    std::io::Error::from_raw_os_error(status as i32)
                )));
            }
            let forbidden = FILE_WRITE_DATA
                | FILE_APPEND_DATA
                | FILE_WRITE_EA
                | FILE_WRITE_ATTRIBUTES
                | FILE_DELETE_CHILD
                | DELETE
                | WRITE_DAC
                | WRITE_OWNER
                | GENERIC_WRITE
                | GENERIC_ALL;
            if rights & forbidden != 0 {
                return Err(Error::Other(format!(
                    "{label} {} grants {name} write/delete/control rights (mask 0x{:08x})",
                    path.display(),
                    rights & forbidden
                )));
            }
        }
        Ok(())
    }

    fn owner_matches_current_token(owner: PSID) -> Result<bool> {
        let current_user = current_user_sid()?;
        if unsafe { EqualSid(owner, current_user.as_ptr()) } != 0 {
            return Ok(true);
        }

        // Windows assigns a newly created object's owner from TokenOwner, not
        // necessarily TokenUser. Elevated tokens commonly use the exact
        // BUILTIN\Administrators SID here. Comparing against the token value
        // preserves an exact security-principal binding without accepting an
        // arbitrary administrator, group, account name, or path owner.
        let default_owner = current_default_owner_sid()?;
        Ok(unsafe { EqualSid(owner, default_owner.as_ptr()) } != 0)
    }

    fn current_user_sid() -> Result<CurrentUserSid> {
        // Keep an aligned token-information buffer alive for the duration of
        // the caller's EqualSid comparison.
        let buffer = current_token_information(TokenUser, "user")?;
        let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        if user.User.Sid.is_null() {
            return Err(Error::Other(
                "current Windows process token has no user SID".to_string(),
            ));
        }
        Ok(CurrentUserSid { storage: buffer })
    }

    fn current_default_owner_sid() -> Result<CurrentDefaultOwnerSid> {
        // TokenOwner is the exact SID Windows uses as the default owner for
        // objects created by this security context. Keep the aligned token
        // information buffer alive for the caller's EqualSid comparison.
        let buffer = current_token_information(TokenOwner, "default-owner")?;
        let owner = unsafe { &*(buffer.as_ptr().cast::<TOKEN_OWNER>()) };
        if owner.Owner.is_null() {
            return Err(Error::Other(
                "current Windows process token has no default-owner SID".to_string(),
            ));
        }
        Ok(CurrentDefaultOwnerSid { storage: buffer })
    }

    fn current_token_information(
        information_class: TOKEN_INFORMATION_CLASS,
        label: &str,
    ) -> Result<Vec<usize>> {
        let mut token: HANDLE = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(Error::Other(format!(
                "failed to open the current Windows process token: {}",
                std::io::Error::last_os_error()
            )));
        }
        let token = OwnedHandle(token);
        let mut required = 0u32;
        unsafe {
            GetTokenInformation(token.0, information_class, null_mut(), 0, &mut required);
        }
        if required == 0 {
            return Err(Error::Other(format!(
                "failed to size the current Windows {label} token: {}",
                std::io::Error::last_os_error()
            )));
        }
        let words = (required as usize).div_ceil(size_of::<usize>());
        let mut buffer = vec![0usize; words];
        if unsafe {
            GetTokenInformation(
                token.0,
                information_class,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(Error::Other(format!(
                "failed to read the current Windows {label} token: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(buffer)
    }

    fn well_known_sid(sid_type: i32) -> Result<WellKnownSid> {
        // SECURITY_MAX_SID_SIZE is 68 bytes; ask Windows for the exact size so
        // this remains correct if a future supported platform differs.
        let mut required = 0u32;
        unsafe {
            CreateWellKnownSid(sid_type, null_mut(), null_mut(), &mut required);
        }
        if required == 0 {
            return Err(Error::Other(format!(
                "failed to size Windows well-known SID {sid_type}: {}",
                std::io::Error::last_os_error()
            )));
        }
        let words = (required as usize).div_ceil(size_of::<usize>());
        let mut storage = vec![0usize; words];
        if unsafe {
            CreateWellKnownSid(
                sid_type,
                null_mut(),
                storage.as_mut_ptr().cast(),
                &mut required,
            )
        } == 0
        {
            return Err(Error::Other(format!(
                "failed to create Windows well-known SID {sid_type}: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(WellKnownSid { storage })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn owner_matching_accepts_only_exact_current_token_principals() {
            let default_owner = current_default_owner_sid().unwrap();
            assert!(owner_matches_current_token(default_owner.as_ptr()).unwrap());

            let world = well_known_sid(WinWorldSid).unwrap();
            assert!(!owner_matches_current_token(world.as_ptr()).unwrap());
        }
    }
}

/// Convert a user/content supplied identifier into a safe single filename.
///
/// The returned value never contains path separators, parent traversal, control
/// characters, or absolute path components. Spaces are normalized to `_`.
pub fn safe_filename(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Error::Other("filename cannot be empty".to_string()));
    }
    if trimmed == "." || trimmed == ".." || trimmed.contains("..") {
        return Err(Error::Other(format!("unsafe filename: {input}")));
    }

    let mut out = String::with_capacity(trimmed.len());
    for c in trimmed.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-' | '.' => out.push(c),
            ' ' => out.push('_'),
            _ => {
                return Err(Error::Other(format!(
                    "unsafe character in filename: {input}"
                )))
            }
        }
    }

    if out.is_empty() || out == "." || out == ".." || out.contains("..") {
        return Err(Error::Other(format!("unsafe filename: {input}")));
    }

    Ok(out)
}

/// Safely join a single child path under a trusted base directory.
pub fn safe_join_under(base: &Path, child: &str) -> Result<PathBuf> {
    let filename = safe_filename(child)?;
    let candidate = base.join(filename);
    ensure_under_base(base, &candidate)?;
    Ok(candidate)
}

/// Ensure a candidate path cannot escape the base directory through absolute
/// components or parent traversal.
pub fn ensure_under_base(base: &Path, candidate: &Path) -> Result<()> {
    if candidate.is_absolute() && !candidate.starts_with(base) {
        return Err(Error::Other(format!(
            "path {} is outside base {}",
            candidate.display(),
            base.display()
        )));
    }

    for component in candidate.components() {
        match component {
            Component::ParentDir => {
                return Err(Error::Other(format!(
                    "path traversal is not allowed: {}",
                    candidate.display()
                )));
            }
            Component::Prefix(_) if !(candidate.is_absolute() && candidate.starts_with(base)) => {
                return Err(Error::Other(format!(
                    "platform path prefixes are not allowed: {}",
                    candidate.display()
                )));
            }
            _ => {}
        }
    }

    if candidate.is_absolute() && !candidate.starts_with(base) {
        return Err(Error::Other(format!(
            "path {} is outside base {}",
            candidate.display(),
            base.display()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn protected_temp_objects_validate_under_current_windows_security_context() {
        let directory = tempfile::tempdir().unwrap();
        let _directory_guard =
            validate_sensitive_directory(directory.path(), "test directory").unwrap();

        let path = directory.path().join("protected.txt");
        std::fs::write(&path, b"protected").unwrap();
        let _file =
            open_sensitive_file(&path, "test file", SensitiveFilePolicy::IntegrityProtected)
                .unwrap();
    }

    #[test]
    fn safe_filename_allows_expected_identifiers() {
        assert_eq!(
            safe_filename("Windows_Server_2022_STIG").unwrap(),
            "Windows_Server_2022_STIG"
        );
        assert_eq!(safe_filename("site answers").unwrap(), "site_answers");
        assert_eq!(safe_filename("rhel8-v1.2").unwrap(), "rhel8-v1.2");
    }

    #[test]
    fn safe_filename_rejects_path_traversal_and_separators() {
        for value in [
            "",
            "..",
            "../evil",
            "a/evil",
            "a\\evil",
            "evil\0name",
            "a..b",
        ] {
            assert!(safe_filename(value).is_err(), "{value} should be rejected");
        }
    }

    #[test]
    fn safe_join_under_rejects_unsafe_children() {
        let base = Path::new("/tmp/automatestig");
        assert!(safe_join_under(base, "benchmark")
            .unwrap()
            .ends_with("benchmark"));
        assert!(safe_join_under(base, "../../etc/passwd").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn sensitive_file_open_binds_identity_and_rejects_links() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("private.key");
        std::fs::write(&path, b"secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let first = open_sensitive_file(&path, "test key", SensitiveFilePolicy::Private).unwrap();
        let second = open_sensitive_file(&path, "test key", SensitiveFilePolicy::Private).unwrap();
        ensure_same_open_file(&first, &second, &path, "test key").unwrap();

        let link = directory.path().join("private-link.key");
        symlink(&path, &link).unwrap();
        assert!(open_sensitive_file(&link, "test key", SensitiveFilePolicy::Private).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn sensitive_file_open_rejects_an_intermediate_ancestor_link() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        let real_parent = directory.path().join("real").join("nested");
        std::fs::create_dir_all(&real_parent).unwrap();
        let path = real_parent.join("private.key");
        std::fs::write(&path, b"secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let linked_parent = directory.path().join("linked");
        symlink(directory.path().join("real"), &linked_parent).unwrap();
        let linked_path = linked_parent.join("nested").join("private.key");
        let error = open_sensitive_file(&linked_path, "test key", SensitiveFilePolicy::Private)
            .unwrap_err();

        assert!(error.to_string().contains("contains a symbolic link"));
        assert!(error
            .to_string()
            .contains(&linked_parent.display().to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn sensitive_directory_rejects_an_intermediate_ancestor_link() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let sensitive = directory
            .path()
            .join("real")
            .join("nested")
            .join("sensitive");
        std::fs::create_dir_all(&sensitive).unwrap();

        let linked_parent = directory.path().join("linked");
        symlink(directory.path().join("real"), &linked_parent).unwrap();
        let linked_path = linked_parent.join("nested").join("sensitive");
        let error = validate_sensitive_directory(&linked_path, "test directory").unwrap_err();

        assert!(error.to_string().contains("contains a symbolic link"));
        assert!(error
            .to_string()
            .contains(&linked_parent.display().to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn ancestor_check_allows_a_nonexistent_tail() {
        let directory = tempfile::tempdir().unwrap();
        let future_path = directory.path().join("not-created").join("child");

        reject_reparse_ancestors(&future_path, "future path").unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ancestor_check_allows_the_protected_macos_var_system_alias() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let var = std::fs::symlink_metadata("/var").unwrap();
        assert!(var.file_type().is_symlink());
        assert_eq!(var.uid(), 0);
        let root = std::fs::metadata("/").unwrap();
        assert_eq!(root.uid(), 0);
        assert_eq!(root.permissions().mode() & 0o022, 0);

        reject_reparse_ancestors(Path::new("/var/folders"), "system path").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn sensitive_directory_rejects_group_writable_custody_boundary() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        let error = validate_sensitive_directory(directory.path(), "test directory").unwrap_err();
        assert!(error.to_string().contains("writable by group"));
    }
}
