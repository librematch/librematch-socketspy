//! Finding the running game on Linux by scanning `/proc`.
//!
//! Under Proton the game is a native Linux process, so the same `/proc` scan the
//! dump tooling uses finds it here: a process whose executable name matches and
//! whose address space contains the PE image base. The scan reads from a root
//! path, so it is unit-tested against a fake `/proc` tree.

use std::path::{Path, PathBuf};

/// The default AoE2:DE main executable name.
pub const DEFAULT_EXE: &str = "AoE2DE_s.exe";

/// The image base every AoE:DE title maps its main module at.
pub const IMAGE_BASE: u64 = 0x140000000;

/// A found target: its process id and the base its main module is mapped at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    pub pid: i32,
    pub base: u64,
}

/// Scan a `/proc`-shaped tree for a process whose `comm` matches `exe_name` and
/// whose `maps` contains a mapping at `base`. Returns the first match.
pub fn find_target(proc_root: &Path, exe_name: &str, base: u64) -> Option<Target> {
    let mut pids: Vec<i32> = std::fs::read_dir(proc_root)
        .ok()?
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .collect();
    pids.sort_unstable();

    for pid in pids {
        let dir = proc_root.join(pid.to_string());
        if !process_comm_matches(&dir, exe_name) {
            continue;
        }
        if maps_contain_base(&dir, base) {
            return Some(Target { pid, base });
        }
    }
    None
}

/// True if the process's `comm` (or the basename of its `cmdline`) matches.
///
/// Linux truncates `comm` to 15 characters, so a long Windows name like
/// `AoE2DE_s.exe` fits, but the match also falls back to the `cmdline`
/// basename in case the launcher renamed `comm`.
fn process_comm_matches(dir: &Path, exe_name: &str) -> bool {
    if let Ok(comm) = std::fs::read_to_string(dir.join("comm"))
        && comm.trim() == exe_name
    {
        return true;
    }
    if let Ok(cmdline) = std::fs::read(dir.join("cmdline")) {
        // cmdline is NUL-separated; the first field is the program path.
        let first = cmdline.split(|&b| b == 0).next().unwrap_or(&[]);
        if let Ok(s) = std::str::from_utf8(first)
            && basename(s) == exe_name
        {
            return true;
        }
    }
    false
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// True if `pid`'s address space has a mapping at `base` (used to check a
/// `--pid` target before attaching).
pub fn maps_have_base(proc_root: &Path, pid: i32, base: u64) -> bool {
    maps_contain_base(&proc_root.join(pid.to_string()), base)
}

/// True if any line of `maps` starts at `base`.
fn maps_contain_base(dir: &Path, base: u64) -> bool {
    let Ok(maps) = std::fs::read_to_string(dir.join("maps")) else {
        return false;
    };
    let want = format!("{base:x}-");
    maps.lines().any(|l| l.starts_with(&want))
}

/// The path to a process's readable memory, `/proc/<pid>/mem`.
pub fn mem_path(proc_root: &Path, pid: i32) -> PathBuf {
    proc_root.join(pid.to_string()).join("mem")
}

/// Find the load base of a mapped module by the basename of its backing file.
///
/// Under Wine the game maps `winhttp.dll` as an ordinary file mapping, so its
/// base is the lowest start address among the `maps` lines whose path ends in
/// that module name (case-insensitive). Returns `None` if the module is not
/// mapped.
pub fn find_module_base(proc_root: &Path, pid: i32, module: &str) -> Option<u64> {
    let maps = std::fs::read_to_string(proc_root.join(pid.to_string()).join("maps")).ok()?;
    module_base_in_maps(&maps, module)
}

/// The lowest start address of any mapping backed by a file named `module`.
fn module_base_in_maps(maps: &str, module: &str) -> Option<u64> {
    let module = module.to_ascii_lowercase();
    maps.lines()
        .filter_map(|line| {
            let base = map_basename(line)?;
            if base.eq_ignore_ascii_case(&module) {
                let start = line.split(['-', ' ']).next()?;
                u64::from_str_radix(start, 16).ok()
            } else {
                None
            }
        })
        .min()
}

/// The basename of a `maps` line's path. The path is everything after the first
/// five whitespace columns and can itself contain spaces (e.g. a Steam library
/// under `.../Proton Hotfix/...`), so it is rejoined rather than taken as one
/// token.
fn map_basename(line: &str) -> Option<String> {
    let path: String = {
        let rest: Vec<&str> = line.split_whitespace().skip(5).collect();
        if rest.is_empty() {
            return None;
        }
        rest.join(" ")
    };
    path.rsplit(['/', '\\']).next().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_proc(root: &Path, pid: i32, comm: &str, maps: &str) {
        let d = root.join(pid.to_string());
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("comm"), format!("{comm}\n")).unwrap();
        fs::write(d.join("maps"), maps).unwrap();
    }

    #[test]
    fn finds_the_process_with_the_matching_name_and_base() {
        let tmp = std::env::temp_dir().join(format!("ss_proc_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        write_proc(
            &tmp,
            100,
            "some-daemon",
            "7f0000000000-7f0000001000 r--p 0 0 0\n",
        );
        write_proc(
            &tmp,
            200,
            "AoE2DE_s.exe",
            "140000000-140002000 r-xp 0 0 0\n7ffe00000000-7ffe00001000 r--p 0 0 0\n",
        );
        let t = find_target(&tmp, DEFAULT_EXE, IMAGE_BASE).unwrap();
        assert_eq!(
            t,
            Target {
                pid: 200,
                base: IMAGE_BASE
            }
        );
        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn skips_a_matching_name_without_the_image_base() {
        let tmp = std::env::temp_dir().join(format!("ss_proc_nb_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        write_proc(
            &tmp,
            200,
            "AoE2DE_s.exe",
            "555500000000-555500001000 r-xp 0 0 0\n",
        );
        assert!(find_target(&tmp, DEFAULT_EXE, IMAGE_BASE).is_none());
        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn finds_a_module_base_by_basename_taking_the_lowest_mapping() {
        let maps = "\
7f0000000000-7f0000001000 r--p 00000000 00:00 0 /usr/lib/other.so
c0d0e0000000-c0d0e0001000 r--p 00000000 01:02 3 Z:\\game\\lib\\winhttp.dll
c0d0e0001000-c0d0e0040000 r-xp 00001000 01:02 3 Z:\\game\\lib\\winhttp.dll
";
        assert_eq!(
            module_base_in_maps(maps, "winhttp.dll"),
            Some(0xc0d0e0000000)
        );
        assert_eq!(
            module_base_in_maps(maps, "WINHTTP.DLL"),
            Some(0xc0d0e0000000)
        );
        assert_eq!(module_base_in_maps(maps, "absent.dll"), None);
    }

    #[test]
    fn module_path_with_spaces_is_parsed() {
        // A real Proton path contains a space ("Proton Hotfix").
        let maps = "\
6ffffc8c0000-6ffffc8c1000 r--p 00000000 fe:05 123   /steam/common/Proton Hotfix/files/lib/wine/x86_64-windows/winhttp.dll
6ffffc8c1000-6ffffc8e2000 r-xp 00001000 fe:05 123   /steam/common/Proton Hotfix/files/lib/wine/x86_64-windows/winhttp.dll
";
        assert_eq!(
            module_base_in_maps(maps, "winhttp.dll"),
            Some(0x6ffffc8c0000)
        );
    }

    #[test]
    fn matches_on_cmdline_basename_when_comm_differs() {
        let tmp = std::env::temp_dir().join(format!("ss_proc_cl_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let d = tmp.join("200");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("comm"), "AoE2DE_s.ex\n").unwrap(); // truncated / renamed
        fs::write(d.join("cmdline"), b"Z:\\game\\AoE2DE_s.exe\0-arg\0").unwrap();
        fs::write(d.join("maps"), "140000000-140002000 r-xp 0 0 0\n").unwrap();
        let t = find_target(&tmp, DEFAULT_EXE, IMAGE_BASE).unwrap();
        assert_eq!(t.pid, 200);
        fs::remove_dir_all(&tmp).unwrap();
    }
}
