use proxy_dll::proxy;
use retour::static_detour;
use serde::Deserialize;
use skidscan::signature;
use std::{cell::OnceCell, ptr::read_unaligned};

static_detour! {
    static AspectRatioChanger: fn(u64, u64, u64, u64, u64, u64, u64, u8, u64);

    static GetResourceSync: fn(u64, u64, u64, u64, u64, u64) -> u64;
    static GetResourceAsync: fn(u64, u64, u64, u64, u64, u64, u8) -> u64;
    static ReadSqPack: fn(u64, u64, i32, u8) -> u8;
    static TexFileLoader: fn(u64, u64, u8) -> u8;
    static MdlFileLoader: fn(u64, u64, u8) -> u8;
}

static mut CONFIG: OnceCell<Config> = OnceCell::new();
static mut READ_FILE: OnceCell<fn(u64, u64, i32, u8) -> u8> = OnceCell::new();
static mut LOAD_TEX_LOCAL: OnceCell<fn(u64, u64, u64, u8) -> u8> = OnceCell::new();
static mut LOAD_MDL_LOCAL: OnceCell<fn(u64, u64, u8) -> u8> = OnceCell::new();

#[derive(Deserialize, Default)]
struct Config {
    pub widescreen_fix: bool,
    pub mod_dir: Option<String>,
}

fn aspect_ratio_changer_detour(
    _a1: u64,
    _a2: u64,
    _a3: u64,
    _a4: u64,
    _a5: u64,
    _a6: u64,
    _a7: u64,
    _a8: u8,
    _a9: u64,
) {
    // just do nothing 4head
}

#[allow(dead_code)]
fn poor_mans_print(str: &str) {
    msgbox::create("Info", str, msgbox::IconType::Info).ok();
}

const CRC: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
fn handle(
    is_sync: bool,
    resource_manager: u64,
    category_id: u64,
    resource_type: u64,
    resource_hash: u64,
    path: u64,
    params: u64,
    unk: u8,
) -> u64 {
    let config = unsafe { CONFIG.get().unwrap() };

    let path_str = unsafe { std::ffi::CStr::from_ptr(path as *const i8) }.to_str();
    if let Ok(path_str) = path_str {
        let new_path = std::path::Path::new(&config.mod_dir.as_ref().unwrap()).join(path_str);
        let should_replace = std::fs::metadata(&new_path).is_ok();

        if should_replace {
            let new_path = new_path.to_str().unwrap();
            let new_path = new_path.replace('\\', "/").to_lowercase();

            let ascii_path = new_path.as_bytes();
            let cstr = std::ffi::CString::new(ascii_path).unwrap();
            let b_path = cstr.as_ptr();

            unsafe {
                *(resource_hash as *mut u32) = CRC.checksum(ascii_path);
                return if is_sync {
                    GetResourceSync.call(
                        resource_manager,
                        category_id,
                        resource_type,
                        resource_hash,
                        b_path as u64,
                        params,
                    )
                } else {
                    GetResourceAsync.call(
                        resource_manager,
                        category_id,
                        resource_type,
                        resource_hash,
                        b_path as u64,
                        params,
                        unk,
                    )
                };
            }
        }
    }

    if is_sync {
        GetResourceSync.call(
            resource_manager,
            category_id,
            resource_type,
            resource_hash,
            path,
            params,
        )
    } else {
        GetResourceAsync.call(
            resource_manager,
            category_id,
            resource_type,
            resource_hash,
            path,
            params,
            unk,
        )
    }
}

fn get_resource_sync_detour(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    handle(true, a1, a2, a3, a4, a5, a6, 0)
}

fn get_resource_async_detour(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u8) -> u64 {
    handle(false, a1, a2, a3, a4, a5, a6, a7)
}

fn read_sqpack_detour(
    resource_manager: u64,
    file_descriptor: u64,
    priority: i32,
    is_sync: u8,
) -> u8 {
    if file_descriptor == 0 {
        return ReadSqPack.call(resource_manager, file_descriptor, priority, is_sync);
    }

    let handle = unsafe { *((file_descriptor + 0x50) as *const u64) };
    if handle == 0 {
        return ReadSqPack.call(resource_manager, file_descriptor, priority, is_sync);
    }

    let filename = read_basic_string(handle + 0x48);
    let is_rooted = std::path::Path::new(&filename).is_absolute();
    if !is_rooted {
        return ReadSqPack.call(resource_manager, file_descriptor, priority, is_sync);
    }

    unsafe {
        *(file_descriptor as *mut u8) = 0;

        let utf_path = filename.encode_utf16().collect::<Vec<u16>>();
        let utf_path = bytemuck::cast_slice::<u16, u8>(&utf_path);
        let utf_path_len = utf_path.len();
        std::ptr::copy_nonoverlapping(
            utf_path.as_ptr(),
            (file_descriptor + 0x70) as *mut u8,
            utf_path_len,
        );

        let fd_ptr = vec![0u8; 0x20 + utf_path.len() + 0x16].as_mut_ptr();
        std::ptr::copy_nonoverlapping(utf_path.as_ptr(), fd_ptr.add(0x21), utf_path.len());

        *((file_descriptor + 0x30) as *mut u64) = fd_ptr as u64;
        READ_FILE.get().unwrap()(resource_manager, file_descriptor, priority, is_sync)
    }
}

fn read_basic_string(ptr: u64) -> String {
    let len = unsafe { *((ptr + 0x10) as *const u64) };
    if len < 16 {
        // TODO: is this correct? lol
        String::from_utf8_lossy(unsafe {
            std::slice::from_raw_parts(ptr as *const u8, len as usize)
        })
        .to_string()
    } else {
        unsafe {
            let str = std::ffi::CStr::from_ptr(*(ptr as *const *const i8));
            str.to_string_lossy().to_string()
        }
    }
}

fn mdl_file_loader_detour(a1: u64, a2: u64, a3: u8) -> u8 {
    let file = read_basic_string(a1 + 0x48);
    if std::path::Path::new(&file).is_absolute() {
        MdlFileLoader.call(a1, a2, a3);
        unsafe { LOAD_MDL_LOCAL.get().unwrap()(a1, a2, a3) }
    } else {
        MdlFileLoader.call(a1, a2, a3)
    }
}

fn tex_file_loader_detour(a1: u64, a2: u64, a3: u8) -> u8 {
    let file = read_basic_string(a1 + 0x48);
    if std::path::Path::new(&file).is_absolute() {
        TexFileLoader.call(a1, a2, a3);
        unsafe { LOAD_TEX_LOCAL.get().unwrap()(a1, 0, a2, a3) }
    } else {
        TexFileLoader.call(a1, a2, a3)
    }
}

fn find_sig(sig: skidscan::Signature, module: &str) -> anyhow::Result<*mut u8> {
    unsafe {
        let pos = sig
            .scan_module(module)
            .map_err(|_| anyhow::anyhow!(format!("Signature not found: {:?}", sig)))?;

        let first_byte = *pos;
        if first_byte == 0xE8 || first_byte == 0xE9 {
            let offset = pos.add(1) as *const i32;
            let offset: i32 = read_unaligned(offset);
            let addr = pos.wrapping_add(5);
            if offset > 0 {
                Ok(addr.wrapping_add(offset as usize))
            } else {
                Ok(addr.wrapping_sub(offset.abs() as usize))
            }
        } else {
            Ok(pos)
        }
    }
}

fn get_config() -> Config {
    std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::read_to_string(p.join("../benchtweaks.toml")).ok())
        .and_then(|s| toml::from_str::<Config>(&s).ok())
        .unwrap_or_default()
}

unsafe fn do_stuff() -> anyhow::Result<()> {
    let config = unsafe { CONFIG.get().unwrap() };

    if config.widescreen_fix {
        let aspect_ratio_changer_addr = find_sig(
            signature!("E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 89 45 50"),
            "ffxiv_dx11.exe",
        )?;
        let aspect_ratio_changer = std::mem::transmute::<
            *mut u8,
            fn(u64, u64, u64, u64, u64, u64, u64, u8, u64),
        >(aspect_ratio_changer_addr);
        AspectRatioChanger.initialize(aspect_ratio_changer, aspect_ratio_changer_detour)?;
        AspectRatioChanger.enable()?;
    }

    if config.mod_dir.is_some() {
        let get_resource_sync_addr = find_sig(
            signature!("E8 ?? ?? ?? ?? 48 8B D8 8B C7"),
            "ffxiv_dx11.exe",
        )?;
        let get_resource_sync = std::mem::transmute::<
            *mut u8,
            fn(u64, u64, u64, u64, u64, u64) -> u64,
        >(get_resource_sync_addr);
        GetResourceSync.initialize(get_resource_sync, get_resource_sync_detour)?;
        GetResourceSync.enable()?;

        let get_resource_async_addr = find_sig(
            signature!("E8 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 83 C4 68"),
            "ffxiv_dx11.exe",
        )?;
        let get_resource_async = std::mem::transmute::<
            *mut u8,
            fn(u64, u64, u64, u64, u64, u64, u8) -> u64,
        >(get_resource_async_addr);
        GetResourceAsync.initialize(get_resource_async, get_resource_async_detour)?;
        GetResourceAsync.enable()?;

        let read_sqpack_addr = find_sig(
            signature!("40 56 41 56 48 83 EC 28 0F BE 02"),
            "ffxiv_dx11.exe",
        )?;
        let read_sqpack =
            std::mem::transmute::<*mut u8, fn(u64, u64, i32, u8) -> u8>(read_sqpack_addr);
        ReadSqPack.initialize(read_sqpack, read_sqpack_detour)?;
        ReadSqPack.enable()?;

        let read_file_addr = find_sig(
            signature!("48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 54 41 55 41 56 41 57 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 ?? ?? ?? ?? 48 63 42 28"),
            "ffxiv_dx11.exe",
        )?;
        let read_file = std::mem::transmute::<*mut u8, fn(u64, u64, i32, u8) -> u8>(read_file_addr);
        READ_FILE.set(read_file).ok();

        let tex_file_loader_addr = find_sig(
            signature!("40 53 55 41 54 41 55 41 56 41 57 48 81 EC ?? ?? ?? ?? 48 8B D9"),
            "ffxiv_dx11.exe",
        )?;
        let tex_file_loader =
            std::mem::transmute::<*mut u8, fn(u64, u64, u8) -> u8>(tex_file_loader_addr);
        TexFileLoader.initialize(tex_file_loader, tex_file_loader_detour)?;
        TexFileLoader.enable()?;

        let load_tex_local_addr = find_sig(
            signature!("48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC 30 49 8B F0 44 88 4C 24 ??"),
            "ffxiv_dx11.exe",
        )?;
        let load_tex_local =
            std::mem::transmute::<*mut u8, fn(u64, u64, u64, u8) -> u8>(load_tex_local_addr);
        LOAD_TEX_LOCAL.set(load_tex_local).ok();

        let mdl_file_loader_addr = find_sig(
            signature!("48 89 5C 24 ?? 48 89 6C 24 ?? 57 48 83 EC 20 80 3A 0B"),
            "ffxiv_dx11.exe",
        )?;
        let mdl_file_loader =
            std::mem::transmute::<*mut u8, fn(u64, u64, u8) -> u8>(mdl_file_loader_addr);
        MdlFileLoader.initialize(mdl_file_loader, mdl_file_loader_detour)?;
        MdlFileLoader.enable()?;

        let load_mdl_local_addr = find_sig(
            signature!("48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 45 17 48 8B 72 18"),
            "ffxiv_dx11.exe",
        )?;
        let load_mdl_local =
            std::mem::transmute::<*mut u8, fn(u64, u64, u8) -> u8>(load_mdl_local_addr);
        LOAD_MDL_LOCAL.set(load_mdl_local).ok();
    }

    Ok(())
}

#[proxy]
fn main() {
    let current_exe = std::env::current_exe().unwrap();
    let current_exe = current_exe.file_name().unwrap();
    if current_exe != "ffxiv_dx11.exe" {
        return;
    }

    unsafe {
        CONFIG.set(get_config()).ok();
    }

    unsafe {
        if let Err(e) = do_stuff() {
            msgbox::create(
                "Error",
                &format!("An error occurred: {:?}", e),
                msgbox::IconType::Error,
            )
            .ok();
        }
    }
}
