//! Extracts program icons (from .exe/.dll/.ico resources or image files) as PNG data URLs.

use crate::util::{clean_path, wide};
use base64::Engine;
use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::null_mut;
use windows_sys::Win32::Graphics::Gdi::{
    CreateCompatibleDC, DeleteDC, DeleteObject, GetDIBits, GetObjectW, BITMAP, BITMAPINFO, BITMAPINFOHEADER, BI_RGB,
    DIB_RGB_COLORS, HBITMAP,
};
use windows_sys::Win32::UI::Shell::{ExtractIconExW, SHDefExtractIconW};
use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON, ICONINFO};

pub fn load_many(specs: &[String]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for s in specs {
        if !out.contains_key(s) {
            if let Some(d) = load(s) {
                out.insert(s.clone(), d);
            }
        }
    }
    out
}

fn load(spec: &str) -> Option<String> {
    let (path, index) = parse_icon_spec(spec);
    let lower = path.to_lowercase();
    let png = if lower.ends_with(".png") {
        std::fs::read(&path).ok()?
    } else {
        extract(&path, index)?
    };
    Some(format!("data:image/png;base64,{}", base64::engine::general_purpose::STANDARD.encode(png)))
}

/// `"C:\x\app.exe",0` / `C:\x\app.exe,-101` / `C:\x\app.ico` -> (path, index)
pub fn parse_icon_spec(spec: &str) -> (String, i32) {
    let s = spec.trim();
    let (p, idx) = match s.rfind(',') {
        Some(i) => match s[i + 1..].trim().parse::<i32>() {
            Ok(n) => (&s[..i], n),
            Err(_) => (s, 0),
        },
        None => (s, 0),
    };
    (clean_path(p), idx)
}

fn extract(path: &str, index: i32) -> Option<Vec<u8>> {
    let w = wide(path);
    let mut icon: HICON = null_mut();
    unsafe {
        let hr = SHDefExtractIconW(w.as_ptr(), index, 0, &mut icon, null_mut(), 64);
        if hr != 0 || icon.is_null() {
            icon = null_mut();
            if ExtractIconExW(w.as_ptr(), index, &mut icon, null_mut(), 1) == 0 || icon.is_null() {
                return None;
            }
        }
        let png = icon_to_png(icon);
        DestroyIcon(icon);
        png
    }
}

unsafe fn icon_to_png(icon: HICON) -> Option<Vec<u8>> {
    let mut info: ICONINFO = zeroed();
    if GetIconInfo(icon, &mut info) == 0 {
        return None;
    }
    let result = convert(&info);
    if !info.hbmColor.is_null() {
        DeleteObject(info.hbmColor);
    }
    if !info.hbmMask.is_null() {
        DeleteObject(info.hbmMask);
    }
    result
}

unsafe fn convert(info: &ICONINFO) -> Option<Vec<u8>> {
    if info.hbmColor.is_null() {
        return None;
    }
    let mut bm: BITMAP = zeroed();
    if GetObjectW(info.hbmColor, size_of::<BITMAP>() as i32, &mut bm as *mut _ as *mut c_void) == 0 {
        return None;
    }
    let (w, h) = (bm.bmWidth, bm.bmHeight);
    if w <= 0 || h <= 0 || w > 512 || h > 512 {
        return None;
    }
    let mut px = read_bits(info.hbmColor, w, h)?;
    if px.chunks_exact(4).all(|p| p[3] == 0) {
        // Legacy icon without an alpha channel: derive transparency from the AND mask.
        match (!info.hbmMask.is_null()).then(|| read_bits(info.hbmMask, w, h)).flatten() {
            Some(mask) => {
                for (p, m) in px.chunks_exact_mut(4).zip(mask.chunks_exact(4)) {
                    p[3] = if m[0] == 0 { 255 } else { 0 };
                }
            }
            None => px.chunks_exact_mut(4).for_each(|p| p[3] = 255),
        }
    }
    px.chunks_exact_mut(4).for_each(|p| p.swap(0, 2)); // BGRA -> RGBA
    encode_png(&px, w as u32, h as u32)
}

unsafe fn read_bits(bmp: HBITMAP, w: i32, h: i32) -> Option<Vec<u8>> {
    let dc = CreateCompatibleDC(null_mut());
    let mut bi: BITMAPINFO = zeroed();
    bi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h; // top-down
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    let mut buf = vec![0u8; (w * h * 4) as usize];
    let lines = GetDIBits(dc, bmp, 0, h as u32, buf.as_mut_ptr() as *mut c_void, &mut bi, DIB_RGB_COLORS);
    DeleteDC(dc);
    (lines == h).then_some(buf)
}

fn encode_png(rgba: &[u8], w: u32, h: u32) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, w, h);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        let mut writer = enc.write_header().ok()?;
        writer.write_image_data(rgba).ok()?;
    }
    Some(out)
}
