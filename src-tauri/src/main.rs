#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod allusers;
mod cleanup;
mod discover;
mod icons;
mod leftovers;
mod programs;
mod reg;
mod rollback;
mod stubborn;
mod uninstall;
mod util;
mod winproc;

use leftovers::Leftover;
use programs::Program;
use std::collections::HashMap;
use std::sync::atomic::Ordering;

/// Runs blocking work off the main thread so the window stays responsive.
async fn blocking<T, F>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn list_programs(include_store: bool, all_users: bool) -> Result<Vec<Program>, String> {
    blocking(move || Ok(programs::list_all(include_store, all_users))).await
}

#[tauri::command]
async fn discover_programs() -> Result<Vec<Program>, String> {
    blocking(|| Ok(discover::discover())).await
}

#[tauri::command]
async fn get_icons(paths: Vec<String>) -> Result<HashMap<String, String>, String> {
    blocking(move || Ok(icons::load_many(&paths))).await
}

#[tauri::command]
async fn program_footprints(programs: Vec<Program>) -> Result<Vec<leftovers::Footprint>, String> {
    blocking(move || Ok(leftovers::footprints(&programs))).await
}

#[tauri::command]
async fn run_uninstaller(program: Program, quiet: bool) -> Result<uninstall::Outcome, String> {
    blocking(move || uninstall::run(&program, quiet)).await
}

#[tauri::command]
fn stop_waiting() {
    winproc::CANCEL_WAIT.store(true, Ordering::SeqCst);
}

#[tauri::command]
async fn prepare_force_removal(program: Program) -> Result<Vec<String>, String> {
    blocking(move || Ok(uninstall::prepare_force(&program))).await
}

#[tauri::command]
fn check_stubborn(program: Program) -> Option<stubborn::StubbornInfo> {
    stubborn::detect(&program)
}

/// Lists the user accounts on this PC (for the "shown for all users" note in the UI).
#[tauri::command]
async fn list_users() -> Result<Vec<String>, String> {
    blocking(|| Ok(allusers::list_profiles().into_iter().map(|u| u.name).collect())).await
}

#[tauri::command]
async fn scan_leftovers(program: Program, force: bool) -> Result<Vec<Leftover>, String> {
    blocking(move || Ok(leftovers::scan(&program, force))).await
}

#[tauri::command]
async fn delete_leftovers(items: Vec<Leftover>, recycle: bool, program_name: String) -> Result<cleanup::Report, String> {
    blocking(move || Ok(cleanup::delete(items, recycle, program_name))).await
}

#[tauri::command]
async fn list_backups() -> Result<Vec<rollback::Session>, String> {
    blocking(|| Ok(rollback::list())).await
}

#[tauri::command]
async fn restore_backup(id: String) -> Result<rollback::RestoreReport, String> {
    blocking(move || rollback::restore(&id)).await
}

#[tauri::command]
async fn delete_backup(id: String) -> Result<(), String> {
    blocking(move || rollback::delete(&id)).await
}

#[tauri::command]
fn is_elevated() -> bool {
    winproc::is_elevated()
}

#[tauri::command]
fn relaunch_as_admin(app: tauri::AppHandle) -> Result<(), String> {
    if tauri::is_dev() {
        winproc::relaunch_dev_elevated()?;
    } else {
        winproc::relaunch_elevated()?;
    }
    app.exit(0);
    Ok(())
}

#[tauri::command]
fn open_path(path: String) -> Result<(), String> {
    util::reveal(&path)
}

#[tauri::command]
fn open_registry_key(key: String) -> Result<(), String> {
    util::open_regedit(&key)
}

/// Where releases are published; update downloads are only accepted from here.
const RELEASES: &str = "https://github.com/Puirkle/PuirkleUninstaller/releases/";

#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    let ours = url.starts_with("https://github.com/Puirkle/PuirkleUninstaller");
    if !ours && !stubborn::is_known_remover_url(&url) {
        return Err("Refusing to open an unexpected address.".into());
    }
    winproc::shell_execute(Some("open"), &url, "")
}

/// Downloads the new installer from the GitHub release, starts it, and closes the app so the
/// installer can replace it.
#[tauri::command]
async fn install_update(app: tauri::AppHandle, url: String) -> Result<(), String> {
    if !url.starts_with(&format!("{RELEASES}download/")) || !url.to_lowercase().ends_with(".exe") {
        return Err("Refusing to download an update from an unexpected address.".into());
    }
    let setup = blocking(move || {
        let dir = std::env::temp_dir().join("PuirkleUninstaller-update");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let file = dir.join("PuirkleUninstaller-setup.exe");
        let _ = std::fs::remove_file(&file);
        util::powershell(&format!(
            "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -Uri '{}' -OutFile '{}'",
            url.replace('\'', "''"),
            file.to_string_lossy().replace('\'', "''")
        ))
        .map_err(|e| format!("Download failed: {e}"))?;
        if std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0) < 100 * 1024 {
            return Err("The downloaded installer looks incomplete. Try again later.".into());
        }
        Ok(file)
    })
    .await?;
    winproc::shell_execute(None, &setup.to_string_lossy(), "")?;
    app.exit(0);
    Ok(())
}

#[tauri::command]
fn open_backups() -> Result<(), String> {
    let dir = cleanup::backup_root();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    util::reveal(&dir.to_string_lossy())
}

fn main() {
    // Start elevated so every leftover can be removed. If the user declines the prompt (or passes
    // --limited) we carry on in limited mode. Dev builds skip this: their UI is served by the CLI.
    // The relaunched copy carries --elevated so it can never loop if elevation silently fails.
    let skip = std::env::args().any(|a| a == "--limited" || a == "--elevated");
    if !tauri::is_dev() && !skip && !winproc::is_elevated() && winproc::relaunch_elevated().is_ok() {
        return;
    }

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            list_programs,
            discover_programs,
            get_icons,
            program_footprints,
            run_uninstaller,
            stop_waiting,
            prepare_force_removal,
            check_stubborn,
            list_users,
            scan_leftovers,
            delete_leftovers,
            list_backups,
            restore_backup,
            delete_backup,
            is_elevated,
            relaunch_as_admin,
            open_path,
            open_registry_key,
            open_backups,
            open_url,
            install_update,
        ])
        .run(tauri::generate_context!())
        .expect("error while running PuirkleUninstaller");
}
