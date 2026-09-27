// Hide the console window on Windows release builds; a security tool that opens a
// stray terminal alongside its window looks broken.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    nullhawk_desktop::run();
}
