#[cfg(target_os = "macos")]
pub mod darwin;

#[cfg(target_os = "macos")]
pub use darwin::find_process_by_socket;

pub enum Network {
    Tcp,
    Udp,
}
