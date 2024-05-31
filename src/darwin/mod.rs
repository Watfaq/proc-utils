#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::{
    ffi::CStr,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr::null_mut,
};

use crate::Network;
include!(concat!(env!("OUT_DIR"), "/darwin.rs"));

pub fn find_process_by_socket(
    src: Option<IpAddr>,
    sport: Option<u16>,
    network: Network,
) -> Option<String> {
    if src.is_none() && sport.is_none() {
        return None;
    }

    let n = unsafe { proc_listpids(PROC_ALL_PIDS, 0, null_mut(), 0) };

    if n <= 0 {
        return None;
    }

    let mut pids = vec![0; n as usize];

    let n = unsafe { proc_listpids(PROC_ALL_PIDS, 0, pids.as_mut_ptr() as _, n) };

    if n <= 0 {
        return None;
    }

    for pid in pids {
        if pid == 0 {
            continue;
        }

        let buf_size =
            unsafe { proc_pidinfo(pid, PROC_PIDLISTFDS as _, 0, null_mut(), 0) } as usize;

        let fd_size = std::mem::size_of::<proc_fdinfo>();

        let mut fds: Vec<proc_fdinfo> = Vec::new();
        fds.resize(buf_size / fd_size, unsafe { std::mem::zeroed() });

        unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDLISTFDS as _,
                0,
                fds.as_mut_ptr() as _,
                buf_size as _,
            )
        };

        for fd in fds {
            if fd.proc_fd == 0 {
                continue;
            }

            if fd.proc_fdtype == PROX_FDTYPE_SOCKET {
                let mut socket_info: socket_fdinfo = unsafe { std::mem::zeroed() };
                let n = unsafe {
                    proc_pidfdinfo(
                        pid,
                        fd.proc_fd as _,
                        PROC_PIDFDSOCKETINFO as _,
                        &mut socket_info as *mut _ as _,
                        std::mem::size_of::<socket_fdinfo>() as _,
                    )
                };

                if std::mem::size_of::<socket_fdinfo>() == n as _
                    && vec![AF_INET as i32, AF_INET6 as i32].contains(&socket_info.psi.soi_family)
                {
                    match network {
                        Network::Tcp => {
                            if socket_info.psi.soi_kind != SOCKINFO_TCP as _ {
                                continue;
                            }

                            let p =
                                unsafe { socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport };

                            // TODO: figure out endianness
                            let mut local_port = 0;
                            local_port |= p >> 8 & 0xff;
                            local_port |= p << 8 & 0xff00;

                            let local_ip = unsafe {
                                match socket_info.psi.soi_family as _ {
                                    AF_INET => IpAddr::V4(Ipv4Addr::from(
                                        socket_info
                                            .psi
                                            .soi_proto
                                            .pri_tcp
                                            .tcpsi_ini
                                            .insi_laddr
                                            .ina_46
                                            .i46a_addr4
                                            .s_addr
                                            .to_be(),
                                    )),
                                    AF_INET6 => IpAddr::V6(Ipv6Addr::from(
                                        socket_info
                                            .psi
                                            .soi_proto
                                            .pri_tcp
                                            .tcpsi_ini
                                            .insi_laddr
                                            .ina_6
                                            .__u6_addr
                                            .__u6_addr16
                                            .map(|x| x.to_be()),
                                    )),
                                    _ => unreachable!(),
                                }
                            };

                            if src.is_some() && src != Some(local_ip) {
                                continue;
                            }

                            if sport.is_some() && sport != Some(local_port as _) {
                                continue;
                            }

                            let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE as usize];
                            unsafe {
                                proc_pidpath(pid, buf.as_mut_ptr() as _, PROC_PIDPATHINFO_MAXSIZE)
                            };

                            let path = CStr::from_bytes_until_nul(&buf)
                                .unwrap()
                                .to_owned()
                                .to_string_lossy()
                                .to_string();

                            return Some(path);
                        }
                        Network::Udp => {
                            let p = unsafe { socket_info.psi.soi_proto.pri_in.insi_lport };

                            let mut local_port = 0;
                            local_port |= p >> 8 & 0xff;
                            local_port |= p << 8 & 0xff00;

                            let local_ip = unsafe {
                                match socket_info.psi.soi_family as _ {
                                    AF_INET => IpAddr::V4(Ipv4Addr::from(
                                        socket_info
                                            .psi
                                            .soi_proto
                                            .pri_in
                                            .insi_laddr
                                            .ina_46
                                            .i46a_addr4
                                            .s_addr
                                            .to_be(),
                                    )),
                                    AF_INET6 => IpAddr::V6(Ipv6Addr::from(
                                        socket_info
                                            .psi
                                            .soi_proto
                                            .pri_in
                                            .insi_laddr
                                            .ina_6
                                            .__u6_addr
                                            .__u6_addr16
                                            .map(|x| x.to_be()),
                                    )),
                                    _ => unreachable!(),
                                }
                            };

                            if src.is_some() && src != Some(local_ip) {
                                continue;
                            }

                            if sport.is_some() && sport != Some(local_port as _) {
                                continue;
                            }

                            let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE as usize];
                            unsafe {
                                proc_pidpath(pid, buf.as_mut_ptr() as _, PROC_PIDPATHINFO_MAXSIZE)
                            };

                            let path = CStr::from_bytes_until_nul(&buf)
                                .unwrap()
                                .to_owned()
                                .to_string_lossy()
                                .to_string();

                            return Some(path);
                        }
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    #[test]
    fn test_get_find_tcp_socket() {
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let path =
            super::find_process_by_socket(Some(addr.ip()), Some(addr.port()), super::Network::Tcp);

        assert!(path.is_some());

        let current_exe = std::env::current_exe().unwrap();
        assert_eq!(path.unwrap(), current_exe.to_str().unwrap());
    }

    #[test]
    fn test_get_find_udp_socket() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let path =
            super::find_process_by_socket(Some(addr.ip()), Some(addr.port()), super::Network::Udp);

        assert!(path.is_some());

        let current_exe = std::env::current_exe().unwrap();
        assert_eq!(path.unwrap(), current_exe.to_str().unwrap());
    }
}
