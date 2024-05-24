#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
include!(concat!(env!("OUT_DIR"), "/darwin.rs"));

#[cfg(test)]
mod tests {
    use std::ptr::null_mut;

    use crate::darwin::proc_listpids;

    use super::PROC_ALL_PIDS;

    #[test]
    fn test_get_pid() {
        let n = unsafe { proc_listpids(PROC_ALL_PIDS, 0, null_mut(), 0) };

        assert!(n > 0);

        let mut pids = vec![0; n as usize];

        let n = unsafe { proc_listpids(PROC_ALL_PIDS, 0, pids.as_mut_ptr() as _, n) };

        assert!(n > 0);

        for pid in pids {
            if pid == 0 {
                continue;
            }
            println!("pid: {}", pid);
        }
    }
}
