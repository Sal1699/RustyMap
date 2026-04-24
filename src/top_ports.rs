//! Most-frequently-open ports for `--top-ports N`.
//!
//! Curated from the public nmap-services frequency rankings — top 200 TCP
//! ports cover ~95% of services seen on the open internet. For >200 we
//! fall through to the full 1-1024 well-known range.

const TOP_200: &[u16] = &[
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993,
    5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000,
    8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156,
    543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986,
    13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 1000, 3001, 5001,
    82, 10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801, 5050, 19, 8031, 1041, 255, 2967, 1049,
    1048, 2018, 1053, 3703, 1056, 1065, 1064, 1054, 17, 808, 3689, 1031, 1044, 1071, 5901, 100,
    9102, 8010, 2869, 1039, 5120, 4001, 9000, 2105, 636, 1038, 2601, 1, 7000, 1066, 1069, 625,
    311, 280, 254, 4000, 1761, 5003, 2002, 2005, 1998, 1032, 1050, 6112, 3690, 1521, 2161, 1080,
    6002, 2401, 902, 4045, 787, 7937, 1058, 2383, 32771, 1033, 1040, 1059, 50000, 5555, 10001,
    1494, 593, 2301, 3268, 7938, 1234, 1022, 1074, 8002, 1036, 1035, 9595, 9594, 9593, 16080,
    480, 843, 1042, 5550, 2148, 12345, 1043, 9020, 9080, 9050, 9091, 5269, 7634, 4321, 5810,
];

pub fn top(n: usize) -> Vec<u16> {
    if n >= TOP_200.len() {
        // Fallback: top200 + remaining well-known + ephemeral hot spots
        let mut out: Vec<u16> = TOP_200.to_vec();
        for p in 1u16..=1024 {
            if !out.contains(&p) {
                out.push(p);
                if out.len() >= n {
                    break;
                }
            }
        }
        return out;
    }
    TOP_200[..n].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_zero_is_empty() {
        assert!(top(0).is_empty());
    }

    #[test]
    fn top_one_is_port_80() {
        assert_eq!(top(1), vec![80]);
    }

    #[test]
    fn top_n_returns_n() {
        assert_eq!(top(50).len(), 50);
        assert_eq!(top(100).len(), 100);
    }

    #[test]
    fn top_above_200_extends() {
        let v = top(500);
        assert_eq!(v.len(), 500);
        // First N must still be the curated top
        assert_eq!(&v[..5], &TOP_200[..5]);
    }

    #[test]
    fn top_no_duplicates() {
        let v = top(500);
        let mut sorted = v.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(v.len(), sorted.len());
    }
}
