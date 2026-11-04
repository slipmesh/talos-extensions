//! Random AmneziaWG obfuscation parameters, for whatever `slipmesh.yaml` leaves unset - see
//! `secrets`, which writes what was generated back into the field it belongs to. Deliberately
//! scoped to "the original nine" (`jc/jmin/jmax/s1/s2/h1-h4` - see `docs/extension-services.md`'s
//! own framing of that set vs. the AmneziaWG 3.0 additions): those are the only params with a
//! well-known safe range from AmneziaWG's own defaults/docs. `s3/s4/i1-i5/header_protection_key`
//! and the timing knobs are left `None` unless `slipmesh.yaml` sets them explicitly - no established
//! safe default exists for them, and `header_protection_key` specifically must match between both
//! ends of a link, which a per-node independent random draw cannot guarantee on its own.

use common::Obfuscation;
use rand::{Rng, RngExt};

/// From 5 up, the floor the kernel module's README recommends: 1..4 are WireGuard's own message
/// types, `common::obfuscation::DEFAULT_MAGIC_HEADERS`, which amneziawg-tools' generator avoids too.
fn random_magic_headers(rng: &mut impl Rng) -> [u32; 4] {
    let mut values = Vec::with_capacity(4);
    while values.len() < 4 {
        let candidate = rng.random_range(5..=2_147_483_647);
        if !values.contains(&candidate) {
            values.push(candidate);
        }
    }
    [values[0], values[1], values[2], values[3]]
}

/// Every range is the recommended one from the kernel module's README. The s1/s2 floor of 15
/// also leaves room for the 12-byte header protection nonce, should `slipmesh.yaml` set a key.
pub fn generate() -> Obfuscation {
    let mut rng = rand::rng();
    let jmin: u16 = rng.random_range(10..=100);
    let jmax: u16 = jmin + rng.random_range(1..=900);
    let s1: u16 = rng.random_range(15..=150);
    // S2 = S1 + 56 would give the handshake initiation and response the same length.
    let s2 = loop {
        let s2: u16 = rng.random_range(15..=150);
        if s2 != s1 + 56 {
            break s2;
        }
    };
    let [h1, h2, h3, h4] = random_magic_headers(&mut rng);
    Obfuscation {
        jc: Some(rng.random_range(4..=12)),
        jmin: Some(jmin),
        jmax: Some(jmax),
        s1: Some(s1),
        s2: Some(s2),
        h1: Some(h1),
        h2: Some(h2),
        h3: Some(h3),
        h4: Some(h4),
        ..Obfuscation::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_jmin_less_than_jmax() {
        let o = generate();
        assert!(o.jmin.unwrap() < o.jmax.unwrap());
    }

    #[test]
    fn generates_four_distinct_magic_headers_avoiding_reserved_message_types() {
        let o = generate();
        let headers = [o.h1.unwrap(), o.h2.unwrap(), o.h3.unwrap(), o.h4.unwrap()];
        for h in headers {
            assert!(!common::obfuscation::DEFAULT_MAGIC_HEADERS.contains(&h));
        }
        let mut sorted = headers.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 4, "h1-h4 must all be distinct");
    }

    // The recommended ranges of the kernel module's README; s1/s2 also hold the header
    // protection nonce, and S1 + 56 = S2 would give initiation and response the same length.
    #[test]
    fn generates_values_in_the_documented_ranges() {
        for _ in 0..2000 {
            let o = generate();
            assert!((4..=12).contains(&o.jc.unwrap()), "{o:?}");
            assert!(
                o.jmin.unwrap() < o.jmax.unwrap() && o.jmax.unwrap() <= 1280,
                "{o:?}"
            );
            let (s1, s2) = (o.s1.unwrap(), o.s2.unwrap());
            assert!(
                (15..=150).contains(&s1) && (15..=150).contains(&s2),
                "{o:?}"
            );
            assert_ne!(s1 + 56, s2, "{o:?}");
            for h in [o.h1, o.h2, o.h3, o.h4] {
                assert!((5..=2_147_483_647).contains(&h.unwrap()), "{o:?}");
            }
            o.validate().unwrap();
        }
    }

    #[test]
    fn leaves_amneziawg_3_0_fields_unset() {
        let o = generate();
        assert_eq!(o.s3, None);
        assert_eq!(o.s4, None);
        assert_eq!(o.i1, None);
        assert_eq!(o.header_protection_key, None);
        assert_eq!(o.content_padding_addition, None);
    }
}
