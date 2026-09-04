//! Random AmneziaWG obfuscation parameters, used only as the last-resort tier of the idempotency
//! rule (explicit in `mesh.yaml` -> already in the existing patch -> generate here). Deliberately
//! scoped to "the original nine" (`jc/jmin/jmax/s1/s2/h1-h4` - see `docs/extension-services.md`'s
//! own framing of that set vs. the AmneziaWG 3.0 additions): those are the only params with a
//! well-known safe range from AmneziaWG's own defaults/docs. `s3/s4/i1-i5/header_protection_key`
//! and the timing knobs are left `None` unless `mesh.yaml` sets them explicitly - no established
//! safe default exists for them, and `header_protection_key` specifically must match between both
//! ends of a link, which a per-node independent random draw cannot guarantee on its own.

use common::Obfuscation;
use rand::Rng;

/// WireGuard's own reserved message-type values (`MessageInitiation`=1, `MessageResponse`=2,
/// `MessageCookieReply`=3, `MessageTransport`=4) - avoided when picking h1-h4, same as
/// amneziawg-tools' own config generator does.
const RESERVED_MESSAGE_TYPES: [u32; 4] = [1, 2, 3, 4];

fn random_magic_headers(rng: &mut impl Rng) -> [u32; 4] {
    let mut values = Vec::with_capacity(4);
    while values.len() < 4 {
        let candidate = rng.gen_range(5..=u32::MAX);
        if !RESERVED_MESSAGE_TYPES.contains(&candidate) && !values.contains(&candidate) {
            values.push(candidate);
        }
    }
    [values[0], values[1], values[2], values[3]]
}

pub fn generate() -> Obfuscation {
    let mut rng = rand::thread_rng();
    let jmin: u16 = rng.gen_range(10..=100);
    let jmax: u16 = jmin + rng.gen_range(1..=900);
    let [h1, h2, h3, h4] = random_magic_headers(&mut rng);
    Obfuscation {
        jc: Some(rng.gen_range(3..=10)),
        jmin: Some(jmin),
        jmax: Some(jmax),
        s1: Some(rng.gen_range(0..=1280)),
        s2: Some(rng.gen_range(0..=1280)),
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
            assert!(!RESERVED_MESSAGE_TYPES.contains(&h));
        }
        let mut sorted = headers.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 4, "h1-h4 must all be distinct");
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

    #[test]
    fn generates_different_results_on_each_call() {
        let a = generate();
        let b = generate();
        assert_ne!(a, b);
    }
}
