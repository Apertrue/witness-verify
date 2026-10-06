//! Derives every verifier key this crate accepts and compares its
//! SHA-256 digest with the pinned table below.
//!
//! ```text
//! cargo run --release --example pinned_keys
//! ```
//!
//! Nothing is downloaded: each key comes from the circuit shape and the
//! batch size alone, so any machine derives the same keys. A mismatch
//! means the circuits or the proof backend changed what verifies, and
//! the run exits 1 listing every size that differs. These are the same
//! digests a verifying page pins through `vk_digest`.
//! Use `--release`: key setup in a debug build is slow.

use std::process::ExitCode;
use witness_verify::batch::{MAX_BATCH, MIN_BATCH};
use witness_verify::membership::MembershipVerifier;
use witness_verify::BatchVerifier;

/// The verifier key digest for each batch size, from MIN_BATCH up.
const BATCH_KEYS: &[&str] = &[
    "ba75ef2b570da1a4bd5a49e388375bfbdcabd7a2bfc7e739d6b597da63b778d4", // 2
    "cf3ee9e5aa2c7f74a8504d654ad2eb8a6d3ebaaf6dd2af9da059fe21fde5fcc0", // 3
    "ff0fdf600ca61872560717dd19a97e39fb8a6aa8045e9971c36507bbbcdb008b", // 4
    "aab6c233d49b3060b8d67da6a2a17cadd8c0e024e99d905c1b155c6781a3ea8f", // 5
    "a3d476232bf105f87471449d676b37d687d95837b0f4f9724a3147a27fb5840e", // 6
    "e58c7c2896e409379b938e747adcd9523b2d3778af2b4b75c3c01d8401464fc5", // 7
    "b29ec82fac53e6bda1e10d157e695bfd2213ff360a809c8c11ab8fe6fe2400ac", // 8
    "96ec4736a897319bd9e12b77f3cfa49bae08361f97bee791a71158305a95e9e0", // 9
    "80e79888108532ff2d9573d7f04e6cd9f8d41f18cad158c65653112893aeb660", // 10
    "6165df284a859ea313af3acb028b9ddd217f4a5a76f998edefdbdaf97f8726db", // 11
    "58a584b9cf7c8c40aaa4a56c41ac9c66936b2e6361ab00e69bde6e1d80fdbcf0", // 12
    "f457bcf2f239147bee9f9060b3d78b64ff67d27eba0d7d4b490dd6d44a3c9411", // 13
    "261921fc429717c94ca9cbde4d6b015e1b38fb4eaf58846e48250b64594bbe74", // 14
    "8ea35c732c0b55c4b38233408e257ad852c490d71c009777c32e423cce281c68", // 15
    "c42c7f55d47ca124c9c50138c8d7cb6bd9b0fa5c51c9316e1048264fa3e98ac1", // 16
    "e002fbca0e731be1c22593fd8f6ad0f6da637d9f0e072de79e4fee08a076df0e", // 17
    "8abadde0d4bec0472084f6ff7a85802c797d223fd2f457e6d09691726938c531", // 18
    "1a54edc064f54c3ee8547205d58076183b486d5f8bfc473252bab97ebe8f0da9", // 19
    "aa628b3a02b575313a12abe8eac816894e4b6f78f4ebd501c73a2228773d2052", // 20
    "358aaaeecc217f0ffe24e407586ad70f38c0b6ab67ab9cf47f3dc44d298d767d", // 21
    "67e15e89c93f6a4528b1787ad834a8e21ec9f417381fb0fa234a27df7aac0dee", // 22
    "2f7ea1edc19519ae1342abff115fe99a208121a88522b16a205de9454f163d21", // 23
    "e02412b379c24dde37e1c04f25b80e7e31c7146aa11930aaf93e086d7115fc6c", // 24
    "7ad9894a96dae996f3cc8b1acc55933d4d75028ea81296f7f9b52e0c8397bec1", // 25
    "949d7d6c75327c25b6d707a6a3487a0b6da5e2418461902cff8c70ab8a2f888c", // 26
    "b0bf073da7e2aef19626bc68159cafa377197a0eb0cd33aa971f16aad485944c", // 27
    "ecabc2dbc9055bbfc159b725dfd738546149e988f2a6c940974db61c38c3650e", // 28
    "7fda995c478e5c052564ba310ae01bfdbe8915638d603779c2adb1ea04febe84", // 29
    "f461c8a1da1a3881db456ff41fd0195c1429cbcfee3eb86714d5dbac5e90a9a4", // 30
    "c1aa45c7fe6a044b581a6ebbd512f3a42b9d16065af61e6ca19bf5a8916fd3c1", // 31
    "99569c1673e9c3b04ee6380657bc057eff049c5350a463645cfbe7cf5bd563c9", // 32
    "48014f7392ade264ce92db898c067f1d07c4d6c2e4dfeb88fcba2433b2b4a285", // 33
    "934eee653c7d8fd178b591b07de2aa62f2de9ee6fa7ec8c50c48b5f0086c39cb", // 34
    "1b497fed147f5ee7f41e8b44da0854ff5e4d90dcd4f5bca64e67a20025a1832f", // 35
    "a920db078a8efd3b8ac7cf392135919c3a6aab288c440a5018bbac692dadc1d1", // 36
    "6f26619b4b2cf11b9f4cf0517121b51414e6544b866b5c3416f9fdbf4500dbf2", // 37
    "2b1c124716f66e35072160c937d5c7ac90441b63dd52a492fa33640ce41437c3", // 38
    "b2003127c48af1014db7a471c5ae61c9d4d9c400e085bee68f70de745fb89a7e", // 39
    "a677a027ebb01c2e4a0557374cb7711dd682666498b47cb5f3d1c18ec042fad6", // 40
    "95058ef30569ad398e4aac9c604ec8946bdd8442b5e8a8471fb325b79108304a", // 41
    "8689c9c53f727aeecf9cf7a65fb94a6290c93fd2a8f5144a582444480b551469", // 42
    "6bad7b0870f7db703dac2fff3967f804b2e059a9b647dbcb57d367a69888568d", // 43
    "4ea1b966652e8b7e04ec3ff393de5c2c3a3d685b108b5b86a67b852d377be257", // 44
    "7771ff1d2a7f0eb039c897e64708aa5e95f6f7eccc06fe610cea8a47ce34ceee", // 45
    "1799e3f30522c8d2204c3db7bea18476f3f3ad589d73e51e326ed53ceea7f002", // 46
    "54d35fd9eb5e962130dedc4ac1aa79af5fbf41ca7e12e6fe10211a2d6929b88e", // 47
    "93a20c8354a51f1f0b681114c5c7282caf887a195d9489ccb55a523cb6f6c898", // 48
    "d5f32a80a58445785a11473db1b96d0d6961d67541ef62717341345af2e314cd", // 49
    "41726463f90e2b0794888414b38c2f0ee2da6609bfd2b9a4ca06a429677b36fa", // 50
    "84bea67b19dcbcf1d86bf88a54ba7cb12f0648e041a7c4f775b6a080ae4f29c5", // 51
    "e4bbb2256df29f104e311b69b287d9bfe385fe3d30ab4f69e1f6a71a066a4c2c", // 52
    "ed795f2fc0bf57e30fefca7a2034174f256e993ad29e188a071662fabf143667", // 53
    "f1cd55d79b9338b9312eccf70d92bd9fd7773fd4139bbc2ec17aabfb7b4bc6ec", // 54
    "03f0ac9105b0623496eab4342956d538480ba7898ec205f583ccd081715994d5", // 55
    "287f3d8d4f86b679fa75ca25d5703087fadd72b4ba31bc3d7778ca3562af0f43", // 56
    "9ef1c359d80208f2d9179d0db96f4ff9510d7e052197268aa1cd8c868656254d", // 57
    "8440c08f59064b1a5ec569ee562f2da31e9e9b63258657d5ba90ca50ed83c4cd", // 58
    "e0151ea6c725eee65ab74cb0f6ffb449115540b797231bf885902e03790f6bf2", // 59
    "ab1974eee4c24eb89c21614cfc1bcb8153b2d8410badf3f4c0939c446311edbe", // 60
    "27e6b812947159735f0316dc5932e775269c43a9edbb18fc9110a4dc4efdf437", // 61
    "8e2e2c5d369a247417f56a0f4c188e25f11552d670315439fdf7cf6cf403d93a", // 62
    "4f99482d781feaf44047db121f23d8bbf3ea5e1e2a57d524b9b93f9c25f0c804", // 63
    "cce8b324732825e3ab9856e82633d2e63e41d1547b1f7696e577837c24fa9e69", // 64
];

/// The membership verifier key digest. There is one membership key.
const MEMBERSHIP: &str = "92eca04116a47bf9c6afa5e1dab3041f02e71a0c12f0ba0f8213c2fa4e41d638";

fn main() -> ExitCode {
    let mut changed = Vec::new();
    if BATCH_KEYS.len() != MAX_BATCH - MIN_BATCH + 1 {
        changed.push(format!(
            "the table holds {} digests for {} sizes",
            BATCH_KEYS.len(),
            MAX_BATCH - MIN_BATCH + 1
        ));
    }
    for n in MIN_BATCH..=MAX_BATCH {
        // A fresh verifier per size, so one key is held at a time.
        let got = match BatchVerifier::new().vk_digest(n) {
            Ok(d) => hex::encode(d),
            Err(e) => {
                changed.push(format!("{n}\tsetup failed: {e}"));
                continue;
            }
        };
        let pinned = BATCH_KEYS.get(n - MIN_BATCH).copied().unwrap_or("");
        let mark = if got == pinned { "ok" } else { "DIFFERS" };
        println!("{n:>2}  {got}  {mark}");
        if got != pinned {
            changed.push(format!("{n}\t{got}\t(pinned {pinned:?})"));
        }
    }
    match MembershipVerifier::new().vk_digest() {
        Ok(d) => {
            let got = hex::encode(d);
            let mark = if got == MEMBERSHIP { "ok" } else { "DIFFERS" };
            println!("membership  {got}  {mark}");
            if got != MEMBERSHIP {
                changed.push(format!("membership\t{got}\t(pinned {MEMBERSHIP:?})"));
            }
        }
        Err(e) => changed.push(format!("membership\tsetup failed: {e}")),
    }
    if changed.is_empty() {
        println!("all {} keys match", MAX_BATCH - MIN_BATCH + 2);
        ExitCode::SUCCESS
    } else {
        eprintln!("keys differ from the pinned table:\n{}", changed.join("\n"));
        ExitCode::from(1)
    }
}
