// explicit compile-time mapping to a distro-style arch name

#[cfg(target_arch = "x86")]
pub const DEFAULT_ARCH: &str = "i386";

#[cfg(target_arch = "x86_64")]
pub const DEFAULT_ARCH: &str = "amd64";

#[cfg(target_arch = "aarch64")]
pub const DEFAULT_ARCH: &str = "arm64";

#[cfg(target_arch = "powerpc64")]
pub const DEFAULT_ARCH: &str = "ppc64el";

#[cfg(target_arch = "riscv64")]
pub const DEFAULT_ARCH: &str = "riscv64";

// mips 32-bit -> mipsel
#[cfg(all(target_arch = "mips", target_pointer_width = "32"))]
pub const DEFAULT_ARCH: &str = "mipsel";

// mips 64-bit -> mips64el
#[cfg(any(
    target_arch = "mips64",
    all(target_arch = "mips", target_pointer_width = "64")
))]
pub const DEFAULT_ARCH: &str = "mips64el";

// arm: choose hard-float vs soft-float variant at compile time via target_feature
#[cfg(all(target_arch = "arm", target_feature = "vfp2"))]
pub const DEFAULT_ARCH: &str = "armhf";

#[cfg(all(target_arch = "arm", not(target_feature = "vfp2")))]
pub const DEFAULT_ARCH: &str = "armel";

// Fallback: if none of the above matched, use the literal from std::env::consts::ARCH
#[cfg(not(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "powerpc64",
    target_arch = "riscv64",
    all(target_arch = "mips", target_pointer_width = "32"),
    target_arch = "mips64",
    all(target_arch = "mips", target_pointer_width = "64"),
    all(target_arch = "arm", target_feature = "vfp2"),
    all(target_arch = "arm", not(target_feature = "vfp2"))
)))]
pub const DEFAULT_ARCH: &str = std::env::consts::ARCH;
