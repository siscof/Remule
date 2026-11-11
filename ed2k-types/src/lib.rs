// SPDX-License-Identifier: GPL-2.0-or-later
//! eD2k and Kad protocol constants: opcodes, tag ids, flags and limits.
//!
//! Port of aMule's `src/include/protocol/**` and `src/include/tags/**`
//! (MIGRATION_PLAN.md, step 1.1), plus the two value types everything else
//! is keyed by: [`Md4Hash`] and the Kad id [`UInt128`] (step 1.2). Pure data,
//! no I/O.
//!
//! * Every set of codes that a peer can send is a `#[repr(u8)]` enum with
//!   `TryFrom<u8>`: an unknown value is an [`Unknown`] error, never a panic.
//!   `From<Enum> for u8` goes the other way.
//! * There is one enum per *wire namespace*, i.e. per protocol byte and
//!   transport. Where aMule splits one namespace over several headers (the
//!   Kad2 opcodes that travel as eMule-extended packets), they are merged here.
//! * Each variant's doc comment starts with its C++ name, so a grep for
//!   `OP_HELLO` finds both sides of the port.
//! * Bit flags stay plain `u32` constants, as on the wire. Timings are
//!   [`std::time::Duration`]s, which removes the C++ mix of millisecond and
//!   second macros.

use std::fmt;

/// A value received from the wire that is not a known code of `kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unknown<T> {
    pub kind: &'static str,
    pub value: T,
}

impl<T: fmt::LowerHex> fmt::Display for Unknown<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown {} {:#04x}", self.kind, self.value)
    }
}

impl<T: fmt::LowerHex + fmt::Debug> std::error::Error for Unknown<T> {}

/// Define a fieldless wire enum with `TryFrom`/`From` conversions and an
/// `ALL` list of its variants.
macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident : $repr:ident {
            $( $(#[$vmeta:meta])* $var:ident = $val:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[repr($repr)]
        pub enum $name {
            $( $(#[$vmeta])* $var = $val ),+
        }

        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: &'static [$name] = &[$($name::$var),+];

            /// The wire value.
            pub const fn value(self) -> $repr {
                self as $repr
            }
        }

        impl From<$name> for $repr {
            fn from(v: $name) -> $repr {
                v as $repr
            }
        }

        impl TryFrom<$repr> for $name {
            type Error = $crate::Unknown<$repr>;
            fn try_from(v: $repr) -> Result<Self, Self::Error> {
                match v {
                    $( $val => Ok($name::$var), )+
                    _ => Err($crate::Unknown { kind: stringify!($name), value: v }),
                }
            }
        }
    };
}

pub mod aich;
pub mod ed2k;
pub mod hash;
pub mod kad;
pub mod protocol;
pub mod tags;
pub mod uint128;

pub use aich::AichHash;
pub use hash::Md4Hash;
pub use protocol::Protocol;
pub use uint128::UInt128;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_values_are_errors_with_a_readable_message() {
        let e = Protocol::try_from(0x42).unwrap_err();
        assert_eq!(
            e,
            Unknown {
                kind: "Protocol",
                value: 0x42
            }
        );
        assert_eq!(e.to_string(), "unknown Protocol 0x42");
    }
}
