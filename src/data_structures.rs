// src/data_structures.rs
//
// What survives of the old shared types: the debug macros the Noise stack logs
// through, and the encryption-status enum it reports. Packet types, header
// flags and the legacy BitchatPacket now live in `protocol.rs`.

// Debug levels
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum DebugLevel {
    Clean = 0, // Default - minimal output
    Basic = 1, // Connection info, key exchanges
    Full = 2,  // All debug output
}

// Global debug level
pub static mut DEBUG_LEVEL: DebugLevel = DebugLevel::Clean;

// Debug macro for basic debug (level 1+)
#[macro_export]
macro_rules! debug_println {
    ($($arg:tt)*) => {
        unsafe {
            if crate::data_structures::DEBUG_LEVEL as u8 >= crate::data_structures::DebugLevel::Basic as u8 {
                println!($($arg)*);
            }
        }
    };
}

// Debug macro for full debug (level 2)
#[macro_export]
macro_rules! debug_full_println {
    ($($arg:tt)*) => {
        unsafe {
            if crate::data_structures::DEBUG_LEVEL as u8 >= crate::data_structures::DebugLevel::Full as u8 {
                println!($($arg)*);
            }
        }
    };
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncryptionStatus {
    None,             // Failed or incompatible
    NoHandshake,      // No handshake attempted yet
    NoiseHandshaking, // Currently establishing
    NoiseSecured,     // Established but not verified
    NoiseVerified,    // Established and verified
}

impl EncryptionStatus {
    #[allow(dead_code)]
    pub fn icon(&self) -> Option<&'static str> {
        match self {
            EncryptionStatus::None => Some("🔒❌"),
            EncryptionStatus::NoHandshake => None,
            EncryptionStatus::NoiseHandshaking => Some("🔄"),
            EncryptionStatus::NoiseSecured => Some("🔒"),
            EncryptionStatus::NoiseVerified => Some("🔒✅"),
        }
    }

    #[allow(dead_code)]
    pub fn description(&self) -> &'static str {
        match self {
            EncryptionStatus::None => "Encryption failed",
            EncryptionStatus::NoHandshake => "Not encrypted",
            EncryptionStatus::NoiseHandshaking => "Establishing encryption...",
            EncryptionStatus::NoiseSecured => "Encrypted",
            EncryptionStatus::NoiseVerified => "Encrypted & Verified",
        }
    }
}

// BLE identifiers (unchanged across the protocol overhaul).
pub const BITCHAT_SERVICE_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0xF47B5E2D_4A9E_4C5A_9B3F_8E1D2C3A4B5C);
pub const BITCHAT_CHARACTERISTIC_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0xA1B2C3D4_E5F6_4A5B_8C9D_0E1F2A3B4C5D);
