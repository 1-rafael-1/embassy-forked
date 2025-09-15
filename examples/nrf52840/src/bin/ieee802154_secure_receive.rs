#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_nrf::config::{Config, HfclkSource};
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_nrf::radio::ieee802154::{self, Packet};
use embassy_nrf::{peripherals, radio};
use embassy_time::Timer;
use {defmt_rtt as _, panic_probe as _};

// For HMAC-SHA256
use hmac::{Hmac, Mac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

embassy_nrf::bind_interrupts!(struct Irqs {
    RADIO => radio::InterruptHandler<peripherals::RADIO>;
});

// Pre-shared secret key (32 bytes) - same on sender and receiver
// In production, this would be unique per device pair and securely provisioned
const SECRET_KEY: [u8; 32] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];

// Security state
static mut LAST_SEQUENCE: u32 = 0;
static mut STARTUP_GRACE_PERIOD: bool = true; // Allow first few packets to reset sequence
static mut PACKETS_RECEIVED: u32 = 0;
static mut STARTUP_PACKETS_SEEN: u32 = 0; // Count of startup packets received

const MAX_SEQUENCE_GAP: u32 = 200; // Increased tolerance for packet loss
const STARTUP_PACKETS: u32 = 5; // Grace period for startup/reset scenarios
const MAX_BACKWARD_TOLERANCE: u32 = 10; // Allow some out-of-order packets
const STARTUP_MAGIC: u32 = 0xDEADBEEF; // Must match sender's startup magic
const MIN_STARTUP_PACKETS_FOR_RESET: u32 = 3; // Require multiple startup packets before resetting

fn verify_hmac(data: &[u8], received_mac: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(&SECRET_KEY).unwrap();
    mac.update(data);

    match mac.verify_slice(received_mac) {
        Ok(_) => true,
        Err(_) => false,
    }
}

fn is_startup_packet(message_data: &[u8]) -> Option<u32> {
    if message_data.len() >= 8 {
        let magic = u32::from_le_bytes([message_data[0], message_data[1], message_data[2], message_data[3]]);
        if magic == STARTUP_MAGIC {
            let startup_seq = u32::from_le_bytes([message_data[4], message_data[5], message_data[6], message_data[7]]);
            return Some(startup_seq);
        }
    }
    None
}

fn handle_startup_packet(startup_seq: u32, message_data: &[u8]) -> bool {
    unsafe {
        STARTUP_PACKETS_SEEN += 1;

        let timestamp = if message_data.len() >= 12 {
            u32::from_le_bytes([message_data[8], message_data[9], message_data[10], message_data[11]])
        } else {
            0
        };

        let device_id = if message_data.len() >= 20 {
            match core::str::from_utf8(&message_data[12..20]) {
                Ok(s) => s,
                Err(_) => "INVALID",
            }
        } else {
            "UNKNOWN"
        };

        defmt::info!(
            "🚀 Startup packet {}: device='{}', timestamp={}ms (seen {} total)",
            startup_seq,
            device_id,
            timestamp,
            STARTUP_PACKETS_SEEN
        );

        // After seeing enough startup packets, reset sequence tracking
        if STARTUP_PACKETS_SEEN >= MIN_STARTUP_PACKETS_FOR_RESET {
            defmt::info!("🔄 Sender restart detected! Resetting sequence tracking...");
            LAST_SEQUENCE = 0;
            STARTUP_GRACE_PERIOD = true;
            PACKETS_RECEIVED = 0;
            STARTUP_PACKETS_SEEN = 0; // Reset counter for next startup detection
            return true;
        }

        // Don't reset yet, but acknowledge the startup packet
        true
    }
}

fn check_sequence_number(sequence: u32) -> bool {
    unsafe {
        PACKETS_RECEIVED += 1;

        // During startup grace period, accept reasonable sequence numbers to handle resets
        if STARTUP_GRACE_PERIOD && PACKETS_RECEIVED <= STARTUP_PACKETS {
            if sequence > 0 && sequence < 10000 {
                // Reasonable startup range
                defmt::info!(
                    "🔄 Startup grace: accepting sequence {} (packet {})",
                    sequence,
                    PACKETS_RECEIVED
                );
                LAST_SEQUENCE = sequence;
                if PACKETS_RECEIVED >= STARTUP_PACKETS {
                    STARTUP_GRACE_PERIOD = false;
                    defmt::info!("✅ Startup grace period ended, normal sequence checking enabled");
                }
                return true;
            }
        }

        // Allow some backward tolerance for out-of-order packets
        if sequence > LAST_SEQUENCE.saturating_sub(MAX_BACKWARD_TOLERANCE) && sequence <= LAST_SEQUENCE {
            defmt::info!(
                "📦 Out-of-order packet: {} (last seen {}), accepting within tolerance",
                sequence,
                LAST_SEQUENCE
            );
            // Don't update LAST_SEQUENCE for out-of-order packets
            return true;
        }

        // Check for obvious replay attacks (too old)
        if sequence <= LAST_SEQUENCE.saturating_sub(MAX_BACKWARD_TOLERANCE) {
            defmt::warn!(
                "🚫 Sequence {} too old (last seen {}), possible replay attack",
                sequence,
                LAST_SEQUENCE
            );
            return false;
        }

        // Check for suspiciously large gaps (possible attack or major packet loss)
        if sequence > LAST_SEQUENCE + MAX_SEQUENCE_GAP {
            defmt::warn!(
                "⚠️  Large sequence gap: {} (last seen {}, gap {})",
                sequence,
                LAST_SEQUENCE,
                sequence - LAST_SEQUENCE
            );
            defmt::warn!("📡 Possible causes: sender reset, major packet loss, or attack");
            defmt::warn!("🔄 Accepting packet and resetting sequence tracking");

            // In a real system, you might want to require multiple large-gap packets
            // or implement a more sophisticated reset detection mechanism
            LAST_SEQUENCE = sequence;
            return true;
        }

        // Normal case: sequence is ahead but within reasonable gap
        if sequence > LAST_SEQUENCE {
            let gap = sequence - LAST_SEQUENCE;
            if gap > 1 {
                defmt::info!("📦 Packet loss detected: {} packets missed (gap {})", gap - 1, gap);
            }
            LAST_SEQUENCE = sequence;
            return true;
        }

        // Should never reach here, but just in case
        defmt::error!("🐛 Unexpected sequence check state: {} vs {}", sequence, LAST_SEQUENCE);
        false
    }
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let mut config = Config::default();
    config.hfclk_source = HfclkSource::ExternalXtal;
    let peripherals = embassy_nrf::init(config);

    // assumes LED on P0_15 with active-high polarity
    let mut gpo_led = Output::new(peripherals.P0_15, Level::Low, OutputDrive::Standard);

    let mut radio = ieee802154::Radio::new(peripherals.RADIO, Irqs);
    radio.set_channel(20); // Using channel 20 as requested

    let mut packet = Packet::new();

    defmt::info!("🔒 Secure IEEE 802.15.4 Receiver starting on channel 20");
    defmt::info!("📡 Waiting for authenticated messages...");

    loop {
        gpo_led.set_low();
        let rv = radio.receive(&mut packet).await;
        gpo_led.set_high();

        match rv {
            Err(_) => defmt::error!("receive() Err"),
            Ok(_) => {
                let lqi = packet.lqi();
                let data = &*packet; // Get packet data as slice

                // Expected secure packet format:
                // [sequence(4)] + [timestamp(4)] + [temp(2)] + [humidity(2)] + [device_id(8)] + [pattern(44)] + [hmac(32)]
                // Total: 4 + 4 + 2 + 2 + 8 + 44 + 32 = 96 bytes

                if data.len() >= 96 {
                    // Split message and HMAC
                    let message_data = &data[0..64]; // First 64 bytes are the message
                    let received_hmac = &data[64..96]; // Last 32 bytes are HMAC-SHA256

                    // Verify HMAC first
                    if !verify_hmac(message_data, received_hmac) {
                        defmt::error!("❌ HMAC verification failed - message rejected (possible spoofing attack)");
                        continue;
                    }

                    // Check if this is a startup packet
                    if let Some(startup_seq) = is_startup_packet(message_data) {
                        handle_startup_packet(startup_seq, message_data);
                        continue; // Don't process as normal data packet
                    }

                    // Parse the authenticated message (normal data packet)
                    let sequence =
                        u32::from_le_bytes([message_data[0], message_data[1], message_data[2], message_data[3]]);
                    let timestamp =
                        u32::from_le_bytes([message_data[4], message_data[5], message_data[6], message_data[7]]);
                    let temperature = u16::from_le_bytes([message_data[8], message_data[9]]);
                    let humidity = u16::from_le_bytes([message_data[10], message_data[11]]);

                    // Parse device ID (8 bytes starting at offset 12)
                    let device_id = match core::str::from_utf8(&message_data[12..20]) {
                        Ok(s) => s,
                        Err(_) => "INVALID",
                    };

                    // Check sequence number to prevent replay attacks
                    if !check_sequence_number(sequence) {
                        defmt::error!("❌ Sequence number check failed - message rejected (possible replay attack)");
                        continue;
                    }

                    // Message is authenticated and fresh - process it
                    defmt::info!(
                        "✅ Authenticated Packet #{}: temp={}°C, humidity={}%, device='{}', time={}, LQI={}",
                        sequence,
                        temperature,
                        humidity,
                        device_id,
                        timestamp,
                        lqi
                    );

                    // Optionally show some of the pattern data
                    if message_data.len() >= 24 {
                        defmt::debug!(
                            "Pattern: [{}, {}, {}, {}...]",
                            message_data[20],
                            message_data[21],
                            message_data[22],
                            message_data[23]
                        );
                    }

                    defmt::debug!("🔐 HMAC: verified, Sequence: {} processed successfully", sequence);
                } else if data.len() >= 20 {
                    // Handle legacy unencrypted packets for backward compatibility
                    defmt::warn!(
                        "⚠️  Received unencrypted packet ({} bytes) - consider upgrading sender",
                        data.len()
                    );

                    let counter = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    let timestamp = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                    let temperature = u16::from_le_bytes([data[8], data[9]]);
                    let humidity = u16::from_le_bytes([data[10], data[11]]);

                    let device_id = match core::str::from_utf8(&data[12..20]) {
                        Ok(s) => s,
                        Err(_) => "INVALID",
                    };

                    defmt::warn!(
                        "🔓 Unverified Packet #{}: temp={}°C, humidity={}%, device='{}', time={}, LQI={}",
                        counter,
                        temperature,
                        humidity,
                        device_id,
                        timestamp,
                        lqi
                    );
                } else {
                    // Handle short packets (fallback to raw data)
                    defmt::warn!("📦 Short packet ({} bytes): {:?}, LQI: {}", data.len(), data, lqi);
                }
            }
        }
        Timer::after_millis(100u64).await;
    }
}
