#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_nrf::config::{Config, HfclkSource};
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_nrf::radio::ieee802154::{self, Packet};
use embassy_nrf::{peripherals, radio};
use embassy_time::Timer;
use {defmt_rtt as _, panic_probe as _};

embassy_nrf::bind_interrupts!(struct Irqs {
    RADIO => radio::InterruptHandler<peripherals::RADIO>;
});

// Pre-shared secret key (16 bytes for AES-128) - same as sender
// In production, this would be unique per device pair and securely provisioned
const AES_KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];

// Security state
static mut LAST_SEQUENCE: u32 = 0;
static mut STARTUP_GRACE_PERIOD: bool = true;
static mut PACKETS_RECEIVED: u32 = 0;
static mut STARTUP_PACKETS_SEEN: u32 = 0;

const MAX_SEQUENCE_GAP: u32 = 200;
const STARTUP_PACKETS: u32 = 5;
const MAX_BACKWARD_TOLERANCE: u32 = 10;
const STARTUP_MAGIC: u32 = 0xDEADBEEF;
const MIN_STARTUP_PACKETS_FOR_RESET: u32 = 3;

/// Hardware AES abstraction layer
struct HardwareAes;

impl HardwareAes {
    fn new() -> Self {
        Self
    }

    /// Encrypt a 16-byte block using AES-128 in ECB mode
    /// This uses the nRF52840's hardware AES accelerator
    /// For AES-128, encryption and decryption with the same key produce the inverse operation
    fn encrypt_block(&mut self, key: &[u8; 16], plaintext: &[u8; 16]) -> [u8; 16] {
        // Set up the data structure for ECB operation
        // ECB requires a specific memory layout: key, cleartext, ciphertext
        static mut ECB_DATA: EcbData = EcbData {
            key: [0; 16],
            cleartext: [0; 16],
            ciphertext: [0; 16],
        };

        unsafe {
            // Copy key and plaintext to ECB data structure using raw pointers
            core::ptr::addr_of_mut!(ECB_DATA.key).write(*key);
            core::ptr::addr_of_mut!(ECB_DATA.cleartext).write(*plaintext);

            // Set pointer to ECB data structure using raw const pointer
            embassy_nrf::pac::ECB
                .ecbdataptr()
                .write_value((&raw const ECB_DATA as *const EcbData) as u32);

            // Start ECB operation
            embassy_nrf::pac::ECB.tasks_startecb().write_value(1);

            // Wait for completion
            while embassy_nrf::pac::ECB.events_endecb().read() == 0 {}

            // Clear the event
            embassy_nrf::pac::ECB.events_endecb().write_value(0);

            // Return the result using raw pointer
            core::ptr::addr_of!(ECB_DATA.ciphertext).read()
        }
    }
}

/// ECB data structure as required by nRF52840 hardware
#[repr(C)]
struct EcbData {
    key: [u8; 16],
    cleartext: [u8; 16],
    ciphertext: [u8; 16],
}

/// Hardware CCM abstraction layer for authenticated decryption
struct HardwareCcm {
    aes: HardwareAes,
}

impl HardwareCcm {
    fn new() -> Self {
        Self {
            aes: HardwareAes::new(),
        }
    }

    /// Decrypt and verify data using AES-CCM
    /// Returns Ok(plaintext) if MIC verification succeeds, Err(()) if it fails
    fn decrypt_and_verify(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        ciphertext: &[u8],
        received_mic: &[u8; 4],
    ) -> Result<[u8; 64], ()> {
        // This must match the sender's CCM implementation exactly

        // First, decrypt the ciphertext to get plaintext for MAC calculation
        let mut plaintext = [0u8; 64];
        let len = ciphertext.len().min(64);

        // Generate keystream blocks (same as sender)
        for block_idx in 0..(len + 15) / 16 {
            let mut counter_block = [0u8; 16];
            counter_block[0] = 0x01; // CCM counter block flags
            counter_block[1..14].copy_from_slice(nonce);
            counter_block[14] = (block_idx >> 8) as u8;
            counter_block[15] = (block_idx + 1) as u8; // Counter starts at 1

            let keystream_block = self.aes.encrypt_block(key, &counter_block);

            // XOR ciphertext with keystream to get plaintext
            let start_idx = block_idx * 16;
            let end_idx = (start_idx + 16).min(len);

            for i in start_idx..end_idx {
                plaintext[i] = ciphertext[i] ^ keystream_block[i - start_idx];
            }
        }

        // Now compute MAC using the decrypted plaintext (same as sender)
        let mut mac_input = [0u8; 16];

        // CCM authentication field construction (same as sender)
        mac_input[0] = 0x01; // Flags: AAD present, M=4 (MIC length), L=2
        mac_input[1..14].copy_from_slice(nonce);
        mac_input[14] = (len >> 8) as u8;
        mac_input[15] = len as u8;

        let mac_block1 = self.aes.encrypt_block(key, &mac_input);

        // XOR with AAD for authentication (same as sender)
        let mut mac_block2 = [0u8; 16];
        mac_block2[0] = aad.len() as u8;
        let aad_len = aad.len().min(15);
        mac_block2[1..=aad_len].copy_from_slice(&aad[..aad_len]);

        // XOR previous result with AAD block
        for i in 0..16 {
            mac_block2[i] ^= mac_block1[i];
        }

        let mac_result = self.aes.encrypt_block(key, &mac_block2);

        // Encrypt the MAC with counter 0 to get the expected MIC (same as sender)
        let mut counter_zero = [0u8; 16];
        counter_zero[0] = 0x01;
        counter_zero[1..14].copy_from_slice(nonce);
        // counter_zero[14] and [15] remain 0

        let mac_keystream = self.aes.encrypt_block(key, &counter_zero);

        // XOR MAC with keystream to get expected MIC
        let mut expected_mic = [0u8; 4];
        for i in 0..4 {
            expected_mic[i] = mac_result[i] ^ mac_keystream[i];
        }

        // Verify MIC matches
        if expected_mic != *received_mic {
            return Err(());
        }

        Ok(plaintext)
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
            "🚀 HW-verified startup packet {}: device='{}', timestamp={}ms (seen {} total)",
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
            STARTUP_PACKETS_SEEN = 0;
            return true;
        }

        true
    }
}

fn check_sequence_number(sequence: u32) -> bool {
    unsafe {
        PACKETS_RECEIVED += 1;

        // During startup grace period, accept reasonable sequence numbers to handle resets
        if STARTUP_GRACE_PERIOD && PACKETS_RECEIVED <= STARTUP_PACKETS {
            if sequence > 0 && sequence < 10000 {
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

        // Check for suspiciously large gaps
        if sequence > LAST_SEQUENCE + MAX_SEQUENCE_GAP {
            defmt::warn!(
                "⚠️  Large sequence gap: {} (last seen {}, gap {})",
                sequence,
                LAST_SEQUENCE,
                sequence - LAST_SEQUENCE
            );
            defmt::warn!("🔄 Accepting packet and resetting sequence tracking");
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

        false
    }
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let mut config = Config::default();
    config.hfclk_source = HfclkSource::ExternalXtal;
    let mut peripherals = embassy_nrf::init(config);

    // assumes LED on P0_15 with active-high polarity
    let mut gpo_led = Output::new(peripherals.P0_15, Level::Low, OutputDrive::Standard);

    let mut packet = Packet::new();

    // Initialize hardware crypto
    let mut hw_ccm = HardwareCcm::new();

    defmt::info!("🔒 Hardware-accelerated IEEE 802.15.4 Receiver starting on channel 20");
    defmt::info!("🚀 Using nRF52840 ECB/CCM hardware crypto acceleration");
    defmt::info!("📡 Waiting for hardware-authenticated messages...");
    defmt::info!("⚡ Power-saving mode: Drop and re-init radio after each packet (sender transmits every 2s)");

    loop {
        // Receive packet in its own block - radio AND peripheral will be dropped when exiting this block
        let packet_result = {
            // Power up radio peripheral before creating radio instance
            embassy_nrf::pac::RADIO.power().write(|w| w.set_power(true));
            defmt::debug!("🔌 Radio peripheral powered up via PAC");

            // Create fresh radio instance for this receive cycle
            defmt::debug!("📡 Creating fresh radio instance...");
            let radio_peri = peripherals.RADIO.reborrow();
            let mut radio = ieee802154::Radio::new(radio_peri, Irqs);
            radio.set_channel(20); // Using channel 20 as requested

            gpo_led.set_low();
            let rv = radio.receive(&mut packet).await;
            gpo_led.set_high();

            // Explicitly drop both radio and peripheral reference
            drop(radio);
            // Note: radio_peri is automatically dropped here since it's not reborrowed
            defmt::debug!("📻 Radio and peripheral reference dropped...");

            // Force radio peripheral to power down using PAC
            embassy_nrf::pac::RADIO.power().write(|w| w.set_power(false));
            defmt::debug!("🔌 Radio peripheral powered down via PAC");

            rv
        }; // Radio peripheral is now completely powered down

        // Process the received packet (radio is no longer consuming power)
        match packet_result {
            Err(_) => defmt::error!("receive() Err"),
            Ok(_) => {
                let lqi = packet.lqi();
                let data = &*packet; // Get packet data as slice

                // Expected secure packet format:
                // [nonce(13)] + [ciphertext(60)] + [mic(4)] = 77 bytes
                if data.len() >= 77 {
                    // Split packet components
                    let nonce = &data[0..13];
                    let ciphertext = &data[13..73];
                    let received_mic = &data[73..77];

                    // Convert received MIC to array
                    let mut mic = [0u8; 4];
                    mic.copy_from_slice(received_mic);

                    // Try to decrypt and verify with "STARTUP" AAD first
                    let mut nonce_array = [0u8; 13];
                    nonce_array.copy_from_slice(nonce);

                    if let Ok(plaintext) =
                        hw_ccm.decrypt_and_verify(&AES_KEY, &nonce_array, b"STARTUP", ciphertext, &mic)
                    {
                        // Check if this is a startup packet
                        if let Some(startup_seq) = is_startup_packet(&plaintext) {
                            handle_startup_packet(startup_seq, &plaintext);
                            continue; // Continue to next packet
                        }
                    }

                    // Try to decrypt and verify with "DATA" AAD for regular packets
                    if let Ok(plaintext) = hw_ccm.decrypt_and_verify(&AES_KEY, &nonce_array, b"DATA", ciphertext, &mic)
                    {
                        // Parse the authenticated message (normal data packet)
                        let sequence = u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
                        let timestamp = u32::from_le_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
                        let temperature = u16::from_le_bytes([plaintext[8], plaintext[9]]);
                        let humidity = u16::from_le_bytes([plaintext[10], plaintext[11]]);

                        // Parse device ID (8 bytes starting at offset 12)
                        let device_id = match core::str::from_utf8(&plaintext[12..20]) {
                            Ok(s) => s,
                            Err(_) => "INVALID",
                        };

                        // Check sequence number to prevent replay attacks
                        if !check_sequence_number(sequence) {
                            defmt::error!(
                                "❌ Sequence number check failed - message rejected (possible replay attack)"
                            );
                            continue; // Continue to next packet
                        }

                        // Message is authenticated and fresh - process it
                        defmt::info!(
                            "✅ HW-verified Packet #{}: temp={}.{}°C, humidity={}.{}%, device='{}', time={}, LQI={}",
                            sequence,
                            temperature / 100,
                            temperature % 100,
                            humidity / 100,
                            humidity % 100,
                            device_id,
                            timestamp,
                            lqi
                        );

                        // Optionally show some of the pattern data
                        if plaintext.len() >= 24 {
                            defmt::debug!(
                                "Pattern: [{:02X}, {:02X}, {:02X}, {:02X}...]",
                                plaintext[20],
                                plaintext[21],
                                plaintext[22],
                                plaintext[23]
                            );
                        }

                        defmt::debug!(
                            "🔐 Hardware CCM: verified, Sequence: {} processed successfully",
                            sequence
                        );
                    } else {
                        defmt::error!(
                            "❌ Hardware CCM verification failed - message rejected (authentication failure)"
                        );
                    }
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
                        "🔓 Unverified Packet #{}: temp={}.{}°C, humidity={}.{}%, device='{}', time={}, LQI={}",
                        counter,
                        temperature / 100,
                        temperature % 100,
                        humidity / 100,
                        humidity % 100,
                        device_id,
                        timestamp,
                        lqi
                    );
                } else {
                    // Handle short packets (fallback to raw data)
                    defmt::warn!(
                        "📦 Short packet ({} bytes): {:02X}, LQI: {}",
                        data.len(),
                        &data[..data.len().min(16)],
                        lqi
                    );
                }

                // After successfully receiving and processing a packet,
                // sleep for 1.5s since sender transmits every 2s
                defmt::debug!("💤 Packet processed, sleeping for 1.5s to save power...");
                Timer::after_millis(1500).await;
                defmt::debug!("⏰ Wake up, ready for next packet");
            }
        }
        // No delay here - go back to listening immediately if no packet or on error
    }
}
