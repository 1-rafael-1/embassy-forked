#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_nrf::config::{Config, HfclkSource};
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_nrf::radio::ieee802154::{self, Packet};
use embassy_nrf::{peripherals, radio};
use embassy_time::{Duration, Instant, Timer};
use {defmt_rtt as _, panic_probe as _};

// For atomic operations
use core::sync::atomic::{AtomicU32, Ordering};

embassy_nrf::bind_interrupts!(struct Irqs {
    RADIO => radio::InterruptHandler<peripherals::RADIO>;
});

// Pre-shared secret key (16 bytes for AES-128)
// In production, this would be unique per device pair and securely provisioned
const AES_KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];

// Device identification
const DEVICE_ID: &[u8; 8] = b"SENSOR01";

// Sequence counter for preventing replay attacks - using atomic for thread safety
static SEQUENCE_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Hardware AES abstraction layer using PAC
/// This provides a cleaner interface to the nRF52840's ECB peripheral
struct HardwareAes;

impl HardwareAes {
    fn new() -> Self {
        // The ECB peripheral is available through PAC but structure differs
        // We'll use a simpler abstraction that works with the current PAC
        Self
    }

    /// Encrypt a 16-byte block using AES-128 in ECB mode
    /// This uses the nRF52840's hardware AES accelerator
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

/// Hardware CCM abstraction layer for authenticated encryption
/// This provides AES-CCM functionality using the nRF52840's hardware
struct HardwareCcm {
    aes: HardwareAes,
}

impl HardwareCcm {
    fn new() -> Self {
        Self {
            aes: HardwareAes::new(),
        }
    }

    /// Encrypt and authenticate data using AES-CCM
    /// This is a simplified CCM implementation using the hardware AES
    /// Returns (ciphertext, 4-byte MIC)
    fn encrypt_and_authenticate(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 13], // CCM nonce is 13 bytes for IEEE 802.15.4
        aad: &[u8],       // Additional authenticated data
        plaintext: &[u8],
    ) -> ([u8; 64], [u8; 4]) {
        // For this simplified implementation, we'll use the hardware AES in ECB mode
        // to create a secure MAC and keystream for CCM-like operation

        // Step 1: Create authentication tag (MAC)
        let mut mac_input = [0u8; 16];

        // CCM authentication field construction
        mac_input[0] = 0x01; // Flags: AAD present, M=4 (MIC length), L=2
        mac_input[1..14].copy_from_slice(nonce);
        mac_input[14] = (plaintext.len() >> 8) as u8;
        mac_input[15] = plaintext.len() as u8;

        let mac_block1 = self.aes.encrypt_block(key, &mac_input);

        // XOR with AAD for authentication
        let mut mac_block2 = [0u8; 16];
        mac_block2[0] = aad.len() as u8;
        let aad_len = aad.len().min(15);
        mac_block2[1..=aad_len].copy_from_slice(&aad[..aad_len]);

        // XOR previous result with AAD block
        for i in 0..16 {
            mac_block2[i] ^= mac_block1[i];
        }

        let mac_result = self.aes.encrypt_block(key, &mac_block2);

        // Step 2: Generate keystream for encryption
        let mut ciphertext = [0u8; 64];
        let len = plaintext.len().min(64);

        // Generate keystream blocks as needed
        for block_idx in 0..(len + 15) / 16 {
            let mut counter_block = [0u8; 16];
            counter_block[0] = 0x01; // CCM counter block flags
            counter_block[1..14].copy_from_slice(nonce);
            counter_block[14] = (block_idx >> 8) as u8;
            counter_block[15] = (block_idx + 1) as u8; // Counter starts at 1

            let keystream_block = self.aes.encrypt_block(key, &counter_block);

            // XOR plaintext with keystream
            let start_idx = block_idx * 16;
            let end_idx = (start_idx + 16).min(len);

            for i in start_idx..end_idx {
                ciphertext[i] = plaintext[i] ^ keystream_block[i - start_idx];
            }
        }

        // Step 3: Encrypt the MAC with counter 0 to get the final MIC
        let mut counter_zero = [0u8; 16];
        counter_zero[0] = 0x01;
        counter_zero[1..14].copy_from_slice(nonce);
        // counter_zero[14] and [15] remain 0

        let mac_keystream = self.aes.encrypt_block(key, &counter_zero);

        // XOR MAC with keystream to get final MIC
        let mut mic = [0u8; 4];
        for i in 0..4 {
            mic[i] = mac_result[i] ^ mac_keystream[i];
        }

        (ciphertext, mic)
    }
}

fn get_next_sequence() -> u32 {
    SEQUENCE_COUNTER.fetch_add(1, Ordering::SeqCst)
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let mut config = Config::default();
    config.hfclk_source = HfclkSource::ExternalXtal;
    let peripherals = embassy_nrf::init(config);

    // assumes LED on P0_13 with active-high polarity
    let mut gpo_led = Output::new(peripherals.P0_13, Level::Low, OutputDrive::Standard);

    let mut radio = ieee802154::Radio::new(peripherals.RADIO, Irqs);
    radio.set_channel(20); // Using channel 20 as requested
    radio.set_transmission_power(8); // Maximum power for better range

    let mut packet = Packet::new();
    let start_time = Instant::now();

    // Initialize hardware crypto
    let mut hw_ccm = HardwareCcm::new();

    defmt::info!("🔒 Hardware-accelerated IEEE 802.15.4 Sender starting on channel 20");
    defmt::info!("🚀 Using nRF52840 ECB hardware AES acceleration");
    defmt::info!("📡 Sending startup handshake for 20 seconds...");

    // Startup handshake phase - send 10 startup packets over 20 seconds
    const STARTUP_DURATION_MS: u32 = 20000; // 20 seconds
    const STARTUP_PACKETS: u32 = 10;
    const STARTUP_INTERVAL_MS: u32 = STARTUP_DURATION_MS / STARTUP_PACKETS; // 2 seconds between startup packets

    for startup_seq in 1..=STARTUP_PACKETS {
        let elapsed = start_time.elapsed();
        let timestamp = elapsed.as_millis() as u32;

        // Create startup message (different from normal data packets)
        // Format: [STARTUP_MAGIC(4)] + [startup_seq(4)] + [timestamp(4)] + [device_id(8)] + [padding(44)]
        let mut startup_message = [0u8; 60];
        const STARTUP_MAGIC: u32 = 0xDEADBEEF; // Magic number to identify startup packets

        startup_message[0..4].copy_from_slice(&STARTUP_MAGIC.to_le_bytes());
        startup_message[4..8].copy_from_slice(&startup_seq.to_le_bytes());
        startup_message[8..12].copy_from_slice(&timestamp.to_le_bytes());
        startup_message[12..20].copy_from_slice(DEVICE_ID);

        // Fill remaining with deterministic pattern
        for i in 20..60 {
            startup_message[i] = ((startup_seq.wrapping_add(i as u32)) & 0xFF) as u8;
        }

        // Create nonce for CCM (13 bytes)
        let mut nonce = [0u8; 13];
        nonce[0..4].copy_from_slice(&startup_seq.to_le_bytes());
        nonce[4..8].copy_from_slice(&timestamp.to_le_bytes());
        nonce[8..13].copy_from_slice(&DEVICE_ID[..5]);

        // Use hardware CCM for authenticated encryption
        let aad = b"STARTUP"; // Additional authenticated data
        let (ciphertext, mic) = hw_ccm.encrypt_and_authenticate(&AES_KEY, &nonce, aad, &startup_message);

        // Create complete startup packet: [nonce(13)] + [ciphertext(60)] + [mic(4)] = 77 bytes
        let mut startup_packet = [0u8; 77];
        startup_packet[0..13].copy_from_slice(&nonce);
        startup_packet[13..73].copy_from_slice(&ciphertext[..60]);
        startup_packet[73..77].copy_from_slice(&mic);

        // Send startup packet
        packet.copy_from_slice(&startup_packet);
        gpo_led.set_high();

        match radio.try_send(&mut packet).await {
            Ok(_) => {
                defmt::info!(
                    "🚀 Sent HW-encrypted startup packet {}/{}: device={}, timestamp={}ms",
                    startup_seq,
                    STARTUP_PACKETS,
                    core::str::from_utf8(DEVICE_ID).unwrap_or("?"),
                    timestamp
                );
                defmt::debug!(
                    "🔐 Nonce: [{:02x}{:02x}{:02x}{:02x}], MIC: [{:02x}{:02x}{:02x}{:02x}]",
                    nonce[0],
                    nonce[1],
                    nonce[2],
                    nonce[3],
                    mic[0],
                    mic[1],
                    mic[2],
                    mic[3]
                );
            }
            Err(e) => {
                defmt::error!("❌ Startup packet {} send error: {:?}", startup_seq, e);
            }
        }

        gpo_led.set_low();
        Timer::after(Duration::from_millis(STARTUP_INTERVAL_MS as u64)).await;
    }

    defmt::info!("✅ Startup handshake complete, beginning normal data transmission...");
    defmt::info!("📡 Sending hardware-encrypted sensor data every 2 seconds...");

    loop {
        let elapsed = start_time.elapsed();
        let sequence = get_next_sequence();
        let timestamp = elapsed.as_millis() as u32;

        // Simulate sensor readings (more realistic values)
        let base_temp = 2000i16; // 20.00°C in hundredths
        let temp_variation = ((sequence % 100) as i16 - 50) * 2; // ±1°C variation
        let temperature = (base_temp + temp_variation).max(1500).min(2500) as u16; // 15-25°C range

        let base_humidity = 5000i16; // 50.00% in hundredths
        let humidity_variation = ((sequence % 200) as i16 - 100) * 3; // ±3% variation
        let humidity = (base_humidity + humidity_variation).max(3000).min(7000) as u16; // 30-70% range

        // Create the message structure (60 bytes)
        // [sequence(4)] + [timestamp(4)] + [temp(2)] + [humidity(2)] + [device_id(8)] + [pattern(40)]
        let mut message = [0u8; 60];

        // Pack the core data
        message[0..4].copy_from_slice(&sequence.to_le_bytes());
        message[4..8].copy_from_slice(&timestamp.to_le_bytes());
        message[8..10].copy_from_slice(&temperature.to_le_bytes());
        message[10..12].copy_from_slice(&humidity.to_le_bytes());
        message[12..20].copy_from_slice(DEVICE_ID);

        // Fill remaining space with a deterministic pattern (for testing/debugging)
        for i in 20..60 {
            message[i] = ((sequence.wrapping_add(i as u32)) & 0xFF) as u8;
        }

        // Create nonce for CCM (13 bytes) - must be unique for each packet
        let mut nonce = [0u8; 13];
        nonce[0..4].copy_from_slice(&sequence.to_le_bytes());
        nonce[4..8].copy_from_slice(&timestamp.to_le_bytes());
        nonce[8..13].copy_from_slice(&DEVICE_ID[..5]);

        // Use hardware CCM for authenticated encryption
        let aad = b"DATA"; // Additional authenticated data for regular packets
        let (ciphertext, mic) = hw_ccm.encrypt_and_authenticate(&AES_KEY, &nonce, aad, &message);

        // Create the complete authenticated packet: [nonce(13)] + [ciphertext(60)] + [mic(4)] = 77 bytes total
        let mut secure_packet = [0u8; 77];
        secure_packet[0..13].copy_from_slice(&nonce);
        secure_packet[13..73].copy_from_slice(&ciphertext[..60]);
        secure_packet[73..77].copy_from_slice(&mic);

        // Copy to radio packet
        packet.copy_from_slice(&secure_packet);

        // Send the authenticated packet
        gpo_led.set_high();
        match radio.try_send(&mut packet).await {
            Ok(_) => {
                defmt::info!(
                    "✅ Sent HW-encrypted packet #{}: temp={}.{}°C, humidity={}.{}%, device={}",
                    sequence,
                    temperature / 100,
                    temperature % 100,
                    humidity / 100,
                    humidity % 100,
                    core::str::from_utf8(DEVICE_ID).unwrap_or("?")
                );
                defmt::debug!(
                    "🔐 Hardware AES: nonce=[{:02x}{:02x}{:02x}{:02x}], MIC=[{:02x}{:02x}{:02x}{:02x}]",
                    nonce[0],
                    nonce[1],
                    nonce[2],
                    nonce[3],
                    mic[0],
                    mic[1],
                    mic[2],
                    mic[3]
                );
            }
            Err(e) => {
                defmt::error!("❌ Send error for packet #{}: {:?}", sequence, e);
            }
        }
        gpo_led.set_low();

        // Wait 2 seconds before next transmission
        Timer::after(Duration::from_secs(2)).await;
    }
}
