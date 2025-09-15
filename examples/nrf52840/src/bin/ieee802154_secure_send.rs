#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_nrf::config::{Config, HfclkSource};
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_nrf::radio::ieee802154::{self, Packet};
use embassy_nrf::{peripherals, radio};
use embassy_time::{Duration, Instant, Timer};
use {defmt_rtt as _, panic_probe as _};

// For HMAC-SHA256
use hmac::{Hmac, Mac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

// For atomic operations
use core::sync::atomic::{AtomicU32, Ordering};

embassy_nrf::bind_interrupts!(struct Irqs {
    RADIO => radio::InterruptHandler<peripherals::RADIO>;
});

// Pre-shared secret key (32 bytes) - same as receiver
// In production, this would be unique per device pair and securely provisioned
const SECRET_KEY: [u8; 32] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];

// Device identification
const DEVICE_ID: &[u8; 8] = b"SENSOR01";

// Sequence counter for preventing replay attacks - using atomic for thread safety
static SEQUENCE_COUNTER: AtomicU32 = AtomicU32::new(1);

fn calculate_hmac(data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(&SECRET_KEY).unwrap();
    mac.update(data);
    let result = mac.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result.into_bytes());
    output
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

    defmt::info!("🔒 Secure IEEE 802.15.4 Sender starting on channel 20");
    defmt::info!("� Sending startup handshake for 20 seconds...");

    // Startup handshake phase - send 10 startup packets over 20 seconds
    const STARTUP_DURATION_MS: u32 = 20000; // 20 seconds
    const STARTUP_PACKETS: u32 = 10;
    const STARTUP_INTERVAL_MS: u32 = STARTUP_DURATION_MS / STARTUP_PACKETS; // 2 seconds between startup packets

    for startup_seq in 1..=STARTUP_PACKETS {
        let elapsed = start_time.elapsed();
        let timestamp = elapsed.as_millis() as u32;

        // Create startup message (different from normal data packets)
        // Format: [STARTUP_MAGIC(4)] + [startup_seq(4)] + [timestamp(4)] + [device_id(8)] + [padding(44)]
        let mut startup_message = [0u8; 64];
        const STARTUP_MAGIC: u32 = 0xDEADBEEF; // Magic number to identify startup packets
        
        startup_message[0..4].copy_from_slice(&STARTUP_MAGIC.to_le_bytes());
        startup_message[4..8].copy_from_slice(&startup_seq.to_le_bytes());
        startup_message[8..12].copy_from_slice(&timestamp.to_le_bytes());
        startup_message[12..20].copy_from_slice(DEVICE_ID);
        
        // Fill remaining with deterministic pattern
        for i in 20..64 {
            startup_message[i] = ((startup_seq.wrapping_add(i as u32)) & 0xFF) as u8;
        }

        // Calculate HMAC for startup message (still authenticated!)
        let hmac_tag = calculate_hmac(&startup_message);

        // Create complete startup packet
        let mut startup_packet = [0u8; 96];
        startup_packet[0..64].copy_from_slice(&startup_message);
        startup_packet[64..96].copy_from_slice(&hmac_tag);

        // Send startup packet
        packet.copy_from_slice(&startup_packet);
        gpo_led.set_high();
        
        match radio.try_send(&mut packet).await {
            Ok(_) => {
                defmt::info!(
                    "🚀 Sent startup packet {}/{}: device={}, timestamp={}ms", 
                    startup_seq, STARTUP_PACKETS,
                    core::str::from_utf8(DEVICE_ID).unwrap_or("?"), 
                    timestamp
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
    defmt::info!("📡 Sending authenticated sensor data every 2 seconds...");

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
        let humidity = (base_humidity + humidity_variation).max(3000).min(7000) as u16; // 30-70% range        // Create the message structure (64 bytes)
                                                                                        // [sequence(4)] + [timestamp(4)] + [temp(2)] + [humidity(2)] + [device_id(8)] + [pattern(44)]
        let mut message = [0u8; 64];

        // Pack the core data
        message[0..4].copy_from_slice(&sequence.to_le_bytes());
        message[4..8].copy_from_slice(&timestamp.to_le_bytes());
        message[8..10].copy_from_slice(&temperature.to_le_bytes());
        message[10..12].copy_from_slice(&humidity.to_le_bytes());
        message[12..20].copy_from_slice(DEVICE_ID);

        // Fill remaining space with a deterministic pattern (for testing/debugging)
        for i in 20..64 {
            message[i] = ((sequence.wrapping_add(i as u32)) & 0xFF) as u8;
        }

        // Calculate HMAC-SHA256 over the message
        let hmac_tag = calculate_hmac(&message);

        // Create the complete authenticated packet: [message(64)] + [hmac(32)] = 96 bytes total
        let mut secure_packet = [0u8; 96];
        secure_packet[0..64].copy_from_slice(&message);
        secure_packet[64..96].copy_from_slice(&hmac_tag);

        // Copy to radio packet
        packet.copy_from_slice(&secure_packet);

        // Send the authenticated packet
        gpo_led.set_high();
        match radio.try_send(&mut packet).await {
            Ok(_) => {
                defmt::info!(
                    "✅ Sent authenticated packet #{}: temp={}.{}°C, humidity={}.{}%, device={}, HMAC computed",
                    sequence,
                    temperature / 100,
                    temperature % 100,
                    humidity / 100,
                    humidity % 100,
                    core::str::from_utf8(DEVICE_ID).unwrap_or("?")
                );
                defmt::debug!(
                    "🔐 Message size: {} bytes, HMAC: {:02X}{:02X}{:02X}{:02X}...",
                    secure_packet.len(),
                    hmac_tag[0],
                    hmac_tag[1],
                    hmac_tag[2],
                    hmac_tag[3]
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
