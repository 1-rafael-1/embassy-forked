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

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let mut config = Config::default();
    config.hfclk_source = HfclkSource::ExternalXtal;
    let peripherals = embassy_nrf::init(config);

    // assumes LED on P0_15 with active-high polarity
    let mut gpo_led = Output::new(peripherals.P0_15, Level::Low, OutputDrive::Standard);

    let mut radio = ieee802154::Radio::new(peripherals.RADIO, Irqs);

    // Change to a different channel (default is 11, try 15, 20, or 25 to avoid WiFi interference)
    radio.set_channel(15);

    // set transmit power to maximum
    radio.set_transmission_power(8);

    let mut packet = Packet::new();
    let mut counter: u32 = 0;

    loop {
        // Create interesting data payload
        let mut data = [0u8; 64]; // Use 64 bytes for more interesting content

        // Add packet counter (4 bytes)
        data[0..4].copy_from_slice(&counter.to_le_bytes());

        // Add timestamp-like data (4 bytes)
        let timestamp = embassy_time::Instant::now().as_millis() as u32;
        data[4..8].copy_from_slice(&timestamp.to_le_bytes());

        // Add some sensor-like data (simulated)
        let temperature = 23_u16.wrapping_add((counter % 100) as u16); // Simulated temp 23-122
        let humidity = 45_u16.wrapping_add((counter % 55) as u16); // Simulated humidity 45-99
        data[8..10].copy_from_slice(&temperature.to_le_bytes());
        data[10..12].copy_from_slice(&humidity.to_le_bytes());

        // Add device ID
        let device_id = b"SEND_001"; // 8 bytes
        data[12..20].copy_from_slice(device_id);

        // Add some pattern data for testing
        for i in 20..64 {
            data[i] = ((counter + i as u32) % 256) as u8;
        }

        packet.copy_from_slice(&data);
        gpo_led.set_high();
        let rv = radio.try_send(&mut packet).await;
        match rv {
            Err(_) => defmt::error!("try_send() Err for packet {}", counter),
            Ok(_) => defmt::info!("try_send() packet {} with {} bytes", counter, packet.len()),
        }

        counter = counter.wrapping_add(1);
        Timer::after_millis(1000u64).await;
        gpo_led.set_low();
        Timer::after_millis(1000u64).await;
    }
}
