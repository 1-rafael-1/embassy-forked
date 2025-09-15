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
    radio.set_channel(15);

    let mut packet = Packet::new();

    loop {
        gpo_led.set_low();
        let rv = radio.receive(&mut packet).await;
        gpo_led.set_high();
        match rv {
            Err(_) => defmt::error!("receive() Err"),
            Ok(_) => {
                let lqi = packet.lqi();
                let data = &*packet; // Get packet data as slice

                if data.len() >= 20 {
                    // Parse the structured data from sender
                    let counter = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    let timestamp = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                    let temperature = u16::from_le_bytes([data[8], data[9]]);
                    let humidity = u16::from_le_bytes([data[10], data[11]]);

                    // Parse device ID (8 bytes starting at offset 12)
                    let device_id = match core::str::from_utf8(&data[12..20]) {
                        Ok(s) => s,
                        Err(_) => "INVALID",
                    };

                    defmt::info!(
                        "Packet #{}: temp={}°C, humidity={}%, device='{}', time={}, LQI={}",
                        counter,
                        temperature,
                        humidity,
                        device_id,
                        timestamp,
                        lqi
                    );

                    // Optionally show some of the pattern data
                    if data.len() >= 24 {
                        defmt::debug!("Pattern: [{}, {}, {}, {}...]", data[20], data[21], data[22], data[23]);
                    }
                } else {
                    // Handle short packets (fallback to raw data)
                    defmt::warn!("Short packet ({} bytes): {:?}, LQI: {}", data.len(), data, lqi);
                }
            }
        }
        Timer::after_millis(100u64).await;
    }
}
