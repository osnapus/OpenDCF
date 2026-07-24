# Changelog

All notable public changes to OpenDCF will be documented in this file.

The project follows [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-07-24

### Added

- Initial stable public release.
- Ethernet NTP/SNTP server for WT32-ETH01.
- DS3231 RTC integration with 1 Hz SQW monitoring.
- Full DCF77 time and date decoding.
- Validation of parity, date and CET/CEST information.
- RTC synchronization after three consecutive valid DCF77 frames.
- FIFO-based DCF77 edge acquisition.
- Automatic decoder recovery after signal loss or interference.
- Public web status page.
- Password-protected configuration pages.
- DHCP and static IPv4 configuration.
- Browser-based manual RTC setting.
- 24C32 EEPROM configuration storage with CRC32.
- Persistent boot and DCF77 synchronization statistics.
