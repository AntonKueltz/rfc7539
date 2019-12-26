# Changelog

## [2.0.0] - 2019-12-25

### Added
* This Changelog
* Type hints

### Changed
* All crypto operations (encryption, decryption, tagging) now explicitly only operate on
`bytes` arguments

### Removed
* Python2.x and Python3.4 support
* `utils` module now that interface is explicitly `bytes` arguments