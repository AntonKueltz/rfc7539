# Changelog

## [2.0.1] - 2019-12-25

### Fixed
* Type hints for `encrypt_and_tag`

### Changed
* Moved tag key generation into it's own method `_tag_key(key, nonce)`

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