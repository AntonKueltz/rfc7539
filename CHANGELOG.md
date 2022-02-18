# Changelog

## [2.1.0] - 2022-02-17

### Added
* Support for python3.9 and python3.10

### Removed
* Support for python3.5 and python3.7

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
