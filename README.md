# URL Checker

A CLI tool that checks the input URL for domain information, phishing links, and Malicious URLs.

## Installation

1. Clone the repository
   ```sh
   git clone https://github.com/<username>/url-checker.git
   ```
2. Change the directory
   ```sh
   cd url-checker
   ```
3. Build the binary
   ```sh
   cargo build --release
   ```
4. Run the binary
   ```sh
   ./target/release/url-checker <url>
   ```

## Usage

```sh
./target/release/url-checker <url>
```

## Example

```sh
./target/release/url-checker https://google.com
```

## License

Distributed under the MIT License. See `LICENSE` for more information.
