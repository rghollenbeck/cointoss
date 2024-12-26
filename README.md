# cointoss
A Linux command-line tool for generating Bitcoin BIP39 seed phrases using the multiple flipping of coins.

## Features
- Supports generating entropy for 12, 15, 18, 21, or 24-word BIP39 seed phrases.
- Command-line interface with clear usage instructions.
- GPL-3.0 licensed for full transparency and open-source contribution.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/rghollenbeck/cointoss.git
   cd cointoss
   ```

2. Build the project using Cargo:
   ```bash
   cargo build
   ```

## Usage
Run the following command to generate entropy:
```bash
cargo run -- --words 12
```

Options:
- --12: Generate entropy for a 12-word seed phrase.
- --15: Generate entropy for a 15-word seed phrase.
- --18: Generate entropy for an 18-word seed phrase.
- --21: Generate entropy for a 21-word seed phrase.
- --24: Generate entropy for a 24-word seed phrase.
