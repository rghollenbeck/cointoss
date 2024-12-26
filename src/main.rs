use clap::{Parser, ArgAction};
use rand::Rng; // For randomizing remaining flips

/// A program to generate entropy through coin flipping.
/// GNU General Public License v3.0
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.


#[derive(Parser, Debug)]
#[command(
    author = "Rich Hollenbeck <rghollenbeck@protonmail.com>",
    version = "0.1.0",
    about = "This is a little utility to generate entropy for a BIP39 mnemonic.\n",
    long_about = "This is a long description about this little utility. It goes on and on and on and on and on..."
)]
struct Args {
    /// Generate a mnemonic with 12 words (128 bits)
    #[arg(long = "12", action = ArgAction::SetTrue)]
    twelve: bool,

    /// Generate a mnemonic with 15 words (160 bits)
    #[arg(long = "15", action = ArgAction::SetTrue)]
    fifteen: bool,

    /// Generate a mnemonic with 18 words (192 bits)
    #[arg(long = "18", action = ArgAction::SetTrue)]
    eighteen: bool,

    /// Generate a mnemonic with 21 words (224 bits)
    #[arg(long = "21", action = ArgAction::SetTrue)]
    twenty_one: bool,

    /// Generate a mnemonic with 24 words (256 bits)
    #[arg(long = "24", action = ArgAction::SetTrue)]
    twenty_four: bool,
}

fn main() {
    // Parse command-line arguments
    let args = Args::parse();

    // Determine the number of words
    let words = if args.twelve {
        12
    } else if args.fifteen {
        15
    } else if args.eighteen {
        18
    } else if args.twenty_one {
        21
    } else if args.twenty_four {
        24
    } else {
        panic!("No valid word count specified. Use --help for more information.");
    };

    // Calculate entropy bits
    let entropy_bits = get_entropy_bits(words);

    // Prompt the user for coin flips
    let coin_flips = prompt_for_coin_flips(entropy_bits);

    // Print the collected coin flips
    println!("Collected {} coin flips: {:?}", entropy_bits, coin_flips);
}

// Calculate the number of entropy bits based on the number of words
fn get_entropy_bits(words: u8) -> u16 {
    match words {
        12 => 128,
        15 => 160,
        18 => 192,
        21 => 224,
        24 => 256,
        _ => panic!("Invalid number of words. Choose 12, 15, 18, 21, or 24."),
    }
}

// Prompt the user for coin flips
fn prompt_for_coin_flips(entropy_bits: u16) -> Vec<u8> {
    let mut flips = Vec::new();
    println!("Please input {} coin flips (h for heads, t for tails):", entropy_bits);
    println!("Enter 'qf' to quit flipping and randomize the rest.");
    println!("Enter 'qq' to quit the program.");

    for _ in 0..entropy_bits {
        let mut input = String::new();
        loop {
            print!("Flip {}: ", flips.len() + 1);
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            std::io::stdin().read_line(&mut input).unwrap();
            let flip = input.trim().to_lowercase();

            match flip.as_str() {
                "h" => {
                    flips.push(1);
                    break;
                }
                "t" => {
                    flips.push(0);
                    break;
                }
                "qf" => {
                    println!("Randomizing the remaining flips...");
                    let remaining = (entropy_bits as usize) - flips.len();
                    let mut rng = rand::thread_rng();
                    for _ in 0..remaining {
                        flips.push(rng.gen_range(0..=1)); // Randomize 0 or 1
                    }
                    return flips; // Exit early with completed flips
                }
                "qq" => {
                    println!("Exiting the program.");
                    std::process::exit(0);
                }
                _ => {
                    println!("Invalid input. Please enter 'h', 't', 'qf', or 'qq'.");
                }
            }
            input.clear();
        }
    }

    flips
}
