use clap::Parser;
use colored::Colorize;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use serde_encrypt::serialize::impls::BincodeSerializer;
use serde_encrypt::shared_key::SharedKey;
use serde_encrypt::traits::SerdeEncryptSharedKey;
use serde_encrypt::EncryptedMessage;
use sha2::Digest;
use sha2::Sha256;
use std::fs;
use std::io::Write;

#[derive(Parser, Debug)]
#[command(name = "enc")]
#[command(author = "Corban Procuniar <corbanpro@gmail.com>")]
#[command(version = "1.0")]
#[command(about = "encrypt and decrypt files", long_about = None)]
struct Args {
    #[arg(short, long)]
    encrypt: bool,

    #[arg(short, long)]
    decrypt: bool,

    #[arg(value_name = "READ FILE")]
    read_file: String,

    #[arg(value_name = "WRITE FILE")]
    write_file: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct SecretsManager {
    secrets: String,
}
impl SerdeEncryptSharedKey for SecretsManager {
    type S = BincodeSerializer<Self>;
}

fn main() {
    let args = Args::parse();

    let read_file_path = &args.read_file;

    let write_file_path = &args
        .write_file
        .unwrap_or(format_write_file(read_file_path, args.encrypt));

    let read_file_res = std::fs::read(read_file_path);

    if read_file_res.is_err() {
        println!("\n{}\n", "Problem opening read file".red());
        return;
    };

    let func = if args.decrypt { decrypt } else { encrypt };

    func(read_file_path, write_file_path);
}

// handlers
fn encrypt(plaintext_read_file_path: &str, ciphertext_write_file_path: &str) {
    // get password
    let password = get_password("Enter password: ");
    let confirm_password = get_password("Confirm password: ");
    if password != confirm_password {
        println!("\n{}\n", "Passwords do not match".red());
        return;
    }
    // get plaintext secrets json
    let plaintext_secrets: String = std::fs::read_to_string(plaintext_read_file_path).unwrap();
    write_secrets(&password, plaintext_secrets.clone(), ciphertext_write_file_path);
    println!(
        "\n{}\n\nSet restrictive permissions on encrypted file to prevent corruption. Run:\n\n{}\n",
        "Success!".green(),
        format!("sudo chmod 400 {}", ciphertext_write_file_path).yellow()
    );
}

fn decrypt(read_file_path: &str, write_file_path: &str) {
    // get password
    let password = get_password("Enter password: ");

    // get secrets
    let secrets = match get_secrets(&password, read_file_path) {
        Ok(secrets) => secrets,
        Err(_) => {
            println!("\n{}\n", "Incorrect password".red());
            return;
        }
    };

    fs::write(write_file_path, secrets).expect("Unable to write file");
    println!("\n{}\n", "Success!".green());
}

// helpers
fn get_password(prompt: &str) -> String {
    print!("{prompt}");
    std::io::stdout().flush().unwrap();
    read_password().unwrap()
}

fn get_secrets(password: &str, ciphertext_read_file_path: &str) -> Result<String, ()> {
    // get secrets buffer
    let cipher_secrets_buffer = fs::read(ciphertext_read_file_path).expect("Unable to read file");

    // decrypt buffer
    let shared_key = SharedKey::new(password_to_key(password));
    let encrypted_message = EncryptedMessage::deserialize(cipher_secrets_buffer).unwrap();
    let msg = SecretsManager::decrypt_owned(&encrypted_message, &shared_key);

    match msg {
        Ok(msg) => Ok(msg.secrets),
        Err(_) => Err(()),
    }
}

// helpers
fn write_secrets(password: &str, secrets: String, ciphertext_write_file_path: &str) {
    // encrypt secrets
    let shared_key = SharedKey::new(password_to_key(password));
    let msg = SecretsManager { secrets };
    let encrypted_message = msg.encrypt(&shared_key).unwrap();
    let serialized_encrypted_message: Vec<u8> = encrypted_message.serialize();

    // write out
    fs::write(ciphertext_write_file_path, serialized_encrypted_message).expect("Unable to write file");
}

fn password_to_key(password: &str) -> [u8; 32] {
    // hash password
    let mut hasher = Sha256::new();
    let mut result = [0_u8; 32];
    hasher.update(password.as_bytes());

    // put hash into u8 array as key
    for (index, byte) in hasher.finalize().iter().copied().enumerate() {
        if index > 31 {
            break;
        }
        result[index] = byte
    }

    result
}

fn format_write_file(read_file_path: &str, encrypting: bool) -> String {
    match encrypting {
        true => format!("{read_file_path}.enc").to_string(),
        false => {
            if read_file_path.ends_with(".enc") {
                read_file_path.strip_suffix(".enc").unwrap().to_string()
            } else {
                format!("{read_file_path}.plaintext").to_string()
            }
        }
    }
}
