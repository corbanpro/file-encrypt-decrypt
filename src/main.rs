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

#[derive(Serialize, Deserialize)]
struct SecretsManager {
    secrets: String,
}
impl SerdeEncryptSharedKey for SecretsManager {
    type S = BincodeSerializer<Self>;
}

fn main() {
    let action = std::env::args().nth(1);
    if action.is_none() {
        println!("\n{}\n", "Please use -e or -d flag".red());
        return;
    }

    let action = action.unwrap();

    if action != "-e" && action != "-d" {
        println!("\n{}\n", "Please use -e or -d flag".red());
        return;
    }

    if std::env::args().len() != 4 {
        println!(
            "\n{}\n",
            "Please provide 3 arguments: (flag, read file, write file)".red()
        );
        return;
    }
    let read_file_path = std::env::args().nth(2).unwrap();
    let write_file_path = std::env::args().nth(3).unwrap();

    let read_file_res = std::fs::read(&read_file_path);

    if read_file_res.is_err() {
        println!("\n{}\n", "Problem opening read file".red());
        return;
    };

    // match action input
    match action.as_str() {
        "-d" => decrypt(&read_file_path, &write_file_path),
        "-e" => encrypt(&read_file_path, &write_file_path),
        _ => {
            println!("\n{}\n", "Please use -e or -d flag".red());
        }
    }
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
    write_secrets(
        &password,
        plaintext_secrets.clone(),
        ciphertext_write_file_path,
    );
    println!("\n{}\n", "Success!".green());
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
    fs::write(ciphertext_write_file_path, serialized_encrypted_message)
        .expect("Unable to write file");
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
