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

const CIPHERTEXT_FILE_PATH: &str = "/home/corba/.secrets/bitwarden_encrypted_secrets";
const PLAINTEXT_WRITE_FILE_PATH: &str = "/home/corba/.secrets/bitwarden_dump_plaintext.json";
const PLAINTEXT_READ_FILE_PATH: &str = "/home/corba/.secrets/bitwarden_dump_plaintext.json";

#[derive(Serialize, Deserialize)]
struct SecretsManager {
    secrets: String,
}
impl SerdeEncryptSharedKey for SecretsManager {
    type S = BincodeSerializer<Self>;
}

fn main() {
    while let Some(arg) = std::env::args().nth(1) {
        println!("{}", arg);
    }
    // get password, create files if necessary
    let init_res = init();
    if let Err(err_msg) = init_res {
        println!("\n{}\n", err_msg.red());
        return;
    };
    let password = init_res.unwrap();

    // user event loop
    loop {
        let action = input("Action: ");

        // match action input
        match action.as_str() {
            "d" => decrypt(&password),
            "e" => encrypt(&password),
            "Q" | "q" => {
                break;
            }
            "?" | "h" | "H" | "help" => {
                println!(
                    "\n{}\n[e] encrypt\n[d] decrypt\n[q] quit\n[h] help\n",
                    "Actions: ".cyan()
                );
                continue;
            }
            _ => {
                println!("\n{}\n", "Invalid command".red());
                continue;
            }
        }
    }
}

// handlers
fn encrypt(password: &str) {
    // get plaintext secrets json
    let plaintext_secrets: String = std::fs::read_to_string(PLAINTEXT_READ_FILE_PATH)
        .unwrap_or_else(|_| {
            let plaintext_path = input("Enter path to plaintext secrets file: ");
            std::fs::read_to_string(&plaintext_path).expect("Unable to read file")
        });

    write_secrets(password, plaintext_secrets.clone());
    println!("\n{}\n", "Success!".green());
}

fn decrypt(password: &str) {
    // get secrets buffer
    let plaintext_path = std::env::args()
        .nth(2)
        .unwrap_or(PLAINTEXT_WRITE_FILE_PATH.to_string());

    let secrets = get_secrets(password).unwrap();

    fs::write(plaintext_path, secrets).expect("Unable to write file");
    println!("\n{}\n", "Success!".green());
}

// helpers
fn get_secrets(password: &str) -> Result<String, ()> {
    // get secrets buffer
    let cipher_secrets_buffer = fs::read(CIPHERTEXT_FILE_PATH).expect("Unable to read file");

    // decrypt buffer
    let shared_key = SharedKey::new(password_to_key(password));
    let encrypted_message = EncryptedMessage::deserialize(cipher_secrets_buffer).unwrap();
    let msg = SecretsManager::decrypt_owned(&encrypted_message, &shared_key);

    match msg {
        Ok(msg) => Ok(msg.secrets),
        Err(e) => {
            println!("{:?}", e);
            Err(())
        }
    }
}

// helpers
fn write_secrets(password: &str, secrets: String) {
    // encrypt secrets
    let shared_key = SharedKey::new(password_to_key(password));
    let msg = SecretsManager { secrets };
    let encrypted_message = msg.encrypt(&shared_key).unwrap();
    let serialized_encrypted_message: Vec<u8> = encrypted_message.serialize();

    // write out
    fs::write(CIPHERTEXT_FILE_PATH, serialized_encrypted_message).expect("Unable to write file");
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

fn init() -> Result<String, String> {
    // check for secrets file
    let secrets = fs::read(CIPHERTEXT_FILE_PATH);
    if secrets.is_ok() {
        // get password input
        print!("Password: ");
        std::io::stdout().flush().unwrap();
        let password = read_password().unwrap();

        // verify password
        if get_secrets(&password).is_err() {
            return Err("Incorrect password".to_string());
        }

        println!();
        return Ok(password);
    }
    // initialize password manager
    print!("\nWelcome to password manager\n\nSet a master password: ");
    std::io::stdout().flush().unwrap();
    let password = read_password().unwrap();
    print!("Confirm master password: ");
    std::io::stdout().flush().unwrap();
    let confirm_password = read_password().unwrap();
    if password != confirm_password {
        return Err("Passwords don't match".to_string());
    }

    // create secret and backup files
    let secrets = "{}".to_string();
    write_secrets(&password, secrets);

    println!("\n{}\n", "Secrets file created".green());

    Ok(password)
}

fn input(prompt: &str) -> String {
    // get input
    let mut input = String::new();
    print!("{prompt}");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}
