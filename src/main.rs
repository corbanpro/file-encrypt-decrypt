use colored::Colorize;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use serde_encrypt::serialize::impls::BincodeSerializer;
use serde_encrypt::shared_key::SharedKey;
use serde_encrypt::traits::SerdeEncryptSharedKey;
use serde_encrypt::EncryptedMessage;
use sha2::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::io::Write;

const CIPHER_TEXT_FILE_PATH: &str = "/home/corba/.secrets";
const PLAIN_TEXT_FILE_PATH: &str = "/home/corba/documents/side-projects/rust/secrets/secrets.json";

#[derive(Serialize, Deserialize)]
struct SecretsManager {
    secrets: HashMap<String, String>,
}
impl SerdeEncryptSharedKey for SecretsManager {
    type S = BincodeSerializer<Self>; // you can specify serializer implementation (or implement it by yourself).
}

fn main() {
    // get password input
    print!("Password: ");
    std::io::stdout().flush().unwrap();
    let password = read_password().unwrap();

    // verify password
    if get_decrypted_secrets(&password).is_err() {
        println!("\n{}\n", "Incorrect password".red());
        return;
    }

    loop {
        // get action input
        let mut action = String::new();
        println!(
            "\n{}\n[1] read secrets\n[2] add new secret\n[3] update secret\n[4] delete secret\n[5] reset from file\n", "Input action [1-5]".cyan()
        );
        std::io::stdin().read_line(&mut action).unwrap();
        let action = action.trim().to_string();

        // match action input
        match action.as_str() {
            "1" => print_secrets(&password),
            "2" => add(&password),
            "3" => update(&password),
            "4" => delete(&password),
            "5" => reset_from_file(&password),
            _ => {
                println!("{}", "Invalid command".red());
                continue;
            }
        }

        // ask if they want to do anything else
        let mut again = String::new();
        print!("Perform another action? [Y/n]: ");
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_line(&mut again).unwrap();
        let again = again.trim().to_string();
        if again == "n" || again == "N" {
            break;
        } else {
            continue;
        }
    }
}

fn password_to_key(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let mut result = [0_u8; 32];

    hasher.update(password.as_bytes());

    for (index, byte) in hasher.finalize().iter().copied().enumerate() {
        if index > 31 {
            break;
        }
        result[index] = byte
    }
    result
}

fn get_decrypted_secrets(password: &str) -> Result<HashMap<String, String>, ()> {
    let cipher_secrets_string = fs::read(CIPHER_TEXT_FILE_PATH).expect("Unable to read file");

    // decrypt
    let shared_key = SharedKey::new(password_to_key(password));

    let encrypted_message = EncryptedMessage::deserialize(cipher_secrets_string).unwrap();
    let msg = SecretsManager::decrypt_owned(&encrypted_message, &shared_key);

    match msg {
        Ok(msg) => Ok(msg.secrets),
        Err(_) => Err(()),
    }
}

fn write_secrets(password: &str, plaintext_secrets_json: HashMap<String, String>) {
    // encrypt
    let shared_key = SharedKey::new(password_to_key(password));
    let msg = SecretsManager {
        secrets: plaintext_secrets_json,
    };
    let encrypted_message = msg.encrypt(&shared_key).unwrap();
    let serialized_encrypted_message: Vec<u8> = encrypted_message.serialize();

    // write
    fs::write(CIPHER_TEXT_FILE_PATH, serialized_encrypted_message).expect("Unable to write file");
}

fn print_secrets(password: &str) {
    let decrypted_secrets = get_decrypted_secrets(password).unwrap();
    let mut sorted_secrets: Vec<(String, String)> = decrypted_secrets.into_iter().collect();

    sorted_secrets.sort();

    println!();
    for (key, value) in sorted_secrets {
        println!("{}: {}", key, value);
    }
    println!();
}

fn print_secret_keys(password: &str) {
    let decrypted_secrets = get_decrypted_secrets(password).unwrap();
    let mut sorted_secrets: Vec<String> = decrypted_secrets.into_keys().collect();

    sorted_secrets.sort();

    println!();
    for key in sorted_secrets {
        println!("{}", key);
    }
    println!();
}

fn reset_from_file(password: &str) {
    print!("\nConfirm password: ");
    std::io::stdout().flush().unwrap();
    let confirm_password = read_password().unwrap();
    if password != confirm_password {
        println!("\nPasswords do not match\n");
        return;
    }

    let mut input = String::new();
    print!("Type the path to the plaintext secrets file [./secrets.json]: ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut input).unwrap();
    let mut plaintext_secrets_file_path = input.trim();
    if plaintext_secrets_file_path.is_empty() {
        plaintext_secrets_file_path = PLAIN_TEXT_FILE_PATH;
    }

    let plaintext_secrets_string =
        fs::read_to_string(plaintext_secrets_file_path).expect("Unable to read file");
    let plaintext_secrets_json: HashMap<String, String> =
        serde_json::from_str(&plaintext_secrets_string).unwrap();

    write_secrets(password, plaintext_secrets_json);
    println!("\n{}\n", "Success!".green());
}

fn update(password: &str) {
    print_secret_keys(password);

    let mut secret_id = String::new();
    print!("Secret id: ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut secret_id).unwrap();
    let secret_id = secret_id.trim().to_string();

    let mut decrypted_secrets = get_decrypted_secrets(password).unwrap();
    if !decrypted_secrets.contains_key(&secret_id) {
        println!("{}", "\nInvalid id\n".red());
        return;
    }

    print!("Updated secret: ");
    std::io::stdout().flush().unwrap();
    let secret = read_password().unwrap();

    decrypted_secrets.insert(secret_id, secret);
    write_secrets(password, decrypted_secrets);
    println!("\n{}\n", "Success!".green());
}

fn add(password: &str) {
    println!();
    let mut secret_id = String::new();
    print!("Secret id: ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut secret_id).unwrap();
    let secret_id = secret_id.trim().to_string();

    print!("Secret: ");
    std::io::stdout().flush().unwrap();
    let secret = read_password().unwrap();

    let mut decrypted_secrets = get_decrypted_secrets(password).unwrap();
    decrypted_secrets.insert(secret_id, secret);
    write_secrets(password, decrypted_secrets);
    println!("\n{}\n", "Success!".green());
}

fn delete(password: &str) {
    print_secret_keys(password);

    let mut delete_key = String::new();
    print!("Key to delete: ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut delete_key).unwrap();
    let delete_key = delete_key.trim().to_string();

    let mut secrets = get_decrypted_secrets(password).unwrap();

    if !secrets.contains_key(&delete_key) {
        println!("\n{}\n", "Invalid key".red());
        return;
    }

    let mut confirm = String::new();

    print!("Are you sure? [y/N] ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut confirm).unwrap();
    let confirm = confirm.trim().to_string();
    if confirm == "y" || confirm == "Y" {
        secrets.remove(&delete_key);
        println!("\n{}\n", "Success!".green());
        write_secrets(password, secrets)
    } else {
        println!("\nCanceled Deletion\n")
    }
}
