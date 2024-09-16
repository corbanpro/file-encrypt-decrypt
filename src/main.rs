use arboard::Clipboard;
use colored::Colorize;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use serde_encrypt::serialize::impls::BincodeSerializer;
use serde_encrypt::shared_key::SharedKey;
use serde_encrypt::traits::SerdeEncryptSharedKey;
use serde_encrypt::EncryptedMessage;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Write;

const CIPHERTEXT_FILE_PATH: &str = "/home/corba/.secrets";
const CIPHERTEXT_BACKUP_FILE_PATH: &str = "/home/corba/.secrets_backup";

#[derive(Serialize, Deserialize)]
struct SecretsManager {
    secrets: HashMap<String, String>,
}
impl SerdeEncryptSharedKey for SecretsManager {
    type S = BincodeSerializer<Self>;
}

fn main() {
    let init_res = init();

    if let Err(err_msg) = init_res {
        println!("\n{}\n", err_msg.red());
        return;
    };

    let password = init_res.unwrap();

    loop {
        let action = input("Action: ");

        // match action input
        match action.as_str() {
            "r" => read(&password),
            "s" => search_secrets(&password),
            "k" => read_keys(&password),
            "c" => copy_to_clipboard(&password),
            "a" => add(&password),
            "u" => update(&password),
            "rn" => rename(&password),
            "d" => delete(&password),
            "p" => {
                change_password(&password);
                break;
            }
            "b" => backup(&password),
            "rs" => restore_from_backup(&password),

            "Q" | "q" => {
                break;
            }
            "?" | "h" | "H" | "help" => {
                println!(
                    "\n{}\n{}\n{}\n[k] Show keys\n[c] Copy secret to clipboard\n[a] Add new secret\n[u] Update secret\n[rn] Rename secret\n[d] Delete secret\n[p] Change password\n[b] Backup secrets\n[rs] Restore secrets from backup\n[q] Quit\n",
                    "Actions:".cyan(), "[r] Read plaintext secrets".red(), "[s] Search secrets".red()
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
fn read(password: &str) {
    let secrets = get_secrets(password).unwrap();
    print_secrets(&secrets)
}

fn search_secrets(password: &str) {
    let mut secrets = get_secrets(password).unwrap();

    // get filter string
    let grep_string = input("\nSearch: ");

    // filter list based on string
    secrets.retain(|key, _value| key.to_uppercase().contains(&grep_string.to_uppercase()));

    // return if there are no matches
    if secrets.is_empty() {
        println!("\n{}\n", "No matches".red());
        return;
    }

    print_keys(&secrets);

    // show secrets if they want to
    let show_secrets = input("Show secrets? [y/N] ");

    if show_secrets == "y" || show_secrets == "Y" {
        print_secrets(&secrets)
    } else {
        println!()
    }
}

fn read_keys(password: &str) {
    let secrets = get_secrets(password).unwrap();
    print_keys(&secrets);
}

fn copy_to_clipboard(password: &str) {
    let secrets = get_secrets(password).unwrap();
    if secrets.is_empty() {
        println!("\nNo keys to update\n");
        return;
    }
    let keys = print_keys(&secrets);

    let secret_number = input(&format!("Secret to copy: [1-{}] ", keys.len()));
    let copy_key = keys.get(&secret_number);
    // return if invalid key
    if copy_key.is_none() {
        println!("{}", "\nInvalid number\n".red());
        return;
    }

    let copy_key = copy_key.unwrap();

    let secret = secrets.get(copy_key);

    if secret.is_none() {
        println!("\n{}\n", "Invalid key".red())
    }

    let secret = secret.unwrap();
    let mut clipboard = Clipboard::new().unwrap();

    clipboard.set_text(secret).unwrap();
    println!("\n{}\n", "Copied to clipboard!".green())
}

fn add(password: &str) {
    // get new secret info
    println!();
    let secret_id = input("Secret id: ");

    print!("Secret: ");
    std::io::stdout().flush().unwrap();
    let secret = read_password().unwrap();

    // add secret
    let mut secrets = get_secrets(password).unwrap();
    secrets.insert(secret_id, secret);
    write_secrets(password, secrets);
    println!("\n{}\n", "Success!".green());
}

fn update(password: &str) {
    // get secret id
    let mut secrets = get_secrets(password).unwrap();
    if secrets.is_empty() {
        println!("\nNo keys to update\n");
        return;
    }
    let keys = print_keys(&secrets);
    let secret_number = input(&format!("Secret to update: [1-{}] ", keys.len()));

    let update_key = keys.get(&secret_number);
    // return if invalid key
    if update_key.is_none() {
        println!("{}", "\nInvalid number\n".red());
        return;
    }

    let update_key = update_key.unwrap();

    // return if invalid key
    if !secrets.contains_key(update_key) {
        println!("{}", "\nInvalid key\n".red());
        return;
    }

    print!("Updated secret: ");
    std::io::stdout().flush().unwrap();
    let secret = read_password().unwrap();

    // update secret
    secrets.insert(update_key.to_string(), secret);
    write_secrets(password, secrets);
    println!("\n{}\n", "Success!".green());
}

fn rename(password: &str) {
    let mut secrets = get_secrets(password).unwrap();

    if secrets.is_empty() {
        println!("\nNo keys to update\n");
        return;
    }
    let keys = print_keys(&secrets);

    let secret_number = input(&format!("Key to rename: [1-{}] ", keys.len()));

    let rename_key = keys.get(&secret_number);

    // return if invalid key
    if rename_key.is_none() {
        println!("{}", "\nInvalid number\n".red());
        return;
    }

    let rename_key = rename_key.unwrap();

    if !secrets.contains_key(rename_key) {
        println!("\n{}\n", "Invalid key".red());
        return;
    }

    let new_key = input("New key name: ");

    let secret = secrets.remove(rename_key).unwrap();
    secrets.insert(new_key, secret);

    write_secrets(password, secrets);

    println!("\n{}\n", "Success!".green())
}

fn delete(password: &str) {
    let mut secrets = get_secrets(password).unwrap();
    if secrets.is_empty() {
        println!("\nNo keys to update\n");
        return;
    }
    let keys = print_keys(&secrets);

    // get delete key

    let secret_number = input(&format!("Secret to delete: [1-{}] ", keys.len()));

    let delete_key = keys.get(&secret_number);
    // return if invalid key
    if delete_key.is_none() {
        println!("{}", "\nInvalid number\n".red());
        return;
    }

    let delete_key = delete_key.unwrap();

    if !secrets.contains_key(delete_key) {
        println!("\n{}\n", "Invalid key".red());
        return;
    }

    // confirm and delete
    let confirm = input(&format!(
        "Are you sure you want to delete \"{}\"? [y/N] ",
        delete_key
    ));

    if confirm == "y" || confirm == "Y" {
        secrets.remove(delete_key);
        println!("\n{}\n", "Success!".green());
        write_secrets(password, secrets)
    } else {
        println!("\nCanceled deletion\n")
    }
}

fn change_password(password: &str) {
    print!("\nNew password: ");
    std::io::stdout().flush().unwrap();
    let new_password = read_password().unwrap();

    print!("Confirm new password: ");
    std::io::stdout().flush().unwrap();
    let confirm_new_password = read_password().unwrap();

    if new_password != confirm_new_password {
        println!("\n{}\n", "Passwords do not match".red());
        return;
    }

    let secrets = get_secrets(password).unwrap();
    write_secrets(&new_password, secrets);

    let backup_secrets = get_backup_secrets(password).unwrap();
    write_backup_secrets(&new_password, backup_secrets);

    println!("\n{}\n", "Success!".green())
}

fn backup(password: &str) {
    let confirm = input("\nAre you sure you want to overwrite backup? [y/N] ");

    if confirm == "y" || confirm == "Y" {
        let secrets = get_secrets(password).unwrap();
        write_backup_secrets(password, secrets);
        println!("\n{}\n", "Success!".green());
    } else {
        println!("\nCanceled backup\n")
    }
}

fn restore_from_backup(password: &str) {
    let confirm = input("\nAre you sure you want to overwrite secrets? [y/N] ");

    if confirm == "y" || confirm == "Y" {
        let secrets = get_backup_secrets(password).unwrap();
        write_secrets(password, secrets);
        println!("\n{}\n", "Success!".green());
    } else {
        println!("\nCanceled backup restoration\n")
    }
}

// helpers
fn print_secrets(secrets: &HashMap<String, String>) {
    println!("\n{}", "Secrets:".cyan());
    if secrets.is_empty() {
        println!("No secrets found\n");
        return;
    }

    let mut secrets_vec: Vec<(&String, &String)> = secrets.iter().collect();
    secrets_vec.sort_by(|(akey, _avalue), (bkey, _bvalue)| (akey).cmp(bkey));

    for (key, value) in secrets_vec {
        println!("{}: {}", key, value);
    }
    println!();
}
fn print_keys(secrets: &HashMap<String, String>) -> HashMap<String, String> {
    println!("\n{}", "Keys:".cyan());
    let mut keys = HashMap::new();

    if secrets.is_empty() {
        println!("No keys found\n");

        return keys;
    }

    let mut secrets_vec: Vec<&String> = secrets.keys().collect();

    secrets_vec.sort();

    for (index, key) in secrets_vec.iter().enumerate() {
        let index = (index + 1).to_string();
        println!("[{}] {}", index, key);
        keys.insert(index, key.to_string());
    }
    println!();
    keys
}
fn get_secrets(password: &str) -> Result<HashMap<String, String>, ()> {
    let cipher_secrets_buffer = fs::read(CIPHERTEXT_FILE_PATH).expect("Unable to read file");

    // decrypt
    let shared_key = SharedKey::new(password_to_key(password));

    let encrypted_message = EncryptedMessage::deserialize(cipher_secrets_buffer).unwrap();
    let msg = SecretsManager::decrypt_owned(&encrypted_message, &shared_key);

    match msg {
        Ok(msg) => Ok(msg.secrets),
        Err(_) => Err(()),
    }
}

fn get_backup_secrets(password: &str) -> Result<HashMap<String, String>, ()> {
    let cipher_secrets_buffer = fs::read(CIPHERTEXT_BACKUP_FILE_PATH).expect("Unable to read file");

    // decrypt
    let shared_key = SharedKey::new(password_to_key(password));

    let encrypted_message = EncryptedMessage::deserialize(cipher_secrets_buffer).unwrap();
    let msg = SecretsManager::decrypt_owned(&encrypted_message, &shared_key);

    match msg {
        Ok(msg) => Ok(msg.secrets),
        Err(_) => Err(()),
    }
}

fn write_secrets(password: &str, secrets: HashMap<String, String>) {
    // encrypt
    let shared_key = SharedKey::new(password_to_key(password));
    let msg = SecretsManager { secrets };
    let encrypted_message = msg.encrypt(&shared_key).unwrap();
    let serialized_encrypted_message: Vec<u8> = encrypted_message.serialize();

    // write
    fs::write(CIPHERTEXT_FILE_PATH, serialized_encrypted_message).expect("Unable to write file");
}

fn write_backup_secrets(password: &str, secrets: HashMap<String, String>) {
    let shared_key = SharedKey::new(password_to_key(password));
    let msg = SecretsManager { secrets };
    let encrypted_message = msg.encrypt(&shared_key).unwrap();
    let serialized_encrypted_message: Vec<u8> = encrypted_message.serialize();

    // write
    fs::write(CIPHERTEXT_BACKUP_FILE_PATH, serialized_encrypted_message)
        .expect("Unable to write file");
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

fn init() -> Result<String, String> {
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
    print!("\nWelcome to password manager\n\nSet a master password: ");
    std::io::stdout().flush().unwrap();
    let password = read_password().unwrap();

    print!("Confirm master password: ");
    std::io::stdout().flush().unwrap();
    let confirm_password = read_password().unwrap();

    if password != confirm_password {
        return Err("Passwords don't match".to_string());
    }

    let secrets = HashMap::new();
    write_secrets(&password, secrets);
    println!("\n{}\n", "Secrets file created".green());

    Ok(password)
}

fn input(prompt: &str) -> String {
    let mut input = String::new();
    print!("{prompt}");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut input).unwrap();
    let input = input.trim().to_string();
    input
}
