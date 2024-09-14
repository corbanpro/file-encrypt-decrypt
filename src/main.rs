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
        // get action input
        let mut action = String::new();
        print!("Action [? for help]: ");
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_line(&mut action).unwrap();
        let action = action.trim().to_string();

        // match action input
        match action.as_str() {
            "r" => read(&password),
            "s" => grep_secrets(&password),
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
            "?" => {
                println!(
                    "\n{}\n[r] Read secrets\n[s] Search secrets\n[a] Add new secret\n[u] Update secret\n[rn] Rename secret\n[d] Delete secret\n[p] Change password\n[b] Backup secrets\n[rs] Restore secrets from backup\n[q] Quit\n",
                    "Actions:".cyan()
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

fn grep_secrets(password: &str) {
    let mut secrets = get_secrets(password).unwrap();

    // get filter string
    let mut grep_string = String::new();
    print!("\nSearch: ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut grep_string).unwrap();
    let grep_string = grep_string.trim().to_string();

    // filter list based on string
    secrets.retain(|key, _value| key.to_uppercase().contains(&grep_string.to_uppercase()));

    // return if there are no matches
    if secrets.is_empty() {
        println!("\n{}\n", "No matches".red());
        return;
    }

    print_keys(&secrets);

    // show secrets if they want to
    let mut show_secrets = String::new();
    print!("Show secrets? [y/N] ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut show_secrets).unwrap();
    let show_secrets = show_secrets.trim().to_string();

    if show_secrets == "y" || show_secrets == "Y" {
        print_secrets(&secrets)
    } else {
        println!()
    }
}

fn add(password: &str) {
    // get new secret info
    println!();
    let mut secret_id = String::new();
    print!("Secret id: ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut secret_id).unwrap();
    let secret_id = secret_id.trim().to_string();

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
    print_keys(&secrets);
    let mut secret_id = String::new();
    print!("Secret id: ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut secret_id).unwrap();
    let secret_id = secret_id.trim().to_string();

    // return if invalid key
    if !secrets.contains_key(&secret_id) {
        println!("{}", "\nInvalid id\n".red());
        return;
    }

    print!("Updated secret: ");
    std::io::stdout().flush().unwrap();
    let secret = read_password().unwrap();

    // update secret
    secrets.insert(secret_id, secret);
    write_secrets(password, secrets);
    println!("\n{}\n", "Success!".green());
}

fn rename(password: &str) {
    let secrets = get_secrets(password).unwrap();
    print_keys(&secrets);

    // get delete key
    let mut update_key = String::new();
    print!("Key to rename: ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut update_key).unwrap();
    let update_key = update_key.trim().to_string();

    let mut secrets = get_secrets(password).unwrap();

    if !secrets.contains_key(&update_key) {
        println!("\n{}\n", "Invalid key".red());
        return;
    }

    let mut new_key = String::new();
    print!("New key name: ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut new_key).unwrap();
    let new_key = new_key.trim().to_string();

    let secret = secrets.remove(&update_key).unwrap();
    secrets.insert(new_key, secret);

    write_secrets(password, secrets);

    println!("\n{}\n", "Success!".green())
}

fn delete(password: &str) {
    let secrets = get_secrets(password).unwrap();
    print_keys(&secrets);

    // get delete key
    let mut delete_key = String::new();
    print!("Key to delete: ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut delete_key).unwrap();
    let delete_key = delete_key.trim().to_string();

    let mut secrets = get_secrets(password).unwrap();

    if !secrets.contains_key(&delete_key) {
        println!("\n{}\n", "Invalid key".red());
        return;
    }

    // confirm and delete
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
    let mut confirm = String::new();
    print!("\nAre you sure you want to overwrite backup? [y/N] ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut confirm).unwrap();
    let confirm = confirm.trim().to_string();
    if confirm == "y" || confirm == "Y" {
        let secrets = get_secrets(password).unwrap();
        write_backup_secrets(password, secrets);
        println!("\n{}\n", "Success!".green());
    } else {
        println!("\nCanceled backup\n")
    }
}

fn restore_from_backup(password: &str) {
    let mut confirm = String::new();
    print!("\nAre you sure you want to overwrite secrets? [y/N] ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut confirm).unwrap();
    let confirm = confirm.trim().to_string();
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
fn print_keys(secrets: &HashMap<String, String>) {
    println!("\n{}", "Keys:".cyan());
    if secrets.is_empty() {
        println!("No keys found\n");
        return;
    }

    let mut secrets_vec: Vec<&String> = secrets.keys().collect();

    secrets_vec.sort();

    for key in secrets_vec {
        println!("{}", key);
    }
    println!();
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
