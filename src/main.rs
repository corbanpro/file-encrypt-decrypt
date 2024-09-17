use arboard::Clipboard;
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
            "rb" => read_backup(&password),
            "b" => backup(&password),
            "rs" => restore_from_backup(&password),
            "cl" => clear_terminal(),

            "Q" | "q" => {
                break;
            }
            "?" | "h" | "H" | "help" => {
                println!(
                    "\n{}\n{}\n{}\n[k] Show keys\n[c] Copy secret to clipboard\n[a] Add new secret\n[u] Update secret\n[rn] Rename secret\n[d] Delete secret\n[p] Change password\n{}\n{}\n{}\n[cl] Clear terminal\n[q] Quit\n",
                    "Actions:".cyan(), "[r] Read secrets".red(), "[s] Search secrets".red(), "[rb] Read backup".red(),"[b] Backup secrets".red(), "[rs] Restore secrets from backup".red() 
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

    // print
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
    // return if no keys to copy
    let secrets = get_secrets(password).unwrap();
    if secrets.is_empty() {
        println!("\nNo keys to update\n");
        return;
    }

    // get secret to copy
    let keys = print_keys(&secrets);
    let secret_number = input(&format!("Secret to copy: [1-{}] ", keys.len()));
    let copy_key = keys.get(&secret_number);
    if copy_key.is_none() {
        println!("{}", "\nInvalid number\n".red());
        return;
    }
    let secret = secrets.get(copy_key.unwrap()).unwrap();

    // copy secret to clipboard
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
    // return if now secrets to update
    let mut secrets = get_secrets(password).unwrap();
    if secrets.is_empty() {
        println!("\nNo keys to update\n");
        return;
    }

    // get secret info
    let keys = print_keys(&secrets);
    let secret_number = input(&format!("Secret to update: [1-{}] ", keys.len()));
    let update_key = keys.get(&secret_number);
    if update_key.is_none() {
        println!("{}", "\nInvalid number\n".red());
        return;
    }
    let update_key = update_key.unwrap();
    print!("Updated secret: ");
    std::io::stdout().flush().unwrap();
    let secret = read_password().unwrap();

    // update secret
    secrets.insert(update_key.to_string(), secret);
    write_secrets(password, secrets);
    println!("\n{}\n", "Success!".green());
}

fn rename(password: &str) {
    // return if now secrets to update
    let mut secrets = get_secrets(password).unwrap();

    if secrets.is_empty() {
        println!("\nNo keys to update\n");
        return;
    }

    // get key info
    let keys = print_keys(&secrets);
    let secret_number = input(&format!("Key to rename: [1-{}] ", keys.len()));
    let rename_key = keys.get(&secret_number);
    if rename_key.is_none() {
        println!("{}", "\nInvalid number\n".red());
        return;
    }
    let rename_key = rename_key.unwrap();
    let new_key = input("New key name: ");

    // rename key
    let secret = secrets.remove(rename_key).unwrap();
    secrets.insert(new_key, secret);
    write_secrets(password, secrets);

    println!("\n{}\n", "Success!".green())
}

fn delete(password: &str) {
    // return if now secrets to update
    let mut secrets = get_secrets(password).unwrap();
    if secrets.is_empty() {
        println!("\nNo keys to update\n");
        return;
    }

    // get delete key info
    let keys = print_keys(&secrets);
    let secret_number = input(&format!("Secret to delete: [1-{}] ", keys.len()));
    let delete_key = keys.get(&secret_number);
    if delete_key.is_none() {
        println!("{}", "\nInvalid number\n".red());
        return;
    }
    let delete_key = delete_key.unwrap();

    // confirm deletion
    let confirm = input(&format!(
        "Are you sure you want to delete \"{}\"? [y/N] ",
        delete_key
    ));

    // delete
    if confirm == "y" || confirm == "Y" {
        secrets.remove(delete_key);
        println!("\n{}\n", "Success!".green());
        write_secrets(password, secrets)
    } else {
        println!("\nCanceled deletion\n")
    }
}

fn change_password(password: &str) {
    // get new password
    print!("\nNew password: ");
    std::io::stdout().flush().unwrap();
    let new_password = read_password().unwrap();
    print!("Confirm new password: ");
    std::io::stdout().flush().unwrap();
    let confirm_new_password = read_password().unwrap();

    // make sure passwords match
    if new_password != confirm_new_password {
        println!("\n{}\n", "Passwords do not match".red());
        return;
    }

    // update secrets file password
    let secrets = get_secrets(password).unwrap();
    write_secrets(&new_password, secrets);

    // update backup file password
    let backup_secrets = get_backup_secrets(password).unwrap();
    write_backup_secrets(&new_password, backup_secrets);

    println!("\n{}\n", "Success!".green())
}

fn backup(password: &str) {
    // show diff
    let secrets = get_secrets(password).unwrap();
    let backups = get_backup_secrets(password).unwrap();
    show_diff(&secrets, &backups);

    // confirm changes
    let confirm =
        input("\nAre you sure you want to make the above changes to the backup file? [y/N] ");

    // backup
    if confirm == "y" || confirm == "Y" {
        let secrets = get_secrets(password).unwrap();
        write_backup_secrets(password, secrets);
        println!("\n{}\n", "Success!".green());
    } else {
        println!("\nCanceled backup\n")
    }
}

fn read_backup(password: &str) {
    let backups = get_backup_secrets(password).unwrap();
    print_secrets(&backups);
}

fn restore_from_backup(password: &str) {
    // show diff
    let secrets = get_secrets(password).unwrap();
    let backups = get_backup_secrets(password).unwrap();
    show_diff(&backups, &secrets);

    // confirm change
    let confirm =
        input("\nAre you sure you want to make the above changes to the secrets file? [y/N] ");

    // backup
    if confirm == "y" || confirm == "Y" {
        let secrets = get_backup_secrets(password).unwrap();
        write_secrets(password, secrets);
        println!("\n{}\n", "Success!".green());
    } else {
        println!("\nCanceled backup restoration\n")
    }
}

fn clear_terminal() {
    print!("{}[2J", 27 as char);
    std::io::stdout().flush().unwrap();
}

// helpers
fn print_secrets(secrets: &HashMap<String, String>) {
    println!("\n{}", "Secrets:".cyan());
    // check for secrets
    if secrets.is_empty() {
        println!("No secrets found\n");
        return;
    }

    // sort secrets
    let mut secrets_vec: Vec<(&String, &String)> = secrets.iter().collect();
    secrets_vec.sort_by(|(akey, _avalue), (bkey, _bvalue)| (akey).cmp(bkey));

    // print secets
    for (key, value) in secrets_vec {
        println!("{}: {}", key, value);
    }
    println!();
}

fn print_keys(secrets: &HashMap<String, String>) -> HashMap<String, String> {
    println!("\n{}", "Keys:".cyan());
    let mut keys = HashMap::new();

    // check for keys
    if secrets.is_empty() {
        println!("No keys found\n");
        return keys;
    }

    // sort keys
    let mut secrets_vec: Vec<&String> = secrets.keys().collect();
    secrets_vec.sort();

    // print keys
    for (index, key) in secrets_vec.iter().enumerate() {
        let index = (index + 1).to_string();
        println!("[{}] {}", index, key);
        keys.insert(index, key.to_string());
    }
    println!();
    keys
}

fn get_secrets(password: &str) -> Result<HashMap<String, String>, ()> {
    // get secrets buffer
    let cipher_secrets_buffer = fs::read(CIPHERTEXT_FILE_PATH).expect("Unable to read file");

    // decrypt buffer
    let shared_key = SharedKey::new(password_to_key(password));
    let encrypted_message = EncryptedMessage::deserialize(cipher_secrets_buffer).unwrap();
    let msg = SecretsManager::decrypt_owned(&encrypted_message, &shared_key);

    match msg {
        Ok(msg) => Ok(msg.secrets),
        Err(_) => Err(()),
    }
}

fn get_backup_secrets(password: &str) -> Result<HashMap<String, String>, ()> {
    // get backups buffer
    let cipher_secrets_buffer = fs::read(CIPHERTEXT_BACKUP_FILE_PATH).expect("Unable to read file");

    // decrypt buffer
    let shared_key = SharedKey::new(password_to_key(password));
    let encrypted_message = EncryptedMessage::deserialize(cipher_secrets_buffer).unwrap();
    let msg = SecretsManager::decrypt_owned(&encrypted_message, &shared_key);

    match msg {
        Ok(msg) => Ok(msg.secrets),
        Err(_) => Err(()),
    }
}

fn write_secrets(password: &str, secrets: HashMap<String, String>) {
    // encrypt secrets
    let shared_key = SharedKey::new(password_to_key(password));
    let msg = SecretsManager { secrets };
    let encrypted_message = msg.encrypt(&shared_key).unwrap();
    let serialized_encrypted_message: Vec<u8> = encrypted_message.serialize();

    // write out
    fs::write(CIPHERTEXT_FILE_PATH, serialized_encrypted_message).expect("Unable to write file");
}

fn write_backup_secrets(password: &str, secrets: HashMap<String, String>) {
    // encrypt secrets
    let shared_key = SharedKey::new(password_to_key(password));
    let msg = SecretsManager { secrets };
    let encrypted_message = msg.encrypt(&shared_key).unwrap();
    let serialized_encrypted_message: Vec<u8> = encrypted_message.serialize();

    // write out
    fs::write(CIPHERTEXT_BACKUP_FILE_PATH, serialized_encrypted_message)
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

fn show_diff(
    staying_secrets: &HashMap<String, String>,
    changing_secrets: &HashMap<String, String>,
) {
    // print keys and secrets subject to change
    println!("\n{}", "Diff:".cyan());
    for (key, secret) in changing_secrets.iter() {
        if !staying_secrets.contains_key(key) || staying_secrets.get(key).unwrap() != secret {
            println!("- {}", format!("{key}: {secret}").red());
            if let Some(secret) = staying_secrets.get(key) {
                println!("+ {}", format!("{key}: {secret}").green());
            }
        } else {
            println!("  {key}: {secret}");
        }
    }

    // print adding keys
    for (key, secret) in staying_secrets.iter() {
        if !changing_secrets.contains_key(key) {
            println!("+ {}", format!("{key}: {secret}").green());
        }
    }

    println!();
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
    let secrets = HashMap::new();
    write_secrets(&password, secrets.clone());
    write_backup_secrets(&password, secrets);
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
