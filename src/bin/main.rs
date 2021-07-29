use clap::Clap;
use minkan_client::models::User;
// use directories_next::ProjectDirs;
// use log::{debug, warn};
use rpassword;
// use toml;
use std::io::{self, Write};
// use std::{fs, path};
// use serde::Deserialize;

/// The cli of the minkan client
#[derive(Clap)]
struct Opts {
    #[clap(subcommand)]
    subcommand: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    Login(Login),
    Register(Register),
}

#[derive(Clap)]
/// Login to your account
struct Login {
    /// provide a username or get a prompt
    #[clap(short, long)]
    username: Option<String>,

    /// provide a password or get a prompt (be careful with shell history!)
    #[clap(short, long)]
    password: Option<String>,
}

#[derive(Clap)]
/// Register a new account
struct Register {
    /// the username for login
    #[clap(short, long)]
    username: Option<String>,

    /// the password used for key derivation and authentication (be careful with shell history!)
    #[clap(short, long)]
    password: Option<String>,
}

/// Small helper method to prevent code duplication for optional arguments
fn return_value_or_ask(value: Option<String>, message: Option<&str>, secret: bool) -> String {
    // unwrap the value or else ask the user to type it now
    value.unwrap_or_else(|| {
        // if it is a secret value, use rpassword to read the password from tty
        if secret {
            rpassword::read_password_from_tty(message)
                .expect("Failed to read secret value from TTY.")
        // or else read from stdin
        } else {
            let mut r = String::new();
            if message.is_some() {
                print!("{}", message.unwrap());
                io::stdout().flush().unwrap()
            }
            io::stdin()
                .read_line(&mut r)
                .expect("Failed to read value from stdin");

            r.trim().to_lowercase()
        }
    })
}

#[async_std::main]
async fn main() {
    env_logger::init();

    let opts: Opts = Opts::parse();

    // Match the given subcommand.
    match opts.subcommand {
        SubCommand::Login(login) => {
            // Check if the user has provided a username as a command line argument or else ask them to type one.
            let username =
                return_value_or_ask(login.username, Some("Please type your username: "), false);
            println!("Username is {}", username);

            // Check if the user has provided a password as command line argument or else ask them to type one now.
            let password =
                return_value_or_ask(login.password, Some("Please type your password: "), true);
            User::new(&username).authenticate(password).unwrap();
        }
        SubCommand::Register(register) => {
            let username = return_value_or_ask(
                register.username,
                Some("Please type your username: "),
                false,
            );
            let password =
                return_value_or_ask(register.password, Some("Please type your password: "), true);
            let user = User::create(&username, &password);
            println!(
                "The fingerprint of your pgp key is {}",
                user.cert.fingerprint()
            );
        }
    }
}
