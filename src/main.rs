use azuma_client;
use clap::Clap;
use rpassword;
use std::io::{self, Write};

/// The cli of the azuma client
#[derive(Clap)]
struct Opts {
    #[clap(subcommand)]
    subcommand: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    Login(Login),
}

#[derive(Clap)]
/// Login to your azuma account
struct Login {
    /// provide a username or get a prompt
    #[clap(short, long)]
    username: Option<String>,

    /// provide a password or get a prompt (be careful with shell history!)
    #[clap(short, long)]
    password: Option<String>,
}

fn main() {
    env_logger::init();
    let opts: Opts = Opts::parse();

    // Match the given subcommand.
    match opts.subcommand {
        SubCommand::Login(login) => {
            // Check if the user has provided a username as a command line argument or else ask them to type one.
            let username = login.username.unwrap_or_else(|| {
                let mut r = String::new();
                print!("Please type your username: ");
                io::stdout().flush().unwrap();
                io::stdin()
                    .read_line(&mut r)
                    .expect("Failed to read username.");
                r.trim().to_lowercase()
            });
            println!("Username is {}", username);

            // Check if the user has provided a password as command line argument or else ask them to type one now.
            let password = login.password.unwrap_or_else(|| {
                let prompt = Some("Please type your password: ");
                rpassword::read_password_from_tty(prompt).expect("Failed to read password from TTY")
            });
            azuma_client::models::User::new(username).authenticate(password);
        }
    }
}
