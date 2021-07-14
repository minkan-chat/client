use azuma_client::models::user;
use clap::Clap;
// use directories_next::ProjectDirs;
// use log::{debug, warn};
use rpassword;
// use toml;
use std::io::{self, Write};
// use std::{fs, path};
// use serde::Deserialize;

/// The cli of the azuma client
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
/// Login to your azuma account
struct Login {
    /// provide a username or get a prompt
    #[clap(short, long)]
    username: Option<String>,

    /// provide a password or get a prompt (be careful with shell history!)
    #[clap(short, long)]
    password: Option<String>,
}

#[derive(Clap)]
/// Register a new azuma account
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

/*const DEFAULT_CONFIG: &str = include_str!("../default_config.toml");


fn load_config_or_default() -> toml::Value {
    // use ``directories-next`` to get platform independet directories.
    let project_dir = ProjectDirs::from("chat", "azuma", "azuma_client").expect("Failed to create project dir");
    let config_file = path::Path::new(project_dir.config_dir()).join("config.toml");
    // create all parent dirs
    fs::create_dir_all(project_dir.config_dir()).expect("Failed to create project config dir");

    debug!("Reading config file");
    let config_contents = match fs::read_to_string(&config_file) {
        Ok(contents) => contents,
        Err(e) => match e.kind() {
            // If the error occurred because the file does not exist, we create it with the default values.
            io::ErrorKind::NotFound => {
                debug!("Config file does not exist, creating...");
                let contents = DEFAULT_CONFIG.to_string();
                let file = fs::File::create(&config_file);
                if file.is_ok() {
                    let mut file = file.unwrap();
                    file.write_all(DEFAULT_CONFIG.as_bytes()).expect("Failed to write default config");
                    debug!("wrote default config to {}", config_file.to_string_lossy());
                } else {
                    warn!("Failed to create config file at {}", &config_file.to_string_lossy());
                }
                // The contents in the config file are the same as our default values, so we return them and dont read again.
                contents
            },
            // If it was because some other weird error, we will at least keep the application in a functional state with the default config and warn the user about the issue.
            _ => {
                warn!("Unknown error occurred while trying to read the config file {:#?}", e.kind()); 
                DEFAULT_CONFIG.to_string()
            }
        }
    };
    let value = config_contents.parse::<toml::Value>().unwrap_or(DEFAULT_CONFIG.parse::<toml::Value>().unwrap());
    debug!("Config: {}", value);
    value
}*/

#[async_std::main]
async fn main() {
    env_logger::init();
    //load_config_or_default();

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
            azuma_client::models::User::new(&username).authenticate(password).unwrap();
        }
        SubCommand::Register(register) => {
            let username = return_value_or_ask(
                register.username,
                Some("Please type your username: "),
                false,
            );
            let password =
                return_value_or_ask(register.password, Some("Please type your password: "), true);
            let user = user::User::create(&username, &password);
            println!(
                "The fingerprint of your pgp key is {}",
                user.cert.fingerprint()
            );
        }
    }
}
