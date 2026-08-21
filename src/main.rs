mod config;
use anyhow::Context;
use clap::{Parser, Subcommand};
use std::{
    io::{self, Write},
    path::Path,
};

#[derive(Parser)]
#[command(
    name = "otptool",
    version,
    about = "Print and copy the current TOTP code",
    after_help = "Examples:\n  otptool              Print the code and remaining lifetime\n  otptool --code       Print only the code for scripts and pipes\n  otptool --copy       Copy the code and print the normal output\n  otptool -cC          Copy the code and print only the code\n  otptool setup        Configure the TOTP secret\n  otptool uninstall    Remove the saved configuration and secret"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Print only the six-digit TOTP code, without the expiry time.
    #[arg(short, long)]
    code: bool,

    /// Copy the current TOTP code to the clipboard.
    #[arg(short = 'C', long)]
    copy: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Securely prompt for and save the TOTP secret.
    Setup,
    /// Permanently remove the saved configuration and TOTP secret.
    Uninstall {
        /// Skip the interactive confirmation prompt.
        #[arg(short, long)]
        yes: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Setup) => {
            let secret = rpassword::prompt_password("TOTP secret: ").context(
                "could not read the TOTP secret; run `otptool setup` in an interactive terminal",
            )?;

            let config = config::Config::new(secret.trim().to_owned())?;
            let path = config::config_path()?;

            if path.exists() {
                anyhow::bail!("configuration already exists at {}", path.display());
            }

            config.write_to(&path)?;
            println!("configuration saved to {}", path.display());
        }
        Some(Command::Uninstall { yes }) => {
            let path = config::config_path()?;

            if !yes && !confirm_uninstall(&path)? {
                println!("uninstall cancelled");
                return Ok(());
            }

            let (path, removed) = config::remove_config()?;

            if removed {
                println!(
                    "configuration and TOTP secret removed from {}",
                    path.display()
                );
            } else {
                println!("no configuration found at {}", path.display());
            }

            match std::env::current_exe() {
                Ok(executable) => {
                    println!("to finish uninstalling, delete {}", executable.display())
                }
                Err(_) => println!("to finish uninstalling, delete the otptool executable"),
            }
        }
        None => {
            let config = config::Config::load()?;
            let totp = config.totp()?;
            let code = totp.generate_current().to_string();

            if cli.copy {
                let mut clipboard =
                    arboard::Clipboard::new().context("could not access the clipboard")?;
                clipboard
                    .set_text(code.clone())
                    .context("could not copy the TOTP code to the clipboard")?;
            }

            if cli.code {
                println!("{code}");
            } else {
                println!("{code}");
                println!("Expires in: {} seconds", totp.ttl());
            }
        }
    }
    Ok(())
}

fn confirm_uninstall(path: &Path) -> anyhow::Result<bool> {
    print!(
        "Permanently delete the configuration and TOTP secret at {}? [y/N] ",
        path.display()
    );
    io::stdout()
        .flush()
        .context("could not display the uninstall prompt")?;

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .context("could not read the uninstall confirmation")?;

    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}
