mod config;
use anyhow::Context;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "otptool", version, about = "Print the current TOTP code")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[arg(short, long)]
    code: bool,

    #[arg(short = 'C', long)]
    copy: bool,
}

#[derive(Subcommand)]
enum Command {
    Setup,
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
