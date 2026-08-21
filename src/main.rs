mod config;
use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use std::{
    fmt::Display,
    io::{self, Write},
    path::Path,
    str::FromStr,
};

#[derive(Parser)]
#[command(
    name = "otptool",
    version,
    about = "Print and copy the current TOTP code",
    after_help = "Examples:\n  otptool              Print the code and remaining lifetime\n  otptool --code       Print only the code for scripts and pipes\n  otptool --copy       Copy the code and print the normal output\n  otptool -cC          Copy the code and print only the code\n  otptool setup        Configure the secret and TOTP settings\n  otptool info         Show the non-secret TOTP settings\n  otptool uninstall    Remove the saved configuration and secret"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Print only the TOTP code, without the expiry time.
    #[arg(short, long)]
    code: bool,

    /// Copy the current TOTP code to the clipboard.
    #[arg(short = 'C', long)]
    copy: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Securely prompt for and save the TOTP secret and settings.
    Setup {
        /// HMAC algorithm used to generate codes.
        #[arg(long, value_enum)]
        algorithm: Option<AlgorithmArg>,

        /// Number of digits in each TOTP code (6 to 8).
        #[arg(long, value_parser = parse_digits)]
        digits: Option<u8>,

        /// Number of seconds each TOTP code remains valid.
        #[arg(long, value_parser = parse_period)]
        period: Option<u64>,

        /// Replace an existing configuration and secret.
        #[arg(short, long)]
        force: bool,
    },
    /// Show the configured algorithm, code digits, period, and file path.
    Info,
    /// Permanently remove the saved configuration and TOTP secret.
    Uninstall {
        /// Skip the interactive confirmation prompt.
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum AlgorithmArg {
    Sha1,
    Sha256,
    Sha512,
}

impl From<AlgorithmArg> for config::TotpAlgorithm {
    fn from(value: AlgorithmArg) -> Self {
        match value {
            AlgorithmArg::Sha1 => Self::Sha1,
            AlgorithmArg::Sha256 => Self::Sha256,
            AlgorithmArg::Sha512 => Self::Sha512,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Setup {
            algorithm,
            digits,
            period,
            force,
        }) => {
            let path = config::config_path()?;

            if path.exists() && !force {
                anyhow::bail!(
                    "configuration already exists at {}; use `otptool setup --force` to replace it",
                    path.display()
                );
            }

            let secret = rpassword::prompt_password("TOTP secret: ").context(
                "could not read the TOTP secret; run `otptool setup` in an interactive terminal",
            )?;

            let algorithm = match algorithm {
                Some(value) => value.into(),
                None => prompt_value(
                    "Algorithm (sha1/sha256/sha512)",
                    config::TotpAlgorithm::default(),
                )?,
            };
            let digits = match digits {
                Some(value) => value,
                None => prompt_value("Code digits (6-8)", config::DEFAULT_DIGITS)?,
            };
            let period = match period {
                Some(value) => value,
                None => prompt_value("Period in seconds", config::DEFAULT_PERIOD)?,
            };

            let config =
                config::Config::with_settings(secret.trim().to_owned(), algorithm, digits, period)?;

            config.write_to(&path)?;
            println!("configuration saved to {}", path.display());
        }
        Some(Command::Info) => {
            let config = config::Config::load()?;

            println!("Algorithm: {}", config.algorithm());
            println!("Code digits: {}", config.digits());
            println!("Period: {} seconds", config.period());
            println!("Config: {}", config::config_path()?.display());
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

fn prompt_value<T>(label: &str, default: T) -> anyhow::Result<T>
where
    T: Copy + Display + FromStr,
    T::Err: Display,
{
    print!("{label} [{default}]: ");
    io::stdout()
        .flush()
        .context("could not display the setup prompt")?;

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .context("could not read the setup value")?;

    let answer = answer.trim();
    if answer.is_empty() {
        return Ok(default);
    }

    answer
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid value for {label}: {error}"))
}

fn parse_digits(value: &str) -> Result<u8, String> {
    let digits = value
        .parse::<u8>()
        .map_err(|_| "code digits must be an integer from 6 through 8".to_owned())?;

    if !(6..=8).contains(&digits) {
        return Err("code digits must be from 6 through 8".to_owned());
    }

    Ok(digits)
}

fn parse_period(value: &str) -> Result<u64, String> {
    let period = value
        .parse::<u64>()
        .map_err(|_| "period must be a positive integer of seconds".to_owned())?;

    if period == 0 {
        return Err("period must be greater than zero seconds".to_owned());
    }

    Ok(period)
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
