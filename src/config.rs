use anyhow::{Context, Result};
use std::{
    env, fmt, fs,
    path::{Path, PathBuf},
    str::FromStr,
};
use totp_rs::{Algorithm, Builder, Secret, Totp};

pub const DEFAULT_DIGITS: u8 = 6;
pub const DEFAULT_PERIOD: u64 = 30;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TotpAlgorithm {
    Sha1,
    #[default]
    Sha256,
    Sha512,
}

impl fmt::Display for TotpAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        };

        formatter.write_str(name)
    }
}

impl FromStr for TotpAlgorithm {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            _ => anyhow::bail!("algorithm must be one of: sha1, sha256, sha512"),
        }
    }
}

pub struct Config {
    secret: String,
    algorithm: TotpAlgorithm,
    digits: u8,
    period: u64,
}

impl Config {
    #[cfg(test)]
    fn new(secret: String) -> Result<Self> {
        Self::with_settings(
            secret,
            TotpAlgorithm::default(),
            DEFAULT_DIGITS,
            DEFAULT_PERIOD,
        )
    }

    pub fn with_settings(
        secret: String,
        algorithm: TotpAlgorithm,
        digits: u8,
        period: u64,
    ) -> Result<Self> {
        if secret.is_empty() {
            anyhow::bail!("TOTP secret must not be empty");
        }

        Secret::try_from_base32(&secret).context("TOTP secret must be valid Base32")?;

        if !(6..=8).contains(&digits) {
            anyhow::bail!("code digits must be between 6 and 8");
        }

        if period == 0 {
            anyhow::bail!("period must be greater than zero seconds");
        }

        Ok(Self {
            secret,
            algorithm,
            digits,
            period,
        })
    }

    pub fn totp(&self) -> Result<Totp> {
        let secret = Secret::try_from_base32(&self.secret)
            .context("stored TOTP secret must be valid Base32")?;

        let algorithm = match self.algorithm {
            TotpAlgorithm::Sha1 => Algorithm::SHA1,
            TotpAlgorithm::Sha256 => Algorithm::SHA256,
            TotpAlgorithm::Sha512 => Algorithm::SHA512,
        };

        Ok(Builder::new()
            .with_algorithm(algorithm)
            .with_digits(self.digits)
            .with_step_duration(self.period)
            .with_secret(secret)
            .build_noncompliant())
    }

    pub fn from_toml(contents: &str) -> Result<Self> {
        let value: toml::Table =
            toml::from_str(contents).context("could not parse the configuration file as TOML")?;

        let secret = value
            .get("secret")
            .and_then(toml::Value::as_str)
            .context("configuration is missing a string `secret` field")?
            .to_owned();

        let algorithm = value
            .get("algorithm")
            .map(|value| {
                value
                    .as_str()
                    .context("configuration `algorithm` must be a string")?
                    .parse()
            })
            .transpose()?
            .unwrap_or_default();

        let digits = optional_integer(&value, "digits")?
            .map(|value| u8::try_from(value).context("configuration `digits` is out of range"))
            .transpose()?
            .unwrap_or(DEFAULT_DIGITS);

        let period = optional_integer(&value, "period")?
            .map(|value| u64::try_from(value).context("configuration `period` is out of range"))
            .transpose()?
            .unwrap_or(DEFAULT_PERIOD);

        Self::with_settings(secret, algorithm, digits, period)
    }

    pub fn to_toml(&self) -> Result<String> {
        let mut table = toml::Table::new();

        table.insert(
            "secret".to_owned(),
            toml::Value::String(self.secret.clone()),
        );
        table.insert(
            "algorithm".to_owned(),
            toml::Value::String(self.algorithm.to_string()),
        );
        table.insert(
            "digits".to_owned(),
            toml::Value::Integer(self.digits.into()),
        );
        table.insert(
            "period".to_owned(),
            toml::Value::Integer(
                self.period
                    .try_into()
                    .context("period is too large to serialize")?,
            ),
        );

        toml::to_string(&table).context("could not serialize the configuration")
    }

    pub fn write_to(&self, path: &Path) -> Result<()> {
        let contents = self.to_toml()?;

        let parent = path
            .parent()
            .context("configuration path should have a parent directory")?;

        fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("could not protect {}", parent.display()))?;
        }

        fs::write(path, contents).with_context(|| format!("could not write {}", path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("could not protect {}", path.display()))?;
        }

        Ok(())
    }

    pub fn read_from(path: &Path) -> Result<Self> {
        ensure_private_file(path)?;

        let contents = fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?;

        Self::from_toml(&contents).with_context(|| format!("could not parse {}", path.display()))
    }

    pub fn load() -> Result<Self> {
        let path = config_path()?;

        Self::read_from(&path)
            .with_context(|| format!("run `otptool setup` if {} does not exist", path.display()))
    }

    pub fn algorithm(&self) -> TotpAlgorithm {
        self.algorithm
    }

    pub fn digits(&self) -> u8 {
        self.digits
    }

    pub fn period(&self) -> u64 {
        self.period
    }
}

fn optional_integer(table: &toml::Table, name: &str) -> Result<Option<i64>> {
    table
        .get(name)
        .map(|value| {
            value
                .as_integer()
                .with_context(|| format!("configuration `{name}` must be an integer"))
        })
        .transpose()
}

#[cfg(unix)]
fn ensure_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)
        .with_context(|| format!("could not inspect {}", path.display()))?
        .permissions()
        .mode();

    if mode & 0o077 != 0 {
        anyhow::bail!(
            "{} is readable by group or other users; restrict it to mode 0600",
            path.display()
        );
    }

    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_file(_path: &Path) -> Result<()> {
    Ok(())
}

pub fn config_path() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let config_home = env::var_os("XDG_CONFIG_HOME")
            .filter(|value| std::path::Path::new(value).is_absolute())
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .context("could not determine the Linux configuration directory")?;

        Ok(config_home.join("otptool").join("otprc"))
    }

    #[cfg(target_os = "macos")]
    {
        let home = env::var_os("HOME").context("could not determine the home directory")?;

        Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("otptool")
            .join("otprc"))
    }

    #[cfg(target_os = "windows")]
    {
        let local_app_data =
            env::var_os("LOCALAPPDATA").context("could not determine Local AppData")?;

        Ok(PathBuf::from(local_app_data).join("otptool").join("otprc"))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    anyhow::bail!("otptool does not support this operating system yet")
}

pub fn remove_config() -> Result<(PathBuf, bool)> {
    let path = config_path()?;
    let removed = remove_config_from(&path)?;

    Ok((path, removed))
}

fn remove_config_from(path: &Path) -> Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("could not remove {}", path.display()));
        }
    }

    if let Some(parent) = path.parent() {
        match fs::remove_dir(parent) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("could not remove empty {}", parent.display()));
            }
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{Config, TotpAlgorithm, config_path, remove_config_from};
    use totp_rs::Algorithm;

    #[test]
    fn config_round_trips_through_toml() {
        let original =
            Config::new("JBSWY3DPEHPK3PXP".to_owned()).expect("test secret should be valid");

        let toml = original
            .to_toml()
            .expect("test configuration should serialize");
        let restored = Config::from_toml(&toml).expect("test configuration should parse");

        assert_eq!(restored.secret, original.secret);
        assert_eq!(restored.algorithm, original.algorithm);
        assert_eq!(restored.digits, original.digits);
        assert_eq!(restored.period, original.period);
    }

    #[test]
    fn old_configuration_uses_compatible_defaults() {
        let config = Config::from_toml("secret = \"JBSWY3DPEHPK3PXP\"\n")
            .expect("old configuration should remain valid");

        assert_eq!(config.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(config.digits, 6);
        assert_eq!(config.period, 30);
    }

    #[test]
    fn configured_totp_settings_are_used() {
        let config =
            Config::with_settings("JBSWY3DPEHPK3PXP".to_owned(), TotpAlgorithm::Sha1, 8, 60)
                .expect("settings should be valid");

        let totp = config.totp().expect("TOTP generator should be created");

        assert_eq!(totp.algorithm(), Algorithm::SHA1);
        assert_eq!(totp.digits(), 8);
        assert_eq!(totp.step(), 60);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn config_path_uses_application_support() {
        let path = config_path().expect("the test machine should have a home directory");

        assert!(path.ends_with("Library/Application Support/otptool/otprc"));
    }

    #[test]
    fn writes_configuration_to_a_file() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let path = directory.path().join("otprc");

        let original =
            Config::new("JBSWY3DPEHPK3PXP".to_owned()).expect("test secret should be valid");

        original
            .write_to(&path)
            .expect("configuration should be written");

        let restored = Config::read_from(&path).expect("configuration should be readable");

        assert_eq!(restored.secret, original.secret);
    }

    #[test]
    fn rejects_an_invalid_base32_secret() {
        assert!(Config::new("definitely-not-base32".to_owned()).is_err());
    }

    #[test]
    fn rejects_invalid_totp_settings() {
        let secret = "JBSWY3DPEHPK3PXP".to_owned();

        assert!(Config::with_settings(secret.clone(), TotpAlgorithm::Sha256, 5, 30).is_err());
        assert!(Config::with_settings(secret, TotpAlgorithm::Sha256, 6, 0).is_err());
    }

    #[test]
    fn generates_the_expected_totp_code() {
        let config =
            Config::new("JBSWY3DPEHPK3PXP".to_owned()).expect("test secret should be valid");

        let code = config
            .totp()
            .expect("TOTP generator should be created")
            .generate(59)
            .to_string();

        assert_eq!(code, "344551");
    }

    #[test]
    fn removes_configuration_and_its_empty_directory() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let path = directory.path().join("otptool").join("otprc");
        let parent = path
            .parent()
            .expect("configuration path should have a parent")
            .to_owned();
        let config =
            Config::new("JBSWY3DPEHPK3PXP".to_owned()).expect("test secret should be valid");

        config
            .write_to(&path)
            .expect("configuration should be written");

        assert!(remove_config_from(&path).expect("configuration should be removed"));
        assert!(!path.exists());
        assert!(!parent.exists());
    }

    #[test]
    fn removing_missing_configuration_is_idempotent() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let path = directory.path().join("otptool").join("otprc");

        assert!(!remove_config_from(&path).expect("missing configuration should be accepted"));
    }
}
