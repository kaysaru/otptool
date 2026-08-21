use anyhow::{Context, Result};
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use totp_rs::{Algorithm, Builder, Secret, Totp};

pub struct Config {
    secret: String,
}

impl Config {
    pub fn new(secret: String) -> Result<Self> {
        if secret.is_empty() {
            anyhow::bail!("TOTP secret must not be empty");
        }

        Secret::try_from_base32(&secret).context("TOTP secret must be valid Base32")?;

        Ok(Self { secret })
    }

    pub fn totp(&self) -> Result<Totp> {
        let secret = Secret::try_from_base32(&self.secret)
            .context("stored TOTP secret must be valid Base32")?;

        Ok(Builder::new()
            .with_algorithm(Algorithm::SHA256)
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

        Self::new(secret)
    }

    pub fn to_toml(&self) -> Result<String> {
        let mut table = toml::Table::new();

        table.insert(
            "secret".to_owned(),
            toml::Value::String(self.secret.clone()),
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

        return Ok(config_home.join("otptool").join("otprc"));
    }

    #[cfg(target_os = "macos")]
    {
        let home = env::var_os("HOME").context("could not determine the home directory")?;

        return Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("otptool")
            .join("otprc"));
    }

    #[cfg(target_os = "windows")]
    {
        let local_app_data =
            env::var_os("LOCALAPPDATA").context("could not determine Local AppData")?;

        return Ok(PathBuf::from(local_app_data).join("otptool").join("otprc"));
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    anyhow::bail!("otptool does not support this operating system yet")
}

#[cfg(test)]
mod tests {
    use super::{Config, config_path};

    #[test]
    fn config_round_trips_through_toml() {
        let original =
            Config::new("JBSWY3DPEHPK3PXP".to_owned()).expect("test secret should be valid");

        let toml = original
            .to_toml()
            .expect("test configuration should serialize");
        let restored = Config::from_toml(&toml).expect("test configuration should parse");

        assert_eq!(restored.secret, original.secret);
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
}
