//! Command-line arguments: `--flag value` pairs and bare paths.

use std::collections::BTreeMap;

/// The arguments of one subcommand, taken apart.
pub struct Args {
    flags: BTreeMap<String, Vec<String>>,
    positional: Vec<String>,
}

impl Args {
    /// Splits `args`. Only the flags named in `known` are accepted, and each
    /// takes one value.
    pub fn parse(args: impl Iterator<Item = String>, known: &[&str]) -> Result<Self, String> {
        let mut flags: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut positional = Vec::new();
        let mut args = args;
        while let Some(arg) = args.next() {
            let Some(name) = arg.strip_prefix("--") else {
                positional.push(arg);
                continue;
            };
            if !known.contains(&name) {
                return Err(format!("unknown option --{name}"));
            }
            let value = args
                .next()
                .ok_or_else(|| format!("--{name} needs a value"))?;
            flags.entry(name.to_string()).or_default().push(value);
        }
        Ok(Self { flags, positional })
    }

    /// Every value given for a flag that may repeat.
    pub fn all(&self, name: &str) -> &[String] {
        self.flags.get(name).map_or(&[], Vec::as_slice)
    }

    /// The value of a flag given at most once.
    pub fn optional(&self, name: &str) -> Result<Option<&str>, String> {
        match self.all(name) {
            [] => Ok(None),
            [value] => Ok(Some(value)),
            _ => Err(format!("--{name} was given more than once")),
        }
    }

    /// The value of a flag that has to be given, once.
    pub fn required(&self, name: &str) -> Result<&str, String> {
        self.optional(name)?
            .ok_or_else(|| format!("--{name} is required"))
    }

    /// A required flag whose value is a number.
    pub fn number<T: std::str::FromStr>(&self, name: &str) -> Result<T, String> {
        let value = self.required(name)?;
        value
            .parse()
            .map_err(|_| format!("--{name} {value}: not a number in range"))
    }

    /// The arguments that are not flags.
    pub fn positional(&self) -> &[String] {
        &self.positional
    }

    /// Fails if any bare argument was given to a command that takes none.
    pub fn no_positional(&self) -> Result<(), String> {
        match self.positional.first() {
            None => Ok(()),
            Some(extra) => Err(format!("unexpected argument {extra:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str], known: &[&str]) -> Result<Args, String> {
        Args::parse(args.iter().map(|a| a.to_string()), known)
    }

    #[test]
    fn flags_and_paths_are_told_apart() {
        let args = parse(
            &[
                "a.json", "--quorum", "3", "b.json", "--url", "x", "--url", "y",
            ],
            &["quorum", "url"],
        )
        .unwrap();
        assert_eq!(args.positional(), ["a.json", "b.json"]);
        assert_eq!(args.number::<usize>("quorum"), Ok(3));
        assert_eq!(args.all("url"), ["x", "y"]);
        assert!(args.optional("url").is_err());
        assert!(args.no_positional().is_err());
    }

    #[test]
    fn mistakes_are_reported() {
        assert!(parse(&["--quorm", "3"], &["quorum"]).is_err());
        assert!(parse(&["--quorum"], &["quorum"]).is_err());
        let args = parse(&["--quorum", "three"], &["quorum", "epoch"]).unwrap();
        assert!(args.number::<usize>("quorum").is_err());
        assert!(args.required("epoch").is_err());
        assert_eq!(args.optional("epoch"), Ok(None));
    }
}
