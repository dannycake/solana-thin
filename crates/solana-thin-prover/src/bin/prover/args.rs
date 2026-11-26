//! Command-line arguments: `--option value` pairs, bare `--switch`es and
//! everything else.

use std::collections::BTreeMap;

/// The arguments of one subcommand, taken apart.
pub struct Args {
    options: BTreeMap<String, Vec<String>>,
    switches: Vec<String>,
    positional: Vec<String>,
}

impl Args {
    /// Splits `args`. Only the names in `options`, which each take a value,
    /// and in `switches`, which take none, are accepted.
    pub fn parse(
        args: impl Iterator<Item = String>,
        options: &[&str],
        switches: &[&str],
    ) -> Result<Self, String> {
        let mut parsed = Self {
            options: BTreeMap::new(),
            switches: Vec::new(),
            positional: Vec::new(),
        };
        let mut args = args;
        while let Some(arg) = args.next() {
            let Some(name) = arg.strip_prefix("--") else {
                parsed.positional.push(arg);
                continue;
            };
            if switches.contains(&name) {
                parsed.switches.push(name.to_string());
            } else if options.contains(&name) {
                let value = args
                    .next()
                    .ok_or_else(|| format!("--{name} needs a value"))?;
                parsed
                    .options
                    .entry(name.to_string())
                    .or_default()
                    .push(value);
            } else {
                return Err(format!("unknown option --{name}"));
            }
        }
        Ok(parsed)
    }

    /// Whether a switch was given.
    pub fn has(&self, name: &str) -> bool {
        self.switches.iter().any(|given| given == name)
    }

    /// Every value given for an option that may repeat.
    pub fn all(&self, name: &str) -> &[String] {
        self.options.get(name).map_or(&[], Vec::as_slice)
    }

    /// The value of an option given at most once.
    pub fn optional(&self, name: &str) -> Result<Option<&str>, String> {
        match self.all(name) {
            [] => Ok(None),
            [value] => Ok(Some(value)),
            _ => Err(format!("--{name} was given more than once")),
        }
    }

    /// The value of an option that has to be given, once.
    pub fn required(&self, name: &str) -> Result<&str, String> {
        self.optional(name)?
            .ok_or_else(|| format!("--{name} is required"))
    }

    /// The value of a numeric option, if it was given.
    pub fn number<T: std::str::FromStr>(&self, name: &str) -> Result<Option<T>, String> {
        self.optional(name)?
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| format!("--{name} {value}: not a number in range"))
            })
            .transpose()
    }

    /// The arguments that are not options.
    pub fn positional(&self) -> &[String] {
        &self.positional
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Args, String> {
        Args::parse(
            args.iter().map(|a| a.to_string()),
            &["set", "rate"],
            &["prove-all"],
        )
    }

    #[test]
    fn options_switches_and_the_rest_are_told_apart() {
        let args = parse(&[
            "--set",
            "a",
            "7",
            "--prove-all",
            "--set",
            "b",
            "8",
            "--rate",
            "50",
        ])
        .unwrap();
        assert_eq!(args.all("set"), ["a", "b"]);
        assert!(args.has("prove-all") && !args.has("warmup"));
        assert_eq!(args.positional(), ["7", "8"]);
        assert_eq!(args.number::<u32>("rate"), Ok(Some(50)));
        assert_eq!(args.number::<u32>("peers"), Ok(None));
        assert_eq!(args.required("rate"), Ok("50"));
    }

    #[test]
    fn mistakes_are_reported() {
        assert_eq!(
            parse(&["--sett", "a"]).err().unwrap(),
            "unknown option --sett"
        );
        assert_eq!(parse(&["--set"]).err().unwrap(), "--set needs a value");
        let args = parse(&["--set", "a", "--set", "b", "--rate", "fast"]).unwrap();
        assert!(args.optional("set").unwrap_err().contains("more than once"));
        assert!(args
            .number::<u32>("rate")
            .unwrap_err()
            .contains("not a number"));
        assert!(parse(&[])
            .unwrap()
            .required("set")
            .unwrap_err()
            .contains("is required"));
    }
}
