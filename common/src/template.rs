//! Jinja templates given to a daemon as text at runtime - `router`'s BIRD config, `nftables`'s
//! ruleset - rather than compiled into it, so that changing what a daemon writes is a config
//! change and not a release.

use anyhow::{Context, Result};
use minijinja::syntax::SyntaxConfig;
use minijinja::value::Serde;
use minijinja::{AutoEscape, Environment, UndefinedBehavior};
use serde::Serialize;
use std::collections::BTreeSet;

const NAME: &str = "template";

/// One compiled template whose every variable is known to its daemon.
pub struct Template {
    env: Environment<'static>,
}

impl Template {
    /// Compiles `source`, refusing one that reads a variable outside `known`.
    ///
    /// The check is over the text, not over one rendering: a misspelled name inside a branch the
    /// node at hand never takes is still an error here, rather than on the node that does take it.
    pub fn new(source: impl Into<String>, known: &[&str]) -> Result<Self> {
        let mut env = Environment::new();
        // Strict, so that a value the daemon failed to supply is an error rather than an empty
        // string in a config file that then loads with a hole in it.
        env.set_undefined_behavior(UndefinedBehavior::Strict);
        // The output is BIRD or nft syntax, not HTML.
        env.set_auto_escape_callback(|_| AutoEscape::None);
        // The text is the file, verbatim apart from its tags - final newline included.
        env.set_syntax(
            SyntaxConfig::builder()
                .keep_trailing_newline(true)
                .build()?,
        );
        env.add_template_owned(NAME, source.into())
            .context("the template does not compile")?;

        let template = Self { env };
        let unknown: Vec<String> = template
            .variables()
            .into_iter()
            .filter(|name| !known.contains(&name.as_str()))
            .collect();
        anyhow::ensure!(
            unknown.is_empty(),
            "the template reads {unknown:?}, which this daemon does not supply (it supplies \
             {known:?})"
        );
        Ok(template)
    }

    /// The variables the template reads, builtin functions such as `range` excepted - so a
    /// daemon can resolve only the values a template actually uses.
    pub fn variables(&self) -> BTreeSet<String> {
        let builtins: BTreeSet<&str> = self.env.globals().map(|(name, _)| name).collect();
        self.env
            .get_template(NAME)
            .map(|t| t.undeclared_variables(false))
            .unwrap_or_default()
            .into_iter()
            .filter(|name| !builtins.contains(name.as_str()))
            .collect()
    }

    pub fn render(&self, context: impl Serialize) -> Result<String> {
        self.env
            .get_template(NAME)?
            .render(Serde(context))
            .context("rendering the template")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn context(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn keeps_the_text_around_the_variables_verbatim() {
        let source = "table inet t {\n  # \"quoted\" <tag> & co\n  iifname \"{{ i }}\"\n}\n";
        let t = Template::new(source, &["i"]).unwrap();
        assert_eq!(
            t.render(context(&[("i", "eth0")])).unwrap(),
            "table inet t {\n  # \"quoted\" <tag> & co\n  iifname \"eth0\"\n}\n"
        );
    }

    #[test]
    fn does_not_escape_values() {
        let t = Template::new("{{ v }}", &["v"]).unwrap();
        assert_eq!(t.render(context(&[("v", "\"<&>\"")])).unwrap(), "\"<&>\"");
    }

    #[test]
    fn rejects_an_unknown_variable_even_in_a_branch_that_would_not_run() {
        let err = Template::new("{% if false %}{{ typo }}{% endif %}", &["known"])
            .err()
            .unwrap();
        assert!(format!("{err:#}").contains("typo"), "{err:#}");
    }

    #[test]
    fn accepts_builtin_functions_as_variables() {
        assert!(Template::new("{% for i in range(2) %}{{ i }}{% endfor %}", &[]).is_ok());
    }

    #[test]
    fn variables_are_the_known_names_the_template_reads() {
        let t = Template::new(
            "{{ a }}{% for x in b %}{{ x }}{% endfor %}",
            &["a", "b", "c"],
        )
        .unwrap();
        assert_eq!(
            t.variables(),
            BTreeSet::from(["a".to_string(), "b".to_string()])
        );
    }

    #[test]
    fn rendering_without_a_value_the_template_reads_is_an_error() {
        let t = Template::new("{{ a }}", &["a"]).unwrap();
        assert!(t.render(context(&[])).is_err());
    }
}
