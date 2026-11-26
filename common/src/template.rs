//! Jinja templates given to a daemon as text at runtime - `router`'s BIRD config, `nftables`'s
//! ruleset - rather than compiled into it, so that changing what a daemon writes is a config
//! change and not a release.

use anyhow::{Context, Result};
use minijinja::syntax::SyntaxConfig;
use minijinja::value::Serde;
use minijinja::{AutoEscape, Environment, UndefinedBehavior};
use serde::{Deserialize, Serialize};
use sliplib_config::Mark;
use sliplib_config::v2::network::{Class, Lookup, Rule};
use sliplib_config::v2::{ClassName, Map};
use sliplib_yaml::Mapping;
use std::collections::BTreeSet;
use std::path::Path;

const NAME: &str = "template";

/// Reads the template at `path` and compiles it with its daemon's `compile`.
pub async fn load(
    path: &str,
    compile: impl FnOnce(String) -> Result<Template>,
) -> Result<Template> {
    let source = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read template {path}"))?;
    compile(source).with_context(|| format!("template {path} is invalid"))
}

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

/// What a template of either daemon reads besides that daemon's own values: the route classes of
/// the network and the node's `vars`, both written into the daemon's config by the generator.
#[derive(Deserialize, Serialize, Debug, Default, PartialEq)]
pub struct Values {
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub classes: Map<ClassName, Class>,
    #[serde(default, skip_serializing_if = "Mapping::is_empty")]
    pub vars: Mapping,
}

/// The template's variables of [`Values`].
pub const VALUES: [&str; 2] = ["classes", "vars"];

impl Values {
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty() && self.vars.is_empty()
    }

    /// From a daemon's config file, beside its other keys.
    pub fn read(path: &Path) -> Result<Self> {
        Ok(sliplib_yaml::read(path)?)
    }

    /// As a template sees them, marks written out in hex.
    pub fn context(&self) -> ValuesContext<'_> {
        ValuesContext {
            classes: self
                .classes
                .iter()
                .map(|(name, class)| (name.as_str(), ClassContext::of(class)))
                .collect(),
            vars: &self.vars,
        }
    }
}

#[derive(Serialize)]
pub struct ValuesContext<'a> {
    classes: Map<&'a str, ClassContext<'a>>,
    vars: &'a Mapping,
}

#[derive(Serialize)]
struct ClassContext<'a> {
    protocol: u8,
    table: Option<u8>,
    rules: Map<&'a str, RuleContext>,
}

impl<'a> ClassContext<'a> {
    fn of(class: &'a Class) -> Self {
        Self {
            protocol: class.protocol,
            table: class.table,
            rules: class
                .rules
                .iter()
                .map(|(name, rule)| (name.as_str(), RuleContext::of(rule)))
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct RuleContext {
    priority: u32,
    mark: Option<MarkContext>,
    lookup: Option<&'static str>,
}

impl RuleContext {
    fn of(rule: &Rule) -> Self {
        Self {
            priority: rule.priority,
            mark: rule.mark.map(MarkContext::of),
            lookup: rule.lookup.map(|Lookup::Main| "main"),
        }
    }
}

/// Written out as nft and `ip rule` take them.
#[derive(Serialize)]
struct MarkContext {
    value: String,
    mask: String,
    /// The bits outside the mask.
    keep: String,
}

impl MarkContext {
    fn of(mark: Mark) -> Self {
        Self {
            value: format!("{:#x}", mark.value),
            mask: format!("{:#x}", mark.mask),
            keep: format!("{:#x}", !mark.mask.get()),
        }
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
            t.render(context(&[("i", "eth0\"<&>")])).unwrap(),
            "table inet t {\n  # \"quoted\" <tag> & co\n  iifname \"eth0\"<&>\"\n}\n"
        );
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

    const GUARDED: &str = "\
{% if classes.egress is defined and classes.egress.table %}table {{ classes.egress.table }}
{% endif %}\
{% if classes.egress is defined and classes.egress.rules['uplink-replies'] is defined %}\
{% set rule = classes.egress.rules['uplink-replies'] %}\
mark {{ rule.mark.value }}/{{ rule.mark.mask }} {{ rule.mark.keep }} {{ rule.lookup }} {{ rule.priority }}
{% endif %}\
{% if vars.source is defined %}source {{ vars.source }}
{% endif %}";

    fn render_guarded(values: &Values) -> String {
        Template::new(GUARDED, &VALUES)
            .unwrap()
            .render(values.context())
            .unwrap()
    }

    #[test]
    fn a_template_reads_the_classes_and_vars_it_guards_and_skips_those_left_out() {
        assert_eq!(render_guarded(&Values::default()), "");
        let values: Values = sliplib_yaml::from_str(
            "classes:\n  egress:\n    protocol: 152\n    table: 152\n    rules:\n      \
             uplink-replies: {priority: 1000, mark: 0x100000/0x100000, lookup: main}\n\
             vars: {source: 203.0.113.0/26}\n",
        )
        .unwrap();
        assert_eq!(
            render_guarded(&values),
            "table 152\nmark 0x100000/0x100000 0xffefffff main 1000\nsource 203.0.113.0/26\n"
        );
    }

    #[test]
    fn values_are_empty_only_without_classes_and_without_vars() {
        assert!(Values::default().is_empty());
        for text in ["classes: {egress: {protocol: 152}}", "vars: {a: 1}"] {
            let values: Values = sliplib_yaml::from_str(text).unwrap();
            assert!(!values.is_empty(), "{text}");
        }
    }

    #[test]
    fn values_are_read_from_a_config_file_beside_its_other_keys() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            "bgp_as: 64512\nclasses: {egress: {protocol: 152}}\nvars: {a: 1}\n",
        )
        .unwrap();
        let values = Values::read(file.path()).unwrap();
        assert_eq!(values.classes["egress"].protocol, 152);
        assert_eq!(values.vars, sliplib_yaml::from_str("{a: 1}").unwrap());
    }

    #[test]
    fn a_mark_without_a_mask_and_a_rule_to_the_class_table_are_given_as_they_mean() {
        let values: Values = sliplib_yaml::from_str(
            "classes:\n  egress:\n    protocol: 152\n    rules:\n      \
             egress: {priority: 1001, mark: '0xff'}\n",
        )
        .unwrap();
        let template = Template::new(
            "{% set rule = classes.egress.rules.egress %}{{ classes.egress.table is none }} \
             {{ rule.mark.value }}/{{ rule.mark.mask }} {{ rule.mark.keep }} \
             {{ rule.lookup is none }} {{ classes.egress.protocol }}",
            &VALUES,
        )
        .unwrap();
        assert_eq!(
            template.render(values.context()).unwrap(),
            "True 0xff/0xffffffff 0x0 True 152"
        );
    }

    #[test]
    fn rendering_without_a_value_the_template_reads_is_an_error() {
        let t = Template::new("{{ a }}", &["a"]).unwrap();
        assert!(t.render(context(&[])).is_err());
    }
}
