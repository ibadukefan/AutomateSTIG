//! Bounded, pure predicate evaluation over already-collected adapter observations.
//!
//! The predicate language deliberately has no transport, process, file, shell, or
//! network primitive. A program selects one value already present in `SystemData`,
//! parses it into a bounded document, and evaluates a versioned boolean AST.

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fmt;

use super::SystemData;

pub const PREDICATE_SCHEMA_VERSION: u16 = 1;
const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_AST_DEPTH: usize = 16;
const MAX_AST_NODES: usize = 256;
const MAX_CHILDREN: usize = 64;
const MAX_SET_VALUES: usize = 128;
const MAX_STRING_BYTES: usize = 1_024;
const MAX_POINTER_BYTES: usize = 512;
const MAX_POINTER_SEGMENTS: usize = 16;
const MAX_DOCUMENT_DEPTH: usize = 24;
const MAX_DOCUMENT_NODES: usize = 16_384;
const MAX_ROWS: usize = 4_096;
const MAX_COLUMNS: usize = 128;
const MAX_LINE_BYTES: usize = 4_096;
const MAX_SAFE_NUMBER: f64 = 9_007_199_254_740_991.0;
const MAX_EVALUATION_STEPS: usize = 100_000;

/// JSON decoder that rejects duplicate members at every depth. Accepting the
/// final duplicate could let the scanner and an independent reviewer evaluate
/// different values from the same evidence bytes.
struct UniqueJsonValue(Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct UniqueValueVisitor;

        impl<'de> Visitor<'de> for UniqueValueVisitor {
            type Value = UniqueJsonValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON without duplicate object member names")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .map(UniqueJsonValue)
                    .ok_or_else(|| de::Error::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::String(value.to_string())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::String(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Null))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                UniqueJsonValue::deserialize(deserializer)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<UniqueJsonValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueJsonValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = Map::new();
                while let Some(key) = object.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom(format!(
                            "duplicate JSON member name: {key}"
                        )));
                    }
                    values.insert(key, object.next_value::<UniqueJsonValue>()?.0);
                }
                Ok(UniqueJsonValue(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

/// One complete predicate program. Only schema version 1 is executable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredicateProgram {
    pub schema_version: u16,
    pub source: PredicateSource,
    pub input: PredicateInput,
    pub predicate: Predicate,
}

/// A reference to evidence that collection has already normalized.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PredicateSource {
    /// The complete operator-supplied configuration (for example, IOS-XE).
    NetworkConfig,
    /// One exact adapter observation key. This is data, not a command primitive.
    Observation { key: String },
}

/// Deterministic parsers exposed to predicate programs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PredicateInput {
    /// Preserve the observation as one JSON string value.
    Text,
    /// Parse a JSON value, then validate its complete size/depth/node budget.
    Json,
    /// Parse unique `key<separator>value` lines into one JSON object.
    KeyValue {
        separator: String,
        #[serde(default)]
        comment_prefixes: Vec<String>,
    },
    /// Parse a header plus exact-width rows into `{ "rows": [...] }`.
    DelimitedTable {
        delimiter: String,
        #[serde(default)]
        comment_prefixes: Vec<String>,
    },
    /// Parse indentation into `{ "nodes": [{text,tokens,children}, ...] }`.
    /// This provides configuration block semantics without executing config text.
    StructuredConfig {
        #[serde(default)]
        comment_prefixes: Vec<String>,
        #[serde(default)]
        block_separators: Vec<String>,
    },
}

/// A JSON-pointer selection rooted at the parsed document or current table row.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValueRef {
    #[serde(default)]
    pub scope: ValueScope,
    /// RFC 6901 JSON pointer. The empty string selects the whole scoped value.
    #[serde(default)]
    pub pointer: String,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueScope {
    #[default]
    Root,
    CurrentRow,
}

/// A selected value or bounded scalar literal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operand {
    Value { value: ValueRef },
    Literal { value: Value },
}

/// Pure boolean predicate AST.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Predicate {
    All {
        predicates: Vec<Predicate>,
    },
    Any {
        predicates: Vec<Predicate>,
    },
    Not {
        predicate: Box<Predicate>,
    },
    /// Missing and JSON-null values are absent; all other values are present.
    Present {
        value: ValueRef,
    },
    Equal {
        left: Operand,
        right: Operand,
        #[serde(default = "default_true")]
        case_sensitive: bool,
    },
    InSet {
        value: Operand,
        values: Vec<Value>,
        #[serde(default = "default_true")]
        case_sensitive: bool,
    },
    NumericRange {
        value: Operand,
        #[serde(default)]
        min: Option<f64>,
        #[serde(default)]
        max: Option<f64>,
        #[serde(default = "default_true")]
        include_min: bool,
        #[serde(default = "default_true")]
        include_max: bool,
    },
    /// Compare two values, including two fields in the same row/document.
    Ordered {
        left: Operand,
        relation: OrderedRelation,
        right: Operand,
        value_type: OrderedValueType,
    },
    /// Evaluate a row-relative predicate against every/any/no array entry.
    TableRows {
        rows: ValueRef,
        quantifier: RowQuantifier,
        predicate: Box<Predicate>,
        #[serde(default = "default_true")]
        require_nonempty: bool,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderedRelation {
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderedValueType {
    Number,
    String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowQuantifier {
    Every,
    Any,
    None,
}

fn default_true() -> bool {
    true
}

impl PredicateProgram {
    /// Validate the complete executable schema before evaluation or promotion.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != PREDICATE_SCHEMA_VERSION {
            return Err(format!(
                "unsupported predicate schema version {}; expected {}",
                self.schema_version, PREDICATE_SCHEMA_VERSION
            ));
        }
        match &self.source {
            PredicateSource::NetworkConfig => {}
            PredicateSource::Observation { key } => {
                validate_string(key, "predicate observation key")?;
            }
        }
        validate_input_schema(&self.input)?;
        let mut nodes = 0;
        validate_predicate(&self.predicate, 1, false, &mut nodes)
    }

    /// Evaluate without any I/O. Missing or malformed required evidence is an error.
    pub fn evaluate(&self, data: &SystemData) -> Result<bool, String> {
        self.validate()?;
        let raw = match &self.source {
            PredicateSource::NetworkConfig => data
                .network_config
                .as_deref()
                .ok_or_else(|| "No network config data available".to_string())?,
            PredicateSource::Observation { key } => {
                if let Some(error) = data.collection_errors.get(key) {
                    return Err(format!("Observation collection failed: {error}"));
                }
                data.command_outputs
                    .get(key)
                    .map(String::as_str)
                    .ok_or_else(|| format!("Observation not found: {key}"))?
            }
        };
        if raw.len() > MAX_INPUT_BYTES {
            return Err(format!(
                "predicate input exceeds the {MAX_INPUT_BYTES}-byte limit"
            ));
        }
        let document = parse_input(raw, &self.input)?;
        let mut document_nodes = 0;
        validate_document(&document, 1, &mut document_nodes)?;
        let mut remaining_steps = MAX_EVALUATION_STEPS;
        evaluate_predicate(&self.predicate, &document, None, &mut remaining_steps)
    }

    pub fn observation_key(&self) -> Option<&str> {
        match &self.source {
            PredicateSource::Observation { key } => Some(key),
            PredicateSource::NetworkConfig => None,
        }
    }
}

fn validate_input_schema(input: &PredicateInput) -> Result<(), String> {
    let prefixes = match input {
        PredicateInput::Text | PredicateInput::Json => return Ok(()),
        PredicateInput::KeyValue {
            separator,
            comment_prefixes,
        } => {
            validate_separator(separator, "key/value separator")?;
            comment_prefixes
        }
        PredicateInput::DelimitedTable {
            delimiter,
            comment_prefixes,
        } => {
            validate_separator(delimiter, "table delimiter")?;
            comment_prefixes
        }
        PredicateInput::StructuredConfig {
            comment_prefixes,
            block_separators,
        } => {
            validate_tokens(block_separators, "configuration block separators")?;
            comment_prefixes
        }
    };
    validate_tokens(prefixes, "comment prefixes")
}

fn validate_separator(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 8 || value.chars().any(char::is_control) {
        return Err(format!("{label} must be 1-8 non-control UTF-8 bytes"));
    }
    Ok(())
}

fn validate_tokens(values: &[String], label: &str) -> Result<(), String> {
    if values.len() > 16 {
        return Err(format!("{label} exceeds the 16-value limit"));
    }
    for value in values {
        validate_string(value, label)?;
        if value.trim().is_empty() {
            return Err(format!("{label} must not contain an empty value"));
        }
    }
    Ok(())
}

fn validate_predicate(
    predicate: &Predicate,
    depth: usize,
    in_row: bool,
    nodes: &mut usize,
) -> Result<(), String> {
    if depth > MAX_AST_DEPTH {
        return Err(format!("predicate AST exceeds depth {MAX_AST_DEPTH}"));
    }
    *nodes += 1;
    if *nodes > MAX_AST_NODES {
        return Err(format!("predicate AST exceeds {MAX_AST_NODES} nodes"));
    }
    match predicate {
        Predicate::All { predicates } | Predicate::Any { predicates } => {
            validate_children(predicates)?;
            for child in predicates {
                validate_predicate(child, depth + 1, in_row, nodes)?;
            }
        }
        Predicate::Not { predicate } => {
            validate_predicate(predicate, depth + 1, in_row, nodes)?;
        }
        Predicate::Present { value } => validate_ref(value, in_row)?,
        Predicate::Equal { left, right, .. } => {
            validate_operand(left, in_row)?;
            validate_operand(right, in_row)?;
        }
        Predicate::InSet { value, values, .. } => {
            validate_operand(value, in_row)?;
            if values.is_empty() || values.len() > MAX_SET_VALUES {
                return Err(format!(
                    "set membership requires 1-{MAX_SET_VALUES} scalar values"
                ));
            }
            for value in values {
                validate_scalar(value, "set value")?;
            }
        }
        Predicate::NumericRange {
            value, min, max, ..
        } => {
            validate_operand(value, in_row)?;
            if min.is_none() && max.is_none() {
                return Err("numeric range requires min, max, or both".to_string());
            }
            if min.is_some_and(|value| !value.is_finite() || value.abs() > MAX_SAFE_NUMBER)
                || max.is_some_and(|value| !value.is_finite() || value.abs() > MAX_SAFE_NUMBER)
            {
                return Err("numeric range bounds must be finite safe numbers".to_string());
            }
            if matches!((min, max), (Some(min), Some(max)) if min > max) {
                return Err("numeric range min must not exceed max".to_string());
            }
        }
        Predicate::Ordered { left, right, .. } => {
            validate_operand(left, in_row)?;
            validate_operand(right, in_row)?;
        }
        Predicate::TableRows {
            rows, predicate, ..
        } => {
            validate_ref(rows, in_row)?;
            validate_predicate(predicate, depth + 1, true, nodes)?;
        }
    }
    Ok(())
}

fn validate_children(predicates: &[Predicate]) -> Result<(), String> {
    if predicates.is_empty() || predicates.len() > MAX_CHILDREN {
        return Err(format!(
            "compound predicate requires 1-{MAX_CHILDREN} children"
        ));
    }
    Ok(())
}

fn validate_operand(operand: &Operand, in_row: bool) -> Result<(), String> {
    match operand {
        Operand::Value { value } => validate_ref(value, in_row),
        Operand::Literal { value } => validate_scalar(value, "predicate literal"),
    }
}

fn validate_scalar(value: &Value, label: &str) -> Result<(), String> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
        Value::String(value) => validate_string(value, label),
        Value::Array(_) | Value::Object(_) => Err(format!("{label} must be a scalar JSON value")),
    }
}

fn validate_string(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_STRING_BYTES || value.chars().any(char::is_control) {
        return Err(format!(
            "{label} must be 1-{MAX_STRING_BYTES} non-control UTF-8 bytes"
        ));
    }
    Ok(())
}

fn validate_ref(value: &ValueRef, in_row: bool) -> Result<(), String> {
    if matches!(value.scope, ValueScope::CurrentRow) && !in_row {
        return Err("current_row value reference is valid only inside table_rows".to_string());
    }
    let pointer = &value.pointer;
    if pointer.len() > MAX_POINTER_BYTES {
        return Err(format!(
            "JSON pointer exceeds the {MAX_POINTER_BYTES}-byte limit"
        ));
    }
    if pointer.is_empty() {
        return Ok(());
    }
    if !pointer.starts_with('/') {
        return Err("JSON pointer must be empty or begin with '/'".to_string());
    }
    let segments: Vec<&str> = pointer[1..].split('/').collect();
    if segments.len() > MAX_POINTER_SEGMENTS {
        return Err(format!(
            "JSON pointer exceeds {MAX_POINTER_SEGMENTS} segments"
        ));
    }
    for segment in segments {
        let bytes = segment.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'~' {
                if index + 1 >= bytes.len() || !matches!(bytes[index + 1], b'0' | b'1') {
                    return Err("JSON pointer contains an invalid '~' escape".to_string());
                }
                index += 2;
            } else {
                index += 1;
            }
        }
    }
    Ok(())
}

fn parse_input(raw: &str, input: &PredicateInput) -> Result<Value, String> {
    match input {
        PredicateInput::Text => Ok(Value::String(raw.to_string())),
        PredicateInput::Json => serde_json::from_str::<UniqueJsonValue>(raw)
            .map(|value| value.0)
            .map_err(|error| format!("invalid predicate JSON input: {error}")),
        PredicateInput::KeyValue {
            separator,
            comment_prefixes,
        } => parse_key_value(raw, separator, comment_prefixes),
        PredicateInput::DelimitedTable {
            delimiter,
            comment_prefixes,
        } => parse_delimited_table(raw, delimiter, comment_prefixes),
        PredicateInput::StructuredConfig {
            comment_prefixes,
            block_separators,
        } => parse_structured_config(raw, comment_prefixes, block_separators),
    }
}

fn filtered_lines<'a>(raw: &'a str, comment_prefixes: &[String]) -> Result<Vec<&'a str>, String> {
    let mut lines = Vec::new();
    for line in raw.lines() {
        if line.len() > MAX_LINE_BYTES {
            return Err(format!(
                "predicate input line exceeds the {MAX_LINE_BYTES}-byte limit"
            ));
        }
        let trimmed = line.trim();
        if trimmed.is_empty()
            || comment_prefixes
                .iter()
                .any(|prefix| trimmed.starts_with(prefix))
        {
            continue;
        }
        lines.push(line);
        if lines.len() > MAX_ROWS {
            return Err(format!("predicate input exceeds {MAX_ROWS} rows"));
        }
    }
    Ok(lines)
}

fn parse_key_value(
    raw: &str,
    separator: &str,
    comment_prefixes: &[String],
) -> Result<Value, String> {
    let mut object = Map::new();
    for line in filtered_lines(raw, comment_prefixes)? {
        let (key, value) = line
            .split_once(separator)
            .ok_or_else(|| "key/value input line is missing its separator".to_string())?;
        let key = key.trim();
        let value = value.trim();
        validate_string(key, "key/value field name")?;
        if object
            .insert(key.to_string(), Value::String(value.to_string()))
            .is_some()
        {
            return Err(format!("duplicate key/value field: {key}"));
        }
    }
    if object.is_empty() {
        return Err("key/value input contains no data".to_string());
    }
    Ok(Value::Object(object))
}

fn parse_delimited_table(
    raw: &str,
    delimiter: &str,
    comment_prefixes: &[String],
) -> Result<Value, String> {
    let lines = filtered_lines(raw, comment_prefixes)?;
    let header = lines
        .first()
        .ok_or_else(|| "delimited table contains no header".to_string())?;
    let headers: Vec<&str> = header.split(delimiter).map(str::trim).collect();
    if headers.is_empty() || headers.len() > MAX_COLUMNS {
        return Err(format!("delimited table requires 1-{MAX_COLUMNS} columns"));
    }
    let mut unique = std::collections::HashSet::new();
    for header in &headers {
        validate_string(header, "table header")?;
        if !unique.insert(*header) {
            return Err(format!("duplicate table header: {header}"));
        }
    }
    let mut rows = Vec::new();
    for line in &lines[1..] {
        let values: Vec<&str> = line.split(delimiter).map(str::trim).collect();
        if values.len() != headers.len() {
            return Err(format!(
                "delimited table row has {} columns; expected {}",
                values.len(),
                headers.len()
            ));
        }
        let row = headers
            .iter()
            .zip(values)
            .map(|(header, value)| ((*header).to_string(), Value::String(value.to_string())))
            .collect();
        rows.push(Value::Object(row));
    }
    Ok(serde_json::json!({ "rows": rows }))
}

#[derive(Debug)]
struct ConfigLine<'a> {
    indent: usize,
    text: &'a str,
}

fn parse_structured_config(
    raw: &str,
    comment_prefixes: &[String],
    block_separators: &[String],
) -> Result<Value, String> {
    let mut lines = Vec::new();
    for line in filtered_lines(raw, comment_prefixes)? {
        if line.contains('\t') {
            return Err("structured configuration must use spaces, not tabs".to_string());
        }
        let text = line.trim();
        if block_separators.iter().any(|separator| text == separator) {
            continue;
        }
        lines.push(ConfigLine {
            indent: line.len() - line.trim_start_matches(' ').len(),
            text,
        });
    }
    if lines.is_empty() {
        return Err("structured configuration contains no statements".to_string());
    }
    let mut index = 0;
    let nodes = parse_config_level(&lines, &mut index, lines[0].indent, 1)?;
    if index != lines.len() {
        return Err("structured configuration has inconsistent indentation".to_string());
    }
    Ok(serde_json::json!({ "nodes": nodes }))
}

fn parse_config_level(
    lines: &[ConfigLine<'_>],
    index: &mut usize,
    level_indent: usize,
    depth: usize,
) -> Result<Vec<Value>, String> {
    if depth > MAX_AST_DEPTH {
        return Err(format!(
            "structured configuration exceeds depth {MAX_AST_DEPTH}"
        ));
    }
    let mut nodes = Vec::new();
    while *index < lines.len() {
        let line = &lines[*index];
        if line.indent < level_indent {
            break;
        }
        if line.indent > level_indent {
            return Err("structured configuration indentation has no parent statement".to_string());
        }
        *index += 1;
        let child_indent = lines
            .get(*index)
            .and_then(|next| (next.indent > level_indent).then_some(next.indent));
        let children = if let Some(child_indent) = child_indent {
            parse_config_level(lines, index, child_indent, depth + 1)?
        } else {
            Vec::new()
        };
        nodes.push(serde_json::json!({
            "text": line.text,
            "tokens": line.text.split_whitespace().collect::<Vec<_>>(),
            "children": children,
        }));
    }
    Ok(nodes)
}

fn validate_document(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), String> {
    if depth > MAX_DOCUMENT_DEPTH {
        return Err(format!(
            "predicate document exceeds depth {MAX_DOCUMENT_DEPTH}"
        ));
    }
    *nodes += 1;
    if *nodes > MAX_DOCUMENT_NODES {
        return Err(format!(
            "predicate document exceeds {MAX_DOCUMENT_NODES} nodes"
        ));
    }
    match value {
        Value::String(value) if value.len() > MAX_INPUT_BYTES => {
            Err("predicate document string exceeds the input limit".to_string())
        }
        Value::Array(values) => {
            if values.len() > MAX_ROWS {
                return Err(format!(
                    "predicate document array exceeds {MAX_ROWS} entries"
                ));
            }
            for value in values {
                validate_document(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > MAX_COLUMNS {
                return Err(format!(
                    "predicate document object exceeds {MAX_COLUMNS} fields"
                ));
            }
            for (key, value) in values {
                if key.len() > MAX_STRING_BYTES {
                    return Err("predicate document field name is too long".to_string());
                }
                validate_document(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn evaluate_predicate(
    predicate: &Predicate,
    root: &Value,
    current: Option<&Value>,
    remaining_steps: &mut usize,
) -> Result<bool, String> {
    *remaining_steps = remaining_steps
        .checked_sub(1)
        .ok_or_else(|| format!("predicate evaluation exceeds {MAX_EVALUATION_STEPS} steps"))?;
    match predicate {
        Predicate::All { predicates } => {
            let mut result = true;
            for predicate in predicates {
                result &= evaluate_predicate(predicate, root, current, remaining_steps)?;
            }
            Ok(result)
        }
        Predicate::Any { predicates } => {
            let mut result = false;
            for predicate in predicates {
                result |= evaluate_predicate(predicate, root, current, remaining_steps)?;
            }
            Ok(result)
        }
        Predicate::Not { predicate } => Ok(!evaluate_predicate(
            predicate,
            root,
            current,
            remaining_steps,
        )?),
        Predicate::Present { value } => {
            Ok(resolve_ref(value, root, current).is_some_and(|value| !value.is_null()))
        }
        Predicate::Equal {
            left,
            right,
            case_sensitive,
        } => Ok(values_equal(
            resolve_operand(left, root, current)?,
            resolve_operand(right, root, current)?,
            *case_sensitive,
        )),
        Predicate::InSet {
            value,
            values,
            case_sensitive,
        } => {
            let value = resolve_operand(value, root, current)?;
            Ok(values
                .iter()
                .any(|candidate| values_equal(value, candidate, *case_sensitive)))
        }
        Predicate::NumericRange {
            value,
            min,
            max,
            include_min,
            include_max,
        } => {
            let value = numeric(resolve_operand(value, root, current)?)?;
            let above_min = min.is_none_or(|min| {
                if *include_min {
                    value >= min
                } else {
                    value > min
                }
            });
            let below_max = max.is_none_or(|max| {
                if *include_max {
                    value <= max
                } else {
                    value < max
                }
            });
            Ok(above_min && below_max)
        }
        Predicate::Ordered {
            left,
            relation,
            right,
            value_type,
        } => {
            let left = resolve_operand(left, root, current)?;
            let right = resolve_operand(right, root, current)?;
            let ordering = match value_type {
                OrderedValueType::Number => numeric(left)?.total_cmp(&numeric(right)?),
                OrderedValueType::String => string(left)?.cmp(string(right)?),
            };
            Ok(match relation {
                OrderedRelation::LessThan => ordering.is_lt(),
                OrderedRelation::LessThanOrEqual => !ordering.is_gt(),
                OrderedRelation::GreaterThan => ordering.is_gt(),
                OrderedRelation::GreaterThanOrEqual => !ordering.is_lt(),
            })
        }
        Predicate::TableRows {
            rows,
            quantifier,
            predicate,
            require_nonempty,
        } => {
            let rows = resolve_ref(rows, root, current)
                .ok_or_else(|| "table_rows selection is missing".to_string())?
                .as_array()
                .ok_or_else(|| "table_rows selection is not an array".to_string())?;
            if *require_nonempty && rows.is_empty() {
                return Ok(false);
            }
            let mut matches = Vec::with_capacity(rows.len());
            for row in rows {
                matches.push(evaluate_predicate(
                    predicate,
                    root,
                    Some(row),
                    remaining_steps,
                )?);
            }
            Ok(match quantifier {
                RowQuantifier::Every => matches.iter().all(|value| *value),
                RowQuantifier::Any => matches.iter().any(|value| *value),
                RowQuantifier::None => matches.iter().all(|value| !*value),
            })
        }
    }
}

fn resolve_ref<'a>(
    value: &ValueRef,
    root: &'a Value,
    current: Option<&'a Value>,
) -> Option<&'a Value> {
    let scoped = match value.scope {
        ValueScope::Root => root,
        ValueScope::CurrentRow => current?,
    };
    if value.pointer.is_empty() {
        Some(scoped)
    } else {
        scoped.pointer(&value.pointer)
    }
}

fn resolve_operand<'a>(
    operand: &'a Operand,
    root: &'a Value,
    current: Option<&'a Value>,
) -> Result<&'a Value, String> {
    match operand {
        Operand::Value { value } => resolve_ref(value, root, current)
            .ok_or_else(|| format!("predicate value is missing at {}", value.pointer)),
        Operand::Literal { value } => Ok(value),
    }
}

fn values_equal(left: &Value, right: &Value, case_sensitive: bool) -> bool {
    match (left, right) {
        (Value::String(left), Value::String(right)) if !case_sensitive => {
            left.to_lowercase() == right.to_lowercase()
        }
        _ => left == right,
    }
}

fn numeric(value: &Value) -> Result<f64, String> {
    let parsed = match value {
        Value::Number(value) => value.as_f64(),
        Value::String(value) => value.trim().parse::<f64>().ok(),
        _ => None,
    }
    .ok_or_else(|| "predicate value is not a finite number".to_string())?;
    if !parsed.is_finite() || parsed.abs() > MAX_SAFE_NUMBER {
        return Err("predicate value is not a finite safe number".to_string());
    }
    Ok(parsed)
}

fn string(value: &Value) -> Result<&str, String> {
    value
        .as_str()
        .ok_or_else(|| "predicate value is not a string".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Check;

    fn value(pointer: &str) -> Operand {
        Operand::Value {
            value: ValueRef {
                scope: ValueScope::CurrentRow,
                pointer: pointer.to_string(),
            },
        }
    }

    fn literal(value: Value) -> Operand {
        Operand::Literal { value }
    }

    #[test]
    fn table_predicates_cover_presence_equality_sets_ranges_order_and_cross_fields() {
        let program = PredicateProgram {
            schema_version: 1,
            source: PredicateSource::Observation {
                key: "normalized-users".to_string(),
            },
            input: PredicateInput::Json,
            predicate: Predicate::TableRows {
                rows: ValueRef {
                    scope: ValueScope::Root,
                    pointer: "/rows".to_string(),
                },
                quantifier: RowQuantifier::Every,
                require_nonempty: true,
                predicate: Box::new(Predicate::All {
                    predicates: vec![
                        Predicate::Present {
                            value: ValueRef {
                                scope: ValueScope::CurrentRow,
                                pointer: "/name".to_string(),
                            },
                        },
                        Predicate::Equal {
                            left: value("/enabled"),
                            right: literal(Value::Bool(true)),
                            case_sensitive: true,
                        },
                        Predicate::InSet {
                            value: value("/role"),
                            values: vec![
                                Value::String("admin".into()),
                                Value::String("audit".into()),
                            ],
                            case_sensitive: true,
                        },
                        Predicate::NumericRange {
                            value: value("/idle_minutes"),
                            min: Some(1.0),
                            max: Some(15.0),
                            include_min: true,
                            include_max: true,
                        },
                        Predicate::Ordered {
                            left: value("/minimum"),
                            relation: OrderedRelation::LessThanOrEqual,
                            right: value("/configured"),
                            value_type: OrderedValueType::Number,
                        },
                    ],
                }),
            },
        };
        let mut data = SystemData::default();
        data.command_outputs.insert(
            "normalized-users".into(),
            r#"{"rows":[{"name":"fallback","enabled":true,"role":"admin","idle_minutes":10,"minimum":15,"configured":15}]}"#.into(),
        );
        assert_eq!(program.evaluate(&data), Ok(true));
        data.command_outputs.insert(
            "normalized-users".into(),
            r#"{"rows":[{"name":"fallback","enabled":true,"role":"operator","idle_minutes":30,"minimum":15,"configured":8}]}"#.into(),
        );
        assert_eq!(program.evaluate(&data), Ok(false));
    }

    #[test]
    fn delimited_rows_and_structured_configuration_are_semantic() {
        let table =
            parse_delimited_table("name|enabled\ncluster-a|true\ncluster-b|true\n", "|", &[])
                .unwrap();
        assert_eq!(
            table.pointer("/rows/1/name").and_then(Value::as_str),
            Some("cluster-b")
        );

        let config = parse_structured_config(
            "line vty 0 4\n exec-timeout 10 0\n transport input ssh\n!\nend\n",
            &[],
            &["!".to_string()],
        )
        .unwrap();
        assert_eq!(
            config
                .pointer("/nodes/0/children/0/text")
                .and_then(Value::as_str),
            Some("exec-timeout 10 0")
        );

        let program = PredicateProgram {
            schema_version: 1,
            source: PredicateSource::NetworkConfig,
            input: PredicateInput::StructuredConfig {
                comment_prefixes: vec!["#".to_string()],
                block_separators: vec!["!".to_string()],
            },
            predicate: Predicate::TableRows {
                rows: ValueRef {
                    scope: ValueScope::Root,
                    pointer: "/nodes".to_string(),
                },
                quantifier: RowQuantifier::Any,
                require_nonempty: true,
                predicate: Box::new(Predicate::All {
                    predicates: vec![
                        Predicate::Equal {
                            left: value("/text"),
                            right: literal(Value::String("line vty 0 4".to_string())),
                            case_sensitive: true,
                        },
                        Predicate::TableRows {
                            rows: ValueRef {
                                scope: ValueScope::CurrentRow,
                                pointer: "/children".to_string(),
                            },
                            quantifier: RowQuantifier::Any,
                            require_nonempty: true,
                            predicate: Box::new(Predicate::Equal {
                                left: value("/text"),
                                right: literal(Value::String("transport input ssh".to_string())),
                                case_sensitive: true,
                            }),
                        },
                    ],
                }),
            },
        };
        let mut data = SystemData {
            network_config: Some(
                "line vty 0 4\n exec-timeout 10 0\n transport input ssh\n!\nend\n".to_string(),
            ),
            ..Default::default()
        };
        assert_eq!(program.evaluate(&data), Ok(true));
        data.network_config = Some("line vty 0 4\n transport input telnet\n!\nend\n".into());
        assert_eq!(program.evaluate(&data), Ok(false));
    }

    #[test]
    fn malformed_missing_empty_and_collection_error_inputs_fail_closed() {
        let program = PredicateProgram {
            schema_version: 1,
            source: PredicateSource::Observation { key: "rows".into() },
            input: PredicateInput::Json,
            predicate: Predicate::TableRows {
                rows: ValueRef {
                    scope: ValueScope::Root,
                    pointer: "/rows".into(),
                },
                quantifier: RowQuantifier::Every,
                predicate: Box::new(Predicate::Present {
                    value: ValueRef {
                        scope: ValueScope::CurrentRow,
                        pointer: "/id".into(),
                    },
                }),
                require_nonempty: true,
            },
        };
        assert!(program.evaluate(&SystemData::default()).is_err());

        let mut data = SystemData::default();
        data.command_outputs
            .insert("rows".into(), "not-json".into());
        assert!(program.evaluate(&data).is_err());
        data.command_outputs.insert(
            "rows".into(),
            r#"{"rows":[],"rows":[{"id":"ambiguous"}]}"#.into(),
        );
        assert!(program
            .evaluate(&data)
            .unwrap_err()
            .contains("duplicate JSON member name"));
        data.command_outputs
            .insert("rows".into(), r#"{"rows":[]}"#.into());
        assert_eq!(program.evaluate(&data), Ok(false));
        data.collection_errors
            .insert("rows".into(), "truncated".into());
        assert!(program.evaluate(&data).is_err());
    }

    #[test]
    fn schema_and_resource_bounds_are_rejected() {
        let mut program = PredicateProgram {
            schema_version: 2,
            source: PredicateSource::NetworkConfig,
            input: PredicateInput::Text,
            predicate: Predicate::Present {
                value: ValueRef {
                    scope: ValueScope::Root,
                    pointer: String::new(),
                },
            },
        };
        assert!(program.validate().unwrap_err().contains("schema version"));
        program.schema_version = 1;
        program.predicate = Predicate::Any {
            predicates: Vec::new(),
        };
        assert!(program.validate().unwrap_err().contains("requires 1-"));

        program.predicate = Predicate::Present {
            value: ValueRef {
                scope: ValueScope::Root,
                pointer: format!("/{}", "x/".repeat(MAX_POINTER_SEGMENTS + 1)),
            },
        };
        assert!(program.validate().unwrap_err().contains("segments"));

        program.predicate = Predicate::NumericRange {
            value: literal(Value::Number(1.into())),
            min: Some(MAX_SAFE_NUMBER * 2.0),
            max: None,
            include_min: true,
            include_max: true,
        };
        assert!(program
            .validate()
            .unwrap_err()
            .contains("finite safe numbers"));

        let repeated_rows: Vec<Value> = (0..400)
            .map(|index| serde_json::json!({"id": index}))
            .collect();
        let expensive = PredicateProgram {
            schema_version: 1,
            source: PredicateSource::Observation {
                key: "bounded-rows".to_string(),
            },
            input: PredicateInput::Json,
            predicate: Predicate::TableRows {
                rows: ValueRef {
                    scope: ValueScope::Root,
                    pointer: "/rows".to_string(),
                },
                quantifier: RowQuantifier::Every,
                require_nonempty: true,
                predicate: Box::new(Predicate::TableRows {
                    rows: ValueRef {
                        scope: ValueScope::Root,
                        pointer: "/rows".to_string(),
                    },
                    quantifier: RowQuantifier::Every,
                    require_nonempty: true,
                    predicate: Box::new(Predicate::Present {
                        value: ValueRef {
                            scope: ValueScope::CurrentRow,
                            pointer: "/id".to_string(),
                        },
                    }),
                }),
            },
        };
        let mut data = SystemData::default();
        data.command_outputs.insert(
            "bounded-rows".to_string(),
            serde_json::to_string(&serde_json::json!({"rows": repeated_rows})).unwrap(),
        );
        assert!(expensive
            .evaluate(&data)
            .unwrap_err()
            .contains("evaluation exceeds"));
    }

    #[test]
    fn no_dsl_type_exposes_an_execution_primitive() {
        let schema = serde_json::to_string(&PredicateProgram {
            schema_version: 1,
            source: PredicateSource::Observation {
                key: "normalized-key".into(),
            },
            input: PredicateInput::Text,
            predicate: Predicate::Present {
                value: ValueRef {
                    scope: ValueScope::Root,
                    pointer: String::new(),
                },
            },
        })
        .unwrap();
        for forbidden in ["shell", "command", "network", "http", "script", "process"] {
            assert!(
                !schema.contains(forbidden),
                "schema exposed {forbidden}: {schema}"
            );
        }
    }

    #[test]
    fn check_variant_round_trips_the_strict_versioned_wire_schema() {
        let value = serde_json::json!({
            "type": "predicate",
            "program": {
                "schema_version": 1,
                "source": {"type": "observation", "key": "normalized-setting"},
                "input": {"type": "key_value", "separator": "=", "comment_prefixes": ["#"]},
                "predicate": {
                    "op": "all",
                    "predicates": [
                        {"op": "present", "value": {"pointer": "/enabled"}},
                        {
                            "op": "equal",
                            "left": {"type": "value", "value": {"pointer": "/enabled"}},
                            "right": {"type": "literal", "value": "true"}
                        }
                    ]
                }
            }
        });
        let check: Check = serde_json::from_value(value).unwrap();
        let Check::Predicate { program } = check else {
            panic!("predicate wire schema parsed as the wrong check variant");
        };
        program.validate().unwrap();
        let serialized = serde_json::to_value(Check::Predicate { program }).unwrap();
        assert_eq!(serialized["type"], "predicate");
        assert_eq!(serialized["program"]["schema_version"], 1);

        let mut unknown = serialized;
        unknown["program"]["shell"] = Value::String("id".into());
        assert!(serde_json::from_value::<Check>(unknown).is_err());
    }
}
