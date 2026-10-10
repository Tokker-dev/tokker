//! `run_tool_loop` (issue #665): drives a [`TextModel`] through a tool
//! conversation until it answers without asking for another tool.
//!
//! The port is one request and one buffered answer; a tool conversation is
//! several. This module owns that loop so every caller gets the same shape
//! — append the assistant's requested calls, run them, feed the results
//! back, repeat — with a step budget, a token budget, and fail-closed
//! argument validation so a model cannot reach an executor with arguments
//! its tool's own schema forbids.
//!
//! The loop is also where [`TextModel::supports`] is enforced: a prompt
//! carrying [`ToolSpec`]s to a model that reports no [`Capability::Tools`]
//! is refused before the first call, not sent with its tools silently
//! dropped.
//!
//! **The schema validator is deliberately small.** JSON Schema 2020-12 is
//! enormous and no validator crate is in this workspace's tree. Tool
//! argument schemas use a narrow subset, so this module implements that
//! subset and refuses, up front, any keyword it does not implement — a
//! `$ref`, a `pattern`, an `if`. A schema this validator cannot honour is
//! an error naming the keyword, never a check silently skipped: a tool
//! that reached an executor on arguments its schema forbade would be
//! exactly the failure the schema was there to prevent.

use async_trait::async_trait;
use serde_json::{Map, Value};

use crate::ports::{
    Capability, Completion, Prompt, TextModel, TextModelError, ToolCall, ToolResult, ToolSpec, Turn,
};

/// Runs one tool call and reports its result (issue #665).
///
/// A tool-level failure is `Err(String)`, not a failed loop: the string is
/// fed back to the model as a [`ToolResult::error`], and the model may
/// recover — try again, try another tool, or answer directly.
#[async_trait]
pub trait ToolExecutor: Send + Sync {
    /// Runs `call` and returns the text to show the model.
    ///
    /// # Errors
    ///
    /// Returns the error text to feed back to the model when the tool
    /// itself fails. This is not a failure of the loop.
    async fn execute(&self, call: &ToolCall) -> Result<String, String>;
}

/// How far a tool loop may run (issue #665): a hard cap on model calls, and
/// an optional cap on the tokens those calls may spend.
///
/// `#[non_exhaustive]`: build one with [`ToolBudget::steps`] and the
/// builder method rather than a struct literal, so another limit (wall
/// clock, tool calls per step) is not a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ToolBudget {
    /// The most model calls the loop may make. A budget of `N` means at
    /// most `N` calls: the loop makes no `N+1`th, even when the `N`th still
    /// asks for a tool, and a budget of `0` makes none at all.
    pub max_steps: u32,
    /// The most input + output tokens the loop may spend in total, where a
    /// caller names one. `None` is unbounded.
    pub max_total_tokens: Option<u64>,
}

impl ToolBudget {
    /// A budget of `max_steps` model calls and no token ceiling.
    #[must_use]
    pub fn steps(max_steps: u32) -> Self {
        Self {
            max_steps,
            max_total_tokens: None,
        }
    }

    /// Caps the total input + output tokens the loop may spend.
    #[must_use]
    pub fn max_total_tokens(mut self, max_total_tokens: u64) -> Self {
        self.max_total_tokens = Some(max_total_tokens);
        self
    }
}

/// The usage of one model call inside a tool loop (issue #665): the same
/// three token fields [`Completion`] reports, plus how many tool calls that
/// step's completion asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// The subset of [`StepUsage::input_tokens`] served from the provider's
    /// prompt cache, where it reported one — the same optional fact
    /// [`Completion::cached_input_tokens`] carries, never collapsed.
    pub cached_input_tokens: Option<u64>,
    /// How many tool calls this step's completion asked for.
    pub tool_calls: usize,
}

/// What a finished tool loop produced (issue #665).
#[derive(Debug, Clone, PartialEq)]
pub struct ToolLoopOutcome {
    /// The final completion — the one that asked for no tool.
    pub completion: Completion,
    /// The transcript the loop built: the prompt's own turns, then one
    /// assistant turn carrying each round's requested calls and one user
    /// turn carrying their results. The final answer lives in
    /// [`ToolLoopOutcome::completion`] and is not duplicated here.
    pub messages: Vec<Turn>,
    /// One entry per model call, in order.
    pub steps: Vec<StepUsage>,
}

impl ToolLoopOutcome {
    /// The sum of every step's input tokens.
    #[must_use]
    pub fn input_tokens(&self) -> u64 {
        self.steps.iter().map(|step| step.input_tokens).sum()
    }

    /// The sum of every step's output tokens.
    #[must_use]
    pub fn output_tokens(&self) -> u64 {
        self.steps.iter().map(|step| step.output_tokens).sum()
    }
}

/// Why a tool loop stopped without a usable answer (issue #665).
///
/// `#[non_exhaustive]`: the loop is new and its failure set will grow.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ToolLoopError {
    /// The model failed. The wrapped error's own `Display` already scrubs
    /// any provider text.
    Model(TextModelError),
    /// The model kept asking for tools and the step budget ran out. The
    /// steps recorded so far are kept so a caller can cost or log work
    /// that led nowhere.
    StepBudgetExhausted { steps: Vec<StepUsage> },
    /// The model's calls spent more input + output tokens than the budget
    /// allowed. `used` is the cumulative total that crossed the limit.
    TokenBudgetExhausted { used: u64, steps: Vec<StepUsage> },
    /// A tool's `parameters` schema could not be honoured: it used a
    /// keyword this validator does not implement (a `$ref`, a `pattern`,
    /// an `if`) or was malformed. Nothing was called.
    InvalidToolSchema { tool: String, reason: String },
}

impl std::fmt::Display for ToolLoopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scrub = crate::logging::scrub_text;
        match self {
            Self::Model(error) => write!(f, "the text model failed: {error}"),
            Self::StepBudgetExhausted { steps } => write!(
                f,
                "the tool loop exhausted its step budget after {} model calls",
                steps.len()
            ),
            Self::TokenBudgetExhausted { used, steps } => write!(
                f,
                "the tool loop spent {used} tokens over {} model calls, past its token budget",
                steps.len()
            ),
            Self::InvalidToolSchema { tool, reason } => write!(
                f,
                "tool {tool:?} has an invalid argument schema: {}",
                scrub(reason)
            ),
        }
    }
}

impl std::error::Error for ToolLoopError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Model(error) => Some(error),
            _ => None,
        }
    }
}

/// Runs `prompt` to completion through `model`, running any tool calls with
/// `executor`, within `budget` (issue #665).
///
/// Every offered tool's `parameters` schema is validated before the first
/// model call, and every call's arguments are validated against its tool's
/// schema before any executor sees them — a call with arguments that are
/// not a JSON object, or that do not conform, becomes an error
/// [`ToolResult`] the model is shown, never an execution.
///
/// # Errors
///
/// - [`ToolLoopError::Model`] if the model is asked to carry tools it does
///   not support, or a call to it fails.
/// - [`ToolLoopError::InvalidToolSchema`] if an offered tool's schema uses
///   a keyword this validator cannot honour; the check runs before the
///   first model call.
/// - [`ToolLoopError::StepBudgetExhausted`] if the loop would make more
///   than [`ToolBudget::max_steps`] calls — including a budget of `0`,
///   which makes no call at all.
/// - [`ToolLoopError::TokenBudgetExhausted`] if a completion that still asks
///   for a tool carries the cumulative input + output tokens past
///   [`ToolBudget::max_total_tokens`]; the tools are not run. A completion
///   with no tool calls is the final answer and is returned whatever it
///   cost.
pub async fn run_tool_loop(
    model: &dyn TextModel,
    mut prompt: Prompt,
    executor: &dyn ToolExecutor,
    budget: ToolBudget,
) -> Result<ToolLoopOutcome, ToolLoopError> {
    // Refuse up front rather than send a tools-bearing prompt a model will
    // drop the tools from and then answer as if none were offered. The
    // tier is the prompt's own: the router answers for the tier it would
    // route this prompt to.
    if !prompt.tools.is_empty() && !model.supports(prompt.tier, Capability::Tools) {
        return Err(ToolLoopError::Model(TextModelError::Unsupported(
            Capability::Tools,
        )));
    }
    for tool in &prompt.tools {
        validate_tool_schema(&tool.name, &tool.parameters)?;
    }

    let mut steps: Vec<StepUsage> = Vec::new();
    let mut step_count: u32 = 0;
    let mut used_tokens: u64 = 0;

    loop {
        // A budget of N means at most N calls. The check is here, before
        // the call, so a budget of 0 makes none — not one — and even a
        // model that would keep asking for tools never reaches an N+1th.
        if step_count >= budget.max_steps {
            return Err(ToolLoopError::StepBudgetExhausted { steps });
        }

        let completion = model
            .complete(&prompt)
            .await
            .map_err(ToolLoopError::Model)?;
        step_count += 1;
        steps.push(StepUsage {
            input_tokens: completion.input_tokens,
            output_tokens: completion.output_tokens,
            cached_input_tokens: completion.cached_input_tokens,
            tool_calls: completion.tool_calls.len(),
        });
        used_tokens = used_tokens.saturating_add(
            completion
                .input_tokens
                .saturating_add(completion.output_tokens),
        );

        // An answer with no tool calls is the loop's end, and it is
        // returned whatever it cost: it has already been paid for, and
        // discarding it would spend the tokens and hand back nothing. The
        // budget is a ceiling on work yet to do, not on the last step.
        if completion.tool_calls.is_empty() {
            return Ok(ToolLoopOutcome {
                completion,
                messages: prompt.messages,
                steps,
            });
        }

        // Past the ceiling with tools still to run: stop here, before the
        // executor is asked for anything, rather than spend more on a loop
        // the caller capped.
        if let Some(limit) = budget.max_total_tokens
            && used_tokens > limit
        {
            return Err(ToolLoopError::TokenBudgetExhausted {
                used: used_tokens,
                steps,
            });
        }

        let mut results = Vec::with_capacity(completion.tool_calls.len());
        for call in &completion.tool_calls {
            results.push(execute_call(&prompt.tools, executor, call).await);
        }
        prompt.messages.push(Turn::assistant_tool_calls(
            completion.text,
            completion.tool_calls,
        ));
        prompt.messages.push(Turn::tool_results(results));
    }
}

/// Runs one call, or turns it into an error [`ToolResult`] the model can
/// read: an unknown tool name, arguments that are not a JSON object, or
/// arguments its tool's schema forbids, is fed back rather than run.
async fn execute_call(
    tools: &[ToolSpec],
    executor: &dyn ToolExecutor,
    call: &ToolCall,
) -> ToolResult {
    let Some(spec) = tools.iter().find(|tool| tool.name == call.name) else {
        return ToolResult::error(
            call.id.clone(),
            format!("no tool named {:?} was offered", call.name),
        );
    };
    // Tool arguments are an object, full stop. A schema that names no
    // top-level `type` — `{"properties": {...}, "required": [...]}`, the
    // common shape — asserts nothing about a non-object, so the check has
    // to be here rather than inside `validate_instance`, which must stay
    // spec-correct for the nested subschemas it is also handed. An
    // adapter's unparsable arguments arrive as a `Value::String`, and a
    // bare string must never reach an executor.
    if !call.arguments.is_object() {
        return ToolResult::error(
            call.id.clone(),
            format!("arguments for tool {:?} must be a JSON object", call.name),
        );
    }
    if let Err(violation) = validate_instance(&spec.parameters, &call.arguments) {
        return ToolResult::error(
            call.id.clone(),
            format!("arguments do not match tool {:?}: {violation}", call.name),
        );
    }
    match executor.execute(call).await {
        Ok(content) => ToolResult::ok(call.id.clone(), content),
        Err(message) => ToolResult::error(call.id.clone(), message),
    }
}

/// Keywords that describe a schema rather than assert anything about an
/// instance. JSON Schema 2020-12 treats `format` as an annotation by
/// default; the rest are metadata with no validation meaning here.
const ANNOTATIONS: &[&str] = &[
    "title",
    "description",
    "default",
    "examples",
    "$schema",
    "$id",
    "$comment",
    "format",
];

/// The primitive type names JSON Schema's `type` keyword allows.
const TYPE_NAMES: &[&str] = &[
    "object", "array", "string", "number", "integer", "boolean", "null",
];

fn invalid_schema(tool: &str, reason: impl Into<String>) -> ToolLoopError {
    ToolLoopError::InvalidToolSchema {
        tool: tool.to_owned(),
        reason: reason.into(),
    }
}

/// Validates one tool's `parameters` schema, up front and fail-closed: a
/// keyword this validator does not implement is an error naming it, never a
/// check silently skipped. Recurses into every subschema.
fn validate_tool_schema(tool: &str, schema: &Value) -> Result<(), ToolLoopError> {
    let Some(object) = schema.as_object() else {
        return Err(invalid_schema(tool, "the schema is not a JSON object"));
    };
    for (keyword, value) in object {
        match keyword.as_str() {
            "type" => check_type_keyword(tool, value)?,
            "properties" => check_properties(tool, value)?,
            "required" => check_required(tool, value)?,
            "additionalProperties" => check_additional_properties(tool, value)?,
            "items" => validate_tool_schema(tool, value)?,
            "enum" => {
                if !value.is_array() {
                    return Err(invalid_schema(tool, "`enum` must be an array"));
                }
            }
            "const" => {}
            "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" => {
                if !value.is_number() {
                    return Err(invalid_schema(
                        tool,
                        format!("`{keyword}` must be a number"),
                    ));
                }
            }
            "minLength" | "maxLength" | "minItems" | "maxItems" => {
                if value.as_u64().is_none() {
                    return Err(invalid_schema(
                        tool,
                        format!("`{keyword}` must be a non-negative integer"),
                    ));
                }
            }
            "anyOf" | "oneOf" | "allOf" => check_schema_list(tool, keyword, value)?,
            other if ANNOTATIONS.contains(&other) => {}
            other => {
                return Err(invalid_schema(
                    tool,
                    format!("the `{other}` keyword is not supported"),
                ));
            }
        }
    }
    Ok(())
}

fn check_type_keyword(tool: &str, value: &Value) -> Result<(), ToolLoopError> {
    let names: Vec<&str> = match value {
        Value::String(name) => vec![name.as_str()],
        Value::Array(items) => {
            if !items.iter().all(Value::is_string) {
                return Err(invalid_schema(
                    tool,
                    "`type` must name strings when given as an array",
                ));
            }
            items.iter().filter_map(Value::as_str).collect()
        }
        _ => {
            return Err(invalid_schema(
                tool,
                "`type` must be a string or an array of strings",
            ));
        }
    };
    if names.is_empty() || !names.iter().all(|name| TYPE_NAMES.contains(name)) {
        return Err(invalid_schema(tool, "`type` names an unknown JSON type"));
    }
    Ok(())
}

fn check_properties(tool: &str, value: &Value) -> Result<(), ToolLoopError> {
    let Some(properties) = value.as_object() else {
        return Err(invalid_schema(tool, "`properties` must be an object"));
    };
    for subschema in properties.values() {
        validate_tool_schema(tool, subschema)?;
    }
    Ok(())
}

fn check_required(tool: &str, value: &Value) -> Result<(), ToolLoopError> {
    let Some(names) = value.as_array() else {
        return Err(invalid_schema(tool, "`required` must be an array"));
    };
    if !names.iter().all(Value::is_string) {
        return Err(invalid_schema(tool, "`required` must name strings"));
    }
    Ok(())
}

fn check_additional_properties(tool: &str, value: &Value) -> Result<(), ToolLoopError> {
    match value {
        Value::Bool(_) => Ok(()),
        Value::Object(_) => validate_tool_schema(tool, value),
        _ => Err(invalid_schema(
            tool,
            "`additionalProperties` must be a boolean or a schema",
        )),
    }
}

fn check_schema_list(tool: &str, keyword: &str, value: &Value) -> Result<(), ToolLoopError> {
    let Some(schemas) = value.as_array() else {
        return Err(invalid_schema(
            tool,
            format!("`{keyword}` must be an array of schemas"),
        ));
    };
    if schemas.is_empty() {
        return Err(invalid_schema(
            tool,
            format!("`{keyword}` must not be empty"),
        ));
    }
    for subschema in schemas {
        validate_tool_schema(tool, subschema)?;
    }
    Ok(())
}

/// Validates `instance` against a schema already accepted by
/// [`validate_tool_schema`], returning the first violation it finds.
fn validate_instance(schema: &Value, instance: &Value) -> Result<(), String> {
    let Some(object) = schema.as_object() else {
        return Err("the schema is not an object".to_owned());
    };

    // Combinators first: a value failing `allOf`/`oneOf`/`anyOf` is
    // rejected whatever the rest of the schema says.
    if let Some(subschemas) = object.get("allOf").and_then(Value::as_array) {
        for subschema in subschemas {
            validate_instance(subschema, instance)?;
        }
    }
    if let Some(subschemas) = object.get("anyOf").and_then(Value::as_array)
        && !subschemas
            .iter()
            .any(|subschema| validate_instance(subschema, instance).is_ok())
    {
        return Err("the value matches none of the `anyOf` schemas".to_owned());
    }
    if let Some(subschemas) = object.get("oneOf").and_then(Value::as_array) {
        let matches = subschemas
            .iter()
            .filter(|subschema| validate_instance(subschema, instance).is_ok())
            .count();
        if matches != 1 {
            return Err(format!(
                "the value matches {matches} of the `oneOf` schemas, not exactly one"
            ));
        }
    }

    if let Some(constant) = object.get("const")
        && constant != instance
    {
        return Err("the value is not the required `const`".to_owned());
    }
    if let Some(allowed) = object.get("enum").and_then(Value::as_array)
        && !allowed.contains(instance)
    {
        return Err("the value is none of the `enum` values".to_owned());
    }
    if let Some(type_keyword) = object.get("type")
        && !matches_type(type_keyword, instance)
    {
        return Err("the value is not of the declared `type`".to_owned());
    }

    check_number_bounds(object, instance)?;
    check_string_bounds(object, instance)?;
    check_array_bounds(object, instance)?;
    check_object_shape(object, instance)
}

fn check_number_bounds(object: &Map<String, Value>, instance: &Value) -> Result<(), String> {
    let Some(number) = instance.as_f64() else {
        return Ok(());
    };
    if let Some(minimum) = object.get("minimum").and_then(Value::as_f64)
        && number < minimum
    {
        return Err(format!(
            "the value {number} is below the `minimum` {minimum}"
        ));
    }
    if let Some(minimum) = object.get("exclusiveMinimum").and_then(Value::as_f64)
        && number <= minimum
    {
        return Err(format!(
            "the value {number} is not above the `exclusiveMinimum` {minimum}"
        ));
    }
    if let Some(maximum) = object.get("maximum").and_then(Value::as_f64)
        && number > maximum
    {
        return Err(format!(
            "the value {number} is above the `maximum` {maximum}"
        ));
    }
    if let Some(maximum) = object.get("exclusiveMaximum").and_then(Value::as_f64)
        && number >= maximum
    {
        return Err(format!(
            "the value {number} is not below the `exclusiveMaximum` {maximum}"
        ));
    }
    Ok(())
}

fn check_string_bounds(object: &Map<String, Value>, instance: &Value) -> Result<(), String> {
    let Some(text) = instance.as_str() else {
        return Ok(());
    };
    // Length is counted in characters, as JSON Schema defines it.
    let length = u64::try_from(text.chars().count()).unwrap_or(u64::MAX);
    if let Some(minimum) = object.get("minLength").and_then(Value::as_u64)
        && length < minimum
    {
        return Err(format!("the string is shorter than `minLength` {minimum}"));
    }
    if let Some(maximum) = object.get("maxLength").and_then(Value::as_u64)
        && length > maximum
    {
        return Err(format!("the string is longer than `maxLength` {maximum}"));
    }
    Ok(())
}

fn check_array_bounds(object: &Map<String, Value>, instance: &Value) -> Result<(), String> {
    let Some(items) = instance.as_array() else {
        return Ok(());
    };
    let length = u64::try_from(items.len()).unwrap_or(u64::MAX);
    if let Some(minimum) = object.get("minItems").and_then(Value::as_u64)
        && length < minimum
    {
        return Err(format!("the array has fewer than `minItems` {minimum}"));
    }
    if let Some(maximum) = object.get("maxItems").and_then(Value::as_u64)
        && length > maximum
    {
        return Err(format!("the array has more than `maxItems` {maximum}"));
    }
    if let Some(item_schema) = object.get("items") {
        for item in items {
            validate_instance(item_schema, item)
                .map_err(|reason| format!("an array item is invalid: {reason}"))?;
        }
    }
    Ok(())
}

fn check_object_shape(object: &Map<String, Value>, instance: &Value) -> Result<(), String> {
    let Some(fields) = instance.as_object() else {
        return Ok(());
    };
    if let Some(required) = object.get("required").and_then(Value::as_array) {
        for name in required.iter().filter_map(Value::as_str) {
            if !fields.contains_key(name) {
                return Err(format!("the required property {name:?} is missing"));
            }
        }
    }
    let properties = object.get("properties").and_then(Value::as_object);
    let additional = object.get("additionalProperties");
    for (key, field) in fields {
        if let Some(property_schema) = properties.and_then(|properties| properties.get(key)) {
            validate_instance(property_schema, field)
                .map_err(|reason| format!("the property {key:?} is invalid: {reason}"))?;
            continue;
        }
        match additional {
            Some(Value::Bool(false)) => {
                return Err(format!(
                    "the property {key:?} is not allowed by `additionalProperties`"
                ));
            }
            Some(schema @ Value::Object(_)) => {
                validate_instance(schema, field).map_err(|reason| {
                    format!("the additional property {key:?} is invalid: {reason}")
                })?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Whether `instance` matches the `type` keyword, a name or an array of
/// names (a value matches if it matches any of them).
fn matches_type(type_keyword: &Value, instance: &Value) -> bool {
    match type_keyword {
        Value::String(name) => matches_one_type(name, instance),
        Value::Array(names) => names.iter().any(|name| {
            name.as_str()
                .is_some_and(|name| matches_one_type(name, instance))
        }),
        _ => false,
    }
}

fn matches_one_type(name: &str, instance: &Value) -> bool {
    match name {
        "object" => instance.is_object(),
        "array" => instance.is_array(),
        "string" => instance.is_string(),
        "number" => instance.is_number(),
        "integer" => instance
            .as_f64()
            .is_some_and(|number| number.fract() == 0.0),
        "boolean" => instance.is_boolean(),
        "null" => instance.is_null(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_known_schema_is_accepted_and_an_unknown_keyword_is_named() {
        let good = json!({
            "type": "object",
            "description": "a note",
            "properties": { "q": { "type": "string", "minLength": 1 } },
            "required": ["q"],
            "additionalProperties": false,
        });
        validate_tool_schema("lookup", &good).expect("known keywords are accepted");

        let bad = json!({ "type": "object", "pattern": "^a" });
        let error = validate_tool_schema("lookup", &bad).unwrap_err();
        match error {
            ToolLoopError::InvalidToolSchema { tool, reason } => {
                assert_eq!(tool, "lookup");
                assert!(reason.contains("pattern"), "{reason}");
            }
            other => panic!("expected an invalid-schema error, got {other:?}"),
        }
    }

    #[test]
    fn a_nested_unknown_keyword_is_reached() {
        // The keyword is inside a property's schema, not at the top level:
        // the walk must recurse, or a `$ref` hides one level down.
        let schema = json!({
            "type": "object",
            "properties": { "q": { "$ref": "#/defs/thing" } },
        });
        let error = validate_tool_schema("lookup", &schema).unwrap_err();
        assert!(error.to_string().contains("$ref"), "{error}");
    }

    #[test]
    fn annotations_are_ignored_but_a_malformed_known_keyword_is_refused() {
        let annotated = json!({ "type": "string", "format": "email", "title": "Q" });
        validate_tool_schema("t", &annotated).expect("annotations are ignored");

        let malformed = json!({ "type": "list-of-things" });
        assert!(validate_tool_schema("t", &malformed).is_err());
    }

    #[test]
    fn instance_validation_covers_types_bounds_and_objects() {
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["name", "age"],
            "properties": {
                "name": { "type": "string", "minLength": 1, "maxLength": 5 },
                "age": { "type": "integer", "minimum": 0, "maximum": 120 },
                "tags": { "type": "array", "items": { "enum": ["a", "b"] } },
            },
        });
        let good = json!({ "name": "al", "age": 30, "tags": ["a"] });
        assert_eq!(validate_instance(&schema, &good), Ok(()));

        let short = json!({ "name": "", "age": 30 });
        assert!(validate_instance(&schema, &short).is_err());
        let wrong_type = json!({ "name": "al", "age": "old" });
        assert!(validate_instance(&schema, &wrong_type).is_err());
        let below = json!({ "name": "al", "age": -1 });
        assert!(validate_instance(&schema, &below).is_err());
        let extra = json!({ "name": "al", "age": 30, "extra": true });
        assert!(validate_instance(&schema, &extra).is_err());
        let bad_item = json!({ "name": "al", "age": 30, "tags": ["c"] });
        assert!(validate_instance(&schema, &bad_item).is_err());
        let missing = json!({ "name": "al" });
        assert!(validate_instance(&schema, &missing).is_err());
    }

    #[test]
    fn combinators_are_enforced() {
        let any_of = json!({ "anyOf": [{ "type": "string" }, { "type": "integer" }] });
        assert_eq!(validate_instance(&any_of, &json!("x")), Ok(()));
        assert!(validate_instance(&any_of, &json!(true)).is_err());

        let one_of = json!({ "oneOf": [{ "type": "number" }, { "type": "integer" }] });
        // 3 is both a number and an integer: `oneOf` wants exactly one.
        assert!(validate_instance(&one_of, &json!(3)).is_err());
        assert_eq!(validate_instance(&one_of, &json!(3.5)), Ok(()));

        let all_of = json!({
            "allOf": [
                { "type": "integer" },
                { "minimum": 10 },
            ],
        });
        assert!(validate_instance(&all_of, &json!(3)).is_err());
        assert_eq!(validate_instance(&all_of, &json!(12)), Ok(()));
    }

    #[test]
    fn const_and_enum_are_enforced() {
        let schema = json!({ "const": "fixed" });
        assert_eq!(validate_instance(&schema, &json!("fixed")), Ok(()));
        assert!(validate_instance(&schema, &json!("other")).is_err());

        let schema = json!({ "enum": [1, 2] });
        assert_eq!(validate_instance(&schema, &json!(2)), Ok(()));
        assert!(validate_instance(&schema, &json!(3)).is_err());
    }
}
