# Configurable LLM Providers (Experimental)

This module provides a configuration-driven approach to LLM provider detection and parsing,
making the project more suitable for CNCF/open-source by being vendor-neutral and extensible.

## Current vs Proposed Approach

### Current (Hardcoded)
```rust
// Each provider is a separate Rust file
pub struct OpenAiProvider;
impl LlmProvider for OpenAiProvider { ... }
```
- Requires code changes for new providers
- Not extensible by users
- Maintainer bottleneck

### Proposed (Config-driven)
```yaml
providers:
  - name: openai
    hosts: ["api.openai.com"]
    paths: ["/chat/completions"]
    response:
      usage_path: "usage"
      prompt_tokens: "prompt_tokens"
      completion_tokens: "completion_tokens"
    request_extractor: "messages"
```
- Users add providers via config
- No code changes needed
- Vendor-neutral

## Architecture

```
providers/
├── mod.rs           # Module exports
├── config.rs        # Configuration types (ProviderConfig, ProviderRegistry)
├── usage.rs         # ConfigurableProvider implementation
├── request.rs       # Request text extractors (messages, contents, prompt)
└── README.md        # This file
```

## Configuration Schema

### ProviderConfig
```rust
struct ProviderConfig {
    name: String,                    // Provider name for logs/metrics
    hosts: Vec<String>,              // Host patterns to match
    paths: Vec<String>,              // Path patterns to match
    response: ResponseConfig,        // How to parse response
    request_extractor: ExtractorType // How to extract request text
}
```

### ResponseConfig
```rust
struct ResponseConfig {
    usage_path: String,        // Path to usage object (e.g., "usage", "usageMetadata")
    prompt_tokens: String,     // Field name within usage (e.g., "prompt_tokens")
    completion_tokens: String, // Field name within usage
    thoughts_tokens: Option<String>, // Optional reasoning tokens
    model_path: String,        // Path to model name from root
}
```

### Request Extractors
Built-in extractors for common patterns:
- `messages` - OpenAI/Anthropic style: `messages[].content`
- `contents` - Gemini style: `contents[].parts[].text`
- `prompt` - Simple prompt field: `prompt`
- `none` - Skip extraction

## Usage Example

```rust
use configurable_providers::{ProviderRegistry, ConfigurableProvider};

// Use defaults (OpenAI, Anthropic, Gemini)
let registry = ProviderRegistry::with_defaults();

// Or load custom config
let registry = ProviderRegistry::from_json(r#"{
    "providers": [
        {
            "name": "my-private-llm",
            "hosts": ["llm.internal.company.com"],
            "paths": ["/api/generate"],
            "response": {
                "usage_path": "metadata",
                "prompt_tokens": "input_tokens",
                "completion_tokens": "output_tokens"
            },
            "request_extractor": "messages"
        }
    ]
}"#)?;

// Find matching provider
if let Some(config) = registry.find_provider(host, path) {
    let provider = ConfigurableProvider::new(config.clone());
    if let Some(usage) = provider.parse_usage(&response_json) {
        // Got usage info!
    }
}
```

## Helm Chart Integration

```yaml
# values.yaml
llmProviders:
  # Use built-in defaults
  useDefaults: true

  # Add custom providers
  custom:
    - name: bedrock
      hosts: ["bedrock-runtime.*.amazonaws.com"]
      paths: ["/model/"]
      response:
        usage_path: "usage"
        prompt_tokens: "inputTokens"
        completion_tokens: "outputTokens"
```

## Migration Path

1. Keep current hardcoded providers as "built-in defaults"
2. Add config-driven layer on top
3. Load custom providers from environment/configmap
4. Eventually deprecate hardcoded providers

## Benefits for CNCF

- **Vendor-neutral**: No provider-specific code in core
- **Extensible**: Users add providers without PRs
- **Enterprise-friendly**: Support private/internal LLM endpoints
- **Community-driven**: Default configs can be community-maintained
