# Documentation

Welcome to the comprehensive documentation for `nui-lambda-shared-utils`.

**Last Updated**: 2025-01-19

## Quick Navigation

### 📚 Getting Started

- **[Installation Guide](getting-started/installation.md)** - Setup and dependency management
- **[Configuration Guide](getting-started/configuration.md)** - Environment setup and credential management
- **[Quick Start](getting-started/quickstart.md)** - Common usage patterns and examples

### 📖 Guides

Component-specific guides for major features:

- **[AWS Powertools Integration](guides/powertools-integration.md)** - Standardized logging, metrics, and error handling
- **[Lambda Context Helpers](guides/lambda-utilities.md)** - Environment info extraction for logging and metrics
- **[Slack Integration](guides/slack-integration.md)** - Messaging, formatting, and file uploads
- **[Elasticsearch Integration](guides/elasticsearch-integration.md)** - Search, bulk indexing, health checks
- **[Log Processing](guides/log-processing.md)** - Kinesis log extraction and ES index naming
- Database Connections (planned)
- Error Handling Patterns (planned)
- CloudWatch Metrics (planned)

### 🔧 CLI Tools

Command-line utilities included with the package:

- **[Slack Channel Setup](guides/cli-tools.md)** - Automate Slack workspace channel creation
- Additional CLI tools (planned)

### 📋 Reference

API reference and detailed component documentation:

- **[Shared Types & Data Structures](guides/shared-types.md)** - Core types, interfaces, and response structures
- Client APIs (planned)
- Utility Functions (planned)
- Configuration Options (planned)

### 🛠️ Development

Developer resources and contribution guidelines:

- **[Testing Guide](development/testing.md)** - Test strategies and running tests
- [Contributing](../CONTRIBUTING.md) - Development workflow
- [Changelog](../CHANGELOG.md) - Version history

### 📦 Templates

- **[Slack Account Names](templates/slack_config.yaml.template)** - AWS account name mappings for Slack
- **[Channel Configuration](templates/channels.yaml.template)** - Channel setup for slack-channel-setup CLI

### 📁 Archive

Historical documentation and analysis:

- [Test Coverage Analysis](archive/TEST_COVERAGE_ANALYSIS.md) (outdated - see actual coverage in CI)
- [Lambda Shared Utils Analysis](archive/LAMBDA_SHARED_UTILS_ANALYSIS.md) (migration doc)

## Documentation Structure

```
docs/
├── README.md                    # This file - main documentation homepage
├── getting-started/             # User onboarding
│   ├── installation.md
│   ├── configuration.md
│   └── quickstart.md
├── guides/                      # Component-specific how-to guides
├── reference/                   # API reference documentation
├── development/                 # Developer resources
│   └── testing.md
├── templates/                   # Configuration templates
│   └── slack_config.yaml.template
└── archive/                     # Outdated/historical docs
    ├── TEST_COVERAGE_ANALYSIS.md
    └── LAMBDA_SHARED_UTILS_ANALYSIS.md
```

## User Journeys

### New Users

1. Start with this README for overview
2. Follow [Installation Guide](getting-started/installation.md)
3. Review [Configuration Guide](getting-started/configuration.md)
4. Try examples in [Quick Start](getting-started/quickstart.md)

### Integration Focus

- Jump to specific component guides (when available)
- Reference [Configuration Guide](getting-started/configuration.md) for setup
- Use [Quick Start](getting-started/quickstart.md) for code examples

### Development Contributors

1. Read [Contributing Guidelines](../CONTRIBUTING.md)
2. Review [Testing Guide](development/testing.md)
3. Check [Changelog](../CHANGELOG.md) for recent changes

## Contributing to Documentation

When contributing to documentation:

1. **Follow the structure** - Place new docs in appropriate directories
2. **Include code examples** - Provide working, tested code snippets
3. **Cross-reference** - Link related topics for easy navigation
4. **Add to this README** - Update navigation when adding new docs
5. **Test examples** - Ensure all code works with current version
6. **Add last-updated dates** - Help users know doc freshness

## Documentation Status

### ✅ Available

- Main documentation (this README)
- Getting started guides (installation, configuration, quickstart)
- AWS Powertools integration guide (guides/powertools-integration.md)
- Lambda context helpers guide (guides/lambda-utilities.md)
- Slack integration guide (guides/slack-integration.md)
- Elasticsearch integration guide (guides/elasticsearch-integration.md)
- Shared types reference (guides/shared-types.md)
- CLI tools guide (guides/cli-tools.md)
- Testing guide (development/testing.md)
- Configuration templates (Slack account names, channel setup)

### 🚧 Planned

- Component-specific guides (Database, Metrics, Error Handling)
- API reference documentation
- Advanced topics (AWS infrastructure, Lambda integration)
- Troubleshooting guide

## Local Viewing

### Markdown Viewers

Most IDEs and editors can preview markdown files natively.

### Static Site Generation (Optional)

**Using MkDocs:**

```bash
pip install mkdocs mkdocs-material
mkdocs serve
```

**Using Sphinx:**

```bash
pip install sphinx sphinx-rtd-theme
sphinx-quickstart docs
make html
```

## Online Documentation

- GitHub Repository: https://github.com/nuimarkets/nui-lambda-shared-utils
- Package Page: https://pypi.org/project/nui-lambda-shared-utils/

---

*Documentation last updated 2025-11-19 with AWS Powertools integration guide.*
