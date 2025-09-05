# Documentation Structure

This directory contains the complete documentation for `nui-lambda-shared-utils`.

## Documentation Files

### Getting Started
- [`index.md`](index.md) - Main documentation homepage
- [`installation.md`](installation.md) - Installation and setup guide  
- [`configuration.md`](configuration.md) - Configuration and credential management
- [`quickstart.md`](quickstart.md) - Quick start examples and common patterns

### Core Components
- [`secrets.md`](secrets.md) - AWS Secrets Manager integration
- [`slack.md`](slack.md) - Slack messaging and formatting
- [`elasticsearch.md`](elasticsearch.md) - Elasticsearch operations and query building
- [`database.md`](database.md) - Database connections and operations
- [`metrics.md`](metrics.md) - CloudWatch metrics and monitoring
- [`error-handling.md`](error-handling.md) - Error handling and retry patterns
- [`timezone.md`](timezone.md) - Timezone utilities

### Advanced Topics  
- [`aws-infrastructure.md`](aws-infrastructure.md) - AWS resources and IAM requirements
- [`testing.md`](testing.md) - Testing strategies and tools
- [`lambda-integration.md`](lambda-integration.md) - Lambda-specific integration patterns
- [`cli-tools.md`](cli-tools.md) - Command-line tools and utilities

### Developer Resources
- [`api/`](api/) - Complete API reference documentation
- [`contributing.md`](contributing.md) - Development workflow and contributing guidelines
- [`changelog.md`](changelog.md) - Version history and migration notes
- [`troubleshooting.md`](troubleshooting.md) - Common issues and solutions

## Navigation

The documentation is organized to support different user journeys:

**New Users**: Start with `index.md` → `installation.md` → `configuration.md` → `quickstart.md`

**Integration Focus**: Jump to specific component docs (`slack.md`, `elasticsearch.md`, etc.)

**Development**: See `contributing.md` → `testing.md` → `api/` reference

**Deployment**: Review `aws-infrastructure.md` → `lambda-integration.md`

## Viewing Documentation

### Local Development

For local development, you can view the documentation by:

1. **Markdown Viewers**: Most IDEs and editors can preview markdown files
2. **Static Site Generators**: Use tools like MkDocs, Sphinx, or similar
3. **GitHub**: The documentation renders automatically on GitHub

### Online Documentation

The documentation is available at:
- GitHub Repository: https://github.com/nuimarkets/nui-lambda-shared-utils
- Package Documentation: Linked from PyPI package page

## Contributing to Documentation

When contributing to the documentation:

1. **Follow the existing structure** - Use consistent headers, formatting, and style
2. **Include code examples** - Provide working code snippets where applicable
3. **Cross-reference sections** - Link related topics and create clear navigation
4. **Update multiple files** - Changes may require updates to several docs
5. **Test examples** - Ensure all code examples work with the current version

## Building Documentation

For generating static documentation sites:

### Using MkDocs

```bash
# Install MkDocs
pip install mkdocs mkdocs-material

# Create mkdocs.yml in project root
# Build and serve
mkdocs serve
```

### Using Sphinx

```bash
# Install Sphinx
pip install sphinx sphinx-rtd-theme

# Initialize Sphinx
sphinx-quickstart docs

# Build documentation
make html
```

The documentation files are written in standard Markdown format and should work with most documentation generators.

## Current Documentation Status

**Available Documentation:**
- ✅ Main documentation (`index.md`)
- ✅ Installation guide (`installation.md`) 
- ✅ Configuration guide (`configuration.md`)
- ✅ Quick start guide (`quickstart.md`)

**Planned Documentation:**
- 🚧 Individual component guides (secrets, slack, elasticsearch, database, metrics, error-handling, timezone)
- 🚧 Advanced topics (aws-infrastructure, testing, lambda-integration, cli-tools)
- 🚧 Developer resources (api reference, contributing, changelog, troubleshooting)

**Note:** Some documentation files referenced in the navigation are planned but not yet created. The core documentation (index, installation, configuration, quickstart) provides comprehensive coverage of the package functionality.
