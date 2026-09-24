"""Reference harness for signed, bounded credential-workflow packages.

The harness implements the package schema, restricted BPMN compilation,
canonical serialization, Ed25519 signing, validation, static path analysis,
and a bounded interpreter with scripted native-handler outcomes.
"""

__version__ = "1.0.0"
SCHEMA = "glovebox/1"
