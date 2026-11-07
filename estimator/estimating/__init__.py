"""Estimate service layer: the one place estimates are created and changed.

The web app, the MCP tools and the agents all call these functions, so the
rules (company scoping, roles, revision checks, finalized lock, audit log) are
enforced the same way everywhere.
"""
