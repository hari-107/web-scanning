"""Vulnerability testing modules.

Each module exposes ``run(ctx)`` and performs only non-destructive detection:
probes look for reflected markers, characteristic error strings, boolean
differentials, or timing differentials -- never data-modifying actions.
"""
