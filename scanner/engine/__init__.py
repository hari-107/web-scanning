"""Security assessment engine.

Each scanner lives in its own module and exposes a ``run(ctx)`` callable that
takes a :class:`~scanner.engine.base.ScanContext` and records its results onto
the associated :class:`~scanner.models.Scan`. Modules are deliberately
decoupled: any one can be imported and executed on its own, or chained by the
orchestrator into the full pipeline.
"""
