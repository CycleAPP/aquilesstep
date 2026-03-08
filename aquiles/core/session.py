"""Session state management for Aquiles assessments.

Provides persistent, auto-saving session state with:
- Full execution state tracking
- Scan history with timestamps
- Artifact registry (files produced by tools)
- Normalized findings store with deduplication
- Resumable runs via Session.load()
"""

from __future__ import annotations

import json
import os
import time
import glob
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class ExecutionState(Enum):
    """Current state of the assessment session."""
    SETUP = "setup"
    PLANNING = "planning"
    EXECUTING = "executing"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Finding:
    """A single finding from the assessment."""
    severity: str  # critical, high, medium, low, info
    category: str
    description: str
    target: str
    tool: str
    evidence: str = ""
    phase: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    finding_id: str = ""  # Dedup key: auto-generated if empty

    def __post_init__(self):
        if not self.finding_id:
            self.finding_id = f"{self.category}:{self.description}:{self.target}"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> Finding:
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in valid_keys})


@dataclass
class ToolResult:
    """Result from a single tool execution."""
    tool_name: str
    command: str
    exit_code: int
    output_file: str
    stdout: str
    stderr: str
    duration: float
    phase: int
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    parsed_data: dict = field(default_factory=dict)
    error_info: dict = field(default_factory=dict)  # Structured error from errors.py
    retry_count: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        # Truncate stdout/stderr for serialization
        d["stdout"] = d["stdout"][:5000] if len(d["stdout"]) > 5000 else d["stdout"]
        d["stderr"] = d["stderr"][:2000] if len(d["stderr"]) > 2000 else d["stderr"]
        return d

    @classmethod
    def from_dict(cls, data: dict) -> ToolResult:
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in valid_keys})

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0

    @property
    def has_output(self) -> bool:
        return bool(self.stdout) or (bool(self.output_file) and os.path.exists(self.output_file))


@dataclass
class Phase:
    """A phase in the assessment plan."""
    number: int
    name: str
    description: str
    tools: list[str] = field(default_factory=list)
    status: str = "pending"  # pending, running, done, skipped, failed
    results: list[ToolResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    failed_tools: list[str] = field(default_factory=list)  # Tools that failed in this phase
    skipped_tools: list[str] = field(default_factory=list)  # Tools skipped (binary missing etc)

    def to_dict(self) -> dict:
        return {
            "number": self.number,
            "name": self.name,
            "description": self.description,
            "tools": self.tools,
            "status": self.status,
            "results": [r.to_dict() for r in self.results],
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "failed_tools": self.failed_tools,
            "skipped_tools": self.skipped_tools,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Phase:
        results = [ToolResult.from_dict(r) for r in data.get("results", [])]
        findings = [Finding.from_dict(f) for f in data.get("findings", [])]
        return cls(
            number=data["number"],
            name=data["name"],
            description=data.get("description", ""),
            tools=data.get("tools", []),
            status=data.get("status", "pending"),
            results=results,
            findings=findings,
            summary=data.get("summary", ""),
            failed_tools=data.get("failed_tools", []),
            skipped_tools=data.get("skipped_tools", []),
        )


@dataclass
class ScanEvent:
    """A timestamped event in the scan history."""
    event_type: str  # tool_start, tool_end, phase_start, phase_end, hint_added, error, state_change
    description: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> ScanEvent:
        return cls(**{k: v for k, v in data.items() if k in {"event_type", "description", "timestamp", "metadata"}})


class Session:
    """
    Manages the state of an Aquiles assessment session.
    
    Features:
    - Auto-saves after every significant action
    - Tracks full scan history with timestamps
    - Maintains artifact registry for produced files
    - Supports resume from saved state via Session.load()
    - Deduplicates findings by target+category+description
    """

    def __init__(self, workspace_dir: str | None = None, session_id: str | None = None):
        self.session_id: str = session_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.start_time: str = datetime.now().isoformat()
        self.last_saved: str = ""
        self.execution_state: ExecutionState = ExecutionState.SETUP
        self.assessment_type: dict = {}
        self.scope: dict = {
            "domains": [],
            "ips": [],
            "urls": [],
            "ports": ["1-65535"],
            "exclusions": [],
        }
        self.intensity: str = "medium"
        self.objective: str = ""
        self.phases: list[Phase] = []
        self.current_phase: int = 0
        self.all_findings: list[Finding] = []
        self.tool_results: list[ToolResult] = []
        self.authorization_accepted: bool = False
        self.auditor_hints: list[str] = []  # Legacy simple hints

        # NEW: Enhanced state tracking
        self.scan_history: list[ScanEvent] = []
        self.artifacts: dict[str, list[str]] = {}  # tool_name -> [file_paths]
        self._finding_index: set[str] = set()  # Dedup index
        self.errors: list[dict] = []  # Accumulated errors
        self.hints_data: list[dict] = []  # Structured hints (serialized from HintEngine)

        # Set up workspace directory
        if workspace_dir:
            base = Path(workspace_dir)
            # If the workspace_dir is already a session dir, use it directly
            if base.name.startswith("aquiles_session_"):
                self.workspace = base
            else:
                self.workspace = base / f"aquiles_session_{self.session_id}"
        else:
            self.workspace = Path.cwd() / f"aquiles_session_{self.session_id}"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.outputs_dir = self.workspace / "outputs"
        self.outputs_dir.mkdir(exist_ok=True)
        self.reports_dir = self.workspace / "reports"
        self.reports_dir.mkdir(exist_ok=True)

        # Rebuild finding index from existing findings
        for f in self.all_findings:
            self._finding_index.add(f.finding_id)

    # ── Properties ──

    @property
    def targets(self) -> list[str]:
        """Get all defined targets as a flat list."""
        return self.scope["domains"] + self.scope["ips"] + self.scope["urls"]

    @property
    def exclusions(self) -> list[str]:
        """Get all exclusions."""
        return self.scope.get("exclusions", [])

    @property
    def is_resumable(self) -> bool:
        """Can this session be resumed?"""
        return self.execution_state in (ExecutionState.EXECUTING, ExecutionState.PAUSED, ExecutionState.FAILED)

    @property
    def completed_phases(self) -> list[Phase]:
        return [p for p in self.phases if p.status == "done"]

    @property
    def pending_phases(self) -> list[Phase]:
        return [p for p in self.phases if p.status == "pending"]

    # ── Phase Management ──

    def add_phase(self, name: str, description: str, tools: list[str]) -> Phase:
        """Add a phase to the plan."""
        phase = Phase(
            number=len(self.phases) + 1,
            name=name,
            description=description,
            tools=tools,
        )
        self.phases.append(phase)
        self.log_event("phase_added", f"Phase {phase.number}: {name}")
        return phase

    def clear_phases(self) -> None:
        """Clear all phases (for replanning)."""
        self.phases.clear()
        self.current_phase = 0
        self.log_event("phases_cleared", "All phases cleared for replanning")

    def get_current_phase(self) -> Phase | None:
        """Get the currently active phase."""
        if 0 <= self.current_phase < len(self.phases):
            return self.phases[self.current_phase]
        return None

    def advance_phase(self) -> Phase | None:
        """Move to the next phase."""
        self.current_phase += 1
        return self.get_current_phase()

    # ── Findings (with deduplication) ──

    def add_finding(self, finding: Finding) -> bool:
        """
        Record a finding. Returns True if new, False if duplicate.
        """
        if finding.finding_id in self._finding_index:
            return False
        self._finding_index.add(finding.finding_id)
        self.all_findings.append(finding)
        current = self.get_current_phase()
        if current:
            current.findings.append(finding)
        return True

    def get_findings_by_severity(self, severity: str) -> list[Finding]:
        """Get findings filtered by severity."""
        return [f for f in self.all_findings if f.severity == severity]

    def get_findings_by_target(self, target: str) -> list[Finding]:
        """Get findings filtered by target."""
        return [f for f in self.all_findings if f.target == target]

    # ── Tool Results ──

    def add_tool_result(self, result: ToolResult) -> None:
        """Record a tool execution result and auto-save."""
        self.tool_results.append(result)
        current = self.get_current_phase()
        if current:
            current.results.append(result)

        # Track as artifact if it produced a file
        if result.output_file and os.path.exists(result.output_file):
            self.register_artifact(result.tool_name, result.output_file)

        # Log the event
        status = "success" if result.succeeded else "failure"
        self.log_event(
            "tool_end",
            f"{result.tool_name}: {status} (exit={result.exit_code}, {result.duration:.1f}s)",
            metadata={"tool": result.tool_name, "exit_code": result.exit_code, "duration": result.duration},
        )

        # Track failed/skipped tools
        is_warning = result.error_info and result.error_info.get("severity") == "warning"
        if result.exit_code == -1 and current:
            if result.tool_name not in current.skipped_tools:
                current.skipped_tools.append(result.tool_name)
        elif not result.succeeded and not is_warning and current:
            if result.tool_name not in current.failed_tools:
                current.failed_tools.append(result.tool_name)

        # Auto-save
        self.auto_save()

    # ── Artifact Registry ──

    def register_artifact(self, tool_name: str, file_path: str) -> None:
        """Register a file artifact produced by a tool."""
        if tool_name not in self.artifacts:
            self.artifacts[tool_name] = []
        if file_path not in self.artifacts[tool_name]:
            self.artifacts[tool_name].append(file_path)

    def get_artifacts(self, tool_name: str | None = None) -> list[str]:
        """Get artifact file paths, optionally filtered by tool."""
        if tool_name:
            return self.artifacts.get(tool_name, [])
        return [fp for files in self.artifacts.values() for fp in files]

    # ── Scan History ──

    def log_event(self, event_type: str, description: str, metadata: dict | None = None) -> None:
        """Log a timestamped event to the scan history."""
        event = ScanEvent(
            event_type=event_type,
            description=description,
            metadata=metadata or {},
        )
        self.scan_history.append(event)

    def log_error(self, error_dict: dict) -> None:
        """Log an error to the session."""
        self.errors.append(error_dict)
        self.log_event("error", error_dict.get("message", "Unknown error"), metadata=error_dict)

    # ── Execution State ──

    def set_state(self, state: ExecutionState) -> None:
        """Update execution state with logging and auto-save."""
        old_state = self.execution_state
        self.execution_state = state
        self.log_event("state_change", f"{old_state.value} → {state.value}")
        self.auto_save()

    # ── Output Paths ──

    def get_output_path(self, tool_name: str, extension: str = "txt") -> str:
        """Generate output file path for a tool."""
        phase = self.get_current_phase()
        phase_num = phase.number if phase else 0
        filename = f"phase{phase_num}_{tool_name}_{int(time.time())}.{extension}"
        return str(self.outputs_dir / filename)

    # ── Context Summary ──

    def get_context_summary(self) -> str:
        """Generate a summary of findings so far (for AI context)."""
        lines = [
            f"Assessment: {self.assessment_type.get('name', 'Unknown')}",
            f"Intensity: {self.intensity}",
            f"Targets: {', '.join(self.targets)}",
            f"Objective: {self.objective}",
            f"State: {self.execution_state.value}",
            f"Phases completed: {len(self.completed_phases)}/{len(self.phases)}",
            f"Total findings: {len(self.all_findings)}",
            f"Total errors: {len(self.errors)}",
        ]

        if self.all_findings:
            by_severity = {}
            for f in self.all_findings:
                by_severity.setdefault(f.severity, []).append(f)
            for sev in ["critical", "high", "medium", "low", "info"]:
                if sev in by_severity:
                    lines.append(f"  {sev.upper()}: {len(by_severity[sev])}")

            lines.append("\nKey findings:")
            for f in sorted(self.all_findings, key=lambda x: ["critical", "high", "medium", "low", "info"].index(x.severity))[:10]:
                lines.append(f"  - [{f.severity.upper()}] {f.description} ({f.target})")

        if self.auditor_hints:
            lines.append(f"\nAuditor hints: {'; '.join(self.auditor_hints)}")

        return "\n".join(lines)

    # ── Persistence ──

    def auto_save(self) -> None:
        """Auto-save session state (silent, no console output)."""
        try:
            self._write_session_file()
        except Exception:
            pass  # Don't let save failures break execution

    def save(self) -> str:
        """Explicit save of session data. Returns path."""
        return self._write_session_file()

    def _write_session_file(self) -> str:
        """Write session state to JSON file."""
        self.last_saved = datetime.now().isoformat()
        data = {
            "session_id": self.session_id,
            "start_time": self.start_time,
            "last_saved": self.last_saved,
            "execution_state": self.execution_state.value,
            "assessment_type": self.assessment_type,
            "scope": self.scope,
            "intensity": self.intensity,
            "objective": self.objective,
            "authorization_accepted": self.authorization_accepted,
            "current_phase": self.current_phase,
            "phases": [p.to_dict() for p in self.phases],
            "findings": [f.to_dict() for f in self.all_findings],
            "auditor_hints": self.auditor_hints,
            "hints_data": self.hints_data,
            "scan_history": [e.to_dict() for e in self.scan_history],
            "artifacts": self.artifacts,
            "errors": self.errors,
        }
        path = self.workspace / "session.json"
        # Write atomically (write to tmp then rename)
        tmp_path = self.workspace / "session.json.tmp"
        with open(tmp_path, "w") as f:
            json.dump(data, f, indent=2)
        tmp_path.replace(path)
        return str(path)

    @classmethod
    def load(cls, workspace_path: str) -> Session:
        """
        Load a session from a saved workspace directory.
        
        Reconstructs the full session state for resume.
        """
        workspace = Path(workspace_path)
        session_file = workspace / "session.json"
        if not session_file.exists():
            raise FileNotFoundError(f"No session.json found in {workspace}")

        with open(session_file, "r") as f:
            data = json.load(f)

        session = cls(
            workspace_dir=str(workspace),
            session_id=data["session_id"],
        )
        session.start_time = data["start_time"]
        session.last_saved = data.get("last_saved", "")
        session.execution_state = ExecutionState(data.get("execution_state", "setup"))
        session.assessment_type = data.get("assessment_type", {})
        session.scope = data.get("scope", session.scope)
        session.intensity = data.get("intensity", "medium")
        session.objective = data.get("objective", "")
        session.authorization_accepted = data.get("authorization_accepted", False)
        session.current_phase = data.get("current_phase", 0)
        session.auditor_hints = data.get("auditor_hints", [])
        session.hints_data = data.get("hints_data", [])
        session.artifacts = data.get("artifacts", {})
        session.errors = data.get("errors", [])

        # Restore phases
        session.phases = [Phase.from_dict(p) for p in data.get("phases", [])]

        # Restore findings with dedup index
        session.all_findings = [Finding.from_dict(f) for f in data.get("findings", [])]
        session._finding_index = {f.finding_id for f in session.all_findings}

        # Restore tool results from phases
        session.tool_results = []
        for phase in session.phases:
            session.tool_results.extend(phase.results)

        # Restore scan history
        session.scan_history = [ScanEvent.from_dict(e) for e in data.get("scan_history", [])]

        session.log_event("session_resumed", f"Session resumed from {workspace}")

        return session

    @staticmethod
    def list_sessions(search_dir: str | None = None) -> list[dict]:
        """List all saved sessions in a directory."""
        search = Path(search_dir) if search_dir else Path.cwd()
        sessions = []

        for session_dir in sorted(search.glob("aquiles_session_*"), reverse=True):
            session_file = session_dir / "session.json"
            if session_file.exists():
                try:
                    with open(session_file, "r") as f:
                        data = json.load(f)
                    sessions.append({
                        "path": str(session_dir),
                        "session_id": data.get("session_id", "?"),
                        "start_time": data.get("start_time", "?"),
                        "last_saved": data.get("last_saved", "?"),
                        "state": data.get("execution_state", "?"),
                        "assessment_type": data.get("assessment_type", {}).get("name", "?"),
                        "objective": data.get("objective", "?")[:60],
                        "findings_count": len(data.get("findings", [])),
                        "phases_total": len(data.get("phases", [])),
                        "phases_done": sum(1 for p in data.get("phases", []) if p.get("status") == "done"),
                    })
                except Exception:
                    pass

        return sessions
