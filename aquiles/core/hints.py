"""Structured user hinting system for dynamic assessment guidance."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any


class HintType:
    """Types of hints the auditor can provide."""
    FOCUS = "focus"        # Prioritize a specific area / technology / target
    SKIP = "skip"          # Deprioritize or skip something
    ADD_TOOL = "add_tool"  # Inject a specific tool into the plan
    CONTEXT = "context"    # Background info that influences decisions
    REPRIORITIZE = "reprioritize"  # Reorder remaining phases


@dataclass
class Hint:
    """A single structured hint from the auditor."""
    text: str
    hint_type: str = HintType.CONTEXT
    priority: str = "normal"  # critical, high, normal
    phase_target: int | None = None  # Target a specific phase, or None for global
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    applied: bool = False
    source: str = "user"  # user, system, ai

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> Hint:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class HintEngine:
    """
    Manages auditor hints and applies them to assessment planning.
    
    Hints flow into the planner and analyzer to influence:
    - Phase ordering and prioritization
    - Tool selection within phases
    - AI analysis context
    - Finding severity interpretation
    """

    def __init__(self):
        self.hints: list[Hint] = []
        self._priority_weights = {"critical": 3, "high": 2, "normal": 1}

    def add_hint(
        self,
        text: str,
        priority: str = "normal",
        hint_type: str = HintType.CONTEXT,
        phase_target: int | None = None,
        source: str = "user",
    ) -> Hint:
        """Add a new hint."""
        hint = Hint(
            text=text,
            hint_type=hint_type,
            priority=priority,
            phase_target=phase_target,
            source=source,
        )
        self.hints.append(hint)
        return hint

    def get_active_hints(self, phase_number: int | None = None) -> list[Hint]:
        """Get all active (unapplied or global) hints, optionally filtered by phase."""
        active = []
        for h in self.hints:
            if h.phase_target is not None and phase_number is not None:
                if h.phase_target != phase_number:
                    continue
            active.append(h)
        # Sort by priority weight descending
        return sorted(active, key=lambda h: -self._priority_weights.get(h.priority, 1))

    def get_hints_for_context(self, phase_number: int | None = None) -> str:
        """Format active hints as context string for AI prompts."""
        active = self.get_active_hints(phase_number)
        if not active:
            return ""

        lines = ["Auditor hints:"]
        for h in active:
            prefix = {
                HintType.FOCUS: "*  FOCUS",
                HintType.SKIP: ">> SKIP",
                HintType.ADD_TOOL: "🔧 ADD TOOL",
                HintType.CONTEXT: "💡 CONTEXT",
                HintType.REPRIORITIZE: "🔄 REPRIORITIZE",
            }.get(h.hint_type, "💡")
            prio = f"[{h.priority.upper()}]" if h.priority != "normal" else ""
            lines.append(f"  {prefix} {prio} {h.text}")

        return "\n".join(lines)

    def get_focus_areas(self) -> list[str]:
        """Get areas the auditor wants to focus on."""
        return [
            h.text for h in self.hints
            if h.hint_type == HintType.FOCUS
        ]

    def get_skip_areas(self) -> list[str]:
        """Get areas the auditor wants to skip/deprioritize."""
        return [
            h.text for h in self.hints
            if h.hint_type == HintType.SKIP
        ]

    def get_tool_injections(self) -> list[str]:
        """Get specific tools the auditor wants to inject."""
        return [
            h.text for h in self.hints
            if h.hint_type == HintType.ADD_TOOL
        ]

    def get_priority_adjustments(self, phases: list[dict]) -> list[dict]:
        """
        Adjust phase ordering based on hints.
        
        FOCUS hints push related phases earlier.
        SKIP hints push related phases later.
        """
        # Extract individual keywords from hint text (words with 3+ chars)
        focus_keywords = []
        for h in self.hints:
            if h.hint_type == HintType.FOCUS:
                focus_keywords.extend(w.lower() for w in h.text.split() if len(w) >= 3)

        skip_keywords = []
        for h in self.hints:
            if h.hint_type == HintType.SKIP:
                skip_keywords.extend(w.lower() for w in h.text.split() if len(w) >= 3)

        def score_phase(phase: dict) -> int:
            """Higher score = execute earlier."""
            name = phase.get("name", "").lower()
            desc = phase.get("description", "").lower()
            tools_str = " ".join(phase.get("tools", [])).lower()
            combined = f"{name} {desc} {tools_str}"

            score = 0
            for kw in focus_keywords:
                if kw in combined:
                    score += 10
            for kw in skip_keywords:
                if kw in combined:
                    score -= 10
            return score

        # Sort phases by score (higher first), maintaining relative order for equal scores
        scored = [(score_phase(p), i, p) for i, p in enumerate(phases)]
        scored.sort(key=lambda x: (-x[0], x[1]))
        return [p for _, _, p in scored]

    def apply_to_phase_tools(self, tools: list[str]) -> list[str]:
        """Inject or remove tools based on hints."""
        result = list(tools)

        # Add injected tools
        for tool_name in self.get_tool_injections():
            if tool_name not in result:
                result.append(tool_name)

        return result

    def mark_applied(self, hint: Hint) -> None:
        """Mark a hint as applied."""
        hint.applied = True

    def clear(self) -> None:
        """Clear all hints."""
        self.hints.clear()

    def to_list(self) -> list[dict]:
        """Serialize all hints."""
        return [h.to_dict() for h in self.hints]

    def load_from_list(self, data: list[dict]) -> None:
        """Load hints from serialized data."""
        self.hints = [Hint.from_dict(d) for d in data]

    @property
    def count(self) -> int:
        return len(self.hints)
