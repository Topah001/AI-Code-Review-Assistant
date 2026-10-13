# AI Code Review Assistant

An offline, deterministic static checker for Python source. It inspects Python syntax trees and source text; it does not execute the code, call an LLM, or claim human-level reasoning.

## Run

```powershell
python -m ai_code_review sample.py
python -m ai_code_review --format json sample.py
python -m unittest discover -s tests -v
```

Findings include a rule ID, severity, line number, and explanation. Rules cover common risky patterns such as `eval`/`exec`, shell-enabled subprocess calls, broad exception handlers, mutable defaults, and likely embedded credentials. These are heuristic signals, not proof of a vulnerability. Review findings in context; absence of findings is not a guarantee of safety.
