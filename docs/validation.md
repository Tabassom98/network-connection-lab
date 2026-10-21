# Validation

Local validation on October 21, 2026: Python 3.12.14 on Windows, 8 tests passed.

Command: `python -m unittest discover -s tests -v` from the repository directory. Tests requiring temporary files used a workspace temporary directory because of the execution environment's filesystem restrictions.

The network demo produced the two specified findings. The AI gate demo matched all eight specified authorization decisions; this is not a model robustness result. File integrity tests exercised baseline creation, unchanged comparison, changed content, and overwrite refusal in isolated directories.

No remote CI result is claimed: this repository has not been published yet. Linux and Python 3.10 execution are targeted by the proposed workflow, not locally verified. Tests on synthetic inputs do not establish production effectiveness.
