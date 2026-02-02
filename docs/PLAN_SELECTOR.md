# Plan selector

How to run:
- `python docs/plan_select.py`

What "blocked" means:
- The selector did not find a task that is not done and whose dependencies are
  all done after merging `tasks`, `backlog`, and `items`.

How to resolve:
- If blocked by deps: mark dependency tasks as done or fix missing dependency ids.
- If blocked by missing metadata: add `allowed_paths` (or `allowlist`) and
  `commit_message` (or `commit`) to the task item.
- If blocked by no eligible task: add a new TODO item or fix plan arrays.
