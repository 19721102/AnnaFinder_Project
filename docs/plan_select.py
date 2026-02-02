import json
from pathlib import Path


def load_plan(plan_path: Path) -> dict:
    return json.loads(plan_path.read_text(encoding="utf-8"))


def merge_tasks(data: dict) -> list:
    merged = []
    seen = set()
    for key in ("tasks", "backlog", "items"):
        for t in data.get(key) or []:
            tid = t.get("id") or t.get("task_id")
            if not tid:
                continue
            if tid in seen:
                continue
            merged.append(t)
            seen.add(tid)
    return merged


def deps_ok(task: dict, by_id: dict) -> bool:
    deps = task.get("depends_on") or task.get("deps") or []
    for dep_id in deps:
        dep = by_id.get(dep_id)
        if not dep or dep.get("done") is not True:
            return False
    return True


def blocked(reason: str, needed_from_user: list) -> None:
    print(
        json.dumps(
            {
                "blocked": True,
                "reason": reason,
                "needed_from_user": needed_from_user,
            },
            ensure_ascii=False,
        )
    )


def main() -> None:
    plan_path = Path("docs/PLANO_PLANEJADOR.json")
    data = load_plan(plan_path)
    tasks = merge_tasks(data)
    if not tasks:
        blocked(
            "No tasks array found in plan after merging arrays",
            ["Ensure plan has tasks/backlog/items arrays with task ids."],
        )
        return

    by_id = {t.get("id") or t.get("task_id"): t for t in tasks}

    next_task = None
    for task in tasks:
        if task.get("done") is True:
            continue
        if deps_ok(task, by_id):
            next_task = task
            break

    if not next_task:
        blocked(
            "No eligible TODO task found after merging arrays",
            ["Check plan dependencies or add new tasks."],
        )
        return

    task_id = next_task.get("id") or next_task.get("task_id")
    allowed = next_task.get("allowed_paths") or next_task.get("allowlist") or []
    commit_message = next_task.get("commit_message") or next_task.get("commit") or ""

    missing = []
    if not allowed:
        missing.append(f"Fill allowed_paths/allowlist for task {task_id}.")
    if not commit_message:
        missing.append(f"Fill commit_message/commit for task {task_id}.")

    if missing:
        blocked(
            f"Task {task_id} missing required metadata.",
            missing,
        )
        return

    print(
        json.dumps(
            {
                "selected_task_id": task_id,
                "title": next_task.get("title"),
                "allowed_paths": allowed,
                "commit_message": commit_message,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
