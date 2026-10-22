"""Pure bounded validation of scanner dependency edges."""


def valid_dependencies(edges, selected) -> bool:
    if (not isinstance(edges, tuple) or len(edges) > 169 or any(
            not isinstance(edge, tuple) or len(edge) != 2 or any(not isinstance(key, str) for key in edge)
            for edge in edges)):
        return False
    if len(set(edges)) != len(edges) or any(a == b or a not in selected or b not in selected for a, b in edges):
        return False
    pending = {key for key in selected if isinstance(key, str)}
    while pending:
        ready = {key for key in pending if not any(a == key and b in pending for a, b in edges)}
        if not ready:
            return False
        pending -= ready
    return True
