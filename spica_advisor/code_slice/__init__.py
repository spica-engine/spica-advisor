from dataclasses import dataclass, field

from spica_advisor.code_slice.module import index_module
from spica_advisor.code_slice.render import render
from spica_advisor.code_slice.slicer import Slicer


@dataclass(frozen=True)
class Cut:
    """The statements of each function that some handlers can run, and what could not be resolved."""

    included: dict[str, frozenset[int]] = field(default_factory=dict)
    notes: tuple[str, ...] = ()

    def union(self, other):
        included = {function_id: indexes for function_id, indexes in self.included.items()}
        for function_id, indexes in other.included.items():
            included[function_id] = included.get(function_id, frozenset()) | indexes
        return Cut(included, tuple(dict.fromkeys((*self.notes, *other.notes))))


class CodeIndex:
    """Parses every function once and cuts out the code a function's handlers can run."""

    def __init__(self, functions):
        self.modules = {function["_id"]: index_module(function["_id"], function["name"], function["content"])
                        for function in functions}
        self.ids_by_name = {}
        for function in functions:
            self.ids_by_name.setdefault(function["name"], function["_id"])

    def cut(self, function_id, handlers):
        slicer = Slicer(self.modules, self.ids_by_name)
        included = slicer.slice(function_id, handlers)
        return Cut({function_id: frozenset(indexes) for function_id, indexes in included.items()}, tuple(slicer.notes))

    def render(self, cut, judged_ids):
        return render(self.modules, cut.included, cut.notes, judged_ids)
