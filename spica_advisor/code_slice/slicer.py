from collections import deque

from spica_advisor.code_slice.module import (
    DECLARATION,
    DEFAULT_EXPORT,
    DefaultExport,
    LOAD,
    LocalExport,
    ReExport,
)
from spica_advisor.code_slice.references import free_references


SPICA_FUNCTION_PREFIX = "@spica-fn/"
# Imports and exports only name things; the names they mention are not uses.
EXECUTED_KINDS = {DECLARATION, DEFAULT_EXPORT, LOAD}


class Slicer:
    """Collects the statements a function's handlers can run, following imports into other Spica functions.

    Every unit of work is remembered in a set before it is queued, so shared helpers are kept once and
    circular imports end.
    """

    def __init__(self, modules, ids_by_name):
        self.modules = modules
        self.ids_by_name = ids_by_name
        self.included = {}
        self.notes = {}
        self.queue = deque()
        self.seen = set()

    def slice(self, function_id, handlers):
        self.included.setdefault(function_id, set())
        for handler in handlers:
            self.schedule("export", function_id, handler)
        while self.queue:
            task, *arguments = self.queue.popleft()
            getattr(self, task)(*arguments)
        return self.included

    def schedule(self, task, *arguments):
        key = (task, *arguments)
        if key not in self.seen:
            self.seen.add(key)
            self.queue.append(key)

    def note(self, message):
        self.notes[message] = None

    def spica_module(self, owner, specifier):
        if not specifier.startswith(SPICA_FUNCTION_PREFIX):
            return None
        name = specifier[len(SPICA_FUNCTION_PREFIX):]
        function_id = self.ids_by_name.get(name)
        if function_id is None:
            self.note(f"{owner.name} imports {specifier}, which is not a function in this project")
            return None
        return self.modules[function_id]

    def load(self, function_id):
        module = self.modules[function_id]
        self.included.setdefault(function_id, set())
        for index, statement in enumerate(module.statements):
            if statement.kind == LOAD:
                self.schedule("statement", function_id, index)

    def statement(self, function_id, index):
        module = self.modules[function_id]
        statement = module.statements[index]
        self.included.setdefault(function_id, set()).add(index)
        if statement.kind in EXECUTED_KINDS:
            for reference in free_references(statement.node):
                self.schedule("name", function_id, reference.name, reference.member)
        if statement.kind == LOAD and statement.specifier:
            target = self.spica_module(module, statement.specifier)
            if target:
                self.schedule("load", target.function_id)

    def name(self, function_id, local, member):
        module = self.modules[function_id]
        if local in module.defined_by:
            self.schedule("statement", function_id, module.defined_by[local])
            return
        binding = module.imports.get(local)
        if binding is None:
            return
        self.schedule("statement", function_id, binding.statement)
        target = self.spica_module(module, binding.specifier)
        if target is None:
            return
        if binding.imported != "*":
            self.schedule("export", target.function_id, binding.imported)
        elif member:
            self.schedule("export", target.function_id, member)
        else:
            self.note(f"{module.name} uses `{local}` from {binding.specifier} as a whole, so all its exports are included")
            self.schedule("all_exports", target.function_id)

    def export(self, function_id, exported):
        module = self.modules[function_id]
        self.schedule("load", function_id)
        entry = module.exports.get(exported)
        if isinstance(entry, LocalExport):
            self.schedule("name", function_id, entry.name, None)
        elif isinstance(entry, DefaultExport):
            self.schedule("statement", function_id, entry.statement)
        elif isinstance(entry, ReExport):
            self.schedule("statement", function_id, entry.statement)
            target = self.spica_module(module, entry.specifier)
            if target and entry.name == "*":
                self.schedule("all_exports", target.function_id)
            elif target:
                self.schedule("export", target.function_id, entry.name)
        elif not self.export_from_star(module, exported):
            self.note(f"{module.name} has no export named `{exported}`")

    def export_from_star(self, module, exported):
        for index, specifier in module.star_exports:
            target = self.spica_module(module, specifier)
            if target and self.exports(target, exported, {module.function_id}):
                self.schedule("statement", module.function_id, index)
                self.schedule("export", target.function_id, exported)
                return True
        return False

    def exports(self, module, exported, visited):
        if exported in module.exports:
            return True
        visited = visited | {module.function_id}
        for _, specifier in module.star_exports:
            target = self.spica_module(module, specifier)
            if target and target.function_id not in visited and self.exports(target, exported, visited):
                return True
        return False

    def all_exports(self, function_id):
        module = self.modules[function_id]
        for exported in sorted(module.exports):
            self.schedule("export", function_id, exported)
        for index, specifier in module.star_exports:
            target = self.spica_module(module, specifier)
            self.schedule("statement", function_id, index)
            if target:
                self.schedule("all_exports", target.function_id)
