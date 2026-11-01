from functools import reduce

from spica_advisor.investigation import InvestigationError
from spica_advisor.investigations.unauthenticated_endpoints.prompts import MAX_PROMPT_CHARS, handler_call_prompt


class Packer:
    """Groups functions into prompts so that code shared between them is sent once per prompt."""

    def __init__(self, index, functions):
        self.index = index
        self.order = {function["_id"]: position for position, function in enumerate(functions)}
        self.cuts = {function["_id"]: index.cut(function["_id"], function["handlers"]) for function in functions}

    def prompt(self, functions):
        functions = sorted(functions, key=lambda function: self.order[function["_id"]])
        cut = reduce(lambda total, function: total.union(self.cuts[function["_id"]]), functions,
                     self.cuts[functions[0]["_id"]])
        code = self.index.render(cut, {function["_id"] for function in functions})
        return handler_call_prompt(functions, code)

    def pack(self, functions):
        sizes = {function["_id"]: len(self.prompt([function])) for function in functions}
        for function in functions:
            if sizes[function["_id"]] > MAX_PROMPT_CHARS:
                raise InvestigationError(
                    f"The code that the handlers of function {function['name']} ({function['_id']}) can run is "
                    f"{sizes[function['_id']]:,} characters, above the {MAX_PROMPT_CHARS:,} limit."
                )
        batches = []
        for function in sorted(functions, key=lambda function: -sizes[function["_id"]]):
            self.place(function, batches)
        return [self.prompt(batch["functions"]) for batch in batches]

    def place(self, function, batches):
        # The batch that grows least is the one that already holds most of the code this function needs.
        best = None
        for batch in batches:
            size = len(self.prompt([*batch["functions"], function]))
            if size <= MAX_PROMPT_CHARS and (best is None or size - batch["size"] < best[0]):
                best = (size - batch["size"], batch, size)
        if best is None:
            batches.append({"functions": [function], "size": len(self.prompt([function]))})
        else:
            _, batch, size = best
            batch["functions"].append(function)
            batch["size"] = size
