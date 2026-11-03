from spica_advisor.resources import resource_locations


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_locations_point_at_the_schema_file_of_non_function_resources(tmp_path):
    write(tmp_path / "policy" / "User" / "schema.yaml", "_id: p1\nname: User\n")

    assert resource_locations(tmp_path, "policy") == {"p1": {"name": "User", "path": "policy/User/schema.yaml"}}


def test_function_locations_point_at_the_entry_file(tmp_path):
    write(tmp_path / "function" / "Mail" / "schema.yaml", "_id: f1\nname: Mail\n")
    write(tmp_path / "function" / "Mail" / "index.ts", "export default () => {};")
    write(tmp_path / "function" / "Plain" / "schema.yaml", "_id: f2\nname: Plain\n")

    locations = resource_locations(tmp_path, "function")

    assert locations["f1"]["path"] == "function/Mail/index.ts"
    assert locations["f2"]["path"] == "function/Plain/schema.yaml"
