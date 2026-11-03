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


def test_bucket_locations_span_the_acl_block(tmp_path):
    write(tmp_path / "bucket" / "Plans" / "schema.yaml",
          "_id: b1\ntitle: Plans\nacl:\n  write: true==true\n  read: \"a ||\\r\\n\n    b\"\n\nrequiredFields:\n  - title\n")

    location = resource_locations(tmp_path, "bucket")["b1"]

    assert (location["line"], location["end_line"]) == (3, 6)


def test_env_var_locations_point_at_the_key_line(tmp_path):
    write(tmp_path / "env-var" / "K" / "schema.yaml", "_id: e1\nkey: K\nvalue: v\n")

    assert resource_locations(tmp_path, "env-var")["e1"]["line"] == 2


def test_handler_lines_cover_declared_default_and_listed_exports():
    from spica_advisor.investigations.unauthenticated_endpoints.handlers import handler_line

    source = "const a = 1;\nexport async function run() {}\nexport default () => {};\nexport { a as alias };\n"

    assert handler_line(source, "run") == 2
    assert handler_line(source, "default") == 3
    assert handler_line(source, "alias") == 4
    assert handler_line(source, "missing") is None
