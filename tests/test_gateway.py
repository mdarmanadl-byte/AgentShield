
"""Gateway API and security regression tests."""

def decide(client, tool, arguments=None, agent="demo-agent"):
    return client.post(
        "/v1/decisions",
        json={
            "agent_id": agent,
            "tool_name": tool,
            "arguments": arguments or {},
        },
    )


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_allowlisted_tool_is_allowed(client):
    response = decide(
        client, "read_project_file", {"path": "example.txt"}
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "allow"


def test_unknown_agent_is_denied(client):
    response = decide(
        client, "read_project_file",
        {"path": "example.txt"}, agent="unknown",
    )
    assert response.json()["decision"] == "deny"


def test_unlisted_tool_is_denied(client):
    response = decide(client, "send_email")
    assert response.json()["decision"] == "deny"


def test_explicitly_denied_tool_is_denied(client):
    response = decide(client, "execute_shell")
    assert response.json()["decision"] == "deny"


def test_sensitive_path_is_denied(client):
    response = decide(
        client, "read_project_file", {"path": ".env"}
    )
    assert response.json()["decision"] == "deny"


def test_path_traversal_is_denied(client):
    response = decide(
        client, "read_project_file", {"path": "../outside.txt"}
    )
    assert response.json()["decision"] == "deny"


def test_absolute_path_outside_workspace_is_denied(client, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("not authorized", encoding="utf-8")

    response = decide(
        client, "read_project_file", {"path": str(outside)}
    )
    assert response.json()["decision"] == "deny"


def test_invalid_path_argument_is_denied(client):
    response = decide(
        client, "read_project_file", {"path": 123}
    )
    assert response.json()["decision"] == "deny"


def test_extra_request_fields_are_rejected(client):
    response = client.post(
        "/v1/decisions",
        json={
            "agent_id": "demo-agent",
            "tool_name": "read_project_file",
            "arguments": {"path": "example.txt"},
            "unexpected": True,
        },
    )
    assert response.status_code == 422


def test_decisions_are_audited_without_arguments(client):
    response = decide(
        client,
        "read_project_file",
        {"path": "example.txt", "secret": "do-not-log"},
    )
    assert response.status_code == 200

    audit = client.get("/v1/audit")
    assert audit.status_code == 200

    events = audit.json()
    assert len(events) == 1
    assert events[0]["decision"] == "allow"
    assert "secret" not in str(events[0])


def test_audit_limit_is_validated(client):
    assert client.get("/v1/audit?limit=0").status_code == 422
    assert client.get("/v1/audit?limit=201").status_code == 422
