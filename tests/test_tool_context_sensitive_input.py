from pathlib import Path

from scopeforgex.registry.tool_base import ToolContext


def test_tool_context_supports_separate_sensitive_input_channel():
    context = ToolContext(
        target="http://127.0.0.1:3000",
        output_dir=Path("/tmp/scopeforgex"),
        input_data=("http://127.0.0.1:3000",),
        sensitive_input_data={
            "jwt": ("header.payload.signature",),
        },
    )

    assert context.input_data == (
        "http://127.0.0.1:3000",
    )
    assert context.sensitive_input_data == {
        "jwt": ("header.payload.signature",),
    }


def test_tool_context_sensitive_input_defaults_to_empty():
    context = ToolContext(
        target="http://127.0.0.1:3000",
        output_dir=Path("/tmp/scopeforgex"),
    )

    assert context.sensitive_input_data == {}


def test_sensitive_input_is_separate_from_normal_input():
    context = ToolContext(
        target="http://127.0.0.1:3000",
        output_dir=Path("/tmp/scopeforgex"),
        input_data=("ordinary-value",),
        sensitive_input_data={
            "jwt": ("sensitive-value",),
        },
    )

    assert "sensitive-value" not in context.input_data
    assert "ordinary-value" not in context.sensitive_input_data["jwt"]


def test_sensitive_input_is_hidden_from_tool_context_repr():
    raw_jwt = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiJzZW5zaXRpdmUtdXNlciJ9."
        "signature"
    )

    context = ToolContext(
        target="http://127.0.0.1:3000",
        output_dir=Path("/tmp/scopeforgex"),
        sensitive_input_data={
            "jwt": (raw_jwt,),
        },
    )

    assert context.sensitive_input_data["jwt"] == (
        raw_jwt,
    )

    representation = repr(context)

    assert "sensitive_input_data" not in representation
    assert raw_jwt not in representation

def test_tool_executor_sensitive_store_supports_multiple_values():
    from scopeforgex.runtime.tool_executor import ToolExecutor

    executor = ToolExecutor()

    executor.set_sensitive_inputs(
        "jwt",
        (
            "jwt-one",
            "jwt-two",
        ),
    )

    assert executor.get_sensitive_inputs(
        "jwt"
    ) == (
        "jwt-one",
        "jwt-two",
    )


def test_tool_executor_sensitive_store_does_not_appear_in_repr():
    from scopeforgex.runtime.tool_executor import ToolExecutor

    executor = ToolExecutor()

    marker = "RAW_JWT_STEP_3M_EXECUTOR_REPR"

    executor.set_sensitive_inputs(
        "jwt",
        (marker,),
    )

    assert marker not in repr(executor)


def test_tool_executor_clear_sensitive_inputs_clears_all():
    from scopeforgex.runtime.tool_executor import ToolExecutor

    executor = ToolExecutor()

    executor.set_sensitive_inputs(
        "jwt",
        ("jwt-one",),
    )
    executor.set_sensitive_inputs(
        "credential",
        ("credential-one",),
    )

    executor.clear_sensitive_inputs()

    assert executor.get_sensitive_inputs("jwt") == ()
    assert executor.get_sensitive_inputs("credential") == ()
