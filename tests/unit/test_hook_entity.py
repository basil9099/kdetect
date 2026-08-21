from kdetect.models import HookEntity, Observation, Status, TrustLevel

def test_hook_entity_roundtrips():
    e = HookEntity(function="__x64_sys_newuname", hook_type="ftrace",
                   callback="kdetect_callback", owner_module="kdetect_hooktest")
    assert HookEntity.from_dict(e.to_dict()) == e

def test_hook_entity_null_owner_module():
    e = HookEntity(function="ip_rcv", hook_type="ftrace",
                   callback="0xdeadbeef", owner_module=None)
    assert HookEntity.from_dict(e.to_dict()).owner_module is None

def test_kernel_hooks_observation_uses_string_ids():
    obs = Observation(
        collector="kernel.hooks", collector_version="1", view="kernel_hooks",
        trust_level=TrustLevel.MEDIUM, status=Status.OK, duration_ms=1,
        entity_ids=["ftrace:__x64_sys_newuname"],
        entities={"ftrace:__x64_sys_newuname": HookEntity(
            "__x64_sys_newuname", "ftrace", "kdetect_callback", "kdetect_hooktest")},
        stats={}, errors=[],
    )
    back = Observation.from_dict(obs.to_dict())
    assert back == obs
    assert list(back.entities.keys()) == ["ftrace:__x64_sys_newuname"]  # stayed str
