from __future__ import annotations
import tempfile
from pathlib import Path
import unittest
import sys
from unittest.mock import patch
from blackbox_rep_alva.alva_bridge import inspect_platform, ALVA_PIN
from blackbox_rep_alva.storage import SessionStore
from blackbox_rep_alva.contracts import Sample, ObserverError


class BridgeTests(unittest.TestCase):
    def test_alva_optional_no_forced_import(self):
        # Simulate no external Alva available even if a developer has it installed.
        with patch.dict(sys.modules, {"alva": None, "alva.host": None}):
            result = inspect_platform()
        self.assertEqual(result["code"], "ALVA_UNAVAILABLE")
        self.assertFalse(result["provenance_verified"])
        self.assertEqual(result["required_ref"], ALVA_PIN)

    def test_fake_contract_is_not_claimed_as_real_qa(self):
        # Synthetic stand-in checks only our consumer adaptation, not Alva binary compatibility.
        class FakeComponent:
            def __init__(self, name, function):self.name,self.fn=name,function
        class FakeCall:
            def __init__(self,response):
                self.response=response
                self.execution_state="RESPONSE_AVAILABLE"
                self.diagnostics={"status":"ok","result":{"visibility":"SCOPE_ONLY"}}
        class FakeScope:
            def __init__(self,comp):self.comp=comp
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def invoke_with_diagnostics(self,request):
                assert request["operation"]=="blackbox.report.inspect"
                return FakeCall({"status":"ok","result":self.comp.fn(request["payload"])})
        class FakeHost:
            def __init__(self,parts,**k):self.comp=parts[0]
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def open_scope(self,**k):return FakeScope(self.comp)
        from types import ModuleType
        root=ModuleType("alva");root.Component=FakeComponent;root.__version__="simulated"
        host=ModuleType("alva.host");host.ComponentHost=FakeHost
        with tempfile.TemporaryDirectory() as tmp:
            store=SessionStore(Path(tmp),33)
            store.write_sample(Sample(10,100,1.0,1,None,None,0))
            folder=store.folder;store.finish("COMPLETED");store.close()
            with patch.dict(sys.modules,{"alva":root,"alva.host":host}):
                result=inspect_platform(folder)
            self.assertEqual(result["status"],"invoked")
            self.assertEqual(result["application_result"]["root_cause"],"UNKNOWN")
            self.assertFalse(result["provenance_verified"])
            self.assertEqual(result["diagnostic_visibility"],"SCOPE_ONLY")

    def test_missing_session_is_real_failure(self):
        class FakeComponent:
            pass
        from types import ModuleType
        root=ModuleType("alva");root.Component=FakeComponent
        host=ModuleType("alva.host");host.ComponentHost=FakeComponent
        with patch.dict(sys.modules,{"alva":root,"alva.host":host}):
            with self.assertRaises(ObserverError):
                inspect_platform(Path("missing-session-directory"))
