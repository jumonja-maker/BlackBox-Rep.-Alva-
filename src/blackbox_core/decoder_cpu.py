"""Conservative CPU-event classification, independent of stack availability.

ETW is accepted only with a typed SampledProfile projection and its exact
provider/event/opcode contract. DPC/ISR and unknown attribution are counted
separately, never charged to application work. One record = one occurrence;
Count, elapsed time, arbitrary GC stacks and PMC samples are not CPU weight.
"""
from .decoder_modules import address_value, integer
from .decoder_profiles import SAMPLE_PROVIDER, SAMPLE_EVENT

ETW_PROVIDER = "Windows Kernel"
ETW_PROVIDER_GUID = "9e814aad-3204-11d2-9a82-006008a86939"
ETW_EVENT = "PerfInfo/Sample"
CPU_SCHEMA = "blackbox.cpu-sample/1"
CPU_SOURCES = {"dotnet": (SAMPLE_PROVIDER, SAMPLE_EVENT),
               "etw": (ETW_PROVIDER, ETW_EVENT)}


def validate_cpu_sample(row):
    """Optional additive contract; older indexes remain readable, not upgraded."""
    sample = row.get("cpu_sample")
    if sample is None:
        return None
    fields = {"schema", "source", "parser", "instruction_pointer",
              "processor_index", "executing_dpc", "executing_isr"}
    if (type(sample) is not dict or set(sample) != fields or
            sample["schema"] != CPU_SCHEMA or
            sample["source"] != "ETW_KERNEL_PROFILE" or
            sample["parser"] != "TRACEEVENT_SAMPLED_PROFILE" or
            row.get("provider") != ETW_PROVIDER or row.get("name") != ETW_EVENT or
            row.get("provider_guid") != ETW_PROVIDER_GUID or
            type(row.get("event_id")) is not int or row["event_id"] != 65535 or
            type(row.get("opcode")) is not int or row["opcode"] != 46 or
            not integer(row.get("version"), 0, 255) or
            not integer(sample["processor_index"], 0, 65535) or
            any(value is not None and type(value) is not bool for value in
                (sample["executing_dpc"], sample["executing_isr"])) or
            ((sample["executing_dpc"] is None) != (sample["executing_isr"] is None))):
        raise ValueError("INVALID_CPU_SAMPLE_CONTRACT")
    if row["version"] < 2 and sample["executing_dpc"] is not None:
        raise ValueError("INVALID_CPU_ATTRIBUTION_VERSION")
    address_value(sample["instruction_pointer"])
    # A partial generic payload is allowed. Contradictory recorded fields are not.
    payload = row.get("payload", {})
    for key, value in (("InstructionPointer", int(sample["instruction_pointer"], 16)),
                       ("ExecutingDPC", sample["executing_dpc"]),
                       ("ExecutingISR", sample["executing_isr"])):
        if key in payload and value is not None:
            if type(payload[key]) is not type(value) or payload[key] != value:
                raise ValueError("CONFLICTING_CPU_SAMPLE_FIELDS")
    return sample


def classify_cpu_sample(row, source):
    """Classification is a claim from imported bytes, not OS authentication."""
    if type(source) is not str or source not in CPU_SOURCES:
        raise ValueError("INVALID_CPU_SOURCE")
    sample = validate_cpu_sample(row)
    if (row.get("provider"), row.get("name")) != CPU_SOURCES[source]:
        return "OTHER_SOURCE"
    if source == "dotnet":
        # Preserve the pre-existing SampleProfiler adapter for legacy indexes.
        return "PROCESS_SAMPLE"
    if sample is None:
        return "TYPED_CLASSIFICATION_MISSING"
    if sample["executing_dpc"] or sample["executing_isr"]:
        return "DPC_ISR_SAMPLE"
    if (sample["executing_dpc"] is None or sample["executing_isr"] is None or
            not integer(row.get("pid"), 1) or not integer(row.get("tid"), 1)):
        return "ATTRIBUTION_UNKNOWN"
    return "PROCESS_SAMPLE"


class CpuSampleAudit:
    def __init__(self):
        self.etw = {key: 0 for key in ("PROCESS_SAMPLE", "DPC_ISR_SAMPLE",
                                      "ATTRIBUTION_UNKNOWN", "TYPED_CLASSIFICATION_MISSING")}

    def accept(self, row):
        kind = classify_cpu_sample(row, "etw")
        if kind in self.etw:
            self.etw[kind] += 1

    def summary(self):
        return {"contract": CPU_SCHEMA, "etw_candidates": sum(self.etw.values()),
                "etw_classification": self.etw.copy(),
                "weight": "ONE_EVENT_OCCURRENCE_NOT_PAYLOAD_COUNT",
                "sample_interval_and_cpu_percent": "NOT_ESTABLISHED",
                "verification_class": "UNVERIFIED_IMPORT"}
