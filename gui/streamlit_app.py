"""Optional local-only Streamlit presentation layer for Ithoka Security Labs."""

from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

from lab.dashboard import (
    archive_evidence,
    collect_evidence,
    construct,
    destroy_experiment,
    dispose,
    experiment_records,
    init_experiment,
    inspect_experiment,
    lab_overview,
    list_experiments,
    reset_experiment,
    stop_experiment,
    validate_and_plan,
)
from lab.foundation import LabError, ROOT, ensure_inside


st.set_page_config(page_title="Ithoka Security Lab", page_icon="🔬", layout="wide")
st.title("Ithoka Security Lab")
st.caption("Local observation and control surface. The CLI and Python control plane remain authoritative.")


def show_error(error: Exception) -> None:
    st.error(str(error))


overview = lab_overview(ROOT)
col1, col2, col3 = st.columns(3)
col1.metric("Backend", overview["backend"])
col2.metric("Preflight record", "Recorded" if overview["preflight_recorded"] else "Not recorded")
col3.metric("Approved capabilities", len(overview["capabilities"]))

with st.expander("Lab overview and readiness record", expanded=True):
    st.json({key: value for key, value in overview.items() if key != "preflight_inventory"})
    if overview["preflight_inventory"]:
        st.code(overview["preflight_inventory"], language="text")
    else:
        st.info("Run scripts/preflight.sh from WSL before attempting runtime construction.")

st.header("Experiments")
experiments = list_experiments(ROOT)
experiment_ids = [item["experiment_id"] for item in experiments]
selected_id = st.selectbox("Initialized experiment", [""] + experiment_ids)

with st.expander("Initialize workspace", expanded=not bool(experiment_ids)):
    new_id = st.text_input("New experiment ID", placeholder="lowercase-and-hyphens")
    if st.button("Initialize empty workspace", type="primary"):
        try:
            path = init_experiment(new_id, ROOT)
            st.success(f"Initialized workspace: {path}")
            st.rerun()
        except (LabError, OSError, ValueError) as error:
            show_error(error)
if selected_id:
    try:
        metadata = inspect_experiment(selected_id, ROOT)
        st.subheader(f"Experiment: `{selected_id}`")
        st.json(metadata)

        records = experiment_records(selected_id, ROOT)
        st.subheader("Run timeline and records")
        if records:
            st.dataframe(records, use_container_width=True)
        else:
            st.info("No bounded command records have been captured.")

        action_tab, construction_tab, evidence_tab = st.tabs(
            ["Lifecycle", "Construct apparatus", "Evidence"]
        )
        with action_tab:
            if st.button("Stop experiment"):
                try:
                    stop_experiment(selected_id, ROOT)
                    st.success("Experiment stopped.")
                    st.rerun()
                except (LabError, OSError, ValueError) as error:
                    show_error(error)
            if st.button("Reset mutable workspace"):
                st.warning("Reset removes mutable workspace contents but preserves collected evidence.")
                if st.checkbox("Confirm reset", key=f"reset-{selected_id}"):
                    try:
                        reset_experiment(selected_id, ROOT)
                        st.success("Experiment reset.")
                        st.rerun()
                    except (LabError, OSError, ValueError) as error:
                        show_error(error)
            if st.button("Destroy experiment"):
                st.warning("Destroy removes the workspace. Collected evidence is preserved separately.")
                if st.checkbox("Confirm destruction", key=f"destroy-{selected_id}"):
                    try:
                        destroy_experiment(selected_id, ROOT)
                        st.success("Experiment destroyed; preserved evidence remains staged.")
                        st.rerun()
                    except (LabError, OSError, ValueError) as error:
                        show_error(error)

        with construction_tab:
            st.caption("The specification must be inside the lab root. Approval still requires REQUIRE_RUNTIME_APPROVAL=true.")
            specification_text = st.text_input(
                "Specification path relative to lab root",
                placeholder="state/specifications/my-investigation.yaml",
            )
            authorization = st.text_input("Construction authorization rationale")
            if st.button("Validate and generate plan"):
                try:
                    specification = ensure_inside(ROOT, ROOT / specification_text, "specification")
                    plan_path = validate_and_plan(specification, selected_id, ROOT)
                    st.success(f"Plan written to {plan_path}")
                    st.json(json.loads(plan_path.read_text(encoding="utf-8")))
                except (LabError, OSError, ValueError, json.JSONDecodeError) as error:
                    show_error(error)
            if st.button("Construct approved apparatus"):
                if not authorization.strip():
                    st.error("An authorization rationale is required.")
                else:
                    try:
                        specification = ensure_inside(ROOT, ROOT / specification_text, "specification")
                        result = construct(specification, selected_id, authorization, ROOT)
                        st.success(f"Constructed project {result['project']}")
                    except (LabError, OSError, ValueError) as error:
                        show_error(error)
            if st.button("Dispose constructed apparatus"):
                if st.checkbox("Confirm apparatus disposal", key=f"dispose-{selected_id}"):
                    try:
                        specification = ensure_inside(ROOT, ROOT / specification_text, "specification")
                        dispose(specification, selected_id, ROOT)
                        st.success("Constructed apparatus disposed.")
                    except (LabError, OSError, ValueError) as error:
                        show_error(error)

        with evidence_tab:
            st.caption("Only explicitly selected files under the lab root can be collected.")
            source_text = st.text_input(
                "Evidence source path relative to lab root",
                placeholder="state/experiments/my-id/records/command.json",
            )
            if st.button("Collect selected evidence"):
                try:
                    source = ensure_inside(ROOT, ROOT / source_text, "evidence source")
                    manifest = collect_evidence(selected_id, [source], ROOT)
                    st.success(f"Evidence collected: {manifest}")
                except (LabError, OSError, ValueError) as error:
                    show_error(error)
            st.divider()
            archive_source = st.text_input(
                "Evidence directory relative to lab root",
                placeholder="state/experiments/local-study-01/evidence",
            )
            archive_destination = st.text_input(
                "Existing archive directory relative to lab root",
                placeholder="state/archives",
            )
            if st.button("Hash and archive evidence"):
                try:
                    source = ensure_inside(ROOT, ROOT / archive_source, "evidence directory")
                    destination = ensure_inside(ROOT, ROOT / archive_destination, "archive destination")
                    manifest = archive_evidence(source, destination, ROOT)
                    st.success(f"Evidence archived and verified: {manifest}")
                except (LabError, OSError, ValueError) as error:
                    show_error(error)
    except (LabError, OSError, ValueError, json.JSONDecodeError) as error:
        show_error(error)
