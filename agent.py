#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, pathlib, re, sys
from appsec_agent import __version__
from appsec_agent.policy import load_policy, validate_url
from appsec_agent.engine import run

def main():
    ap=argparse.ArgumentParser(prog="artemis", description="ARTEMIS: Autonomous Application Security Testing Platform")
    ap.add_argument("--version", action="version", version=f"ARTEMIS {__version__}")
    ap.add_argument("--policy",default="policy.json")
    ap.add_argument("--run-id",default="run-001")
    ap.add_argument("--openapi")
    ap.add_argument("--scenarios")
    ap.add_argument("--workflow")
    ap.add_argument("--catalog",default=str(pathlib.Path(__file__).resolve().parent/"test_catalog.json"))
    ap.add_argument("--sarif",action="append",default=[])
    ap.add_argument("--sarif-only",action="store_true",help="Import SARIF findings without contacting the target")
    ap.add_argument("--provider",choices=["offline","openai","anthropic"],default=None)
    ap.add_argument("--dry-run",action="store_true")
    ap.add_argument("--max-iterations",type=int,default=None)
    ap.add_argument("--hint",action="append",default=[],help="Add a planner hint for this run; may be repeated")
    ap.add_argument("--validate-catalog",action="store_true",help="Validate catalog schema and exit without network traffic")
    ap.add_argument("--validate-state",nargs="?",const="runs/run-001/blackboard.json",default=None,
                    help="Validate a saved blackboard graph and exit (optional path; defaults to runs/run-001/blackboard.json)")
    args=ap.parse_args()
    if args.validate_state is not None:
        from appsec_agent.blackboard import Blackboard
        state_path=pathlib.Path(args.validate_state)
        if not state_path.exists():
            ap.error(f"Blackboard state file does not exist: {state_path}")
        board=Blackboard(state_path)
        result=board.validate_graph()
        print(json.dumps({"path":str(state_path), **result},indent=2))
        if not result["valid"]:
            raise SystemExit(2)
        return
    provider=(args.provider or os.environ.get("AI_PROVIDER","offline")).lower()
    if args.validate_catalog:
        from pathlib import Path
        cat=json.loads(Path(args.catalog).read_text(encoding="utf-8"))
        ids=[x.get("id") for x in cat.get("runnable_tests",[])]
        if not ids or len(ids)!=len(set(ids)):
            ap.error("Catalog runnable_tests must have unique non-empty IDs")
        print(json.dumps({"valid":True,"runnable_test_count":len(ids),"framework_count":len(cat.get("frameworks",{}))},indent=2))
        return
    if args.sarif_only:
        if not args.sarif:
            ap.error("--sarif-only requires at least one --sarif file")
        from appsec_agent.evidence import EvidenceStore
        from appsec_agent.sarif import import_sarif
        from appsec_agent.report import build_coverage, write_report
        catalog=json.loads(pathlib.Path(args.catalog).read_text(encoding="utf-8"))
        run_id=re.sub(r"[^A-Za-z0-9_.-]","_",args.run_id)
        run_dir=pathlib.Path("runs")/run_id
        store=EvidenceStore(run_dir)
        count=import_sarif(args.sarif,store)
        findings=[]
        fp=run_dir/"findings.jsonl"
        if fp.exists():
            findings=[json.loads(line) for line in fp.read_text(encoding="utf-8").splitlines() if line.strip()]
        coverage=build_coverage(catalog,[],findings,[],test_statuses={})
        (run_dir/"coverage.json").write_text(json.dumps(coverage,indent=2)+"\n",encoding="utf-8")
        summary={"run_id":run_id,"target":None,"provider":"none","requests_used":0,"sarif_findings_imported":count,
                 "findings_count":len(findings),"note":"SARIF-only mode; no target requests sent."}
        (run_dir/"run_summary.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
        write_report(run_dir,summary,findings,coverage)
        print(json.dumps(summary,indent=2))
        return
    if provider not in ("offline","openai","anthropic"): ap.error("provider must be offline, openai, or anthropic")
    policy=load_policy(args.policy)
    if args.dry_run:
        targets=[]
        for path in policy.get("baseline_paths",["/"]):
            from urllib.parse import urljoin
            url=urljoin(policy["base_url"].rstrip("/")+"/",path.lstrip("/"))
            validate_url(policy,url,"GET",resolve_dns=False)
            targets.append(url)
        scenario_count=0
        if args.scenarios:
            from appsec_agent.scenarios import load_scenarios, validate_scenario
            for scenario in load_scenarios(args.scenarios):
                if scenario.get("enabled"):
                    validate_scenario(scenario,policy,check_dns=False)
                    scenario_count += 1
        print(json.dumps({"target":policy["base_url"],"targets":targets,"allowed_hosts":policy["allowed_hosts"],
            "allowed_methods":policy["allowed_methods"],"max_requests":policy["max_requests"],"provider":provider,
            "enabled_scenarios_validated":scenario_count,"network_requests":0,"enabled_tests":policy.get("enabled_tests",[])},indent=2))
        return
    if provider=="openai" and not os.environ.get("OPENAI_API_KEY"): ap.error("Set OPENAI_API_KEY or use --provider offline")
    if provider=="anthropic" and not os.environ.get("ANTHROPIC_API_KEY"): ap.error("Set ANTHROPIC_API_KEY or use --provider offline")
    run_id=re.sub(r"[^A-Za-z0-9_.-]","_",args.run_id)
    run_dir=pathlib.Path("runs")/run_id
    result=run(policy,run_dir,provider=provider,openapi_path=args.openapi,scenarios_path=args.scenarios,
               workflow_path=args.workflow,catalog_path=args.catalog,sarif_paths=args.sarif,max_iterations=args.max_iterations,
               hints=args.hint)
    print(json.dumps(result,indent=2))

if __name__=="__main__": main()
