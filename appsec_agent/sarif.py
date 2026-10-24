from __future__ import annotations
import json, pathlib, time

def import_sarif(paths,store):
    count=0
    for path in paths or []:
        data=json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        for run in data.get("runs",[]):
            tool=run.get("tool",{}).get("driver",{}).get("name","Unknown SARIF tool")
            rule_map={r.get("id"):r for r in run.get("tool",{}).get("driver",{}).get("rules",[])}
            for result in run.get("results",[]):
                rule=result.get("ruleId","unknown")
                rule_meta=rule_map.get(rule,{})
                level=result.get("level","warning")
                severity={"error":"high","warning":"medium","note":"low","none":"info"}.get(level,"medium")
                locs=result.get("locations",[])
                uri=None
                if locs:
                    uri=locs[0].get("physicalLocation",{}).get("artifactLocation",{}).get("uri")
                store.finding({"timestamp":time.time(),"check":"sarif_import","title":result.get("message",{}).get("text",rule_meta.get("shortDescription",{}).get("text",rule)),
                    "severity":severity,"confidence":"external-tool","source_tool":tool,"rule_id":rule,"url":uri,
                    "details":{"level":level,"help_uri":rule_meta.get("helpUri"),"tags":rule_meta.get("properties",{}).get("tags",[])}})
                count+=1
    return count
