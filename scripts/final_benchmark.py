"""Real Qwen-only versus Qwen-selected MCP tool benchmark. No synthetic outputs."""
import asyncio
import json
import re
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parents[1]
MODEL = 'qwen3.5:4b-q4_K_M'
ENDPOINT = 'http://127.0.0.1:11434/api/chat'
CASES = json.loads((ROOT / 'benchmarks' / 'url_cases.json').read_text())
# Fixed, balanced subset of the existing synthetic cases; do not tune on outputs.
SELECTED = [*CASES[:5], *CASES[16:21]]
assert len(SELECTED) == 10 and len({x['id'] for x in SELECTED}) == 10
TOOL = {'type':'function','function':{'name':'inspect_url',
 'description':'Assess the URL with the SUS.NOT deterministic security tool; use for URL assessments.',
 'parameters':{'type':'object','properties':{'url':{'type':'string'}},
 'required':['url'],'additionalProperties':False}}}


def parse_baseline(text):
    """Require explicit JSON rather than infer a label from free-form prose."""
    cleaned = text.strip()
    if cleaned.startswith('```'):
        cleaned = re.sub(r'^```(?:json)?\s*|\s*```$', '', cleaned).strip()
    value = json.loads(cleaned)
    if not isinstance(value, dict) or value.get('label') not in ('benign','suspicious'):
        raise ValueError('Expected JSON with label benign or suspicious')
    return value['label']


async def query(client, messages, tools=None):
    payload = {'model':MODEL,'stream':False,'options':{'num_ctx':8192,'temperature':0},
               'messages':messages}
    if tools is not None:
        payload['tools'] = tools
    response = await client.post(ENDPOINT,json=payload)
    response.raise_for_status()
    body = response.json()
    if not isinstance(body.get('message'),dict):
        raise ValueError('Missing model message')
    return body['message']


async def run_one(client, session, case, mode, repeat):
    start = time.monotonic()
    row = {'id':case['id'],'repeat':repeat,'mode':mode,
           'expected_label':case['expected_label'],'url':case['url'],
           'scenario_rationale':case['rationale'],'model':MODEL,
           'label_source':'synthetic scenario; not verified fraud'}
    try:
        if mode == 'baseline':
            messages = [
              {'role':'system','content':('Assess only the supplied URL string. No browsing or tools. '
               'Return ONLY JSON of the form {"label":"benign"} or {"label":"suspicious"}. '
               'You cannot verify website safety from the URL alone; choose the most likely label.')},
              {'role':'user','content':f'Classify this URL string: {case["url"]}'}]
            message = await query(client,messages)
            row['model_response'] = message.get('content','')
            row['predicted_label'] = parse_baseline(row['model_response'])
        else:
            messages = [
              {'role':'system','content':('You are a safety URL investigator. Call inspect_url for the supplied URL. '
               'Do not fabricate a tool result. Do not alter the URL.')},
              {'role':'user','content':f'Investigate this URL with inspect_url: {case["url"]}'}]
            message = await query(client,messages,[TOOL])
            calls = message.get('tool_calls') or []
            row['model_tool_calls'] = calls
            if len(calls) != 1 or calls[0].get('function',{}).get('name') != 'inspect_url':
                raise ValueError('Model did not select exactly one authorized inspect_url call')
            args = calls[0]['function'].get('arguments')
            if isinstance(args,str):
                args = json.loads(args)
            if not isinstance(args,dict) or args != {'url':case['url']}:
                raise ValueError('Model tool arguments were altered or invalid')
            result = await session.call_tool('inspect_url',args)
            if result.is_error or not isinstance(result.structured_content,dict):
                raise ValueError('MCP tool error or missing structured response')
            content = result.structured_content
            row['mcp_result'] = content
            score = content.get('sus_score')
            if isinstance(score,bool) or not isinstance(score,int) or not 0 <= score <= 100:
                raise ValueError('Invalid SUS score')
            # This is the project's established HIGH warning threshold, not a fraud probability.
            row['predicted_label'] = 'suspicious' if score >= 60 else 'benign'
        row['correct'] = row['predicted_label'] == row['expected_label']
        row['status'] = 'ok'
    except Exception as exc:
        row['status'] = 'error'
        row['error'] = f'{type(exc).__name__}: {str(exc)[:240]}'
        row['correct'] = False
    row['elapsed_seconds'] = round(time.monotonic()-start,3)
    return row


def summarize(rows):
    results = {}
    for mode in ('baseline','tool'):
        relevant = [r for r in rows if r['mode'] == mode]
        runs = []
        for repeat in (1,2,3):
            group = [r for r in relevant if r['repeat'] == repeat]
            assert len(group) == 10
            runs.append(sum(r['correct'] for r in group)/len(group))
        results[mode] = {
          'per_run_accuracy':runs,
          'mean_accuracy':statistics.mean(runs),
          'sample_sd_accuracy':statistics.stdev(runs),
          'correct_total':sum(r['correct'] for r in relevant),
          'total':len(relevant),
          'failed_executions':sum(r['status'] != 'ok' for r in relevant),
          'mean_latency_seconds':round(statistics.mean(r['elapsed_seconds'] for r in relevant),3),
        }
    return results


async def main():
    output = ROOT / 'evidence' / 'block9_comparison.json'
    output.parent.mkdir(exist_ok=True)
    rows = []
    # Resume completed executions from the existing checkpoint.
    completed = set()
    if output.exists():
        previous = json.loads(output.read_text())
        if previous.get('status') == 'complete':
            print('Benchmark already complete:', output)
            return
        rows.extend(previous.get('rows', []))
        completed = {
            (row['id'], row['repeat'], row['mode'])
            for row in rows
        }
        print(f'Resuming benchmark: {len(rows)}/60 executions already saved.', flush=True)

    params = StdioServerParameters(command=sys.executable,args=['-m','backend.mcp_server'],cwd=str(ROOT))
    async with httpx.AsyncClient(timeout=180,trust_env=False,follow_redirects=False) as client:
        async with stdio_client(params) as (reader,writer):
            async with ClientSession(reader,writer) as session:
                await session.initialize()
                names = {tool.name for tool in (await session.list_tools()).tools}
                if 'inspect_url' not in names:
                    raise RuntimeError('inspect_url not exposed by MCP')
                for repeat in (1,2,3):
                    for case in SELECTED:
                        for mode in ('baseline','tool'):
                            if (case['id'], repeat, mode) in completed:
                                continue
                            print(
                                f'Starting {len(rows)+1}/60: '
                                f'{mode} / {case["id"]} / repeat {repeat}',
                                flush=True,
                            )
                            row = await run_one(client,session,case,mode,repeat)
                            rows.append(row)
                            print(f'{len(rows):02d}/60 {mode:8} {case["id"]:15} '
                                  f'{row["status"]:5} correct={row["correct"]}',flush=True)
                            # Checkpoint every real execution; interrupted runs remain auditable.
                            output.write_text(json.dumps({'status':'incomplete','rows':rows},indent=2))
    metrics = summarize(rows)
    artifact = {'status':'complete','timestamp_utc':datetime.now(timezone.utc).isoformat(),
      'comparison':'Qwen-only versus Qwen-selected MCP tool',
      'method':'10 existing labelled synthetic URL scenarios; 3 repeats per system; same URL prompts',
      'caveats':['Scenario labels are synthetic, not verified fraud or real-world accuracy.',
                 'URL-only methods cannot infer the scenario context from the URL.',
                 'Tool output is a deterministic heuristic, not a calibrated probability.',
                 'Model output formatting/tool-selection errors count as incorrect.',
                 'Sequential executions are not blinded or independent samples.'],
      'metrics':metrics,'rows':rows}
    output.write_text(json.dumps(artifact,indent=2))
    failures = [r for r in rows if not r['correct']]
    report = ROOT/'evidence'/'block9_report.md'
    report.write_text('# SUS.NOT — Block 9 measured comparison\n\n'
      'Both systems ran locally on Qwen3.5-4B. Synthetic scenario labels are not real-world ground truth.\n\n'
      '| System | Runs | Mean accuracy | Sample SD | Errors | Mean latency |\n|---|---:|---:|---:|---:|---:|\n'
      + ''.join(f'| {mode} | 3 × 10 | {m["mean_accuracy"]:.1%} | {m["sample_sd_accuracy"]:.1%} | '
        f'{m["failed_executions"]} | {m["mean_latency_seconds"]:.2f}s |\n'
        for mode,m in metrics.items())
      + '\n## First observed failure (actual trace)\n\n'
      + ('```json\n'+json.dumps(failures[0],indent=2)+'\n```\n' if failures else
         'No incorrect executions observed; inspect raw traces for limitations.\n')
      + '\n## Limits\n\nURL strings alone do not establish fraud. '
        'The SUS score is a heuristic; results are not real-world safety accuracy.\n')
    print('\nCOMPLETE: ',output,'\nREPORT: ',report,'\nMETRICS:',json.dumps(metrics,indent=2))

if __name__ == '__main__':
    asyncio.run(main())
