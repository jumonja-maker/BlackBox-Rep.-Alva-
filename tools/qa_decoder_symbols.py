"""Real compiler-generated C13 lines/inline acceptance, without target execution."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT)]
from blackbox_core.decoder_native_symbols import load_native_symbols


def build_probe(output):
    clang,linker=shutil.which('clang'),shutil.which('lld-link')
    if not clang or not linker:
        raise RuntimeError('REAL_CLANG_LLD_REQUIRED')
    source=ROOT/'tools/fixtures/NativeSymbolLinesProbe/probe.c'
    obj,pe,pdb=output/'probe.obj',output/'probe.exe',output/'probe.pdb'
    subprocess.run([clang,'--target=x86_64-pc-windows-msvc','-g','-gcodeview','-O2',
        '-c',str(source),'-o',str(obj)],check=True,timeout=40,capture_output=True)
    subprocess.run([linker,'/debug','/nodefaultlib','/entry:entry','/subsystem:console',
        '/out:'+str(pe),'/pdb:'+str(pdb),'/map:'+str(output/'probe.map'),str(obj)],
        check=True,timeout=40,capture_output=True)
    return source,pe,pdb


def require(condition,reason):
    if not condition:raise AssertionError(reason)


def review_probe(output):
    source,pe,pdb=build_probe(output)
    before=[hashlib.sha256(p.read_bytes()).hexdigest() for p in (pe,pdb)]
    table=load_native_symbols(pe,pdb)
    leaf=[(a,b,site) for a,b,site in table.inline_sites if site['name']=='inline_leaf']
    require(bool(leaf),'COMPILER_INLINE_LEAF_REQUIRED')
    cases=[];llvm=shutil.which('llvm-symbolizer')
    for start,end,site in leaf:
        row=table.lookup(start)
        require(row['name']=='blackbox_outer','OUTER_PROCEDURE_MISMATCH')
        require(row['source_location']['line']==9,'CALL_SITE_LINE_MISMATCH')
        require([v['name'] for v in row['inline_frames']]==['inline_parent','inline_leaf'],
                'NESTED_INLINE_CHAIN_MISMATCH')
        parent,child=row['inline_frames']
        require(parent['source_location']['line']==6 and child['source_location']['line'] in (2,3),
                'INLINE_BODY_SOURCE_LINE_MISMATCH')
        require(all(x['source_location']['file']=='probe.c' for x in row['inline_frames']),
                'SOURCE_BASENAME_MISMATCH')
        case={'rva':start,'end_rva':end,'lookup':row}
        if llvm:
            text=subprocess.run([llvm,'--obj='+str(pe),'--relative-address','--inlines',hex(start)],
                check=True,timeout=20,capture_output=True,text=True).stdout
            (output/f'llvm-symbolizer-{start:x}.txt').write_text(text,encoding='utf-8')
            parts=[x for x in text.splitlines() if x]
            require(len(parts)>=6 and parts[0]=='inline_leaf' and parts[2]=='inline_parent' and
                    parts[4]=='blackbox_outer','LLVM_INLINE_ORDER_DISAGREEMENT')
            for pos,line in [(1,child['source_location']['line']),(3,6),(5,9)]:
                require(parts[pos].endswith(f':{line}:0'),'LLVM_SOURCE_LINE_DISAGREEMENT')
            case['independent_llvm_symbolizer']='MATCH'
        cases.append(case)
    checksum=hashlib.md5(source.read_bytes(),usedforsecurity=False).hexdigest()
    require(all(s[2]['checksum']==checksum for s in table.source_lines), 'SOURCE_CHECKSUM_DISAGREEMENT')
    require([hashlib.sha256(p.read_bytes()).hexdigest() for p in (pe,pdb)]==before,
            'INPUT_PE_PDB_CHANGED')
    return {'status':'PASS','scope':'REAL_OPTIMIZED_CLANG_LLD_CODEVIEW_FILES_NO_TARGET_EXECUTION',
        'source_sha':os.environ.get('GITHUB_SHA'),'symbol_table':table.summary(),'cases':cases,
        'independent_llvm_symbolizer':'CHECKED' if llvm else 'NOT_INSTALLED',
        'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
        'omap_acceptance':'SEPARATE_FORMAT_TESTS_NOT_OPTIMIZER_PRODUCED_BINARY',
        'portable_pdb_jit_mapping':'NOT_CLAIMED','network_symbol_lookup':False}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    result={'status':'FAILED'}
    try:
        result=review_probe(args.output)
    except BaseException as exc:
        result.update(error=type(exc).__name__,reason=str(exc)[:400]);raise
    finally:
        (args.output/'symbols-qa.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print('DECODER_SYMBOLS_QA_PASS')


if __name__=='__main__':main()
