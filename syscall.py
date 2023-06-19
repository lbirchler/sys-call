#!/usr/bin/env python
import argparse
import datetime
import json
import pathlib
import sys
from urllib.request import Request
from urllib.request import urlopen

ARCHS = ('arm', 'arm64', 'x64', 'x86')
URL = 'https://api.syscall.sh/v1/syscalls'
SYSCALL_DB = pathlib.Path.cwd() / 'syscalldb.json'
CONVENTIONS = {
    'x86': {'nr': 'eax', 'return': 'eax', 'arg0': 'ebx', 'arg1': 'ecx', 'arg2': 'edx', 'arg3': 'esi', 'arg4': 'edi', 'arg5': 'ebp'},
    'x64': {'nr': 'rax', 'return': 'rax', 'arg0': 'rdi', 'arg1': 'rsi', 'arg2': 'rdx', 'arg3': 'r10', 'arg4': 'r8', 'arg5': 'r9'},
    'arm': {'nr': 'r7', 'return': 'r0', 'arg0': 'r0', 'arg1': 'r1', 'arg2': 'r2', 'arg3': 'r3', 'arg4': 'r4', 'arg5': 'r5'},
    'arm64': {'arch': 'arm64', 'nr': 'x8', 'return': 'x0', 'arg0': 'x0', 'arg1': 'x1', 'arg2': 'x2', 'arg3': 'x3', 'arg4': 'x4', 'arg5': 'x5'},
}


def get_request(url: str) -> None | bytes:
  try:
    req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urlopen(req) as res:
      return res.read() if res.getcode() == 200 else None
  except Exception as e:
    print('Request error: %r' % e)
    return None


def update_syscall_db() -> None:
  db = {}
  db['last_updated_ts'] = datetime.datetime.now().replace(microsecond=0).isoformat()
  for arch in ARCHS:
    data = get_request(f'{URL}/{arch}')
    if data: db[arch] = json.loads(data)
  with open(SYSCALL_DB, 'w') as f:
    json.dump(db, f, indent=4)
    print('Saved syscall db to: %s' % SYSCALL_DB)


def get_syscall(
    arch: str,
    syscall: str | int | None = None
) -> list[dict] | None:
  key = 'name' if isinstance(syscall, str) else 'nr'
  with open(SYSCALL_DB) as f:
    syscalls = json.load(f)
  if not syscall: return syscalls.get(arch)
  try:
    return [next(sc for sc in syscalls.get(arch) if sc.get(key) == syscall)]
  except StopIteration:
    print(f'Invalid {arch} syscall: {syscall}')
    return None


def display_syscall(sc: dict) -> None:
  call = CONVENTIONS.get(sc.get('arch'))
  pad = 50 - 10 - len(sc.get('name'))
  header = f'{sc.get("nr"):<3} {sc.get("name")} {" "*pad} {sc.get("arch")}'
  print(header)
  print('+' * 50)
  for k, v in sc.items():
    if not k or k in ['refs', 'arch', 'name', 'nr'] or not v: continue
    left = f'{k:<7} {call.get(k, "").rstrip()}'
    print(f'{left:<15}: {v}')
  print('')


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('arch', choices=sorted(ARCHS), default='x64')
  parser.add_argument('--syscall', help='syscall name or number')
  # parser.add_argument('--update', action='store_true', help='Update syscall db')

  if len(sys.argv) < 2:
    parser.print_usage()
    sys.exit(1)

  args = parser.parse_args()

  # if args.update: update_syscall_db()
  scs = get_syscall(args.arch, args.syscall)
  if scs:
    for sc in scs: display_syscall(sc)


if __name__ == '__main__':
  main()
