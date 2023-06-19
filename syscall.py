#!/usr/bin/env python
import argparse
import json
import pathlib
import sys
from datetime import datetime
from threading import Thread
from urllib.request import Request
from urllib.request import urlopen

ARCHS = ('arm', 'arm64', 'x64', 'x86')
SYSCALL_DB = pathlib.Path.cwd() / 'syscalldb.json'
CONVENTIONS = {
    'x86': {'return': 'eax', 'arg0': 'ebx', 'arg1': 'ecx', 'arg2': 'edx', 'arg3': 'esi', 'arg4': 'edi', 'arg5': 'ebp'},
    'x64': {'return': 'rax', 'arg0': 'rdi', 'arg1': 'rsi', 'arg2': 'rdx', 'arg3': 'r10', 'arg4': 'r8', 'arg5': 'r9'},
    'arm': {'return': 'r0', 'arg0': 'r0', 'arg1': 'r1', 'arg2': 'r2', 'arg3': 'r3', 'arg4': 'r4', 'arg5': 'r5'},
    'arm64': {'return': 'x0', 'arg0': 'x0', 'arg1': 'x1', 'arg2': 'x2', 'arg3': 'x3', 'arg4': 'x4', 'arg5': 'x5'},
}


class Color():
  @staticmethod
  def red(msg): return f'\033[91m{msg}\033[0m'

  @staticmethod
  def green(msg): return f'\033[92m{msg}\033[0m'

  @staticmethod
  def yellow(msg): return f'\033[93m{msg}\033[0m'

  @staticmethod
  def blue(msg): return f'\033[94m{msg}\033[0m'

  @staticmethod
  def cyan(msg): return f'\033[36m{msg}\033[0m'


def info(msg: str): print(Color.green(f'[+] {msg}'))
def error(msg: str): print(Color.red(f'[!] {msg}'))
def debug(msg: str): print(Color.blue(f'[=] {msg}'))
def warning(msg: str): print(Color.yellow(f'[*] {msg}'))


def get_request(url: str) -> None | bytes:
  try:
    with urlopen(Request(url, headers={'User-Agent': 'Mozilla/5.0'})) as f:
      return f.read()
  except Exception as e:
    error('Request error: %r' % e)
    return None


def update_syscall_db_fast() -> None:
  def fetch(db: dict, arch: str):
    data = get_request(f'https://api.syscall.sh/v1/syscalls/{arch}')
    if data: db[arch] = json.loads(data)

  db = {}
  db['last_updated_ts'] = datetime.now().replace(microsecond=0).isoformat()
  threads = [Thread(target=fetch, args=(db, arch)) for arch in ARCHS]
  for thread in threads: thread.start()
  for thread in threads: thread.join()

  with open(SYSCALL_DB, 'w') as f:
    json.dump(db, f, indent=4)
    info('Saved syscall db to: %s' % SYSCALL_DB)


def get_syscall(arch: str, syscall: str | int) -> None | dict:
  key = 'name' if isinstance(syscall, str) else 'nr'
  with open(SYSCALL_DB) as f:
    syscalls = json.load(f)
  return next((item for item in syscalls.get(arch) if item.get(key) == syscall), None)

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
