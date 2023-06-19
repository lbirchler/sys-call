#!/usr/bin/env python
import argparse
import json
import os
import pathlib
import sys
from datetime import datetime
from threading import Thread
from urllib.request import Request
from urllib.request import urlopen

from rich.console import Console
from rich.table import Table

_debug = os.environ.get('DEBUG')

ARCHS = ('arm', 'arm64', 'x64', 'x86')
PLATFORMS = ('Linux/ARM', 'Linux/x86', 'Linux/x86-x64', 'x86')
SYSCALL_DB = pathlib.Path.cwd() / 'syscalldb.json'

CONVENTIONS = {
    'x86': {
        'return': 'eax',
        'arg0': 'ebx',
        'arg1': 'ecx',
        'arg2': 'edx',
        'arg3': 'esi',
        'arg4': 'edi',
        'arg5': 'ebp'
    },
    'x64': {
        'return': 'rax',
        'arg0': 'rdi',
        'arg1': 'rsi',
        'arg2': 'rdx',
        'arg3': 'r10',
        'arg4': 'r8',
        'arg5': 'r9'
    },
    'arm': {
        'return': 'r0',
        'arg0': 'r0',
        'arg1': 'r1',
        'arg2': 'r2',
        'arg3': 'r3',
        'arg4': 'r4',
        'arg5': 'r5'
    },
    'arm64': {
        'return': 'x0',
        'arg0': 'x0',
        'arg1': 'x1',
        'arg2': 'x2',
        'arg3': 'x3',
        'arg4': 'x4',
        'arg5': 'x5'
    },
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
def warning(msg: str): print(Color.yellow(f'[*] {msg}'))
def debug(msg: str): print(Color.blue(f'[=] {msg}')) if _debug else print('', file=open('/dev/null', 'w'))


def get_request(url: str) -> None | bytes:
  try:
    with urlopen(Request(url, headers={'User-Agent': 'Mozilla/5.0'})) as f:
      return f.read()
  except Exception as e:
    error('Request error: %r' % e)
    return None


def update_syscall_db() -> None:
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
  key = 'nr' if str(syscall).isnumeric() else 'name'
  with open(SYSCALL_DB) as f:
    syscalls = json.load(f)
  return next((item for item in syscalls.get(arch) if item.get(key) == syscall), None)


class Syscalls:

  def __init__(self, arch: str) -> None:
    self.arch = arch
    with open(SYSCALL_DB) as f:
      self._syscalls = json.load(f).get(self.arch)
    self._conventions = CONVENTIONS.get(self.arch)

  def search(self, syscall: str) -> None | dict:
    return next((item for item in self._syscalls if item.get('name') == syscall), None)

  def display(self, syscalls: list[str] | None = None) -> None:
    table = Table(title=f'{self.arch} Syscalls')
    scs = [self.search(sc) for sc in syscalls] if syscalls else self._syscalls
    if any(sc is None for sc in scs):
      error(f'Invalid {self.arch} syscall(s): {" ".join(syscalls)}')
      return
    cols = [
        (f'{k:<7} {self._conventions.get(k, "")}'.rstrip())
        for k in scs[0].keys()
        if k not in ['refs', 'arch']
    ]
    for col in cols: table.add_column(col)
    for sc in scs: table.add_row(*[str(v) for k, v in list(sc.items()) if k not in ['refs', 'arch']])
    console = Console()
    console.print(table)


def main():
  parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
  parser.add_argument(
      'arch',
      metavar='arch',
      nargs='?',
      choices=sorted(ARCHS),
      help=', '.join(ARCHS),
      default='x64'
  )
  parser.add_argument(
      'syscall',
      nargs='*',
      help='syscall name or number'
  )
  parser.add_argument(
      '--update',
      action='store_true',
      help='Update syscall database'
  )

  if len(sys.argv) < 2:
    parser.print_usage()
    sys.exit(1)

  args = parser.parse_args()

  if args.update:
    update_syscall_db()
    sys.exit(0)

  Syscalls(args.arch).display([sc for sc in args.syscall])


if __name__ == '__main__':
  main()
