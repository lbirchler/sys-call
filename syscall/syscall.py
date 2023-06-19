from __future__ import annotations

import argparse
import html
import json
import os
import pathlib
import re
import sys
from collections import namedtuple
from datetime import datetime
from threading import Thread
from urllib.request import Request
from urllib.request import urlopen

from rich.console import Console
from rich.table import Table

_debug = os.environ.get('PYDEBUG')

ARCHS = ('arm', 'arm64', 'x64', 'x86')
DEFAULT_ARCH = 'x64'
SYSCALL_DB = pathlib.Path(__file__).parent / 'syscalldb.json'

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
def warning(msg: str): print(Color.yellow(f'[*] {msg}'))
def debug(msg: str): print(Color.blue(f'[-] {msg}')) if _debug else print('', file=open('/dev/null', 'w'))


def get_request(url: str) -> None | bytes:
  try:
    with urlopen(Request(url, headers={'User-Agent': 'Mozilla/5.0'})) as f:
      debug(f'{f.status} - {url}')
      return f.read()
  except Exception as e:
    error('Request error: %r' % e)
    return None


def update_syscall_db() -> None:
  def fetch(db: dict, arch: str):
    data = get_request(f'https://api.syscall.sh/v1/syscalls/{arch}')
    if data:
      db[arch] = json.loads(data)
      info(f'Updated {arch} syscalls')

  db = {
      'last_updated_ts': datetime.now().replace(microsecond=0).isoformat(),
      'source': 'https://syscall.sh/'
  }
  threads = [Thread(target=fetch, args=(db, arch)) for arch in ARCHS]
  for thread in threads: thread.start()
  for thread in threads: thread.join()

  with open(SYSCALL_DB, 'w') as f:
    json.dump(db, f, indent=4)
    info('Saved syscall db to: %s' % SYSCALL_DB)


def print_table(title: str, cols: list, rows: list):
  table = Table(title=title)
  for col in cols: table.add_column(col)
  for row in rows: table.add_row(*row)
  console = Console()
  console.print(table, markup=False)


class Syscalls:

  def __init__(self, arch: str) -> None:
    self.arch = arch
    if not SYSCALL_DB.exists(): update_syscall_db()
    with open(SYSCALL_DB) as f:
      self._syscalls = json.load(f).get(self.arch)
    self._conventions = CONVENTIONS.get(self.arch)

  def search(self, syscall: str) -> None | dict:
    return next((item for item in self._syscalls if item.get('name') == syscall), None)

  def display(self, syscalls: list[str] | None = None) -> None:
    scs = [self.search(sc) for sc in syscalls] if syscalls else self._syscalls
    if any(sc is None for sc in scs):
      error(f'Invalid {self.arch} syscall(s): {" ".join(syscalls)}')
      return
    print_table(
        title=f'{self.arch} Syscalls',
        cols=[
            (f'{k:<7} {self._conventions.get(k, "")}'.rstrip())
            for k in scs[0].keys()
            if k not in ['refs', 'arch']
        ],
        rows=[
            [str(v) for k, v in list(sc.items()) if k not in ['refs', 'arch']]
            for sc in scs
        ]
    )


class Shellcode:

  Example = namedtuple('Example', ['author', 'platform', 'desc', 'id'])

  def __init__(self, arch: str):
    self.arch = arch

    if 'arm' in self.arch: self.platform = 'Linux/ARM'
    elif self.arch == 'x86': self.platform = 'Linux/x86'
    elif self.arch == 'x64': self.platform = 'Linux/x86-64'

  def search(self, syscall: str) -> list[Example]:
    data = get_request(f'http://shell-storm.org/api/?s={syscall}')
    if not data: error('Unable to find shellcode examples for: %s' % syscall); return
    examples = data.decode().split('\n')
    examples = (e.split('::::') for e in examples)
    examples = (self.Example(*e[:-1]) for e in examples if len(e) == 5)
    return list(e for e in examples if self.platform in e.platform)

  def get(self, sid: int) -> None:
    data = get_request(f'http://shell-storm.org/shellcode/files/shellcode-{sid}.html')
    if not data: error('Invalid shellcode id: %d' % sid); return
    match = re.search(r'<pre[^>]*>([^<]+)</pre>', data.decode())
    if match: print(html.unescape(match.group(1)))

  def display(self, syscalls: list[str]) -> None:
    examples = []
    for sc in syscalls: examples.extend(self.search(sc))
    if any(ex is None for ex in examples): return
    print_table(
        title=f'{self.arch} Shellcode',
        cols=[col for col in examples[0]._fields],
        rows=[ex._asdict().values() for ex in examples]
    )


def main():
  parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
  parser.add_argument(
      '-a', '--arch',
      choices=sorted(ARCHS),
      help=f'\t defaults to {DEFAULT_ARCH}',
      default=DEFAULT_ARCH,
  )

  cmd_parser = parser.add_subparsers(dest='cmd', help='commands')

  info_parser = cmd_parser.add_parser('info')
  info_parser.add_argument('--update', action='store_true', help='Update syscall database')
  info_parser.add_argument('syscall', nargs='*', help='syscall name(s)')

  shellcode_parser = cmd_parser.add_parser('shellcode')
  shellcode_parser.add_argument('--get', type=int, help='download shell-storm example; specify id')
  shellcode_parser.add_argument('syscall', nargs='*', help='syscall name(s)')

  if len(sys.argv) < 2:
    parser.print_usage()
    sys.exit(1)

  args = parser.parse_args()

  if args.cmd == 'info':
    if args.update:
      sys.exit(update_syscall_db())
    Syscalls(args.arch).display([sc for sc in args.syscall])
  if args.cmd == 'shellcode':
    shellcode = Shellcode(args.arch)
    if args.get:
      shellcode.get(args.get)
    else:
      shellcode.display([sc for sc in args.syscall])
