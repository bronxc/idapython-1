from idc import *
from idautils import *
from sets import Set

DEBUG=False

EXEMPT_RANGES=[(0x00010734, 0x00010890), (0x000162AA, 0x00025508), (0x000399F4, 0x00039D5A)]
MAXDEPTH=15

def dprint(s):
	if DEBUG == True:
		print(s)

class CallNode:
	def __init__(self, ea, parent=None):
		self.childs = set()
		self.name = GetFunctionName(ea).rstrip()
		self.ea = ea
		self.start_ea = GetFunctionAttr(ea, FUNCATTR_START)
		self.end_ea = GetFunctionAttr(ea, FUNCATTR_END)
		self.parent = parent

	def _function_contains(self, ea):
		if ea >= self.start_ea and ea <= self.end_ea:
			return True
		
		for (s_ea, e_ea) in Chunks(self.start_ea):
			if ea >= s_ea and ea <= e_ea:
				return True

		return False

	def _exempt_range(self, ea):
		for (s_ea, s_end) in EXEMPT_RANGES:
			if ea >= s_ea and ea <= s_end:
				return True

		return False

	def calls(self):
		calls = set()

		for (s_ea, e_ea) in Chunks(self.start_ea):
			for head in Heads(s_ea, e_ea):
				refs = CodeRefsFrom(head, 0)
				refs = calls.update(filter(lambda x: not self._function_contains(x) and not self._exempt_range(x), refs))
				# TODO: calls to imported functions?

		for c_ea in calls:
			dprint("new child: %x\n" %(c_ea))
			self.childs.add(CallNode(c_ea, parent=self))

def find_childs(ea, indent=0, depth=0):
	cnode = CallNode(ea)
	if depth >= MAXDEPTH and MAXDEPTH != 0:
		return

	cnode.calls()

	print("%s* %s@%x" %(" "*indent, cnode.name, cnode.ea))
	if not cnode.childs: # leaf
		return

	for ccnode in cnode.childs:
		dprint("checking child %x\n" %(ccnode.ea))
		find_childs(ccnode.ea, indent+2, depth+1)

start_ea = ScreenEA()
snode = CallNode(start_ea)
find_childs(snode.ea)
