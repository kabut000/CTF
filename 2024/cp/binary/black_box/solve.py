import angr 
import claripy

p = angr.Project("./chall", load_options={"auto_load_libs": False})
code = claripy.BVS("code", 8*30)
state = p.factory.entry_state(stdin=code)
simgr = p.factory.simulation_manager(state)

addr_main = p.loader.main_object.get_symbol('main').rebased_addr
addr_correct = addr_main + 490
addr_wrong = addr_main + 409

simgr.explore(find=addr_correct, avoid=addr_wrong)
try:
    found = simgr.found[0]
    print(found.solver.eval(code, cast_to=bytes))
except:
    print("Not Found")
    