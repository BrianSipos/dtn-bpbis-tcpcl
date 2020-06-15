'''
Implementation of a symmetric BPv6 agent.
'''

import sys
from multiprocessing import Process
import tcpcl.agent as agent

if __name__ == '__main__':
    cl_agent = Process(target=agent.main, args=tuple(sys.argv))
    cl_agent.start()
    cl_agent.join()
    sys.exit(0)
